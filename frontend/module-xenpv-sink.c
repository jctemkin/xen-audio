/***
  This file is part of PulseAudio.

  Copyright 2004-2006 Lennart Poettering

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#include "pulseaudio/config.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <poll.h>

#include <pulse/xmalloc.h>

#include <pulsecore/core-error.h>
#include <pulsecore/sink.h>
#include <pulsecore/module.h>
#include <pulsecore/core-util.h>
#include <pulsecore/modargs.h>
#include <pulsecore/log.h>
#include <pulsecore/thread.h>
#include <pulsecore/thread-mq.h>
#include <pulsecore/rtpoll.h>

#include <sys/select.h>
#include <xenctrl.h>
#include <xs.h>

#include "module-xenpv-sink-symdef.h"
#include "grant.h"

PA_MODULE_AUTHOR("Lennart Poettering");
PA_MODULE_DESCRIPTION("UNIX pipe sink");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(FALSE);
PA_MODULE_USAGE(
        "sink_name=<name for the sink> "
        "sink_properties=<properties for the sink> "
        "file=<path of the FIFO> "
        "format=<sample format> "
        "rate=<sample rate>"
        "channels=<number of channels> "
        "channel_map=<channel map>");

#define DEFAULT_FILE_NAME "fifo_output"
#define DEFAULT_SINK_NAME "fifo_output"

int device_id = -1;
enum xenbus_state
{
	XenbusStateUnknown      = 0,
	XenbusStateInitialising = 1,
	XenbusStateInitWait     = 2,  /* Finished early
					 initialisation, but waiting
					 for information from the peer
					 or hotplug scripts. */
	XenbusStateInitialised  = 3,  /* Initialised and waiting for a
					 connection from the peer. */
	XenbusStateConnected    = 4,
	XenbusStateClosing      = 5,  /* The device is being closed
					 due to an error or an unplug
					 event. */
	XenbusStateClosed       = 6,

	/*
	* Reconfiguring: The device is being reconfigured.
	*/
	XenbusStateReconfiguring = 7,

	XenbusStateReconfigured  = 8
};

struct userdata {
    pa_core *core;
    pa_module *module;
    pa_sink *sink;

    pa_thread *thread;
    pa_thread_mq thread_mq;
    pa_rtpoll *rtpoll;

//modify for xen event channel fd & grant
    char *filename;
    int fd;
//
    pa_memchunk memchunk;

    pa_rtpoll_item *rtpoll_item;

    int write_type;
};

#define BUFSIZE 2048

struct ring {
    uint8_t buffer[BUFSIZE];
    uint32_t cons_indx, prod_indx;
    //rest of variables
} *ioring;

static const char* const valid_modargs[] = {
    "sink_name",
    "sink_properties",
    "file",
    "format",
    "rate",
    "channels",
    "channel_map",
    NULL
};

// Xen globals
/*xc_evtchn_t, xc_interface */
static int xch, xce, xen_evtchn_port;
static struct xs_handle *xsh;

struct ioctl_gntalloc_alloc_gref gref;
int total_bytes;

int alloc_gref(struct ioctl_gntalloc_alloc_gref *gref, void **addr);
int ring_write(struct ring *r, void *src, int length);
int ring_wait_for_event();
int publish_spec(pa_sample_spec *ss);
int read_spec(pa_sample_spec *ss);
int publish_param(char *paramname, char *value);
int publish_param_int(char *paramname, int value);
char* read_param(char *paramname);

static int sink_process_msg(pa_msgobject *o, int code, void *data, int64_t offset, pa_memchunk *chunk) {
    struct userdata *u = PA_SINK(o)->userdata;

    switch (code) {

        case PA_SINK_MESSAGE_GET_LATENCY: {
            size_t n = 0;
            int l;

#ifdef FIONREAD
            if (ioctl(u->fd, FIONREAD, &l) >= 0 && l > 0)
                n = (size_t) l;
#endif

            n += u->memchunk.length;

            *((pa_usec_t*) data) = pa_bytes_to_usec(n, &u->sink->sample_spec);
            return 0;
        }
    }

    return pa_sink_process_msg(o, code, data, offset, chunk);
}

static int process_render(struct userdata *u) {
    pa_assert(u);

    if (u->memchunk.length <= 0)
        pa_sink_render(u->sink, pa_pipe_buf(u->fd), &u->memchunk);

    pa_assert(u->memchunk.length > 0);

    for (;;) {
        ssize_t l;
        void *p;

        p = pa_memblock_acquire(u->memchunk.memblock);
	    //xen: write data to ring buffer & notify backend
        l = ring_write(ioring, (uint8_t*)p + u->memchunk.index, u->memchunk.length);
        xc_evtchn_notify(xce, xen_evtchn_port);
        pa_memblock_release(u->memchunk.memblock);

        pa_assert(l != 0);

        if (l < 0) {

            if (errno == EINTR)
                continue;
            else if (errno == EAGAIN)
                return 0;
            else {
                pa_log("Failed to write data to FIFO: %s", pa_cstrerror(errno));
                return -1;
            }

        } else {

            u->memchunk.index += (size_t) l;
            u->memchunk.length -= (size_t) l;

            if (u->memchunk.length <= 0) {
                pa_memblock_unref(u->memchunk.memblock);
                pa_memchunk_reset(&u->memchunk);
            }
        }

        return 0;
    }
}

static void thread_func(void *userdata) {
    struct userdata *u = userdata;

    pa_assert(u);

    pa_log_debug("Thread starting up");

    pa_thread_mq_install(&u->thread_mq);

    for (;;) {
        struct pollfd *pollfd;
        int ret;

        pollfd = pa_rtpoll_item_get_pollfd(u->rtpoll_item, NULL);

        /* Render some data and write it to the fifo */
        if (PA_SINK_IS_OPENED(u->sink->thread_info.state)) {

            if (u->sink->thread_info.rewind_requested)
                pa_sink_process_rewind(u->sink, 0);

            if (pollfd->revents) {
                if (process_render(u) < 0)
                    goto fail;

                pollfd->revents = 0;
            }
        }

        /* Hmm, nothing to do. Let's sleep */

        pollfd->events = (short) (u->sink->thread_info.state == PA_SINK_RUNNING ? POLLOUT : 0);

        if ((ret = pa_rtpoll_run(u->rtpoll, TRUE)) < 0)
            goto fail;

        if (ret == 0)
            goto finish;

        pollfd = pa_rtpoll_item_get_pollfd(u->rtpoll_item, NULL);

        if (pollfd->revents & ~POLLOUT) {
            pa_log("FIFO shutdown.");
            goto fail;
        }
    }

fail:
    /* If this was no regular exit from the loop we have to continue
     * processing messages until we received PA_MESSAGE_SHUTDOWN */
    pa_asyncmsgq_post(u->thread_mq.outq, PA_MSGOBJECT(u->core), PA_CORE_MESSAGE_UNLOAD_MODULE, u->module, 0, NULL, NULL);
    pa_asyncmsgq_wait_for(u->thread_mq.inq, PA_MESSAGE_SHUTDOWN);

finish:
    pa_log_debug("Thread shutting down");
}

int pa__init(pa_module*m) {
    struct userdata *u;
    struct stat st;
    pa_sample_spec ss;
    pa_channel_map map;
    pa_modargs *ma;
    struct pollfd *pollfd;
    pa_sink_new_data data;
    char keybuf[128], valbuf[32];
    char *buf;
    char *out; int len;
    char **vec;
    unsigned int my_domid, num_strings;

    total_bytes = 0;
    int ret;
    pa_assert(m);

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log("Failed to parse module arguments.");
        goto fail;
    }

    //Xen init
    xsh = xs_domain_open();
    if(xsh==NULL){ pa_log("xs_domain_open failed"); goto fail; }

    xch = xc_interface_open(NULL, NULL, 0);
    if(xch==0){ pa_log("xc_interface_open failed"); goto fail; }

    xce = xc_evtchn_open(NULL, 0);
    if(xce==0){ pa_log("xc_evtchn_open failed"); goto fail; }

    //use only dom0 as the backend for now
    xen_evtchn_port = xc_evtchn_bind_unbound_port(xce, 0);
    if(xen_evtchn_port<0){ pa_log("xc_evtchn_bind_unbound_port failed"); }

    //get grant reference & map locally
    ret = alloc_gref(&gref, (void**)&ioring);
    device_id = 0;//(int)gref.gref_ids[0];

    my_domid = atoi(xs_read(xsh, 0, "domid", &len));

    //post event chan & grant reference to xenstore
    publish_param_int("event-channel", xen_evtchn_port);
    publish_param_int("ring-ref", gref.gref_ids[0]);

    ss = m->core->default_sample_spec;
    map = m->core->default_channel_map;
    if (pa_modargs_get_sample_spec_and_channel_map(ma, &ss, &map, PA_CHANNEL_MAP_DEFAULT) < 0) {
        pa_log("Invalid sample format specification or channel map");
        goto fail;
    }

    //// Start negiotiation
    //
    //1. publish frontend parameters
    publish_spec(&ss);

    //2. set watch on backend state
    snprintf(keybuf, sizeof(keybuf), "/local/domain/0/backend/audio/%d/%d/state", my_domid, device_id);
    if (!xs_watch(xsh, keybuf, "mytoken")) perror("xs_watch");

    //3. read the backend state
    //XenbusStateInitialising := backend has not responded yet
    //XenbusStateReconfiguring := sample spec unsupported
    //XenbusStateInitialised := sample spec OK
    int backend_state = 0;
    // read initial state and discard
    if(!(vec=xs_read_watch(xsh, &num_strings))) perror("xs_read_watch");

    //4. wait for backend response
    do{
        if(!(vec=xs_read_watch(xsh, &num_strings))) perror("xs_read_watch");
        
        printf("vec contents: %s|%s\n", vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN]);

        buf = xs_read(xsh, 0, vec[XS_WATCH_PATH], &len);
        backend_state = atoi(buf);
    } while(backend_state!=XenbusStateInitialised && \
            backend_state!=XenbusStateReconfiguring);
    
    //5. Two outcomes:

    //backend rejected sample spec?
    if(backend_state!=XenbusStateInitialised){
        //simple fallback; accept backend's parameters
        read_spec(&ss);
    }
    /*else: sample spec was accepted, go on*/

    publish_param_int("state", XenbusStateInitialised);
    //
    ////End of negotiation
    
    /*
    if(!(vec=xs_read_watch(xsh, &num_strings))) perror("xs_read_watch");
    printf("vec contents: %s|%s\n", vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN]);
    */
    
    //set status to initialised


    u = pa_xnew0(struct userdata, 1);
    u->core = m->core;
    u->module = m;
    m->userdata = u;
    pa_memchunk_reset(&u->memchunk);
    u->rtpoll = pa_rtpoll_new();
    pa_thread_mq_init(&u->thread_mq, m->core->mainloop, u->rtpoll);
    u->write_type = 0;

    //init ring buffer
    ioring->prod_indx = ioring->cons_indx = 0;

    pa_sink_new_data_init(&data);
    data.driver = __FILE__;
    data.module = m;
    pa_sink_new_data_set_name(&data, pa_modargs_get_value(ma, "sink_name", DEFAULT_SINK_NAME));
    pa_proplist_sets(data.proplist, PA_PROP_DEVICE_STRING, "xensink");//u->filename);
    pa_proplist_setf(data.proplist, PA_PROP_DEVICE_DESCRIPTION, "Xen PV audio sink", u->filename);
    pa_sink_new_data_set_sample_spec(&data, &ss);
    pa_sink_new_data_set_channel_map(&data, &map);

    if (pa_modargs_get_proplist(ma, "sink_properties", data.proplist, PA_UPDATE_REPLACE) < 0) {
        pa_log("Invalid properties");
        pa_sink_new_data_done(&data);
        goto fail;
    }

    u->sink = pa_sink_new(m->core, &data, PA_SINK_LATENCY);
    pa_sink_new_data_done(&data);

    if (!u->sink) {
        pa_log("Failed to create sink.");
        goto fail;
    }

    u->sink->parent.process_msg = sink_process_msg;
    u->sink->userdata = u;

    pa_sink_set_asyncmsgq(u->sink, u->thread_mq.inq);
    pa_sink_set_rtpoll(u->sink, u->rtpoll);
    //pa_sink_set_max_request(u->sink, pa_pipe_buf(u->fd));
    //pa_sink_set_fixed_latency(u->sink, pa_bytes_to_usec(pa_pipe_buf(u->fd), &u->sink->sample_spec));

    u->rtpoll_item = pa_rtpoll_item_new(u->rtpoll, PA_RTPOLL_NEVER, 1);
    //pollfd = pa_rtpoll_item_get_pollfd(u->rtpoll_item, NULL);
    //pollfd->fd = u->fd;
    //pollfd->events = pollfd->revents = 0;

    if (!(u->thread = pa_thread_new(thread_func, u))) {
        pa_log("Failed to create thread.");
        goto fail;
    }

    pa_sink_put(u->sink);

    pa_modargs_free(ma);

    return 0;

fail:
    if (ma)
        pa_modargs_free(ma);

    pa__done(m);

    return -1;
}

int pa__get_n_used(pa_module *m) {
    struct userdata *u;

    pa_assert(m);
    pa_assert_se(u = m->userdata);

    return pa_sink_linked_by(u->sink);
}

void pa__done(pa_module*m) {
    struct userdata *u;
    char keybuf[64];

    pa_assert(m);

    if (!(u = m->userdata))
        return;

    if (u->sink)
        pa_sink_unlink(u->sink);

    if (u->thread) {
        pa_asyncmsgq_send(u->thread_mq.inq, NULL, PA_MESSAGE_SHUTDOWN, NULL, 0, NULL);
        pa_thread_free(u->thread);
    }

    pa_thread_mq_done(&u->thread_mq);

    if (u->sink)
        pa_sink_unref(u->sink);

    if (u->memchunk.memblock)
       pa_memblock_unref(u->memchunk.memblock);

    if (u->rtpoll_item)
        pa_rtpoll_item_free(u->rtpoll_item);

    if (u->rtpoll)
        pa_rtpoll_free(u->rtpoll);

    if (u->filename) {
        unlink(u->filename);
        pa_xfree(u->filename);
    }

    if (u->fd >= 0)
        pa_assert_se(pa_close(u->fd) == 0);

    pa_xfree(u);

    snprintf(keybuf, sizeof(keybuf), "device/audio/%d", device_id);
    //delete xenstore keys
    xs_rm(xsh, 0, keybuf);

    //munmap((void*)gref.index, 4096);

    //close xen interfaces
    xc_evtchn_close(xce);
    xc_interface_close(xch);
    xs_daemon_close(xsh);
}


int alloc_gref(struct ioctl_gntalloc_alloc_gref *gref, void **addr)
{
    int alloc_fd, dev_fd, rv;
    alloc_fd = open("/dev/xen/gntalloc", O_RDWR);
    dev_fd = open("/dev/xen/gntdev", O_RDWR);

    /*use dom0*/
    gref->domid = 0;
    gref->flags = GNTALLOC_FLAG_WRITABLE;
    gref->count = 1;

    rv = ioctl(alloc_fd, IOCTL_GNTALLOC_ALLOC_GREF, gref);
    if (rv) {
        printf("src-add error: %s (rv=%d)\n", strerror(errno), rv);
        return rv;
    }

    /*addr=NULL(default),length, prot,             flags,    fd,   offset*/
    *addr = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, alloc_fd, gref->index);
    if (*addr == MAP_FAILED) {
        *addr = 0;
        printf("mmap failed: SHOULD NOT HAPPEN\n");
        return rv;
    }

    printf("Got grant #%d. Mapped locally at %Ld=%p\n",
            gref->gref_ids[0], gref->index, *addr);

    /* skip this for now
       struct ioctl_gntalloc_unmap_notify uarg = {
       .index = gref->index + offsetof(struct shr_page, notifies[0]),
       .action = UNMAP_NOTIFY_CLEAR_BYTE
       };

       rv = ioctl(a_fd, IOCTL_GNTALLOC_SET_UNMAP_NOTIFY, &uarg);
       if (rv)
       printf("gntalloc unmap notify error: %s (rv=%d)\n", strerror(errno), rv);
       */

    close(alloc_fd);
    close(dev_fd);

    return rv;
}

int ring_write(struct ring *r, void *src, int length)
{
#define RING_FREE_BYTES ((sizeof(r->buffer) - (r->prod_indx-r->cons_indx) -1) % sizeof(r->buffer))
    int full = 0;
    int total_bytes = 0;
    for(;;){
        //free space may be split over the end of the buffer
        int first_chunk_size = (sizeof(r->buffer)-r->prod_indx);
        int second_chunk_size = (r->cons_indx>=r->prod_indx)? (r->cons_indx) : 0;
        int l, fl, sl;

        //full?
        if(RING_FREE_BYTES==0) {
            //printf("XEN: Buffer is full: bufsize:%d prod_indx:%d consindx:%d, free:%d total:%d\n", sizeof(r->buffer), r->prod_indx, r->cons_indx,ring_free_bytes, total_bytes);
            //TODO This should be replaced by something that checks whether the backend is alive
            if(full>=100){
                errno = EINTR;
                return -1;
            }
            usleep(1000);
            //should return in 100ms max; definitely not midstream
            full++;
            continue;
        }

        //calculate lengths in case of a split buffer
        l = PA_MIN(RING_FREE_BYTES, length);
        fl = PA_MIN(l, first_chunk_size);
        sl = PA_MIN(l-fl, second_chunk_size);

        //copy to both chunks
        //printf("XEN: Copying chunks: bufsize:%d prod_indx:%d consindx:%d, free:%d, total:%d\n", sizeof(r->buffer), r->prod_indx, r->cons_indx, ring_free_bytes, total_bytes);
        //printf("XEN: Copying chunks: l%d fl:%d sl%d length:%d\n",l,fl,sl,length);
        memcpy(r->buffer+r->prod_indx, src, fl);
        if(sl)
            memcpy(r->buffer, src+fl, sl);
        r->prod_indx = (r->prod_indx+fl+sl) % sizeof(r->buffer);

        total_bytes += sl+fl;
        return sl+fl;
    }
}

int ring_wait_for_event()
{
    //puts("XEN:Blocking");
    //fflush(stdout);
	fd_set readfds;
	int xcefd, ret;
	struct timeval timeout;

	xcefd = xc_evtchn_fd(xce);
	FD_ZERO(&readfds);
	FD_SET(xcefd, &readfds);

	xc_evtchn_unmask(xce, xen_evtchn_port);

	timeout.tv_sec=1000;
	timeout.tv_usec=0;

	ret = select(xcefd+1, &readfds, NULL, NULL, &timeout);
        xc_evtchn_pending(xce);

	if(ret==-1) {
            perror("select() returned error while waiting for backend");
            return ret;
        }
	else if(ret && FD_ISSET(xcefd, &readfds)){
            return EAGAIN; //OK
        }

	else{
            perror("select() timed out while waiting for backend\n");
            return 0;
        }
}

int publish_param(char *paramname, char *value)
{
    char keybuf[128], valbuf[32];

    snprintf(keybuf, sizeof keybuf, "device/audio/%d/%s", device_id, paramname);
    snprintf(valbuf, sizeof valbuf, "%s", value);
    return xs_write(xsh, 0, keybuf, valbuf, strlen(valbuf));
}

int publish_param_int(char *paramname, int value)
{
    char keybuf[128], valbuf[32];
    snprintf(keybuf, sizeof keybuf, "device/audio/%d/%s", device_id, paramname);
    snprintf(valbuf, sizeof valbuf, "%d", value);
    return xs_write(xsh, 0, keybuf, valbuf, strlen(valbuf));
}

char* read_param(char *paramname)
{
    char keybuf[128], valbuf[32];
    int len;
    int my_domid;

    my_domid = atoi(xs_read(xsh, 0, "domid", &len));
    snprintf(keybuf, sizeof(keybuf), "/local/domain/0/backend/audio/%d/%d/%s", my_domid, device_id, paramname);
    //remember to free lvalue!
    return xs_read(xsh, 0, keybuf, &len);
}


int publish_spec(pa_sample_spec *ss){
    /* Publish spec and set state to XenbusStateInitWait*/
    int ret;

    ret = publish_param("format", pa_sample_format_to_string(ss->format));
    ret += publish_param_int("rate", ss->rate);
    ret += publish_param_int("channels", ss->channels);

    ret += publish_param_int("state", XenbusStateInitWait);
    return ret;
}


int read_spec(pa_sample_spec *ss){
    /*Read spec from backend*/
    char *out;

    out = read_param("default-format"); 
    ss->format = pa_parse_sample_format(out);
    free(out);

    out = read_param("default-rate"); 
    ss->rate = atoi(out);
    free(out);

    out = read_param("default-channels"); 
    ss->channels = atoi(out);
    free(out);

    return 0;
}
