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

int alloc_gref(struct ioctl_gntalloc_alloc_gref *gref, void **addr);

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

#define DEVID 0

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

struct ring {
    uint8_t buffer[2048];
    uint32_t cons_idx, prod_indx;
    //rest of variables
};

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

/*xc_evtchn_t, xc_interface */
static int xch, xce, event_channel_port;
static struct xs_handle *xsh;


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
        l = pa_write(u->fd, (uint8_t*) p + u->memchunk.index, u->memchunk.length, &u->write_type);
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
    char *out; int len;
    void *page;

    int ret;
    struct ioctl_gntalloc_alloc_gref gref;
    pa_assert(m);

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log("Failed to parse module arguments.");
        goto fail;
    }

    //xen init
    xsh = xs_domain_open();
    if(xsh==NULL){
        pa_log("xs_domain_open failed");
        goto fail;
    }
    xch = xc_interface_open();
    if(xch==0){
        pa_log("xc_interface_open failed");
        goto fail;
    }
    xce = xc_evtchn_open();
    if(xce==0){
        pa_log("xc_evtchn_open failed");
        goto fail;
    }
    //use only dom0 as the backend for now
    event_channel_port = xc_evtchn_bind_unbound_port(xce, 0);
    if(event_channel_port<0){
        pa_log("xc_evtchn_bind_unbound_port failed");
    }

    //get grant reference & map locally
    ret = alloc_gref(&gref, &page);

    //post event chan & grant reference to xenstore
    snprintf(keybuf, sizeof keybuf, "device/audio/%d/event-channel", DEVID);
    snprintf(valbuf, sizeof valbuf, "%d", event_channel_port);
    xs_write(xsh, 0, keybuf, valbuf, strlen(valbuf));
    snprintf(keybuf, sizeof keybuf, "device/audio/%d/ring-ref", DEVID);
    snprintf(valbuf, sizeof valbuf, "%d", gref.gref_ids[0]);
    xs_write(xsh, 0, keybuf, valbuf, strlen(valbuf));

    //wait for backend to connect
    //xc_evtchn_pending(event_channel_port);
    sleep(10);
    //send notification
    xc_evtchn_notify(xce, event_channel_port);

    puts(page);
    goto fail; ///////////////testing

    /*
    snprintf(keybuf, sizeof keybuf, "device/audio/%d/ring-ref", DEVID);
    snprintf(valbuf, sizeof valbuf, "%d", grantref);
    xs_write(xsh, 0, keybuf, valbuf, strlen(valbuf));
    */
    //get sample spec from xen store

    /*
    snprintf(keybuf, sizeof keybuf, "/local/domain/0/backend/audio/%d/default-channels", DEVID);
    out = xs_read(xsh, 0, keybuf, &len);
    if (out==NULL){
        pa_log("Failed to read sample spec from xenstore");
        goto fail;
    }*/

    ss = m->core->default_sample_spec;
    map = m->core->default_channel_map;
    if (pa_modargs_get_sample_spec_and_channel_map(ma, &ss, &map, PA_CHANNEL_MAP_DEFAULT) < 0) {
        pa_log("Invalid sample format specification or channel map");
        goto fail;
    }

    u = pa_xnew0(struct userdata, 1);
    u->core = m->core;
    u->module = m;
    m->userdata = u;
    pa_memchunk_reset(&u->memchunk);
    u->rtpoll = pa_rtpoll_new();
    pa_thread_mq_init(&u->thread_mq, m->core->mainloop, u->rtpoll);
    u->write_type = 0;

    u->filename = pa_runtime_path(pa_modargs_get_value(ma, "file", DEFAULT_FILE_NAME));

    //todo xen : init ring buffer
    mkfifo(u->filename, 0666);
    if ((u->fd = open(u->filename, O_RDWR|O_NOCTTY)) < 0) {
        pa_log("open('%s'): %s", u->filename, pa_cstrerror(errno));
        goto fail;
    }

    pa_make_fd_cloexec(u->fd);
    pa_make_fd_nonblock(u->fd);

    if (fstat(u->fd, &st) < 0) {
        pa_log("fstat('%s'): %s", u->filename, pa_cstrerror(errno));
        goto fail;
    }

    if (!S_ISFIFO(st.st_mode)) {
        pa_log("'%s' is not a FIFO.", u->filename);
        goto fail;
    }
//
    pa_sink_new_data_init(&data);
    data.driver = __FILE__;
    data.module = m;
    pa_sink_new_data_set_name(&data, pa_modargs_get_value(ma, "sink_name", DEFAULT_SINK_NAME));
    pa_proplist_sets(data.proplist, PA_PROP_DEVICE_STRING, u->filename);
    pa_proplist_setf(data.proplist, PA_PROP_DEVICE_DESCRIPTION, "Unix FIFO sink %s", u->filename);
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
    pa_sink_set_max_request(u->sink, pa_pipe_buf(u->fd));
    pa_sink_set_fixed_latency(u->sink, pa_bytes_to_usec(pa_pipe_buf(u->fd), &u->sink->sample_spec));

    u->rtpoll_item = pa_rtpoll_item_new(u->rtpoll, PA_RTPOLL_NEVER, 1);
    pollfd = pa_rtpoll_item_get_pollfd(u->rtpoll_item, NULL);
    pollfd->fd = u->fd;
    pollfd->events = pollfd->revents = 0;

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

    snprintf(keybuf, sizeof(keybuf), "device/audio/%d", DEVID);
    //delete xenstore keys
    xs_rm(xsh, 0, keybuf);

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

        return rv;
}
