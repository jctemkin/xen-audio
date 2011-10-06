#include <stdio.h>
#include <sys/select.h>

#include <xenctrl.h>
#include <xs.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <pulse/simple.h>
#include <pulse/error.h>
#include <pulse/gccmacro.h>


#include "grant.h"

#define DEBUG 1

#define EVENT_TIMEOUT_SECONDS 60
#define BUFSIZE 2047

#if DEBUG
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

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

struct ring {
    uint32_t cons_indx, prod_indx;
    uint32_t usable_buffer_space; /* kept here for convenience */
    uint8_t buffer[BUFSIZE];
    //rest of variables
} *ioring;

int map_grant(int frontend_id, int grant_ref, struct ring **addr);
int ring_wait_for_event();
int publish_param(const char *paramname, const char *value);
int publish_param_int(const char *paramname, int value);
char* read_param(const char *paramname);
int read_frontend_spec(pa_sample_spec *ss);
int play_stream();
int wait_for_frontend_state_change();
int frontend_is_alive();
int set_state(int state);
int register_frontend_state_watch();

xc_interface* xci;
xc_evtchn* xce;
evtchn_port_t local_port, remote_port;

int frontend_domid;
int device_id;
/* default sample format to use */
static pa_sample_spec ss = {
    .format = PA_SAMPLE_S16LE,
    .rate = 44100,
    .channels = 2
};
int state_unknown_cb()
{
    DPRINTF("frontend state was XenbusStateUnknown\n");

    /* TODO: publish supported-*/
    publish_param("default-format", pa_sample_format_to_string(ss.format));
    publish_param_int("default-rate", ss.rate);
    publish_param_int("default-channels", ss.channels);


    return 0;
}

int state_initialising_cb()
{
    DPRINTF("frontend state was XenbusStateInitialising\n");
    set_state(XenbusStateInitialising);
    return 0;
}

int state_initwait_cb()
{
    DPRINTF("frontend state was XenbusStateInitWait\n");
    return 0;
}

int state_initialised_cb()
{
    pa_sample_spec frontss;
    DPRINTF("frontend state was XenbusStateInitialised\n");
    set_state(XenbusStateInitialised);
    /* negotiation cycle */
    read_frontend_spec(&frontss);

    if(pa_sample_spec_valid(&frontss) && 
            pa_usec_to_bytes(1000, &frontss) <= pa_usec_to_bytes(1000, &ss))
    {
        /* accept frontend params */
        read_frontend_spec(&ss);
        set_state(XenbusStateConnected);
    }
    else
    {
        /* reject; set state to reconfiguring and wait for frontend to post new parameters */
        set_state(XenbusStateReconfiguring);
    }

    return 0;
}

int state_connected_cb()
{
    /*TODO at this stage, we should check that the negotiation has gone through;
     * if not, the frontend might have been restored/etc.
     */
    set_state(XenbusStateConnected);
    int grant_ref;
    DPRINTF("frontend state was XenbusStateConnected\n");
    char *out;
    
    /* Phase 2: negotiation ended, continue initialization */
    out = read_param("event-channel");
    remote_port = atoi(out);
    free(out);

    out = read_param("ring-ref");
    grant_ref = atoi(out);
    free(out);


    char sss[100];
    pa_sample_spec_snprint(sss, 100, &ss);
    DPRINTF(sss);


    /* bind event channel */
    local_port = xc_evtchn_bind_interdomain(xce, frontend_domid, remote_port);

    /* map ioring to local space */
    map_grant(frontend_domid, grant_ref, &ioring);

    /* everything OK, end of Phase 2 */
    /* begin playback cycle */
    for(;;){
        if(play_stream()){
            DPRINTF("Stream timed out\n");

        }
        /* block until next event */
        ring_wait_for_event();

        if(!frontend_is_alive()){
            DPRINTF("Frontend died, exiting\n");
            return 1;
        }


    }
    return 0;
}

int state_closing_cb()
{
    DPRINTF("frontend state was XenbusStateClosing\n");
    return 0;
}

int state_closed_cb()
{
    DPRINTF("frontend state was XenbusStateClosed\n");
    return 0;
}

int state_reconfiguring_cb()
{
    DPRINTF("frontend state was XenbusStateReconfiguring\n");
    return 0;
}

int state_reconfigured_cb()
{
    DPRINTF("frontend state was XenbusStateReconfigured\n");
    return 0;
}

int (*state_callbacks[9])(void) = {
    state_unknown_cb,
    state_initialising_cb,
    state_initwait_cb,
    state_initialised_cb,
    state_connected_cb,
    state_closing_cb,
    state_closed_cb,
    state_reconfiguring_cb,
    state_reconfigured_cb
};


struct xs_handle *xsh;
int main(int argc,  char** argv)
{
    bool ret; /* xen error variable */
    int frontend_state;

    if(argc<2){
        fprintf(stderr, "Usage: %s <dom_id> \n", argv[0]);
        exit(2);
    }

    frontend_domid = atoi(argv[1]);

    device_id = 0; /* hardcoded for now */

    /* Basic Initialization */
    xsh = xs_domain_open();
    if(!xs_write(xsh, 0, "/local/domain/0/backend/audio", "", strlen(""))) {
        perror("xs_write");
    };
    xci = xc_interface_open(NULL/*log to stderr*/, NULL, 0);
    xce = xc_evtchn_open(NULL/*log to stderr*/, 0);
    if(register_frontend_state_watch()){
        //error
        perror("Failed to register frontend xenstore watch!");
    };

    set_state(XenbusStateUnknown);

    /* Begin State cycle */
    while(!ret){
        frontend_state = wait_for_frontend_state_change();
        ret = state_callbacks[frontend_state]();
    }

    /* Cleanup */
    set_state(XenbusStateClosing);

    munmap(ioring, 4096);
    xc_evtchn_close(xce);
    perror("xc_evtchn_close");
    xc_interface_close(xci);
    perror("xc_interface_close");


    set_state(XenbusStateClosed);
    xs_rm(xsh, 0, "/local/domain/0/backend/audio");
    xs_daemon_close(xsh);
    return 0;
}

int map_grant(int frontend_id, int grant_ref, struct ring **addr) {

    int dev_fd;
    int rv;
    struct ioctl_gntdev_map_grant_ref arg = {
        .count = 1,
        .refs[0].domid = frontend_id,
        .refs[0].ref = grant_ref,
    };

    dev_fd = open("/dev/xen/gntdev", O_RDWR);
    if(dev_fd<=0){
        perror("Could not open gntdev! Have you loaded the xen_gntdev module?");
        return 1;
    }

    rv = ioctl(dev_fd, IOCTL_GNTDEV_MAP_GRANT_REF, &arg);
    if (rv) {
        DPRINTF("Could not map grant %d.%d: %s (rv=%d)\n", frontend_id, grant_ref, strerror(errno), rv);
        return 1;
    }

    *addr = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, dev_fd, arg.index);
    if (*addr == MAP_FAILED) {
        *addr = 0;
        DPRINTF("Could not map grant %d.%d: %s (map failed) (rv=%d)\n", frontend_id, grant_ref, strerror(errno), rv);
        return 1;
    }

    //DPRINTF("Mapped grant %d.%d as %Ld=%p\n", frontend_id, grant_ref, arg.index, *addr);

    /*
       struct ioctl_gntdev_unmap_notify uarg = {
       .index = arg.index + offsetof(struct shr_page, notifies[j]),
       .action = UNMAP_NOTIFY_CLEAR_BYTE
       };
       rv = ioctl(d_fd, IOCTL_GNTDEV_SET_UNMAP_NOTIFY, &uarg);
       if (rv)
       DPRINTF("gntdev unmap notify error: %s (rv=%d)\n", strerror(errno), rv);
       */
    close(dev_fd);
    return 0;
}



int ring_wait_for_event()
{
    fd_set readfds;
    int xcefd;
    int ret;
    //DPRINTF("Blocking");
    struct timeval timeout;

    xcefd = xc_evtchn_fd(xce);
    FD_ZERO(&readfds);
    FD_SET(xcefd, &readfds);

    xc_evtchn_unmask(xce, local_port);

    timeout.tv_sec=EVENT_TIMEOUT_SECONDS;
    timeout.tv_usec=0;

    ret = select(xcefd+1, &readfds, NULL, NULL, &timeout);
    if(ret==-1) {
        perror("select() returned error while waiting for frontend");
        return ret;
    }
    else if(ret && FD_ISSET(xcefd, &readfds)){
        xc_evtchn_pending(xce);
        return 0; //OK
    }
    else{
        perror("select() timed out while waiting for frontend");
        return -1;
    }
}

char* read_param(const char *paramname)
{
    char keybuf[128];
    char *out;
    unsigned int len;

    snprintf(keybuf, sizeof(keybuf), "/local/domain/%d/device/audio/%d/%s", frontend_domid, device_id, paramname);
    //remember to free lvalue!
    out = xs_read(xsh, 0, keybuf, &len);
    return out;
}

int read_frontend_spec(pa_sample_spec *ss){
    char *out;

    out = read_param("format");
    ss->format = pa_parse_sample_format(out);
    free(out);

    out = read_param("rate");
    ss->rate = atoi(out);
    free(out);

    out = read_param("channels");
    ss->channels = atoi(out);
    free(out);

    return 0;
}

int publish_param(const char *paramname, const char *value)
{
    char keybuf[128], valbuf[32];
    snprintf(keybuf, sizeof keybuf, "/local/domain/0/backend/audio/%d/%d/%s", frontend_domid, device_id, paramname);
    snprintf(valbuf, sizeof valbuf, "%s", value);
    return xs_write(xsh, 0, keybuf, valbuf, strlen(valbuf));
}

int publish_param_int(const char *paramname, int value)
{
    char keybuf[128], valbuf[32];
    snprintf(keybuf, sizeof keybuf, "/local/domain/0/backend/audio/%d/%d/%s", frontend_domid, device_id, paramname);
    snprintf(valbuf, sizeof valbuf, "%d", value);
    return xs_write(xsh, 0, keybuf, valbuf, strlen(valbuf));
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


int register_frontend_state_watch(){
    char keybuf[128];

    snprintf(keybuf, sizeof(keybuf), "/local/domain/%d/device/audio/%d/state", frontend_domid, device_id);
    if (!xs_watch(xsh, keybuf, "xenpvaudiobackendsinktoken")) {
        perror("xs_watch failed");
        return -EINVAL;
    }

    return 0;
}

int wait_for_frontend_state_change()
{
    char *buf, **vec;
    unsigned int len;
    int frontend_state;
    int seconds;

    int xs_fd;
    struct timeval tv;
	fd_set watch_fdset;
    int start, now;

    frontend_state = -1;
    xs_fd = xs_fileno(xsh);
    start = now = time(NULL);

    seconds = EVENT_TIMEOUT_SECONDS;
	do {
		tv.tv_usec = 0;
		tv.tv_sec = (start + seconds) - now;
		FD_ZERO(&watch_fdset);
		FD_SET(xs_fd, &watch_fdset);
		if (select(xs_fd + 1, &watch_fdset, NULL, NULL, &tv)) {
			/* Read the watch to drain the buffer */
			vec = xs_read_watch(xsh, &len);

            buf = xs_read(xsh, XBT_NULL, vec[0], &len);
            if(buf == 0){
                /* usually means that the frontend isn't there yet */
                continue; 
            };
            frontend_state = atoi(buf);

            free(buf); 
            free(vec);
		}
	} while (frontend_state == -1 && (now = time(NULL)) < start + seconds);

    return frontend_state;
}

int play_stream()
{
    pa_simple *s = NULL;
    int empty = 0;
    int sync = 0; /* skip zeros in stream (frame alignment) */
    char buf[65536];
    int error;
    int stream_timeout = 0;
    int r = 0; int rl = 0;

    /* setup playback stream */
    if(!(s=pa_simple_new(NULL, "xen-backend", PA_STREAM_PLAYBACK, NULL, "playback", &ss, NULL, NULL, &error))) 
        DPRINTF(pa_strerror(error));

    for(;;){
        /* skip index until != 0 */
        while(ioring->cons_indx != ioring->prod_indx && !sync){
            if(*(ioring->buffer+ioring->cons_indx))
                sync=1;
            else 
                ioring->cons_indx = (ioring->cons_indx+1)%ioring->usable_buffer_space;
        }

        /* skip playback loop */
        if(!sync) goto empty;

        /* play until stream is drained */
        while(ioring->cons_indx != ioring->prod_indx){
            empty = 0;
            //buf[r]=*(ioring->buffer+ioring->cons_indx);
            //rl = ioring->prod_indx>ioring->cons_indx? (ioring->prod_indx-ioring->cons_indx) : (BUFSIZE-ioring->cons_indx);
            rl = ioring->prod_indx>ioring->cons_indx? (ioring->prod_indx-ioring->cons_indx) : (ioring->usable_buffer_space-ioring->cons_indx);
            memcpy(buf+r, (ioring->buffer+ioring->cons_indx), rl);
            //putchar(*(ioring->buffer+ioring->cons_indx));
            //write(dspfd, ioring->buffer+ioring->cons_indx, 1);
            //wrap
            ioring->cons_indx = (ioring->cons_indx+rl)%ioring->usable_buffer_space;

            r+=rl;
            if(r>=ioring->usable_buffer_space){
                if((pa_simple_write(s, buf, (size_t) r, &error))<0) DPRINTF(pa_strerror(error));
                r=0;
            }
        }
empty:
        empty++;
        usleep(pa_bytes_to_usec((ioring->usable_buffer_space)>>2, &ss));
        if(empty>100) {
            stream_timeout = 1;
            break;
        }
    }
    if(r) {
        /* write remaining bytes to stream */
        if((pa_simple_write(s, buf, (size_t) r, &error))<0) DPRINTF(pa_strerror(error));
        r=0;
    }
    if((pa_simple_drain(s, &error))<0) DPRINTF(pa_strerror(error));

    pa_simple_flush(s, &error);
    pa_simple_free(s);

    /* reset ring buffer */
    ioring->cons_indx = ioring->prod_indx = 0;
    return stream_timeout;
}

int frontend_is_alive()
{
    char keybuf[128];
    char *out;
    unsigned int len;
    int frontend_state;

    snprintf(keybuf, sizeof(keybuf), "/local/domain/%d", frontend_domid);
    out = xs_read(xsh, 0, keybuf, &len);
    if(out==NULL){
        /* frontend domain is pushing the daisies */
        return 0;
    }

    /* frontend domain is there, let's check the driver */
    out = read_param("state");
    if(out==NULL){
        /* driver was unloaded */
        return 0;
    }
    else{
        frontend_state = atoi(out);
        free(out);
    }

    if(frontend_state==XenbusStateClosing || frontend_state==XenbusStateClosed) {
        /* frontend driver is shutting down */
        return 0;
    }
    /*TODO: find a way to check if the frontend crashed*/

    /* all OK */
    return 1;
}

int set_state(int state)
{
    static int current_state = 0;
    DPRINTF("State transition %d->%d\n", current_state, state);
    publish_param_int("state", state);
    current_state = state;
    return state;
}
