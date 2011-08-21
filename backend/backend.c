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
#define BUFSIZE 2048


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
    uint8_t buffer[BUFSIZE];
    uint32_t cons_indx, prod_indx;
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

xc_interface* xci;
xc_evtchn* xce;
evtchn_port_t local_port, remote_port;

int frontend_domid;
int device_id;
/* The Sample format to use */
static pa_sample_spec ss = {
    .format = PA_SAMPLE_S16LE,
    .rate = 44100,
    .channels = 2
};
int watch_first_time;
struct xs_handle *xsh;
int main(int argc,  char** argv)
{
    int grant_ref;
    pa_sample_spec frontss;
    ssize_t r;
    char *out;
    bool xerr; /* xen error variable */
    int error; /* pulseaudio */
    int frontend_state;

    frontend_domid = atoi(argv[1]);

    device_id = 0; /* hardcoded for now */

    /* Basic Initialization */
    xsh = xs_domain_open();
    if(!xs_write(xsh, 0, "/local/domain/0/backend/audio", "", strlen(""))) {
        perror("xs_write");
    };
    xci = xc_interface_open(NULL/*log to stderr*/, NULL, 0);
    xce = xc_evtchn_open(NULL/*log to stderr*/, 0);


    /* Begin Phase 1*/
    /* Wait for frontend to appear */
    watch_first_time = 1;
    printf("Waiting for frontend XenbusStateUnknown\n");
    publish_param_int("state", XenbusStateUnknown);
    frontend_state = wait_for_frontend_state_change(); /*XenbusStateUnknown; discard*/
    publish_param_int("state", XenbusStateUnknown);
    printf("STATE=XenbusStateUnknown : frontend state was %d\n", frontend_state);
    if(frontend_state != XenbusStateUnknown) while(0) {}; /*TODO: Frontend is pre-configured, handle accordingly*/


    /* TODO: publish supported-*/
    publish_param("default-format", pa_sample_format_to_string(ss.format));
    publish_param_int("default-rate", ss.rate);
    publish_param_int("default-channels", ss.channels);

    /*now wait for the frontend to publish its own parameters*/
    printf("STATE=XenbusStateUnknown : Waiting for frontend XenbusStateInitialising\n");
    frontend_state = wait_for_frontend_state_change(); /*XenbusStateInitialising; discard*/
    printf("STATE=XenbusStateUnknown : frontend state was %d\n", frontend_state);

    /* Begin Phase 2 */
    publish_param_int("state", XenbusStateInitialising);
    printf("STATE=XenbusStateInitialising\n");

    /* negotiation cycle */
    while(1){
        read_frontend_spec(&frontss);

        if(pa_sample_spec_valid(&frontss) && 
                pa_usec_to_bytes(1000, &frontss) <= pa_usec_to_bytes(1000, &ss))
        {
            /* accept frontend params */
            read_frontend_spec(&ss);
            break;
        }
        else
        {
            /* reject; set state to reconfiguring and wait for frontend to post new parameters */
            printf("STATE=XenbusStateReconfiguring : Waiting for frontend XenbusStateReconfiguring\n");
            publish_param_int("state", XenbusStateReconfiguring);
            frontend_state = wait_for_frontend_state_change(); /*XenbusStateReconfiguring*/
            printf("STATE=XenbusStateReconfiguring : frontend state was %d\n", frontend_state);
        }
    }


    /* Phase 2: negotiation ended, continue initialization */
    out = read_param("event-channel");
    remote_port = atoi(out);
    free(out);

    out = read_param("ring-ref");
    grant_ref = atoi(out);
    free(out);


    char sss[100];
    pa_sample_spec_snprint(sss, 100, &ss);
    puts(sss);


    /* bind event channel */
    local_port = xc_evtchn_bind_interdomain(xce, frontend_domid, remote_port);

    /* map ioring to local space */
    map_grant(frontend_domid, grant_ref, &ioring);


    /* everything OK, end of Phase 2 */
    publish_param_int("state", XenbusStateConnected);
    printf("STATE=XenbusStateConnected\n");

    /* begin playback cycle */
    for(;;){
        if(play_stream()){
            puts("Stream timed out\n");
            //TODO: check if backend is alive, etc.
        }
         /* block until next event */
        ring_wait_for_event();
    }

    publish_param_int("state", XenbusStateClosing);
    printf("STATE=XenbusStateClosing\n");

    //cleanup
    munmap(ioring, 4096);
    xc_evtchn_close(xce);
    perror("xc_evtchn_close");
    xc_interface_close(xci);
    perror("xc_interface_close");


    publish_param_int("state", XenbusStateClosed);
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
        perror("");
    }

    rv = ioctl(dev_fd, IOCTL_GNTDEV_MAP_GRANT_REF, &arg);
    if (rv) {
        printf("Could not map grant %d.%d: %s (rv=%d)\n", frontend_id, grant_ref, strerror(errno), rv);
        return 1;
    }

    *addr = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, dev_fd, arg.index);
    if (*addr == MAP_FAILED) {
        *addr = 0;
        printf("Could not map grant %d.%d: %s (map failed) (rv=%d)\n", frontend_id, grant_ref, strerror(errno), rv);
        return 1;
    }

    //printf("Mapped grant %d.%d as %Ld=%p\n", frontend_id, grant_ref, arg.index, *addr);

    /*
       struct ioctl_gntdev_unmap_notify uarg = {
       .index = arg.index + offsetof(struct shr_page, notifies[j]),
       .action = UNMAP_NOTIFY_CLEAR_BYTE
       };
       rv = ioctl(d_fd, IOCTL_GNTDEV_SET_UNMAP_NOTIFY, &uarg);
       if (rv)
       printf("gntdev unmap notify error: %s (rv=%d)\n", strerror(errno), rv);
       */
    close(dev_fd);
    return 0;
}



int ring_wait_for_event()
{
    fd_set readfds;
    int xcefd;
    int ret;
    //printf("Blocking");
    struct timeval timeout;

    xcefd = xc_evtchn_fd(xce);
    FD_ZERO(&readfds);
    FD_SET(xcefd, &readfds);

    xc_evtchn_unmask(xce, local_port);

    timeout.tv_sec=30;
    timeout.tv_usec=0;

    ret = select(xcefd+1, &readfds, NULL, NULL, &timeout);
    xc_evtchn_pending(xce);
    return 0;

    if(ret==-1) {
        perror("select() returned error while waiting for frontend");
        return ret;
    }
    else if(ret && FD_ISSET(xcefd, &readfds)){
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

int wait_for_frontend_state_change()
{
    char keybuf[128];
    char *buf;
    int len;
    int frontend_state;
    int num_strings;
    char **vec;
    static first_time=1;

    if(first_time){
        snprintf(keybuf, sizeof(keybuf), "/local/domain/%d/device/audio/%d/state", frontend_domid, device_id);
        puts(keybuf); fflush(stdout);
        if (!xs_watch(xsh, keybuf, "xenpvaudiobackendsinktoken")) perror("xs_watch failed");
        first_time=0;
        if(!(vec=xs_read_watch(xsh, &num_strings))) perror("xs_read_watch failed");
        printf("vec contents: %s|%s\n", vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN]);
    }

    if(!(vec=xs_read_watch(xsh, &num_strings))) perror("xs_read_watch failed");
    printf("vec contents: %s|%s\n", vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN]);
    //if(!(vec=xs_read_watch(xsh, &num_strings))) perror("xs_read_watch failed");
    //printf("vec contents: %s|%s\n", vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN]);

    buf = xs_read(xsh, 0, vec[XS_WATCH_PATH], &len);
    puts(buf);fflush(stdout);
    frontend_state = atoi(buf);
    free(buf);

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
        puts(pa_strerror(error));

    for(;;){
        /* skip index until != 0 */
        while(ioring->cons_indx != ioring->prod_indx && !sync){
            if(*(ioring->buffer+ioring->cons_indx))
                sync=1;
            else 
                ioring->cons_indx = (ioring->cons_indx+1)%sizeof(ioring->buffer);
        }

        /* skip playback loop */
        if(!sync) goto empty;

        /* play until stream is drained */
        while(ioring->cons_indx != ioring->prod_indx){
            empty = 0;
            //buf[r]=*(ioring->buffer+ioring->cons_indx);
            rl = ioring->prod_indx>ioring->cons_indx? (ioring->prod_indx-ioring->cons_indx) : (BUFSIZE-ioring->cons_indx);
            memcpy(buf+r, (ioring->buffer+ioring->cons_indx), rl);
            //putchar(*(ioring->buffer+ioring->cons_indx));
            //write(dspfd, ioring->buffer+ioring->cons_indx, 1);
            //wrap
            ioring->cons_indx = (ioring->cons_indx+rl)%sizeof(ioring->buffer);

            r+=rl;
            if(r>=BUFSIZE){
                if((pa_simple_write(s, buf, (size_t) r, &error))<0) puts(pa_strerror(error));
                r=0;
            }
        }
empty:
        empty++;
        usleep(pa_bytes_to_usec(BUFSIZE>>2, &ss));
        if(empty>100) {
            stream_timeout = 1;
            break;
        }
    }
    if(r) {
        /* write remaining bytes to stream */
        if((pa_simple_write(s, buf, (size_t) r, &error))<0) puts(pa_strerror(error));
        r=0;
    }
    if((pa_simple_drain(s, &error))<0) puts(pa_strerror(error));

    pa_simple_flush(s, &error);
    pa_simple_free(s);

    /* reset ring buffer */
    ioring->cons_indx = ioring->prod_indx = 0;
    return stream_timeout;
}
