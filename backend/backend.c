#include <stdio.h>
#include <sys/select.h>
#include <ctype.h>

#include <xenctrl.h>
#include <xs.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#include <pulse/simple.h>
#include <pulse/error.h>
#include <pulse/gccmacro.h>


#include "grant.h"

#define EVENT_TIMEOUT_SECONDS 60
#define BUFSIZE 2047

#define DEBUG 1
#if DEBUG
#define DPRINTF(_f, _a...) {printf("XEN_AUDIO_BACKEND_DEBUG: ");printf ( _f , ## _a );}
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

enum xenbus_state
{
    XenbusStateUnknown      = 0,
    XenbusStateInitialising = 1,
    XenbusStateInitWait     = 2,  
    XenbusStateInitialised  = 3,
    XenbusStateConnected    = 4,
    XenbusStateClosing      = 5,
    XenbusStateClosed       = 6,
    XenbusStateReconfiguring = 7,
    XenbusStateReconfigured  = 8
};

static char* xenbus_names[] = {
    "XenbusStateUnknown",
    "XenbusStateInitialising",
    "XenbusStateInitWait",
    "XenbusStateInitialised",
    "XenbusStateConnected",
    "XenbusStateClosing",
    "XenbusStateClosed",
    "XenbusStateReconfiguring",
    "XenbusStateReconfigured"
};

struct ring {
    uint32_t cons_indx, prod_indx;
    uint32_t usable_buffer_space; /* kept here for convenience */
    uint8_t buffer[BUFSIZE];
    //rest of variables
} *ioring;

xc_interface* xci;
xc_evtchn* xce;
struct xs_handle *xsh;
evtchn_port_t local_port, remote_port;

int frontend_domid = -1;
int interactive = 1;
int device_id;
int current_state = 0;

/* default sample format to use */
static pa_sample_spec ss = {
    .format = PA_SAMPLE_S16LE,
    .rate = 44100,
    .channels = 2
};


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

    DPRINTF("Mapped grant %d.%d as %Ld=%p\n", frontend_id, grant_ref, (long long int)arg.index, *addr);

    close(dev_fd);
    return 0;
}

int ring_wait_for_event()
{
    fd_set readfds;
    int xcefd;
    int ret;
    DPRINTF("Blocking on event channel...\n");
    struct timeval timeout;

    xcefd = xc_evtchn_fd(xce);
    FD_ZERO(&readfds);
    FD_SET(xcefd, &readfds);

    xc_evtchn_unmask(xce, local_port);

    timeout.tv_sec = EVENT_TIMEOUT_SECONDS;
    timeout.tv_usec=0;

    ret = select(xcefd+1, &readfds, NULL, NULL, &timeout);
    if(ret==-1) {
        perror("select() returned error while waiting for frontend: ");
        return ret;
    }
    else if(ret && FD_ISSET(xcefd, &readfds)){
        xc_evtchn_pending(xce);
        return 0; //OK
    }
    else{
        DPRINTF("select() timed out while waiting for frontend");
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
#define LOCAL_BUFFER_SIZE 65536
    pa_simple *s = NULL;
    int empty = 0;
    int sync = 0; /* skip zeros in stream (frame alignment) */
    char buf[LOCAL_BUFFER_SIZE];
    int error; int ret;
    int stream_timeout = 0;
    int r = 0; int rl = 0;

    /* setup playback stream */
    s = pa_simple_new(NULL, "xen-backend", PA_STREAM_PLAYBACK,
            NULL, "playback", &ss, NULL, NULL, &error);
    if(!s) {
        DPRINTF(pa_strerror(error));
    }

    for(;;){
        /* skip until != 0 */
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
            /* if the data block is solid 
             * (i.e. doesn't go over the end of the buffer */
            if( ioring->prod_indx > ioring->cons_indx ){
                /* then its size is the index difference */
                rl = ioring->prod_indx - ioring->cons_indx;
            } else {
                /* otherwise just get the size up to the buffer's end
                 * (we'll get the rest on the next cycle) */
                rl = ioring->usable_buffer_space - ioring->cons_indx;
            }
            memcpy(buf+r, (ioring->buffer+ioring->cons_indx), rl);

            /* wrap the index if we went over the edge */
            ioring->cons_indx = (ioring->cons_indx+rl)%ioring->usable_buffer_space;

            r+=rl;

            /* if the chunk is larger than our ring buffer,
             * write it to the stream. could be anything in the
             * range 0<size<LOCAL_BUFFER_SIZE */

            if(r>=ioring->usable_buffer_space){
                ret=pa_simple_write(s, buf, (size_t) r, &error);
                if(ret<0){
                    DPRINTF(pa_strerror(error));
                }
                r=0;
            }

        }
empty:
        empty++;
        /* sleep for half the buffer's size worth in usec */
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
    if((pa_simple_drain(s, &error))<0)
        DPRINTF(pa_strerror(error));

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
    DPRINTF("State transition %s->%s\n", xenbus_names[current_state], xenbus_names[state]);
    publish_param_int("state", state);
    current_state = state;
    return state;
}
int state_unknown_cb()
{
    DPRINTF("Frontend state was XenbusStateUnknown\n");

    return 0;
}

int state_initialising_cb()
{
    DPRINTF("Frontend state was XenbusStateInitialising\n");
    set_state(XenbusStateInitialising);
    return 0;
}

int state_initwait_cb()
{
    DPRINTF("Frontend state was XenbusStateInitWait\n");
    return 0;
}

int state_initialised_cb()
{
    pa_sample_spec frontss;
    DPRINTF("Frontend state was XenbusStateInitialised\n");
    /* negotiation cycle */
    read_frontend_spec(&frontss);

    /* compare the sizes of 1 msec */
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
    char strbuf[100];
    if(current_state==XenbusStateUnknown){
        DPRINTF("Frontend is already initialised!\n");
        DPRINTF("Bypassing negotiation...\n");
        /* In this case, we have a frontend that has already negotiated
         * with a previous backend. For now, cowardly accept the frontend's
         * parameters */
        read_frontend_spec(&ss);
    }
    set_state(XenbusStateConnected);
    int grant_ref;
    DPRINTF("Frontend state was XenbusStateConnected\n");
    char *out;
    
    /* Phase 2: negotiation ended, continue initialization */
    out = read_param("event-channel");
    remote_port = atoi(out);
    free(out);

    out = read_param("ring-ref");
    grant_ref = atoi(out);
    free(out);


    pa_sample_spec_snprint(strbuf, 100, &ss);
    DPRINTF("Negotiation ended, the result was: %s\n", strbuf);


    /* bind event channel */
    local_port = xc_evtchn_bind_interdomain(xce, frontend_domid, remote_port);

    /* map ioring to local space */
    map_grant(frontend_domid, grant_ref, &ioring);

    /* everything OK, end of Phase 2 */
    /* begin playback cycle */
    while(true){
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
    DPRINTF("Frontend state was XenbusStateClosing\n");
    return 0;
}

int state_closed_cb()
{
    DPRINTF("Frontend state was XenbusStateClosed\n");
    return 0;
}

int state_reconfiguring_cb()
{
    DPRINTF("Frontend state was XenbusStateReconfiguring\n");
    return 0;
}

int state_reconfigured_cb()
{
    DPRINTF("Frontend state was XenbusStateReconfigured\n");
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

void cleanup( int signal ) {
    /* and signal handler*/

    char keybuf[100];
    static int we_are_shutting_down = 0;

    if(we_are_shutting_down) return;
    we_are_shutting_down = 1;

    if(signal){
        printf("Killed by signal:%s\n", strsignal(signal));
        fflush(stdout);
    }

    set_state(XenbusStateClosing);

    xc_evtchn_close(xce);
    perror("xc_evtchn_close");
    xc_interface_close(xci);
    perror("xc_interface_close");

    set_state(XenbusStateClosed);
    snprintf(keybuf, sizeof keybuf, "/local/domain/0/backend/audio/%d", frontend_domid);
    xs_rm(xsh, 0, keybuf);
    xs_daemon_close(xsh);
    if(ioring) munmap(ioring, 4096);
    exit(signal?
            1 : 0);
} 

static char* program_name;
void usage()
{
    printf("Usage: %s [OPTIONS] <DOMID>\n", program_name);
    printf("\n\
Start the Xen paravirtualized audio backend for a Xen guest domain.\n\
\n\
\t-d, --daemon\n\
\t\tRun as a daemon\n\
\t-F, --format={u8|s8|u16le|u16be|s16le|s16be|u24le|alaw|mulaw|...}\n\
\t-C, --channels=N\n\
\t-B, --bitrate=N\n\
\t\tSpecify the sample format, number of channels and bitrate\n\
\t\tto propose to the frontend.\n\n"); 
}

int main(int argc,  char** argv)
{
    bool ret; /* xen error variable */
    int frontend_state;
    program_name = argv[0];

    int c;
    while (1)
    {
        static struct option long_options[] =
        {
            {"help",     no_argument,       0, 'h'},
            {"daemon",   no_argument,       0, 'd'},
            {"format",   required_argument, 0, 'F'},
            {"channels", required_argument, 0, 'C'},
            {"bitrate",  required_argument, 0, 'B'},
            {0, 0, 0, 0}
        };
        int option_index = 0;

        c = getopt_long (argc, argv, "dF:C:B:h",
                long_options, &option_index);

        if (c == -1)
            break;

        switch (c)
        {
            /* TODO: check user input*/
            case 'F':
                ss.format = pa_parse_sample_format(optarg);
                break;
            case 'C':
                ss.channels = atoi(optarg);
                break;
            case 'B':
                ss.rate = atoi(optarg);
                break;
            case 'd':
                interactive = 0;
                daemon(0,0);
                break;
            case 'h':
            case '?':
            default:
                usage();
                exit(0);
        }
    }

    if (optind < argc)
    {
        frontend_domid = atoi(argv[optind]);
        if(!frontend_domid && !isdigit(argv[optind][0])){
            printf("Invalid domain id - %s\n", argv[optind]);
            exit(1);
        }
    }
    else{
        usage();
        exit(0);
    }

    signal(SIGINT, cleanup);
    signal(SIGABRT, cleanup);
    signal(SIGTERM, cleanup);

    ioring = NULL;
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

    /* TODO: publish supported-*/
    publish_param("default-format", pa_sample_format_to_string(ss.format));
    publish_param_int("default-rate", ss.rate);

    set_state(XenbusStateUnknown);
    publish_param_int("default-channels", ss.channels);

    /* Begin State cycle */
    while(!ret){
        frontend_state = wait_for_frontend_state_change();
        ret = state_callbacks[frontend_state]();
    }

    /* Cleanup */
    cleanup(0);
    return 0;
}
