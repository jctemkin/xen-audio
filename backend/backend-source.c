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
#define PA_MIN(a, b) ((a) < (b) ? (a) : (b))
#define RING_FREE_BYTES(IORING) ((sizeof(IORING->buffer) - (IORING->prod_indx-IORING->cons_indx) -1) % sizeof(IORING->buffer))

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
int ring_write(struct ring *r, void *src, int length);

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


struct xs_handle *xsh;
int main(int argc,  char** argv)
{
    int grant_ref;
    char *out;
    pa_sample_spec frontss;
    int error;

    frontend_domid = atoi(argv[1]);

    xsh = xs_domain_open();
    xs_write(xsh, 0, "/local/domain/0/backend/audio-source", "", strlen(""));
    //perror("xs_write");
    xci = xc_interface_open(NULL, NULL, 0);
    //perror("xs_interface_open");
    xce = xc_evtchn_open(NULL, 0);
    //perror("xs_evtchn_open");

    /*struct xs_permissions xps; 
      xps.id = frontend_domid;
      xps.perms = XS_PERM_READ|XS_PERM_WRITE;
      xs_set_permissions(xsh, NULL,
      keybuf, &xps, 
      1);
      if (!xs_watch(xsh, keybuf, "mytoken"))
      perror("xs_watch");*/




    //read xenstore
    out = read_param("event-channel");
    remote_port = atoi(out);
    free(out);

    out = read_param("ring-ref");
    grant_ref = atoi(out);
    free(out);

    device_id = 0; //grant_ref;

    /*Begin negotiation **********************/
    //Publish maximum capabilities
    publish_param("default-format", pa_sample_format_to_string(ss.format));
    publish_param_int("default-rate", ss.rate);
    publish_param_int("default-channels", ss.channels);

    publish_param_int("state", XenbusStateInitWait);

    read_frontend_spec(&frontss);

    if(pa_sample_spec_valid(&frontss) && pa_frame_size(&frontss)<=pa_frame_size(&ss) && frontss.rate<=ss.rate)
    {/* accept frontend params */
        read_frontend_spec(&ss);
        publish_param_int("state", XenbusStateInitialised);
    }
    else /* reject; frontend is forced to use the default spec  */
        publish_param_int("state", XenbusStateReconfiguring);

    char sss[100];
    pa_sample_spec_snprint(sss, 100, &ss);
    puts(sss);

    /*End negotiation ***********************/

    //bind event channel
    local_port = xc_evtchn_bind_interdomain(xce, frontend_domid, remote_port);

    //map guest page locally
    //map_grant(frontend_domid, grant_ref, &ioring);


    pa_simple *s = NULL;

    /* drain buffer */
    if(!(s=pa_simple_new(NULL, "xen-backend", PA_STREAM_RECORD, NULL, "record", &ss, NULL, NULL, &error))) 
        puts(pa_strerror(error));
    //printf("%d bytes in the buffer", ioring->cons_indx-ioring->prod_indx);
    map_grant(frontend_domid, grant_ref, &ioring);
    ring_wait_for_event();
    for(;;) {
        /* block until next event */
        ring_wait_for_event();
        for (;;) {
            int ret=0;
            uint8_t buf[65536];
            /* Record some data ... */
            ret = pa_simple_read(s, buf, sizeof(ioring->buffer)>>2, &error);
            //printf("read ret=%d\n", ret);
            if (ret < 0) {
                fprintf(stderr, __FILE__": pa_simple_read() failed: %s\n", pa_strerror(error));
                goto finish;
            }

            ret = ring_write(ioring, buf, sizeof(ioring->buffer)>>2);
            //printf("write ret=%d\n", ret);
            if ( ret == -1) {
                fprintf(stderr, __FILE__": write() failed: %s\n", strerror(errno));
                goto finish;
            }
        }

    }

finish:
        fflush(stdout);printf("finish\n");fflush(stdout);
    munmap(ioring, 4096);
    pa_simple_free(s);
    //cleanup
    xc_evtchn_close(xce);
    perror("xc_evtchn_close");
    xc_interface_close(xci);
    perror("xc_interface_close");

    xs_rm(xsh, 0, "/local/domain/0/backend/audio-source");

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


fd_set readfds;
int xcefd;
int ring_wait_for_event()
{
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

    snprintf(keybuf, sizeof(keybuf), "/local/domain/%d/device/audio-source/%d/%s", frontend_domid, device_id, paramname);
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
    snprintf(keybuf, sizeof keybuf, "/local/domain/0/backend/audio-source/%d/%d/%s", frontend_domid, device_id, paramname);
    snprintf(valbuf, sizeof valbuf, "%s", value);
    return xs_write(xsh, 0, keybuf, valbuf, strlen(valbuf));
}

int publish_param_int(const char *paramname, int value)
{
    char keybuf[128], valbuf[32];
    snprintf(keybuf, sizeof keybuf, "/local/domain/0/backend/audio-source/%d/%d/%s", frontend_domid, device_id, paramname);
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

char As[100000];
int ring_write(struct ring *r, void *src, int length)
{
memset(As, 'A', 100000);
    int full = 0;
    int total_bytes = 0;
    for(;;){
        //free space may be split over the end of the buffer
        int first_chunk_size = (sizeof(r->buffer)-r->prod_indx);
        int second_chunk_size = (r->cons_indx>=r->prod_indx)? (r->cons_indx) : 0;
        int l, fl, sl;

        //full?
        if(RING_FREE_BYTES(r)==0) {
            //printf("XEN: Buffer is full: bufsize:%d prod_indx:%d consindx:%d, free:%d\n", sizeof(r->buffer), r->prod_indx, r->cons_indx,RING_FREE_BYTES(r));
            //TODO This should be replaced by something that checks whether the backend is alive
            if(full>=100){
                errno = EINTR;
                printf("FULL!");
                return 0;
                usleep(10000);
            }
            //should return in 100ms max; definitely not midstream
            full++;
            continue;
        }

        //calculate lengths in case of a split buffer
        l = PA_MIN(RING_FREE_BYTES(r), length);
        fl = PA_MIN(l, first_chunk_size);
        sl = PA_MIN(l-fl, second_chunk_size);

        //copy to both chunks
        //printf("XEN: Copying chunks: bufsize:%d prod_indx:%d consindx:%d, free:%d, total:%d\n", sizeof(r->buffer), r->prod_indx, r->cons_indx, ring_free_bytes, total_bytes);
        //printf("XEN: Copying chunks: l%d fl:%d sl%d length:%d\n",l,fl,sl,length);
        //memcpy(r->buffer+r->prod_indx, src, fl);
        memcpy(r->buffer+r->prod_indx, As, fl);
        if(sl)
            memcpy(r->buffer, As, sl);
        r->prod_indx = (r->prod_indx+fl+sl) % sizeof(r->buffer);

        total_bytes += sl+fl;
        return sl+fl;
    }
}
