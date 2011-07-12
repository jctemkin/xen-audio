#include <stdio.h>
#include <sys/select.h>
#include <xenctrl.h>
#include <xs.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include <pulse/simple.h>
#include <pulse/error.h>
#include <pulse/gccmacro.h>


#include "grant.h"

#define DEBUG 1
#define BUFSIZE 2048

struct ring {
    uint8_t buffer[BUFSIZE];
    uint32_t cons_indx, prod_indx;
    //rest of variables
} *ioring;

int map_grant(int frontend_id, int grant_ref, struct ring **addr);
int ring_wait_for_event();

int xci,xce;
evtchn_port_or_error_t local_port, remote_port;

int frontend_domid;

int main(int argc,  char** argv)
{
    struct xs_handle *xsh;
    int grant_ref;
    char keybuf[64], valbuf[32];
    char *out; unsigned int len;
    int ret;
    pid_t pid;

    int error;

    frontend_domid = atoi(argv[1]);

    xsh = xs_domain_open();
    xs_write(xsh, 0, "/local/domain/0/backend/audio", "", strlen(""));
    //perror("xs_write");
    xci = xc_interface_open(NULL, NULL, 0);
    //perror("xs_interface_open");
    xce = xc_evtchn_open(NULL, 0);
    //perror("xs_evtchn_open");

    //read xenstore
    snprintf(keybuf, sizeof(keybuf), "/local/domain/%d/device/audio/0/event-channel", frontend_domid);
    out = xs_read(xsh, 0, keybuf, &len);
    //perror("xs_read");
    remote_port = atoi(out);

    snprintf(keybuf, sizeof(keybuf), "/local/domain/%d/device/audio/0/ring-ref", frontend_domid);
    out = xs_read(xsh, 0, keybuf, &len);
    //perror("xs_read");
    grant_ref = atoi(out);

    //bind event channel
    local_port = xc_evtchn_bind_interdomain(xce, frontend_domid, remote_port);

    //map guest page locally
    //map_grant(frontend_domid, grant_ref, &ioring);

    /* The Sample format to use */
    static const pa_sample_spec ss = {
        .format = PA_SAMPLE_S16LE,
        .rate = 44100,
        .channels = 2
    };
    pa_simple *s = NULL;

    char buf[65536];
    ssize_t r = 0;
    while(1){
        if((pid=fork())<0){
            perror("Fork failed:");
            return -1;
        }
        else { //success
            if(pid!=0){ //parent
                /* wait for event, fork again when it happens*/
                wait(pid);
                ring_wait_for_event();
            }
            else{ //child
                /* drain buffer, then quit */
                if(!(s=pa_simple_new(NULL, "xen-backend", PA_STREAM_PLAYBACK, NULL, "playback", &ss, NULL, NULL, &error))) 
                    puts(pa_strerror(error));
                //printf("%d bytes in the buffer", ioring->cons_indx-ioring->prod_indx);
                map_grant(frontend_domid, grant_ref, &ioring);

                int empty = 0;
                int sync=0; //skip until non-zero(ensures frame alignment)
                for(;;){
                    while(ioring->cons_indx != ioring->prod_indx){
                        empty = 0;
                        buf[r]=*(ioring->buffer+ioring->cons_indx);
                        //putchar(*(ioring->buffer+ioring->cons_indx));
                        //write(dspfd, ioring->buffer+ioring->cons_indx, 1);
                        //wrap
                        ioring->cons_indx = (ioring->cons_indx+1)%sizeof(ioring->buffer);

                        if(r==128*pa_frame_size(&ss)){
                            if((pa_simple_write(s, buf, (size_t) r, &error))<0) puts(pa_strerror(error));
                            r=0;
                            //usleep(pa_bytes_to_usec(32*pa_frame_size(&ss),&ss)>>2); //TODO: calculate
                        }
                        if(buf[r]) sync=1;
                        if(sync) r++;
                    }
                    empty++;
                    usleep(100);
                    if(empty>10) break; 
                }

                if(r) {
                    if((pa_simple_write(s, buf, (size_t) r, &error))<0) puts(pa_strerror(error));
                    r=0;
                }
                if((pa_simple_drain(s, &error))<0) puts(pa_strerror(error));
                pa_simple_flush(s, &error);
                ioring->cons_indx = ioring->prod_indx = 0;
                munmap(ioring, 4096);
                pa_simple_free(s);
                exit(0);
            }
        }
    }

    //cleanup
    xc_evtchn_close(xce);
    perror("xc_evtchn_close");
    xc_interface_close(xci);
    perror("xc_interface_close");

    xs_rm(xsh, 0, "/local/domain/0/backend/audio");

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
        return;
    }

    *addr = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, dev_fd, arg.index);
    if (*addr == MAP_FAILED) {
        *addr = 0;
        printf("Could not map grant %d.%d: %s (map failed) (rv=%d)\n", frontend_id, grant_ref, strerror(errno), rv);
        return;
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
        perror("select() returned error while waiting for backend");
        return ret;
    }
    else if(ret && FD_ISSET(xcefd, &readfds)){
        return 0; //OK
    }
    else{
        perror("select() timed out while waiting for backend");
        return -1;
    }
}

