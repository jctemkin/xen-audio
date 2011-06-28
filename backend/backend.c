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

struct ring {
    uint8_t buffer[2048];
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

        int error;

	frontend_domid = atoi(argv[1]);

	xsh = xs_domain_open();
	xs_write(xsh, 0, "/local/domain/0/backend/audio", "", strlen(""));
	//perror("xs_write");
       	xci = xc_interface_open();
	//perror("xs_interface_open");
	xce = xc_evtchn_open();
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
        map_grant(frontend_domid, grant_ref, &ioring);

        //strcpy(ioring->buffer, "test");




	/* The Sample format to use */
	static const pa_sample_spec ss = {
		.format = PA_SAMPLE_S16LE,
		.rate = 44100,
		.channels = 2
	};
	static const pa_buffer_attr custom_bufattr ={
	        .maxlength = 8192,
	        .minreq = (uint32_t)-1,
	        .prebuf = (uint32_t)-1,
	        .tlength = 4096
        };
        pa_buffer_attr * bufattr = &custom_bufattr;
	pa_simple *s = NULL;

        if(!(s=pa_simple_new(NULL, "xen-backend", PA_STREAM_PLAYBACK, NULL, "playback", &ss, NULL, bufattr, &error)))
        puts(pa_strerror(error));
        char buf[10000];
        ssize_t r = 0;
        while(1){
            while(ioring->cons_indx != ioring->prod_indx){
                buf[r]=*(ioring->buffer+ioring->cons_indx);
                //putchar(*(ioring->buffer+ioring->cons_indx));
                //write(dspfd, ioring->buffer+ioring->cons_indx, 1);
                ioring->cons_indx = (ioring->cons_indx+1)%sizeof(ioring->buffer);
                r++;
            }
            if(r>=4096){
            pa_simple_write(s, buf, (size_t) r, &error);
            r=0;
            }
            xc_evtchn_notify(xce, local_port);
            if(ring_wait_for_event()) break;
        }

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

	printf("Mapped grant %d.%d as %Ld=%p\n", frontend_id, grant_ref, arg.index, *addr);

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

