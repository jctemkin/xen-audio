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

int map_grant(int frontend_id, int grant_ref, void** addr);

int main(int argc,  char** argv)
{
	int xci,xce;
	struct xs_handle *xsh;
	evtchn_port_or_error_t local_port, remote_port;
        int grant_ref;
	fd_set readfds;
	int xcefd, ret;
	struct timeval timeout;
	char keybuf[64], valbuf[32];
	char *out; unsigned int len;
	int frontend_domid;
        void* page;

	frontend_domid = atoi(argv[1]);

	xsh = xs_domain_open();
	xs_write(xsh, 0, "/local/domain/0/backend/audio", "", strlen(""));
	perror("xs_write");
       	xci = xc_interface_open();
	perror("xs_interface_open");
	xce = xc_evtchn_open();
	perror("xs_evtchn_open");

        //read xenstore
	snprintf(keybuf, sizeof(keybuf), "/local/domain/%d/device/audio/0/event-channel", frontend_domid);
	out = xs_read(xsh, 0, keybuf, &len);
	perror("xs_read");
	remote_port = atoi(out);

	snprintf(keybuf, sizeof(keybuf), "/local/domain/%d/device/audio/0/ring-ref", frontend_domid);
	out = xs_read(xsh, 0, keybuf, &len);
	perror("xs_read");
	grant_ref = atoi(out);

        //bind event channel
    	local_port = xc_evtchn_bind_interdomain(xce, frontend_domid, remote_port);

        //map guest page locally
        map_grant(frontend_domid, grant_ref, &page);

        strcpy(page, "test");

	xcefd = xc_evtchn_fd(xce);
	FD_ZERO(&readfds);
	FD_SET(xcefd, &readfds);

	xc_evtchn_unmask(xce, local_port);

	timeout.tv_sec=30;
	timeout.tv_usec=0;

	ret = select(xcefd+1, &readfds, NULL, NULL, &timeout);

	if(ret==-1) perror("select");
	else if(ret && FD_ISSET(xcefd, &readfds)){
		puts("received event");
        }
	else puts("timeout\n");

	xc_evtchn_close(xce);
	perror("xc_evtchn_close");
	xc_interface_close(xci);
	perror("xc_interface_close");

	xs_rm(xsh, 0, "/local/domain/0/backend/audio");

	return 0;
}

int map_grant(int frontend_id, int grant_ref, void** addr) {

        int alloc_fd, dev_fd;
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
		printf("Could not map grant %d.%d: %s (map failed)\n", frontend_id, grant_ref, strerror(errno), rv);
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
}
