#include <stdio.h>
#include <sys/select.h>
#include <xenctrl.h>
#include <xs.h>
#include <string.h>
#include <stdlib.h>

#include <pulse/simple.h>
#include <pulse/error.h>
#include <pulse/gccmacro.h>


#define DEBUG 1

int main(int argc,  char** argv)
{
	int xci,xce;
	struct xs_handle *xsh;
	evtchn_port_or_error_t local_port, remote_port;
	fd_set readfds;
	int xcefd, ret;
	struct timeval timeout;
	char keybuf[64], valbuf[32];
	char *out; unsigned int len;
	int frontend_domid;

	frontend_domid = atoi(argv[1]);

	xsh = xs_domain_open();
	xs_write(xsh, 0, "/local/domain/0/backend/audio", "", strlen(""));
	perror("xs_write");
       	xci = xc_interface_open();
	perror("xs_interface_open");
	xce = xc_evtchn_open();
	perror("xs_evtchn_open");
	
	snprintf(keybuf, sizeof(keybuf), "/local/domain/%d/device/audio/0/event-channel", frontend_domid);
	out = xs_read(xsh, 0, keybuf, &len);
	perror("xs_read");
	remote_port = atoi(out);
    	local_port = xc_evtchn_bind_interdomain(xce, frontend_domid, remote_port);

	xcefd = xc_evtchn_fd(xce);
	FD_ZERO(&readfds);
	FD_SET(xcefd, &readfds);
	
	xc_evtchn_unmask(xce, local_port);

	timeout.tv_sec=30;
	timeout.tv_usec=0;

	ret = select(xcefd+1, &readfds, NULL, NULL, &timeout);

	if(ret==-1) perror("select");
	else if(ret && FD_ISSET(xcefd, &readfds))
		puts("received event");
	else puts("timeout\n");

	xc_evtchn_close(xce);
	perror("xc_evtchn_close");
	xc_interface_close(xci);
	perror("xc_interface_close");
	
	xs_rm(xsh, 0, "/local/domain/0/backend/audio");

	return 0;
}
