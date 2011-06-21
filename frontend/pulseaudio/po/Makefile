# Makefile for program source directory in GNU NLS utilities package.
# Copyright (C) 1995, 1996, 1997 by Ulrich Drepper <drepper@gnu.ai.mit.edu>
# Copyright (C) 2004-2008 Rodney Dawes <dobey.pwns@gmail.com>
#
# This file may be copied and used freely without restrictions.  It may
# be used in projects which are not available under a GNU Public License,
# but which still want to provide support for the GNU gettext functionality.
#
# - Modified by Owen Taylor <otaylor@redhat.com> to use GETTEXT_PACKAGE
#   instead of PACKAGE and to look for po2tbl in ./ not in intl/
#
# - Modified by jacob berkman <jacob@ximian.com> to install
#   Makefile.in.in and po2tbl.sed.in for use with glib-gettextize
#
# - Modified by Rodney Dawes <dobey.pwns@gmail.com> for use with intltool
#
# We have the following line for use by intltoolize:
# INTLTOOL_MAKEFILE

GETTEXT_PACKAGE = pulseaudio
PACKAGE = pulseaudio
VERSION = 0.9.21-rebootstrapped

SHELL = /bin/bash

srcdir = .
top_srcdir = ..
top_builddir = ..


prefix = /usr/local
exec_prefix = ${prefix}
datadir = ${datarootdir}
datarootdir = ${prefix}/share
libdir = ${exec_prefix}/lib
DATADIRNAME = share
itlocaledir = $(prefix)/$(DATADIRNAME)/locale
subdir = po
install_sh = ${SHELL} /root/xen-audio/frontend/pulseaudio/install-sh
# Automake >= 1.8 provides /bin/mkdir -p.
# Until it can be supposed, use the safe fallback:
mkdir_p = $(install_sh) -d

INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644

GMSGFMT = /usr/bin/msgfmt
MSGFMT = /usr/bin/msgfmt
XGETTEXT = /usr/bin/xgettext
INTLTOOL_UPDATE = /usr/bin/intltool-update
INTLTOOL_EXTRACT = /usr/bin/intltool-extract
MSGMERGE = INTLTOOL_EXTRACT=$(INTLTOOL_EXTRACT) srcdir=$(srcdir) $(INTLTOOL_UPDATE) --gettext-package $(GETTEXT_PACKAGE) --dist
GENPOT   = INTLTOOL_EXTRACT=$(INTLTOOL_EXTRACT) srcdir=$(srcdir) $(INTLTOOL_UPDATE) --gettext-package $(GETTEXT_PACKAGE) --pot

ALL_LINGUAS = 

PO_LINGUAS=$(shell if test -r $(srcdir)/LINGUAS; then grep -v "^\#" $(srcdir)/LINGUAS; else echo "$(ALL_LINGUAS)"; fi)

USER_LINGUAS=$(shell if test -n "$(LINGUAS)"; then LLINGUAS="$(LINGUAS)"; ALINGUAS="$(ALL_LINGUAS)"; for lang in $$LLINGUAS; do if test -n "`grep \^$$lang$$ $(srcdir)/LINGUAS 2>/dev/null`" -o -n "`echo $$ALINGUAS|tr ' ' '\n'|grep \^$$lang$$`"; then printf "$$lang "; fi; done; fi)

USE_LINGUAS=$(shell if test -n "$(USER_LINGUAS)" -o -n "$(LINGUAS)"; then LLINGUAS="$(USER_LINGUAS)"; else if test -n "$(PO_LINGUAS)"; then LLINGUAS="$(PO_LINGUAS)"; else LLINGUAS="$(ALL_LINGUAS)"; fi; fi; for lang in $$LLINGUAS; do printf "$$lang "; done)

POFILES=$(shell LINGUAS="$(PO_LINGUAS)"; for lang in $$LINGUAS; do printf "$$lang.po "; done)

DISTFILES = Makefile.in.in POTFILES.in $(POFILES)
EXTRA_DISTFILES = ChangeLog POTFILES.skip Makevars LINGUAS

POTFILES = \
	../src/modules/module-rescue-streams.c \
	../src/modules/module-tunnel.c \
	../src/modules/module-native-protocol-fd.c \
	../src/modules/module-zeroconf-discover.c \
	../src/modules/alsa/module-alsa-source.c \
	../src/modules/module-device-restore.c \
	../src/modules/module-match.c \
	../src/pulsecore/dbus-util.c \
	../src/modules/module-console-kit.c \
	../src/modules/oss/module-oss.c \
	../src/modules/oss/oss-util.c \
	../src/modules/module-mmkbd-evdev.c \
	../src/modules/module-position-event-sounds.c \
	../src/modules/alsa/alsa-util.c \
	../src/modules/module-pipe-source.c \
	../src/modules/module-solaris.c \
	../src/modules/module-default-device-restore.c \
	../src/modules/x11/module-x11-xsmp.c \
	../src/modules/module-remap-sink.c \
	../src/modules/bluetooth/module-bluetooth-proximity.c \
	../src/modules/module-detect.c \
	../src/modules/module-always-sink.c \
	../src/modules/module-lirc.c \
	../src/modules/module-hal-detect.c \
	../src/modules/module-sine.c \
	../src/modules/module-zeroconf-publish.c \
	../src/modules/jack/module-jack-source.c \
	../src/modules/module-cli.c \
	../src/modules/gconf/module-gconf.c \
	../src/modules/gconf/gconf-helper.c \
	../src/modules/module-esound-sink.c \
	../src/modules/alsa/module-alsa-sink.c \
	../src/modules/module-volume-restore.c \
	../src/modules/x11/module-x11-bell.c \
	../src/modules/module-protocol-stub.c \
	../src/modules/module-stream-restore.c \
	../src/modules/jack/module-jack-sink.c \
	../src/modules/module-esound-compat-spawnfd.c \
	../src/modules/module-esound-compat-spawnpid.c \
	../src/modules/module-combine.c \
	../src/modules/bluetooth/proximity-helper.c \
	../src/modules/x11/module-x11-publish.c \
	../src/modules/rtp/module-rtp-recv.c \
	../src/modules/rtp/sdp.c \
	../src/modules/rtp/rtp.c \
	../src/modules/rtp/sap.c \
	../src/modules/rtp/module-rtp-send.c \
	../src/modules/module-ladspa-sink.c \
	../src/modules/module-suspend-on-idle.c \
	../src/modules/module-pipe-sink.c \
	../src/modules/module-null-sink.c \
	../src/pulsecore/memblock.c \
	../src/pulsecore/queue.c \
	../src/pulsecore/core.c \
	../src/pulsecore/x11wrap.c \
	../src/pulsecore/ioline.c \
	../src/pulsecore/asyncq.c \
	../src/pulsecore/mutex-posix.c \
	../src/pulsecore/protocol-esound.c \
	../src/pulsecore/proplist-util.c \
	../src/pulsecore/pstream.c \
	../src/pulsecore/cli-command.c \
	../src/pulsecore/ltdl-helper.c \
	../src/pulsecore/ipacl.c \
	../src/pulsecore/sample-util.c \
	../src/pulsecore/log.c \
	../src/pulsecore/auth-cookie.c \
	../src/pulsecore/protocol-cli.c \
	../src/pulsecore/resampler.c \
	../src/pulsecore/pdispatch.c \
	../src/pulsecore/hook-list.c \
	../src/pulsecore/conf-parser.c \
	../src/pulsecore/mcalign.c \
	../src/pulsecore/core-subscribe.c \
	../src/pulsecore/protocol-native.c \
	../src/pulsecore/source-output.c \
	../src/pulsecore/modargs.c \
	../src/pulsecore/core-scache.c \
	../src/pulsecore/iochannel.c \
	../src/pulsecore/shared.c \
	../src/pulsecore/socket-client.c \
	../src/pulsecore/idxset.c \
	../src/pulsecore/pipe.c \
	../src/pulsecore/asyncmsgq.c \
	../src/pulsecore/inet_pton.c \
	../src/pulsecore/socket-util.c \
	../src/pulsecore/object.c \
	../src/pulsecore/sioman.c \
	../src/pulsecore/sink-input.c \
	../src/pulsecore/x11prop.c \
	../src/pulsecore/sconv-s16be.c \
	../src/pulsecore/thread-posix.c \
	../src/pulsecore/client.c \
	../src/pulsecore/inet_ntop.c \
	../src/pulsecore/strlist.c \
	../src/pulsecore/msgobject.c \
	../src/pulsecore/mutex-win32.c \
	../src/pulsecore/dynarray.c \
	../src/pulsecore/once.c \
	../src/pulsecore/source.c \
	../src/pulsecore/memchunk.c \
	../src/pulsecore/protocol-simple.c \
	../src/pulsecore/sink.c \
	../src/pulsecore/sconv-s16le.c \
	../src/pulsecore/sconv.c \
	../src/pulsecore/core-error.c \
	../src/pulsecore/strbuf.c \
	../src/pulsecore/play-memblockq.c \
	../src/pulsecore/dllmain.c \
	../src/pulsecore/envelope.c \
	../src/pulsecore/pid.c \
	../src/pulsecore/thread-mq.c \
	../src/pulsecore/shm.c \
	../src/pulsecore/play-memchunk.c \
	../src/pulsecore/hashmap.c \
	../src/pulsecore/avahi-wrap.c \
	../src/pulsecore/authkey.c \
	../src/pulsecore/namereg.c \
	../src/pulsecore/poll.c \
	../src/pulsecore/tokenizer.c \
	../src/pulsecore/semaphore-posix.c \
	../src/pulsecore/cli-text.c \
	../src/pulsecore/g711.c \
	../src/pulsecore/core-util.c \
	../src/pulsecore/thread-win32.c \
	../src/pulsecore/tagstruct.c \
	../src/pulsecore/socket-server.c \
	../src/pulsecore/flist.c \
	../src/pulsecore/fdsem.c \
	../src/pulsecore/random.c \
	../src/pulsecore/modinfo.c \
	../src/pulsecore/start-child.c \
	../src/pulsecore/packet.c \
	../src/pulsecore/pstream-util.c \
	../src/pulsecore/rtpoll.c \
	../src/pulsecore/sound-file.c \
	../src/pulsecore/module.c \
	../src/pulsecore/ffmpeg/resample2.c \
	../src/pulsecore/cli.c \
	../src/pulsecore/time-smoother.c \
	../src/pulsecore/parseaddr.c \
	../src/pulsecore/sound-file-stream.c \
	../src/pulsecore/memblockq.c \
	../src/pulsecore/protocol-http.c \
	../src/pulsecore/semaphore-win32.c \
	../src/daemon/cpulimit.c \
	../src/daemon/ltdl-bind-now.c \
	../src/daemon/main.c \
	../src/daemon/cmdline.c \
	../src/daemon/dumpmodules.c \
	../src/daemon/daemon-conf.c \
	../src/daemon/caps.c \
	../src/daemon/pulseaudio.desktop.in \
	../src/pulse/channelmap.c \
	../src/pulse/error.c \
	../src/pulse/proplist.c \
	../src/pulse/xmalloc.c \
	../src/pulse/ext-stream-restore.c \
	../src/pulse/stream.c \
	../src/pulse/i18n.c \
	../src/pulse/util.c \
	../src/pulse/utf8.c \
	../src/pulse/mainloop-api.c \
	../src/pulse/sample.c \
	../src/pulse/client-conf-x11.c \
	../src/pulse/client-conf.c \
	../src/pulse/browser.c \
	../src/pulse/volume.c \
	../src/pulse/simple.c \
	../src/pulse/subscribe.c \
	../src/pulse/introspect.c \
	../src/pulse/mainloop.c \
	../src/pulse/mainloop-signal.c \
	../src/pulse/operation.c \
	../src/pulse/context.c \
	../src/pulse/thread-mainloop.c \
	../src/pulse/scache.c \
	../src/pulse/glib-mainloop.c \
	../src/pulse/timeval.c \
	../src/utils/pacat.c \
	../src/utils/pasuspender.c \
	../src/utils/pabrowse.c \
	../src/utils/pactl.c \
	../src/utils/padsp.c \
	../src/utils/pax11publish.c \
	../src/utils/pacmd.c \
	../src/pulsecore/lock-autospawn.c \
	../src/modules/alsa/alsa-sink.c \
	../src/modules/alsa/alsa-source.c \
	../src/modules/alsa/module-alsa-card.c \
	../src/modules/bluetooth/module-bluetooth-device.c \
	../src/modules/reserve-wrap.c \
	../src/modules/module-rygel-media-server.c \
	../src/modules/alsa/alsa-mixer.c

CATALOGS=$(shell LINGUAS="$(USE_LINGUAS)"; for lang in $$LINGUAS; do printf "$$lang.gmo "; done)

.SUFFIXES:
.SUFFIXES: .po .pox .gmo .mo .msg .cat

.po.pox:
	$(MAKE) $(GETTEXT_PACKAGE).pot
	$(MSGMERGE) $< $(GETTEXT_PACKAGE).pot -o $*.pox

.po.mo:
	$(MSGFMT) -o $@ $<

.po.gmo:
	file=`echo $* | sed 's,.*/,,'`.gmo \
	  && rm -f $$file && $(GMSGFMT) -o $$file $<

.po.cat:
	sed -f ../intl/po2msg.sed < $< > $*.msg \
	  && rm -f $@ && gencat $@ $*.msg


all: all-yes

all-yes: $(CATALOGS)
all-no:

$(GETTEXT_PACKAGE).pot: $(POTFILES)
	$(GENPOT)

install: install-data
install-data: install-data-yes
install-data-no: all
install-data-yes: all
	linguas="$(USE_LINGUAS)"; \
	for lang in $$linguas; do \
	  dir=$(DESTDIR)$(itlocaledir)/$$lang/LC_MESSAGES; \
	  $(mkdir_p) $$dir; \
	  if test -r $$lang.gmo; then \
	    $(INSTALL_DATA) $$lang.gmo $$dir/$(GETTEXT_PACKAGE).mo; \
	    echo "installing $$lang.gmo as $$dir/$(GETTEXT_PACKAGE).mo"; \
	  else \
	    $(INSTALL_DATA) $(srcdir)/$$lang.gmo $$dir/$(GETTEXT_PACKAGE).mo; \
	    echo "installing $(srcdir)/$$lang.gmo as" \
		 "$$dir/$(GETTEXT_PACKAGE).mo"; \
	  fi; \
	  if test -r $$lang.gmo.m; then \
	    $(INSTALL_DATA) $$lang.gmo.m $$dir/$(GETTEXT_PACKAGE).mo.m; \
	    echo "installing $$lang.gmo.m as $$dir/$(GETTEXT_PACKAGE).mo.m"; \
	  else \
	    if test -r $(srcdir)/$$lang.gmo.m ; then \
	      $(INSTALL_DATA) $(srcdir)/$$lang.gmo.m \
		$$dir/$(GETTEXT_PACKAGE).mo.m; \
	      echo "installing $(srcdir)/$$lang.gmo.m as" \
		   "$$dir/$(GETTEXT_PACKAGE).mo.m"; \
	    else \
	      true; \
	    fi; \
	  fi; \
	done

# Empty stubs to satisfy archaic automake needs
dvi info ctags tags CTAGS TAGS ID:

# Define this as empty until I found a useful application.
install-exec installcheck:

uninstall:
	linguas="$(USE_LINGUAS)"; \
	for lang in $$linguas; do \
	  rm -f $(DESTDIR)$(itlocaledir)/$$lang/LC_MESSAGES/$(GETTEXT_PACKAGE).mo; \
	  rm -f $(DESTDIR)$(itlocaledir)/$$lang/LC_MESSAGES/$(GETTEXT_PACKAGE).mo.m; \
	done

check: all $(GETTEXT_PACKAGE).pot
	rm -f missing notexist
	srcdir=$(srcdir) $(INTLTOOL_UPDATE) -m
	if [ -r missing -o -r notexist ]; then \
	  exit 1; \
	fi

mostlyclean:
	rm -f *.pox $(GETTEXT_PACKAGE).pot *.old.po cat-id-tbl.tmp
	rm -f .intltool-merge-cache

clean: mostlyclean

distclean: clean
	rm -f Makefile Makefile.in POTFILES stamp-it
	rm -f *.mo *.msg *.cat *.cat.m *.gmo

maintainer-clean: distclean
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."
	rm -f Makefile.in.in

distdir = ../$(PACKAGE)-$(VERSION)/$(subdir)
dist distdir: $(DISTFILES)
	dists="$(DISTFILES)"; \
	extra_dists="$(EXTRA_DISTFILES)"; \
	for file in $$extra_dists; do \
	  test -f $(srcdir)/$$file && dists="$$dists $(srcdir)/$$file"; \
	done; \
	for file in $$dists; do \
	  test -f $$file || file="$(srcdir)/$$file"; \
	  ln $$file $(distdir) 2> /dev/null \
	    || cp -p $$file $(distdir); \
	done

update-po: Makefile
	$(MAKE) $(GETTEXT_PACKAGE).pot
	tmpdir=`pwd`; \
	linguas="$(USE_LINGUAS)"; \
	for lang in $$linguas; do \
	  echo "$$lang:"; \
	  result="`$(MSGMERGE) -o $$tmpdir/$$lang.new.po $$lang`"; \
	  if $$result; then \
	    if cmp $(srcdir)/$$lang.po $$tmpdir/$$lang.new.po >/dev/null 2>&1; then \
	      rm -f $$tmpdir/$$lang.new.po; \
            else \
	      if mv -f $$tmpdir/$$lang.new.po $$lang.po; then \
	        :; \
	      else \
	        echo "msgmerge for $$lang.po failed: cannot move $$tmpdir/$$lang.new.po to $$lang.po" 1>&2; \
	        rm -f $$tmpdir/$$lang.new.po; \
	        exit 1; \
	      fi; \
	    fi; \
	  else \
	    echo "msgmerge for $$lang.gmo failed!"; \
	    rm -f $$tmpdir/$$lang.new.po; \
	  fi; \
	done

Makefile POTFILES: stamp-it
	@if test ! -f $@; then \
	  rm -f stamp-it; \
	  $(MAKE) stamp-it; \
	fi

stamp-it: Makefile.in.in $(top_builddir)/config.status POTFILES.in
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/Makefile.in CONFIG_HEADERS= CONFIG_LINKS= \
	       $(SHELL) ./config.status

# Tell versions [3.59,3.63) of GNU make not to export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
