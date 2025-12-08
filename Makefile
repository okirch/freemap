CFLAGS	= -Wall -g -D_GNU_SOURCE -D_MISC_SOURCE -I./lib -lcurlies

OBJS	= lib/projects.o \
	  lib/scanner.o \
	  lib/scheduler.o \
	  lib/events.o \
	  lib/extant.o \
	  lib/probe.o \
	  lib/addrgen.o \
	  lib/target.o \
	  lib/protocols.o \
	  lib/tcp.o \
	  lib/udp.o \
	  lib/icmp.o \
	  lib/arp.o \
	  lib/rawip.o \
	  lib/traceroute.o \
	  lib/ipproto.o \
	  lib/rawpacket.o \
	  lib/ratelimit.o \
	  lib/addresses.o \
	  lib/ports.o \
	  lib/network.o \
	  lib/socket.o \
	  lib/packet.o \
	  lib/local.o \
	  lib/routing.o \
	  lib/netlink.o \
	  lib/neighbor.o \
	  lib/assets.o \
	  lib/assetio.o \
	  lib/report.o \
	  lib/program.o \
	  lib/config.o \
	  lib/defaults.o \
	  lib/services.o \
	  lib/subcommand.o \
	  lib/logging.o \
	  lib/buffer.o \
	  lib/utils.o
LIB	= libfreemap.a
UTILS	= freemap
freemap_OBJS = \
	  util/main.o \
	  util/cmd_project.o \
	  util/cmd_scan.o \
	  util/cmd_report.o

include Makefile.inc

all::	$(LIB) $(UTILS)

clean::
	rm -f $(LIB) lib/*.o util/*.o

all clean::
	make -C fakenet $@
	make -C tests $@

install::
	install -d -m 755 $(INSTALL_ETCDIR)
	install -d -m 755 $(INSTALL_LIBDIR)
	install -d -m 755 $(INSTALL_BINDIR)
	install -d -m 755 $(INSTALL_PROBESDIR)
	install -s -m 755 freemap $(INSTALL_BINDIR)
	install -m 644 etc/freemap.conf $(INSTALL_ETCDIR)
	cp -r probes/* $(INSTALL_PROBESDIR)
	find $(INSTALL_PROBESDIR) -type d | xargs chmod 755
	find $(INSTALL_PROBESDIR) -type f | xargs chmod 644

test: $(LIB)
	make -C tests runall

$(LIB): $(OBJS)
	$(AR) cr $@ $(OBJS)

freemap: $(freemap_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(freemap_OBJS) $(OBJS) -lc_malloc_debug

