CFLAGS	= -Wall -g -D_GNU_SOURCE -D_MISC_SOURCE -I. -lcurlies

OBJS	= projects.o \
	  scanner.o \
	  scheduler.o \
	  events.o \
	  extant.o \
	  probe.o \
	  addrgen.o \
	  target.o \
	  protocols.o \
	  tcp.o \
	  udp.o \
	  icmp.o \
	  arp.o \
	  rawpacket.o \
	  traceroute.o \
	  ratelimit.o \
	  addresses.o \
	  ports.o \
	  network.o \
	  socket.o \
	  packet.o \
	  local.o \
	  routing.o \
	  netlink.o \
	  neighbor.o \
	  assets.o \
	  assetio.o \
	  report.o \
	  program.o \
	  config.o \
	  defaults.o \
	  services.o \
	  subcommand.o \
	  logging.o \
	  buffer.o \
	  utils.o
LIB	= libfreemap.a
UTILS	= freemap
freemap_OBJS = \
	  main.o \
	  cmd_project.o \
	  cmd_scan.o \
	  cmd_report.o

include Makefile.inc

all::	$(LIB) $(UTILS)

clean::
	rm -f $(LIB) *.o

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

