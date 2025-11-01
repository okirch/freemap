CFLAGS	= -Wall -g -D_GNU_SOURCE -I. -lcurlies

OBJS	= projects.o \
	  scanner.o \
	  scheduler.o \
	  probe.o \
	  target.o \
	  protocols.o \
	  tcp.o \
	  udp.o \
	  icmp.o \
	  arp.o \
	  ipproto.o \
	  rawpacket.o \
	  traceroute.o \
	  ratelimit.o \
	  addresses.o \
	  network.o \
	  socket.o \
	  local.o \
	  routing.o \
	  netlink.o \
	  neighbor.o \
	  assets.o \
	  report.o \
	  program.o \
	  filefmt.o \
	  config.o \
	  defaults.o \
	  wellknown.o \
	  wellknown/rpc.o \
	  wellknown/dns.o \
	  subcommand.o \
	  logging.o \
	  buffer.o \
	  utils.o
LIB	= libfreemap.a
UTILS	= freemap
freemap_OBJS = \
	  main.o \
	  cmd_project.o \
	  cmd_scan.o

all::	$(LIB) $(UTILS)

clean::
	rm -f $(LIB) *.o

all clean::
	make -C tests $@

test: $(LIB)
	make -C tests runall

$(LIB): $(OBJS)
	$(AR) cr $@ $(OBJS)

freemap: $(freemap_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(freemap_OBJS) $(OBJS) -lc_malloc_debug

