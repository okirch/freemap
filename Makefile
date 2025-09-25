CFLAGS	= -Wall -g -D_GNU_SOURCE -I.

OBJS	= scanner.o \
	  target.o \
	  tcp.o \
	  udp.o \
	  icmp.o \
	  ratelimit.o \
	  addresses.o \
	  socket.o \
	  facts.o \
	  report.o \
	  wellknown.o \
	  wellknown/rpc.o \
	  wellknown/dns.o \
	  logging.o
LIB	= libfreemap.a
UTILS	= freemap
freemap_OBJS = main.o

all::	$(LIB) $(UTILS)

clean::
	rm -f $(LIB) *.o

all clean::
	make -C tests $@

test: $(LIB)
	make -C tests runall

$(LIB): $(OBJS)
	$(AR) crv $@ $(OBJS)

freemap: $(freemap_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(freemap_OBJS) -L. -lfreemap -lc_malloc_debug

