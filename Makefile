CFLAGS	= -Wall -g -D_GNU_SOURCE

OBJS	= scanner.o \
	  target.o \
	  tcp.o \
	  udp.o \
	  icmp.o \
	  ratelimit.o \
	  addresses.o \
	  socket.o \
	  facts.o \
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

