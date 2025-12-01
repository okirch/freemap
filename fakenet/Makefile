CFLAGS	= -Wall -I.. -g -D_GNU_SOURCE -lcurlies -lm

ALL	= \
	  fakenet

fakenet_OBJS = \
	  main.o \
	  interface.o \
	  respond.o \
	  firewall.o \
	  build.o \
	  config.o \
	  random.o

all:	$(ALL)

clean:
	rm -f $(ALL) *.o

fakenet: $(fakenet_OBJS) ../libfreemap.a
	$(CC) -o $@ $(CFLAGS) $(fakenet_OBJS) -L.. -lfreemap -lc_malloc_debug

