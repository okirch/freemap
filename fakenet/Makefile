CFLAGS	= -Wall -I.. -g -lcurlies

ALL	= \
	  fakenet

fakenet_OBJS = \
	  main.o \
	  interface.o \
	  build.o \
	  config.o

all:	$(ALL)

clean:
	rm -f $(ALL) *.o

fakenet: $(fakenet_OBJS) ../libfreemap.a
	$(CC) -o $@ $(CFLAGS) $(fakenet_OBJS) -L.. -lfreemap -lc_malloc_debug

