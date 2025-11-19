CFLAGS	= -Wall -I.. -g -lcurlies

ALL	= \
	  addrs \
	  argparse \
	  ratelimit \
	  fakenet

fakenet_OBJS = \
	  fakenet.o

all:	$(ALL)

clean:
	rm -f $(ALL)

runall:	$(ALL)
	for t in $(ALL); do \
		./$$t; \
	done

%: %.c ../libfreemap.a
	$(CC) -o $@ $(CFLAGS) $< -L.. -lfreemap

fakenet: $(fakenet_OBJS) ../libfreemap.a
	$(CC) -o $@ $(CFLAGS) $(fakenet_OBJS) -L.. -lfreemap -lc_malloc_debug

