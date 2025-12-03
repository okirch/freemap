CFLAGS	= -Wall -I../lib -g -lcurlies

ALL	= \
	  addrs \
	  argparse \
	  ratelimit

all:	$(ALL)

clean:
	rm -f $(ALL)

runall:	$(ALL)
	for t in $(ALL); do \
		./$$t; \
	done

%: %.c ../libfreemap.a
	$(CC) -o $@ $(CFLAGS) $< -L.. -lfreemap
