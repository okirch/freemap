/*
 * Copyright (C) 2023 Olaf Kirch <okir@suse.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "freemap.h"

struct event {
	double		when;
	unsigned int	packets;
};

struct eventlog {
	unsigned int	count;
	unsigned int	chunk;
	struct event *	events;
};

void
eventlog_init(struct eventlog *log)
{
	memset(log, 0, sizeof(*log));
	log->chunk = 1000;
}

void
eventlog_clear(struct eventlog *log)
{
	if (log->events)
		free(log->events);
	eventlog_init(log);
}

void
eventlog_add(struct eventlog *log, double when, unsigned int npackets)
{
	struct event  *ev;

	if ((log->count % log->chunk) == 0) {
		log->events = realloc(log->events, (log->count + log->chunk) * sizeof(log->events[0]));
	}

	ev = &log->events[log->count++];
	ev->when = when;
	ev->packets = npackets;
}

static void
analyze_eventlog(struct eventlog *log, unsigned int duration, unsigned int rate, unsigned int max_burst)
{
	unsigned int packets_in_window = 0, total_packets = 0;
	struct event *window_start, *window_end, *last_event;
	unsigned int min_rate = 0, max_rate = 0, avg_rate;
	double t0, dt;

	if (log->count == 0) {
		printf("No packet events\n");
		return;
	}

	printf("  events:        %5u\n", log->count);

	window_start = log->events;
	window_end = log->events;
	last_event = log->events + log->count;

	if (window_start->when == 0) {
		printf("  initial burst: %5u\n", window_start->packets);
		window_start = window_end = log->events + 1;
	}

	t0 = window_start->when;

	/* run a 1 second sliding window across the event log and compute the
	 * rate of packets within that window */
	while (window_end < last_event) {
		double end_time = window_start->when + 1.0;

		while (window_end->when <= end_time && window_end < last_event) {
			packets_in_window += window_end->packets;
			total_packets += window_end->packets;
			window_end ++;
		}

		if (min_rate == 0 || packets_in_window < min_rate)
			min_rate = packets_in_window;
		if (packets_in_window > max_rate)
			max_rate = packets_in_window;

		/* Now slide the window 1 event to the right */
		packets_in_window -= window_start->packets;
		window_start += 1;
	}

	dt = last_event[-1].when - t0;
	avg_rate = (unsigned int) (total_packets / dt);

	printf("  avg rate:      %5u\n", avg_rate);
	printf("  min rate:      %5u\n", min_rate);
	printf("  max rate:      %5u\n", max_rate);
}

static int
run_test(unsigned int duration, unsigned int rate, unsigned int max_burst)
{
	struct eventlog eventlog;
	struct timeval timestamp;
	fm_ratelimit_t rl;
	time_t end;

	printf("Testing ratelimit for %u seconds", duration);

	end = time(NULL) + duration;

	eventlog_init(&eventlog);
	fm_ratelimit_init(&rl, rate, max_burst);
	fm_timestamp_update(&timestamp);

	while (time(NULL) < end) {
		double when = fm_timestamp_since(&timestamp);
		unsigned int npackets = 0, delay;

		while (fm_ratelimit_okay(&rl) && npackets < 10000)
			npackets += 1;

		eventlog_add(&eventlog, when, npackets);

		/* sleep for 0..100 ms */
		delay = ((unsigned long)random()) % 100000;
		usleep(delay);

		printf("."); fflush(stdout);

		/* replenish the bucket */
		fm_ratelimit_update(&rl);
	}

	printf("\n");

	analyze_eventlog(&eventlog, duration, rate, max_burst);
	eventlog_clear(&eventlog);

	return 0;
}


int
main(int argc, char **argv)
{
	run_test(10, 100, 100);
}
