/*
 * Copyright (C) 2025 Olaf Kirch <okir@suse.com>
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
 *
 * Simple token bucket algorithm for rate limiting.
 */

#include <sys/time.h>
#include <sys/param.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freemap.h"

double
__fm_timestamp_do(struct timeval *ts, bool update)
{
	struct timespec now;
	struct timeval now_ts, delta;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		fprintf(stderr, "Fatal error: cannot get monotonic clock: %m\n");
		exit(1);
	}

	TIMESPEC_TO_TIMEVAL(&now_ts, &now);
	if (timercmp(&now_ts, ts, <)) {
		/* normally, monotonic shouldn't walk backwards */
		if (update)
			*ts = now_ts;
		return 0;
	}

	timersub(&now_ts, ts, &delta);

	if (update)
		*ts = now_ts;

	return delta.tv_sec + 1e-6 * delta.tv_usec;
}

void
fm_timestamp_init(struct timeval *ts)
{
	if (!timerisset(ts))
		__fm_timestamp_do(ts, true);
}

void
fm_timestamp_clear(struct timeval *ts)
{
	timerclear(ts);
}

bool
fm_timestamp_is_set(const struct timeval *ts)
{
	return timerisset(ts);
}

double
fm_timestamp_update(struct timeval *ts)
{
	return __fm_timestamp_do(ts, true);
}

double
fm_timestamp_since(struct timeval *ts)
{
	if (!timerisset(ts))
		return 0;

	return __fm_timestamp_do(ts, false);
}

const struct timeval *
fm_timestamp_now(void)
{
	static struct timeval now;

	fm_timestamp_update(&now);
	return &now;
}

void
fm_timestamp_set_timeout(struct timeval *ts, long timeout)
{
	if (timeout <= 0) {
		fm_timestamp_update(ts);
	} else {
		fm_timestamp_update(ts);
		ts->tv_sec += timeout / 1000;
		ts->tv_usec += 1000 * (timeout % 1000);

		if (ts->tv_usec > 1000000) {
			ts->tv_usec -= 1000000;
			ts->tv_sec += 1;
		}
	}
}

bool
fm_timestamp_older(const struct timeval *expiry, const struct timeval *now)
{
	if (!timerisset(expiry))
		return false;

	if (now == NULL)
		now = fm_timestamp_now();
	return timercmp(expiry, now, <=);
}

void
fm_ratelimit_init(fm_ratelimit_t *rl, unsigned int rate, unsigned int max_burst)
{
	if (max_burst == 0)
		max_burst = 1;

	memset(rl, 0, sizeof(*rl));
	rl->rate = rate;
	rl->max_burst = max_burst;
	rl->value = max_burst;
	fm_timestamp_update(&rl->last_ts);
}

void
fm_ratelimit_update(fm_ratelimit_t *rl)
{
	double elapsed;

	elapsed = fm_timestamp_update(&rl->last_ts);

	rl->value += elapsed * rl->rate;

	if (rl->value > rl->max_burst)
		rl->value = rl->max_burst;
}

/*
 * How long would we have to wait until we could extract ntokens?
 */
double
fm_ratelimit_wait_until(const fm_ratelimit_t *rl, unsigned int ntokens)
{
	if (rl->value >= ntokens)
		return 0;
	return (ntokens - rl->value) / rl->rate;
}

bool
fm_ratelimit_okay(fm_ratelimit_t *rl)
{
	if (rl->value < 1)
		return false;

	rl->value -= 1;
	return true;
}

unsigned int
fm_ratelimit_available(const fm_ratelimit_t *rl)
{
	return rl->value;
}

void
fm_ratelimit_consume(fm_ratelimit_t *rl, unsigned int ntokens)
{
	if (ntokens <= rl->value)
		rl->value -= ntokens;
	else
		rl->value = 0;
}
