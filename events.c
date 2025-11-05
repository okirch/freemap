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
 */

#include <string.h>
#include <stdio.h>

#include "events.h"

/*
 * Straightforward for now: we use a single linked list of listeners.
 * Once the number of events grow, it will become more expensive to
 * traverse this list all the time, so we may want to optimize this.
 */
static struct hlist_head	fm_event_listeners;
static struct hlist_head	fm_event_recycler;

/*
 * Events are not delivered synchronously, but get posted here and
 * will be processed by the job scheduler when convenient/safe.
 * This should help avoid the usual messy recursion and race condition
 * issues.
 */
typedef struct fm_posted_event {
	struct hlist		link;
	fm_event_t		event;
} fm_posted_event_t;

static struct hlist_head	fm_posted_events;

/*
 * Allocate an event listener.
 */
fm_event_listener_t *
fm_event_listener_alloc(fm_job_t *job, fm_event_callback_t *callback, fm_event_t event)
{
	fm_event_listener_t *evl;

	evl = calloc(1, sizeof(*evl));
	evl->job = job;
	evl->callback = callback;
	evl->event = event;

	hlist_insert(&fm_event_listeners, &evl->link);

	return evl;
}

void
fm_event_listener_disable(fm_event_listener_t *evl)
{
	if (evl->job && evl->job->event_listener == evl)
		evl->job->event_listener = NULL;
	hlist_remove(&evl->link);

	hlist_insert(&fm_event_recycler, &evl->link);
}

/*
 * Nothing outside this file should ever free the event listener
 * themselves.
 * If they really need to, they can call fm_event_listener_disable
 * to detach the listener, allowing them to wait for some other
 * event.
 */
void
fm_event_listener_free(fm_event_listener_t *evl)
{
	if (evl->job && evl->job->event_listener == evl)
		evl->job->event_listener = NULL;
	hlist_remove(&evl->link);

	free(evl);
}

/*
 * Handle an event.
 * Note that the iterator tolerates dropping the current list item.
 */
static void
fm_event_dispatch(fm_event_t event)
{
	fm_event_listener_t *evl;
	hlist_iterator_t it;

	hlist_iterator_init(&it, &fm_event_listeners);
	while ((evl = hlist_iterator_next(&it)) != NULL) {
		if (evl->event == event
		 && evl->callback(evl->job, event)) {
			fm_job_finish_waiting(evl->job);
			assert(evl->job->event_listener == NULL);
		}
	}

	/* Garbage collection.
	 */
	hlist_iterator_init(&it, &fm_event_recycler);
	while ((evl = hlist_iterator_next(&it)) != NULL)
		fm_event_listener_free(evl);
}

/*
 * Event posting
 */
void
fm_event_post(fm_event_t event)
{
	fm_posted_event_t *posted;

	posted = calloc(1, sizeof(*posted));
	hlist_insert(&fm_posted_events, &posted->link);
	posted->event = event;
}

/*
 * Drain and process the entire event queue.
 * This ensures that we immediately process new events generated
 * by one of the callbacks.
 */
void
fm_event_process_all(void)
{
	fm_posted_event_t *posted;

	while ((posted = hlist_head_get_first(&fm_posted_events)) != NULL) {
		fm_event_dispatch(posted->event);
		hlist_remove(&posted->link);
		free(posted);
	}
}
