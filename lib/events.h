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

#ifndef FREEMAP_EVENTS_H
#define FREEMAP_EVENTS_H

#include "scheduler.h"

/*
 * We implement a simple and hopefully robust mechanism that allows
 * jobs to wait for certain events.
 *
 * A job can point to a event_listener object that describes the event(s)
 * it is waiting for.
 * These objects, when active, are inserted into a linked list managed
 * by the job scheduler. When an event is signaled, the job scheduler
 * walks this list and calls every job that is waiting for this
 * specific event.
 */
struct fm_event_listener {
	struct hlist		link;

	/* Callback to invoke.
	 * returns true to indicate that the job is done waiting.
	 */
	fm_event_callback_t *	callback;

	/* Back pointer to the job */
	fm_job_t *		job;

	/* Event we're waiting for.
	 * Right now, a job cannot wait for more than one event at
	 * a time (but extending that should be easy).
	 */
	fm_event_t		event;
};

extern fm_event_listener_t *fm_event_listener_alloc(fm_job_t *job, fm_event_callback_t *callback, fm_event_t event);
extern void		fm_event_listener_disable(fm_event_listener_t *evl);
extern void		fm_event_listener_free(fm_event_listener_t *evl);
extern void		fm_event_post(fm_event_t event);
extern void		fm_event_process_all(void);

#endif /* FREEMAP_EVENTS_H */
