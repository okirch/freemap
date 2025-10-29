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
#include "target.h"
#include "network.h"
#include "utils.h"
#include "lists.h"

/*
 * We implement a simple and hopefully robust mechanism that allows
 * probes to wait for certain events.
 *
 * A probe can point to a event_listener object that describes the event(s)
 * it is waiting for.
 * These objects, when active, are inserted into a linked list managed
 * by the job scheduler. When an event is signaled, the job scheduler
 * walks this list and calls every probe that is waiting for this
 * specific event.
 */
struct fm_event_listener {
	struct hlist		link;

	/* Callback to invoke.
	 * returns true to indicate that the probe is done waiting.
	 */
	fm_event_callback_t *	callback;

	/* Back pointer to the probe */
	fm_probe_t *		probe;

	/* Event we're waiting for.
	 * Right now, a probe cannot wait for more than one event at
	 * a time (but extending that should be easy).
	 */
	fm_event_t		event;
};

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
static fm_event_listener_t *
fm_event_listener_alloc(fm_probe_t *probe, fm_event_callback_t *callback, fm_event_t event)
{
	fm_event_listener_t *evl;

	evl = calloc(1, sizeof(*evl));
	evl->probe = probe;
	evl->callback = callback;
	evl->event = event;

	hlist_insert(&fm_event_listeners, &evl->link);

	return evl;
}

static void
fm_event_listener_disable(fm_event_listener_t *evl)
{
	if (evl->probe && evl->probe->event_listener == evl)
		evl->probe->event_listener = NULL;
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
static void
fm_event_listener_free(fm_event_listener_t *evl)
{
	if (evl->probe && evl->probe->event_listener == evl)
		evl->probe->event_listener = NULL;
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
		 && evl->callback(evl->probe, event)) {
			fm_probe_finish_waiting(evl->probe);
			assert(evl->probe->event_listener == NULL);
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

/*
 * Probe objects
 */
fm_probe_t *
fm_probe_alloc(const char *id, const struct fm_probe_ops *ops, fm_protocol_t *proto, fm_target_t *target)
{
	fm_probe_t *probe;

	assert(ops->obj_size >= sizeof(*probe));
	probe = calloc(1, ops->obj_size);
	probe->target = target;
	probe->name = strdup(id);
	probe->ops = ops;
	probe->proto = proto;

	return probe;
}

void
fm_probe_free(fm_probe_t *probe)
{
	if (probe->ops->destroy)
		probe->ops->destroy(probe);

	if (probe->status != NULL)
		fm_fact_free(probe->status);

	if (probe->target != NULL)
		fm_target_forget_pending(probe->target, probe);

	if (probe->event_listener != NULL)
		fm_event_listener_free(probe->event_listener);

	fm_probe_unlink(probe);

	memset(probe, 0, sizeof(*probe));
	free(probe);
}

fm_fact_t *
fm_probe_send(fm_probe_t *probe)
{
	fm_fact_t *error;

	probe->timeout = 0;

	error = probe->ops->send(probe);
	if (error == NULL) {
		/* Record when we sent the first packet */
		fm_timestamp_init(&probe->sent);

		/* If we have an RTT estimator, use the timeout it suggests */
		if (probe->timeout == 0 && probe->rtt != NULL)
			probe->timeout = probe->rtt->timeout + probe->rtt_application_bias;

		if (probe->timeout == 0)
			probe->timeout = probe->ops->default_timeout;

		if (probe->timeout > 0)
			fm_timestamp_set_timeout(&probe->expires, probe->timeout);
		else
			fm_log_warning("%s: timeout=0\n", probe->name);
	}
	return error;
}

void
fm_probe_set_status(fm_probe_t *probe, fm_fact_t *fact)
{
	if (probe->status) {
		fm_fact_free(fact);
	} else {
		fact->elapsed = fm_timestamp_since(&probe->sent);
		probe->status = fact;
	}
}

static void
fm_probe_render_verdict(fm_probe_t *probe, fm_probe_verdict_t verdict)
{
	fm_fact_t *fact;

	if (probe->status != NULL) {
		fm_log_error("%s: ignoring redundant verdict", probe->name);
		return;
	}

	fact = probe->ops->render_verdict(probe, verdict);
	if (fact == NULL) {
		fm_log_error("%s: cannot render verdict %d", probe->name, verdict);
		return;
	}

	fact->elapsed = fm_timestamp_since(&probe->sent);
	probe->status = fact;
}

void
fm_probe_set_rtt_estimator(fm_probe_t *probe, fm_rtt_stats_t *rtt)
{
	probe->rtt = rtt;
}

static inline void
fm_probe_update_rtt_estimate(fm_probe_t *probe, double *rtt)
{
	if (probe->rtt) {
		if (rtt == NULL || *rtt < 0) {
			/* This fallback should probably go away soon */
			fm_rtt_stats_update(probe->rtt, fm_timestamp_since(&probe->sent));
		} else {
			fm_rtt_stats_update(probe->rtt, *rtt);
		}

	}
}

void
fm_probe_received_reply(fm_probe_t *probe, double *rtt)
{
	fm_probe_render_verdict(probe, FM_PROBE_VERDICT_REACHABLE);
	fm_probe_update_rtt_estimate(probe, rtt);
}

void
fm_probe_received_error(fm_probe_t *probe, double *rtt)
{
	fm_probe_render_verdict(probe, FM_PROBE_VERDICT_UNREACHABLE);
	fm_probe_update_rtt_estimate(probe, rtt);
}

void
fm_probe_timed_out(fm_probe_t *probe)
{
	fm_probe_render_verdict(probe, FM_PROBE_VERDICT_TIMEOUT);
}

/*
 * Handle probe event listening
 */
bool
fm_probe_wait_for_event(fm_probe_t *probe, fm_event_callback_t *callback, fm_event_t event)
{
	fm_event_listener_t *evl;

	if ((evl = probe->event_listener) != NULL) {
		if (evl->callback == callback && evl->event == event)
			return true;
		fm_log_error("%s: cannot wait for more than one event at a time", probe->name);
		return false;
	}

	probe->event_listener = fm_event_listener_alloc(probe, callback, event);
	return true;
}

void
fm_probe_finish_waiting(fm_probe_t *probe)
{
	fm_event_listener_t *evl;

	if ((evl = probe->event_listener) != NULL) {
		fm_event_listener_disable(evl);
		probe->event_listener = NULL;
	}

	if (probe->target == NULL) {
		fm_log_warning("%s: probe %s not associated with any target?!", __func__, probe->name);
	} else {
		fm_target_continue_probe(probe->target, probe);
	}
}

/*
 * Tracking of extant requests
 */
fm_extant_t *
fm_extant_alloc(fm_probe_t *probe, int af, int ipproto, const void *payload, size_t payload_size)
{
	fm_target_t *target = probe->target;
	fm_extant_t *extant;

	extant = calloc(1, sizeof(*extant) + payload_size);

	extant->family = af;
	extant->ipproto = ipproto;
	extant->probe = probe;

	fm_socket_timestamp_update(&extant->timestamp);

	if (payload != NULL)
		memcpy(extant + 1, payload, payload_size);

	fm_extant_append(&target->expecting, extant);

	return extant;
}

void
fm_extant_free(fm_extant_t *extant)
{
	fm_extant_unlink(extant);
	free(extant);
}

/*
 * Process the verdict on an extant packet.
 * If the kernel did not give us a timestamp via SO_TIMESTAMP, recv_time will be
 * unset. In this case, fm_timestamp_delta() will just use the current wall time
 * instead.
 */
void
fm_extant_received_reply(fm_extant_t *extant, const fm_pkt_t *pkt)
{
	double rtt = fm_pkt_rtt(pkt, &extant->timestamp);

	fm_probe_received_reply(extant->probe, &rtt);
}

void
fm_extant_received_error(fm_extant_t *extant, const fm_pkt_t *pkt)
{
	double rtt = fm_pkt_rtt(pkt, &extant->timestamp);

	fm_probe_received_error(extant->probe, &rtt);
}
