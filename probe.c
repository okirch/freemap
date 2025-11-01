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
#include "protocols.h"

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
 * Handle registration of probe classes
 */
#define FM_PROBE_CLASS_MAX	128
static unsigned int		probe_class_count;
static struct fm_probe_class *	probe_class_registry[FM_PROBE_CLASS_MAX];

void
fm_probe_class_register(struct fm_probe_class *probe_class)
{
	assert(probe_class_count < FM_PROBE_CLASS_MAX);
	probe_class_registry[probe_class_count++] = probe_class;
}

static void
fm_probe_classes_init(void)
{
	static bool initialized = false;
	struct fm_probe_class *pclass;
	unsigned int i;

	if (!initialized) {
		for (i = 0; i < probe_class_count; ++i) {
			fm_protocol_t *proto;

			pclass = probe_class_registry[i];

			if (pclass->proto_id == 0)
				continue;

			proto = fm_protocol_by_id(pclass->proto_id);
			if (proto == NULL) {
				fm_log_debug("probe class %s requires protocol %s, which is not available",
						pclass->name, fm_protocol_id_to_string(pclass->proto_id));

				/* disable by cleaning out the mask of supported modes */
				pclass->modes = 0;
				continue;
			}

			pclass->proto = proto;
			pclass->features |= proto->supported_parameters;
		}
		initialized = true;
	}
}

const fm_probe_class_t *
fm_probe_class_find(const char *name, int mode)
{
	struct fm_probe_class *pclass;
	unsigned int i;

	fm_probe_classes_init();
	for (i = 0; i < probe_class_count; ++i) {
		pclass = probe_class_registry[i];

		if (!(pclass->modes & mode))
			continue;

		if (!strcmp(pclass->name, name))
			return pclass;
	}

	return NULL;
}

fm_probe_class_t *
fm_probe_class_by_proto_id(unsigned int proto_id, int mode)
{
	struct fm_probe_class *pclass;
	unsigned int i;

	fm_probe_classes_init();
	for (i = 0; i < probe_class_count; ++i) {
		pclass = probe_class_registry[i];

		if (!(pclass->modes & mode))
			continue;

		if (pclass->proto_id == proto_id)
			return pclass;
	}

	return NULL;
}

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
fm_probe_alloc(const char *id, const struct fm_probe_ops *ops, fm_target_t *target)
{
	fm_probe_t *probe;

	if (ops->schedule == NULL)
		fm_log_fatal("BUG: probe implementation %s lacks a schedule() function", ops->name);

	assert(ops->obj_size >= sizeof(*probe));
	probe = calloc(1, ops->obj_size);
	probe->target = target;
	probe->name = strdup(id);
	probe->ops = ops;

	return probe;
}

void
fm_probe_free(fm_probe_t *probe)
{
	if (probe->completion)
		fm_log_fatal("BUG: %s(%s) with pending completion", __func__, probe->name);

	if (probe->ops->destroy)
		probe->ops->destroy(probe);

	if (probe->target != NULL)
		fm_target_forget_pending(probe->target, probe);

	if (probe->event_listener != NULL)
		fm_event_listener_free(probe->event_listener);

	fm_probe_unlink(probe);

	memset(probe, 0, sizeof(*probe));
	free(probe);
}

void
fm_probe_set_expiry(fm_probe_t *probe, double seconds)
{
	if (seconds < 0)
		fm_log_error("%s: asking to set a negative expiry value %f", probe->name, seconds);

	if (seconds <= 0) {
		fm_timestamp_init(&probe->expires);
	} else {
		fm_timestamp_set_timeout(&probe->expires, 1000 * seconds);
	}
}

static void
fm_probe_adjust_expiry(fm_probe_t *probe)
{
	double target_wait, probe_wait;

	/* The probe may want to be scheduled sooner that we're prepared to allow */
	target_wait = fm_ratelimit_wait_until(&probe->target->host_rate_limit, 1);
	if (target_wait == 0)
		return;

	probe_wait = fm_timestamp_expires_when(&probe->expires, NULL);
	if (probe_wait < target_wait) {
		fm_log_debug("%s %s ready delayed by %u ms due to target rate limiting",
				fm_address_format(&probe->target->address), probe->name,
				(unsigned int) (1000 * (target_wait - probe_wait)));
		fm_timestamp_set_timeout(&probe->expires, 1000 * target_wait);
	}
}

/*
 * used by traceroute
 */
fm_error_t
fm_probe_set_socket(fm_probe_t *probe, fm_socket_t *sock)
{
	if (probe->ops->set_socket == NULL) {
		fm_log_error("%s: %s does not support shared sockets", __func__, probe->name);
		return FM_NOT_SUPPORTED;
	}

	return probe->ops->set_socket(probe, sock);
}

/*
 * This kicks the probe to make it send another packet (if it feels like it)
 */
fm_error_t
fm_probe_send(fm_probe_t *probe)
{
	fm_error_t error;

	fm_timestamp_clear(&probe->expires);
	probe->timeout = 0;

	/* In theory, we could fold schedule() and send() into one, and some
	 * probe implementations actually do this (eg traceroute). But in most
	 * cases, the code looks just cleaner if we don't conflate these two steps. */
	error = probe->ops->schedule(probe);
	if (error == 0)
		error = probe->ops->send(probe);

	if (error == 0) {
		fm_ratelimit_consume(&probe->target->host_rate_limit, 1);
		fm_probe_adjust_expiry(probe);
	}

	if (error == 0 || error == FM_TRY_AGAIN) {
		if (!fm_timestamp_is_set(&probe->expires)) {
			fm_log_warning("BUG: probe %s returned status=%d but did not set expiry", probe->name, -error);
			fm_timestamp_set_timeout(&probe->expires, 10000);
		}
	} else {
		fm_log_debug("%s: %s: %s", fm_address_format(&probe->target->address), probe->name, fm_strerror(error));
		fm_probe_set_error(probe, error);
	}

	return error;
}

/*
 * Probe completion
 */
fm_completion_t *
fm_probe_wait_for_completion(fm_probe_t *probe, void (*func)(const fm_probe_t *, void *), void *user_data)
{
	fm_completion_t *completion;

	if (probe->completion != NULL) {
		fm_log_error("%s: refusing to install more than one completion", probe->name);
		return NULL;
	}

	completion = calloc(1, sizeof(*completion));
	completion->callback = func;
	completion->user_data = user_data;

	probe->completion = completion;
	return completion;
}

void
fm_probe_invoke_completion(fm_probe_t *probe)
{
	fm_completion_t *completion;

	if ((completion = probe->completion) != NULL) {
		probe->completion = NULL;
		completion->callback(probe, completion->user_data);
	}
}

void
fm_probe_cancel_completion(fm_probe_t *probe, const fm_completion_t *completion)
{
	if (probe->completion == completion)
		probe->completion = NULL;
}

void
fm_completion_free(fm_completion_t *completion)
{
	completion = NULL;
}

/*
 * Another set of callbacks; this time for inspecting packets received
 * an errors encountered.
 * Returns true if the probe should keep going, false if is considered complete.
 */
void
fm_probe_install_status_callback(fm_probe_t *probe, fm_probe_status_callback_t *cb, void *user_data)
{
	probe->status_callback.cb = cb;
	probe->status_callback.user_data = user_data;
}

static inline bool
fm_probe_invoke_status_callback(const fm_probe_t *probe, const fm_pkt_t *pkt, double rtt)
{
	if (!probe->status_callback.cb)
		return false;

	return probe->status_callback.cb(probe, pkt, rtt, probe->status_callback.user_data);
}

void
fm_probe_set_error(fm_probe_t *probe, fm_error_t error)
{
	if (!probe->done) {
		if (!probe->error)
			probe->error = error;

		if (error != FM_TIMED_OUT) {
			/* for later */
			/* probe->elapsed = fm_timestamp_since(&probe->sent); */
		}
	}
	fm_probe_mark_complete(probe);
}

void
fm_probe_mark_complete(fm_probe_t *probe)
{
	if (!probe->done) {
		/* for later */
		/* probe->elapsed = fm_timestamp_since(&probe->sent); */
	}
	probe->done = true;

	fm_probe_invoke_completion(probe);
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
	fm_probe_update_rtt_estimate(probe, rtt);
	fm_probe_mark_complete(probe);
}

void
fm_probe_received_error(fm_probe_t *probe, double *rtt)
{
	fm_probe_update_rtt_estimate(probe, rtt);
	fm_probe_mark_complete(probe);
}

void
fm_probe_timed_out(fm_probe_t *probe)
{
	fm_probe_mark_complete(probe);
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
 * If the kernel did not give us a timestamp via SO_TIMESTAMP, the packet's timetstamp will be
 * unset. In this case, fm_timestamp_delta() will just use the current wall time
 * instead.
 */
void
fm_extant_received_reply(fm_extant_t *extant, const fm_pkt_t *pkt)
{
	double rtt = fm_pkt_rtt(pkt, &extant->timestamp);
	fm_probe_t *probe = extant->probe;

	fm_probe_update_rtt_estimate(probe, &rtt);

	if (fm_probe_invoke_status_callback(probe, pkt, rtt))
		return; /* whoever is watching this probe wants us to keep going */

	fm_probe_mark_complete(probe);
}

void
fm_extant_received_error(fm_extant_t *extant, const fm_pkt_t *pkt)
{
	double rtt = fm_pkt_rtt(pkt, &extant->timestamp);
	fm_probe_t *probe = extant->probe;

	fm_probe_update_rtt_estimate(probe, &rtt);

	if (fm_probe_invoke_status_callback(probe, pkt, rtt))
		return; /* whoever is watching this probe wants us to keep going */

	fm_probe_mark_complete(probe);
}
