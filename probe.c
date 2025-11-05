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
#include "events.h"

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
 * probe modes
 */
const char *
fm_probe_mode_to_string(int mode)
{
	switch (mode) {
	case FM_PROBE_MODE_TOPO:
		return "topo";
	case FM_PROBE_MODE_HOST:
		return "host";
	case FM_PROBE_MODE_PORT:
		return "port";
	}
	return "bad";
}

/*
 * Throw away a probe.
 */
void
fm_probe_destroy(fm_probe_t *probe)
{
	/* When we get here, the job part of this should have been pretty much torn already. */
	assert(probe->job.group == NULL);

	if (probe->ops->destroy)
		probe->ops->destroy(probe);

	if (probe->_target != NULL)
		fm_target_forget_pending(probe->_target, probe);
}

void
fm_probe_free(fm_probe_t *probe)
{
	fm_probe_destroy(probe);
	free(probe);
}

/*
 * Add a probe to the global scheduler queue
 */
void
fm_probe_run_globally(fm_probe_t *probe)
{
	fm_job_group_add_new(fm_scheduler_create_global_queue(), &probe->job);
}

/*
 * The probe<->job glue
 */
static fm_error_t
fm_probe_job_run(fm_job_t *job, fm_sched_stats_t *stats)
{
	fm_probe_t *probe = (fm_probe_t *) job;
	fm_error_t error;
	bool first_transmission;

	first_transmission = !fm_timestamp_is_set(&probe->sent);

	error = fm_probe_send(probe);
	if (error == FM_TRY_AGAIN) {
		/* the probe asked to be postponed. */
	} else {
		if (error != FM_SEND_ERROR)
			stats->num_sent += 1;

		if (error != 0) {
			/* complain about probes that are so broken they don't even manage to
			 * send a single package. */
			if (first_transmission)
				fm_log_warning("%s: probe is DOA", probe->job.fullname);
		} else if (first_transmission)
			fm_timestamp_init(&probe->sent);
	}

	return error;
}

static void
fm_probe_job_destroy(fm_job_t *job)
{
	fm_probe_t *probe = (fm_probe_t *) job;

	fm_probe_destroy(probe);
}

static fm_job_ops_t	fm_probe_job_ops = {
	.run		= fm_probe_job_run,
	.destroy	= fm_probe_job_destroy,
};

fm_probe_t *
fm_probe_from_job(fm_job_t *job)
{
	if (job->ops != &fm_probe_job_ops)
		return NULL;

	return (fm_probe_t *) job;
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
	probe->_target = target;
	probe->name = strdup(id);
	probe->ops = ops;

	fm_job_init(&probe->job, &fm_probe_job_ops, probe->name);

	return probe;
}

void
fm_probe_set_expiry(fm_probe_t *probe, double seconds)
{
	fm_job_set_expiry(&probe->job, seconds);
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
 * Associate a service probe with a port probe.
 * The service probe provides a list of payloads to send.
 */
fm_error_t
fm_probe_set_service(fm_probe_t *probe, fm_service_probe_t *service_probe)
{
	if (probe->ops->set_service == NULL) {
		fm_log_error("%s: %s does not support service probes", __func__, probe->name);
		return FM_NOT_SUPPORTED;
	}

	return probe->ops->set_service(probe, service_probe);
}

/*
 * This kicks the probe to make it send another packet (if it feels like it)
 */
fm_error_t
fm_probe_send(fm_probe_t *probe)
{
	fm_error_t error;

	/* In theory, we could fold schedule() and send() into one, and some
	 * probe implementations actually do this (eg traceroute). But in most
	 * cases, the code looks just cleaner if we don't conflate these two steps. */
	error = probe->ops->schedule(probe);
	if (error == 0)
		error = probe->ops->send(probe);

	return error;
}

/*
 * Probe completion
 */
fm_completion_t *
fm_probe_wait_for_completion(fm_probe_t *probe, void (*func)(const fm_job_t *, void *), void *user_data)
{
	return fm_job_wait_for_completion(&probe->job, func, user_data);
}

void
fm_probe_cancel_completion(fm_probe_t *probe, const fm_completion_t *completion)
{
	fm_job_cancel_completion(&probe->job, completion);
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
fm_probe_mark_complete(fm_probe_t *probe)
{
	fm_job_mark_complete(&probe->job);
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
	return fm_job_wait_for_event(&probe->job, callback, event);
}

void
fm_probe_finish_waiting(fm_probe_t *probe)
{
	fm_job_finish_waiting(&probe->job);
}

/*
 * Tracking of extant requests
 */
fm_extant_t *
fm_extant_alloc(fm_probe_t *probe, int af, int ipproto, const void *payload, size_t payload_size)
{
	fm_target_t *target;
	fm_extant_t *extant;

	if ((target = probe->_target) == NULL) {
		/* Dont do that */
		fm_log_warning("%s: cannot allocate and extant because the probe is not associated with a specific target",
				fm_probe_name(probe));
		return NULL;
	}

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
