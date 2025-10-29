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
