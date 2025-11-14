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
#include "extant.h"
#include "probe.h"
#include "protocols.h"

/*
 * Tracking of extant requests
 */
fm_extant_t *
fm_extant_alloc_list(fm_probe_t *probe, int af, int ipproto, const void *payload, size_t payload_size, fm_extant_list_t *exlist)
{
	fm_extant_t *extant;

	extant = calloc(1, sizeof(*extant) + payload_size);

	extant->family = af;
	extant->ipproto = ipproto;
	extant->probe = probe;

	/* by default, an extant will be destroyed as soon as we have a reply. */
	extant->single_shot = true;

	fm_socket_timestamp_update(&extant->timestamp);

	if (payload != NULL)
		memcpy(extant + 1, payload, payload_size);

	fm_extant_append(exlist, extant);

	return extant;
}

void
fm_extant_list_forget_probe(fm_extant_list_t *list, const fm_probe_t *probe)
{
	hlist_iterator_t iter;
	fm_extant_t *extant;

	fm_extant_iterator_init(&iter, list);
	while ((extant = fm_extant_iterator_next(&iter)) != NULL) {
		if (extant->probe == probe)
			fm_extant_free(extant);
	}
}

void
fm_extant_free(fm_extant_t *extant)
{
	fm_extant_unlink(extant);
	extant->probe = NULL;
	extant->tasklet = NULL;
	free(extant);
}

/*
 * Add a notifier to the extant. This will be invoked when the extant matched
 * an incoming packet.
 */
void
fm_extant_set_notifier(fm_extant_t *extant, const fm_extant_notifier_t *notifier)
{
	if (extant->notifier == notifier)
		return;
	if (extant->notifier != NULL) {
		fm_log_error("Conflicting notifier on extant");
		return;
	}

	extant->notifier = notifier;
}

static inline void
fm_extant_invoke_notifier(fm_extant_t *extant, const fm_pkt_t *pkt, const double *rtt)
{
	fm_extant_notifier_t *notify = extant->notifier;

	if (notify != NULL) {
		double rtt;

		rtt = fm_pkt_rtt(pkt, &extant->timestamp);
		notify->callback(extant, pkt, &rtt, notify->user_data);
	}
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
	fm_tasklet_t *tasklet;

	if (probe != NULL) {
		fm_probe_update_rtt_estimate(probe, &rtt);

		if (fm_probe_invoke_status_callback(probe, pkt, rtt))
			return; /* whoever is watching this probe wants us to keep going */

		fm_probe_mark_complete(probe);
	}

	fm_extant_invoke_notifier(extant, pkt, NULL);

	if (extant->single_shot && (tasklet = extant->tasklet) != NULL)
		fm_tasklet_extant_done(tasklet, extant);
}

void
fm_extant_received_error(fm_extant_t *extant, const fm_pkt_t *pkt)
{
	double rtt = fm_pkt_rtt(pkt, &extant->timestamp);
	fm_probe_t *probe = extant->probe;
	fm_tasklet_t *tasklet;

	if (probe != NULL) {
		fm_probe_update_rtt_estimate(probe, &rtt);

		if (fm_probe_invoke_status_callback(probe, pkt, rtt))
			return; /* whoever is watching this probe wants us to keep going */

		fm_probe_mark_complete(probe);
	}

	fm_extant_invoke_notifier(extant, pkt, NULL);

	if (extant->single_shot && (tasklet = extant->tasklet) != NULL)
		fm_tasklet_extant_done(tasklet, extant);
}

/*
 * Extant maps are usually attached to a socket and act as a quick and generic way
 * of matching response/error packets with outstanding probe packets.
 */
fm_extant_map_t *
fm_extant_map_alloc(void)
{
	fm_extant_map_t *map;

	map = calloc(1, sizeof(*map));
	return map;
}

/*
 * Add an extant to the map
 */
fm_extant_t *
fm_extant_map_add(fm_extant_map_t *map, fm_host_asset_t *host, int family, int ipproto, const void *data, size_t len)
{
	fm_extant_t *extant;

	extant = fm_extant_alloc_list(NULL, family, ipproto, data, len, &map->pending);
	extant->host = host;
	return extant;
}

void
fm_extant_map_forget_probe(fm_extant_map_t *map, const fm_probe_t *probe)
{
	fm_extant_list_forget_probe(&map->pending, probe);
}

bool
fm_extant_map_process_data(fm_extant_map_t *map, fm_protocol_t *proto, fm_pkt_t *pkt)
{
	hlist_iterator_t iter;
	fm_extant_t *extant;

	fm_extant_iterator_init(&iter, &map->pending);
	if ((extant = fm_protocol_locate_response(proto, pkt, &iter)) == NULL)
		return false;

	/* Mark the probe as successful, and update the RTT estimate */
	fm_extant_received_reply(extant, pkt);

	/* For regular host probes, we can now free the extant.
	 * However, for discovery probes, there will be any number of
	 * responses, and we want to catch them all.
	 * So we just leave the extant untouched.
	 */
	if (extant->single_shot)
		fm_extant_free(extant);

	return true;
}

bool
fm_extant_map_process_error(fm_extant_map_t *map, fm_protocol_t *proto, fm_pkt_t *pkt)
{
	hlist_iterator_t iter;
	fm_extant_t *extant;

	fm_extant_iterator_init(&iter, &map->pending);
	if ((extant = fm_protocol_locate_error(proto, pkt, &iter)) == NULL)
		return false;

	/* Mark the probe as failed, and update the RTT estimate */
	fm_extant_received_error(extant, pkt);

	/* For regular host probes, we can now free the extant.
	 * However, for discovery probes, there will be any number of
	 * responses, and we want to catch them all.
	 * So we just leave the extant untouched.
	 */
	if (extant->single_shot)
		fm_extant_free(extant);

	return true;
}
