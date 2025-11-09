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

