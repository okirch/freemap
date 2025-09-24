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
 * Simple UDP scanning functions
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>

#include "scanner.h"
#include "protocols.h"
#include "wellknown.h"
#include "target.h" /* for fm_probe_t */

static fm_probe_t *	fm_udp_create_port_probe(fm_protocol_engine_t *proto, fm_target_t *target, uint16_t port);

struct fm_udp_engine_default {
	fm_protocol_engine_t	base;
};

static struct fm_protocol_ops	fm_udp_engine_default_ops = {
	.obj_size	= sizeof(struct fm_udp_engine_default),
	.name		= "udp",

	.create_port_probe = fm_udp_create_port_probe,
};

fm_protocol_engine_t *
fm_udp_engine_create(void)
{
	return fm_protocol_engine_create(&fm_udp_engine_default_ops);
}

/*
 * UDP port probes using standard BSD sockets
 */
struct fm_udp_port_probe {
	fm_probe_t	base;

	unsigned int	send_retries;

	unsigned int	port;
	fm_address_t	host_address;
	fm_socket_t *	sock;
};

static void
fm_udp_port_probe_destroy(fm_probe_t *probe)
{
	struct fm_udp_port_probe *udp = (struct fm_udp_port_probe *) probe;

	if (udp->sock != NULL) {
		fm_socket_set_callback(udp->sock, NULL, NULL);
		fm_socket_free(udp->sock);
		udp->sock = NULL;
	}
}

static void
fm_udp_port_probe_callback(fm_socket_t *sock, int bits, void *user_data)
{
	struct fm_udp_port_probe *udp = user_data;

	assert(udp->sock == sock);

	if (bits & POLLERR) {
		printf("UDP probe %s: error\n", fm_address_format(&udp->host_address));
		fm_probe_mark_port_unreachable(&udp->base, "udp", udp->port);
	} else if (bits & POLLIN) {
		printf("UDP probe %s: reachable\n", fm_address_format(&udp->host_address));
		fm_probe_mark_port_reachable(&udp->base, "udp", udp->port);
	}

	fm_socket_close(sock);
}

static fm_fact_t *
fm_udp_port_probe_send(fm_probe_t *probe)
{
	struct fm_udp_port_probe *udp = (struct fm_udp_port_probe *) probe;
	fm_wellknown_service_t *wks;
	const fm_probe_packet_t *pkt;

	if (udp->sock == NULL) {
		udp->sock = fm_socket_create(udp->host_address.ss_family, SOCK_DGRAM, 0);
		if (udp->sock == NULL) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to create UDP socket for %s: %m",
					fm_address_format(&udp->host_address));
		}

		fm_socket_set_callback(udp->sock, fm_udp_port_probe_callback, probe);

		if (!fm_socket_connect(udp->sock, &udp->host_address)) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to connect UDP socket for %s: %m",
					fm_address_format(&udp->host_address));
		}
	}

	/* Check if we can guess a well-known service */
	if ((wks = fm_wellknown_service_for_port("udp", udp->port)) == NULL) {
		/* If we can't guess the UDP service, send a single NUL byte as payload. */
		static fm_probe_packet_t dummy_packet = { "", 1 };
		static fm_wellknown_service_t dummy_udp = {
			.id = "udp", .probe_packet = &dummy_packet
		};

		wks = &dummy_udp;
	}

	pkt = wks->probe_packet;
	if (!fm_socket_send(udp->sock, NULL, pkt->data, pkt->len))
		return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to send UDP packet: %m");

	return NULL;
}

/*
 * This is called when we time out.
 * Assuming that the host in general is reachable, this means either that
 * the port is open (and our packet got dropped on the floor because it
 * wasn't a valid request); or there is a firewall running somewhere that
 * dropped the packet on the floor.
 *
 * We record the port as HEISENBERG and then, when we look at the overall
 * picture for the host, we make an educated guess.
 */
static bool
fm_udp_port_probe_should_resend(fm_probe_t *probe)
{
	struct fm_udp_port_probe *udp = (struct fm_udp_port_probe *) probe;

	fm_probe_mark_port_heisenberg(probe, "udp", udp->port);
	return false;
}

static struct fm_probe_ops fm_udp_port_probe_ops = {
	.obj_size	= sizeof(struct fm_udp_port_probe),
	.name 		= "udp",

	.destroy	= fm_udp_port_probe_destroy,
	.send		= fm_udp_port_probe_send,
	.should_resend	= fm_udp_port_probe_should_resend,
};

static fm_probe_t *
fm_udp_create_port_probe(fm_protocol_engine_t *proto, fm_target_t *target, uint16_t port)
{
	struct sockaddr_storage tmp_address = target->address;
	struct fm_udp_port_probe *probe;

	if (!fm_address_set_port(&tmp_address, port))
		return NULL;

	probe = (struct fm_udp_port_probe *) fm_probe_alloc(&fm_udp_port_probe_ops);

	probe->port = port;
	probe->host_address = tmp_address;
	probe->sock = NULL;

	if (target->rtt_estimate) {
		probe->base.timeout = 10 * target->rtt_estimate;
	} else {
		probe->base.timeout = 1000;
	}

	printf("Created UDP socket probe for %s\n", fm_address_format(&probe->host_address));
	return &probe->base;
}

