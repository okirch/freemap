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

#include "scanner.h"
#include "protocols.h"
#include "wellknown.h"
#include "target.h" /* for fm_probe_t */
#include "socket.h"
#include "buffer.h"

typedef struct fm_udp_request {
	fm_protocol_t *		proto;
	fm_target_t *		target;
	fm_socket_t *		sock;

	fm_address_t		host_address;
	fm_probe_params_t	params;

	/* This should be configurable at the probe level, but
	 * we're not handling that yet.
	 */
	bool			use_connected_socket;
} fm_udp_request_t;

static fm_socket_t *	fm_udp_create_bsd_socket(fm_protocol_t *proto, int af);
static fm_socket_t *	fm_udp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target);
static bool		fm_udp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt);
static bool		fm_udp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt);
static fm_probe_t *	fm_udp_create_parameterized_probe(fm_protocol_t *, fm_target_t *, const fm_probe_params_t *params, const void *extra_params);

static fm_udp_request_t *fm_udp_probe_get_request(const fm_probe_t *probe);
static void		fm_udp_probe_set_request(fm_probe_t *probe, fm_udp_request_t *udp);

static struct fm_protocol_ops	fm_udp_bsdsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "udp",
	.id		= FM_PROTO_UDP,

	.supported_parameters =
			  FM_PARAM_TYPE_PORT_MASK |
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK,

	.create_socket	= fm_udp_create_bsd_socket,
	.create_host_shared_socket = fm_udp_create_shared_socket,
	.process_packet = fm_udp_process_packet,
	.process_error	= fm_udp_process_error,

	.create_parameterized_probe = fm_udp_create_parameterized_probe,
};

FM_PROTOCOL_REGISTER(fm_udp_bsdsock_ops);

static fm_socket_t *
fm_udp_create_bsd_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;

	sock = fm_socket_create(af, SOCK_DGRAM, 0, proto);
	if (sock) {
		fm_socket_enable_ttl(sock);
		fm_socket_enable_tos(sock);
	}
	return sock;
}

static fm_socket_t *
fm_udp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target)
{
	const fm_address_t *dst_address = &target->address;
	fm_address_t bind_address;
	fm_socket_t *sock = NULL;

	sock = fm_protocol_create_socket(proto, dst_address->ss_family);

	/* The following code is not used yet. We will use that eg for
	 * allocating source ports from a given range.
	 * Before we get there, we would have to implement something like a port pool
	 */
	if (0) {
		/* Pick the local host address to use when talking to this target. */
		if (!fm_target_get_local_bind_address(target, &bind_address)) {
			fm_log_error("%s: unable to determine local address to use when binding",
					fm_address_format(dst_address));
			goto failed;
		}

		/* make sure the port number is 0 */
		fm_address_set_port(&bind_address, 0);

		if (!fm_socket_bind(sock, &bind_address)) {
			fm_log_error("%s: unable to bind to local address %s",
					fm_address_format(dst_address),
					fm_address_format(&bind_address));
			goto failed;
		}
	}

	fm_socket_enable_recverr(sock);
	target->udp_sock = sock;

	return sock;

failed:
	fm_socket_free(sock);
	return NULL;
}

static fm_socket_t *
fm_udp_create_connected_socket(fm_protocol_t *proto, const fm_address_t *addr)
{
	fm_socket_t *sock;

	sock = fm_protocol_create_socket(proto, addr->ss_family);
	if (sock == NULL)
		return NULL;

	fm_socket_enable_recverr(sock);

	if (!fm_socket_connect(sock, addr)) {
		fm_socket_free(sock);
		return NULL;
	}

	return sock;
}

/*
 * UDP action
 */
static void
fm_udp_request_free(fm_udp_request_t *udp)
{
	if (udp->sock != NULL) {
		fm_socket_free(udp->sock);
		udp->sock = NULL;
	}
	free(udp);
}

static fm_udp_request_t *
fm_udp_request_alloc(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params)
{
	fm_udp_request_t *udp;

	if (params->port == 0) {
		fm_log_error("%s: trying to create a udp request without destination port");
		return NULL;
	}


	udp = calloc(1, sizeof(*udp));
	udp->proto = proto;
	udp->target = target;
	udp->params = *params;

	udp->host_address = target->address;
	if (!fm_address_set_port(&udp->host_address, params->port)) {
		fm_udp_request_free(udp);
		return NULL;
	}

	return udp;
}

/*
 * Track extant UDP requests.
 * We currently do not track individual packets and their response(s), we just
 * record the fact that we *did* send to a specific port.
 * We do not even distinguish by the source port used on our end.
 */
struct udp_extant_info {
	unsigned int		port;
};

static bool
fm_udp_expect_response(fm_probe_t *probe, int af, unsigned int port)
{
	struct udp_extant_info info = { .port = port };

	fm_extant_alloc(probe, af, IPPROTO_UDP, &info, sizeof(info));
	return true;
}

static fm_extant_t *
fm_udp_locate_probe(fm_protocol_t *proto, fm_pkt_t *pkt, fm_asset_state_t state)
{
	fm_target_t *target;
	unsigned short port;
	hlist_iterator_t iter;
	fm_extant_t *extant;

	target = fm_target_pool_find(&pkt->peer_addr);
	if (target == NULL)
		return NULL;

	port = fm_address_get_port(&pkt->peer_addr);

	/* update the asset */
	fm_target_update_port_state(target, FM_PROTO_UDP, port, state);

	/* If this is an ICMP error, we might as well mark the router/end host
	 * as reachable. */
	if (pkt->info.offender != NULL) {
		fm_host_asset_t *host = fm_host_asset_get(pkt->info.offender, true);

		if (host) {
			fm_host_asset_update_state(host, FM_ASSET_STATE_OPEN);

			/* while we're at it, why don't we update the rtt for this asset? */
		}
	}

	fm_extant_iterator_init(&iter, &target->expecting);
	while ((extant = fm_extant_iterator_match(&iter, pkt->family, IPPROTO_UDP)) != NULL) {
		const struct udp_extant_info *info = (struct udp_extant_info *) (extant + 1);

		if (info->port == port)
			return extant;
	}

	return extant;
}

/*
 * Handle UDP reply packet
 */
static bool
fm_udp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant;

	extant = fm_udp_locate_probe(proto, pkt, FM_ASSET_STATE_OPEN);
	if (extant != NULL) {
		fm_extant_received_reply(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

static bool
fm_udp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant;

	extant = fm_udp_locate_probe(proto, pkt, FM_ASSET_STATE_CLOSED);
	if (extant != NULL) {
		fm_extant_received_error(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

/*
 * UDP port probes using standard BSD sockets
 */
static void
fm_udp_port_probe_destroy(fm_probe_t *probe)
{
	fm_udp_request_t *udp = fm_udp_probe_get_request(probe);

	if (udp != NULL) {
		fm_udp_request_free(udp);
		fm_udp_probe_set_request(probe, NULL);
	}
}

static fm_pkt_t *
fm_udp_build_packet(fm_address_t *dstaddr, unsigned int port)
{
	fm_wellknown_service_t *wks;
	fm_pkt_t *pkt;

	pkt = fm_pkt_alloc(dstaddr->ss_family, 0);
	pkt->peer_addr = *dstaddr;

	/* Check if we can guess a well-known service */
	if ((wks = fm_wellknown_service_for_port("udp", port)) != NULL) {
		pkt->payload = fm_wellknown_service_build_packet(wks);
	} else {
		/* If we can't guess the UDP service, send a single NUL byte as payload. */
		pkt->payload = fm_buffer_alloc(16);
		fm_buffer_append(pkt->payload, "", 1);
	}

	return pkt;
}

static fm_error_t
fm_udp_port_probe_send(fm_probe_t *probe)
{
	fm_udp_request_t *udp = fm_udp_probe_get_request(probe);
	fm_socket_t *sock;
	fm_pkt_t *pkt;

	if (udp->use_connected_socket) {
		udp->sock = fm_udp_create_connected_socket(probe->proto, &udp->host_address);
		sock = udp->sock;
	} else {
		sock = fm_protocol_create_host_shared_socket(probe->proto, probe->target);
	}

	if (sock == NULL) {
		fm_log_error("Unable to create UDP socket for %s: %m",
				fm_address_format(&udp->host_address));
		return FM_SEND_ERROR;
	}

	pkt = fm_udp_build_packet(&udp->host_address, udp->params.port);

	/* apply ttl, tos etc */
	fm_pkt_apply_probe_params(pkt, &udp->params, probe->proto->ops->supported_parameters);

	if (!fm_socket_send_pkt_and_burn(sock, pkt)) {
		fm_log_error("Unable to send UDP packet: %m");
		return FM_SEND_ERROR;
	}

	fm_udp_expect_response(probe, udp->host_address.ss_family, udp->params.port);

	/* update the asset state */
	fm_target_update_port_state(probe->target, FM_PROTO_UDP, udp->params.port, FM_ASSET_STATE_PROBE_SENT);

	return 0;
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
	fm_probe_timed_out(probe);
	return false;
}

struct fm_udp_port_probe {
	fm_probe_t		base;
	fm_udp_request_t *	udp;
};

static struct fm_probe_ops fm_udp_port_probe_ops = {
	.obj_size	= sizeof(struct fm_udp_port_probe),
	.name 		= "udp",

	.destroy	= fm_udp_port_probe_destroy,
	.send		= fm_udp_port_probe_send,
	.should_resend	= fm_udp_port_probe_should_resend,
};

static fm_udp_request_t *
fm_udp_probe_get_request(const fm_probe_t *probe)
{
	return ((struct fm_udp_port_probe *) probe)->udp;
}

static void
fm_udp_probe_set_request(fm_probe_t *probe, fm_udp_request_t *udp)
{
	((struct fm_udp_port_probe *) probe)->udp = udp;
}

static fm_probe_t *
fm_udp_create_parameterized_probe(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_udp_request_t *udp;
	fm_probe_t *probe;
	char name[32];

	udp = fm_udp_request_alloc(proto, target, params);

	snprintf(name, sizeof(name), "udp/%u", params->port);
	probe = fm_probe_alloc(name, &fm_udp_port_probe_ops, proto, target);

	fm_udp_probe_set_request(probe, udp);

	/* UDP services may take up to .5 sec for the queued TCP connection to be accepted. */
	probe->rtt_application_bias = fm_global.udp.application_delay;

	fm_log_debug("Created UDP socket probe for %s\n", fm_address_format(&udp->host_address));
	return probe;
}
