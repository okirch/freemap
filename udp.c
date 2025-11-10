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
#include <errno.h>

#include "scanner.h"
#include "protocols.h"
#include "target.h" /* for fm_probe_t */
#include "socket.h"
#include "services.h"
#include "rawpacket.h"
#include "buffer.h"

typedef struct fm_udp_request {
	fm_protocol_t *		proto;
	fm_target_t *		target;

	fm_socket_t *		sock;
	bool			sock_is_shared;

	int			family;
	fm_address_t		host_address;
	fm_probe_params_t	params;

	/* This should be configurable at the probe level, but
	 * we're not handling that yet.
	 */
	bool			use_connected_socket;

	/* This is used primarily for connected sockets and
	 * for traceroute */
	unsigned int		src_port;

	/* total_retries reflects the complete # of packets we're supposed to
	 * send, accounting for service probes with multiple packets. */
	unsigned int		total_retries;

	/* Set of packages we're supposed to use in probing the port */
	unsigned int		service_index;
	fm_service_probe_t *	service_probe;
} fm_udp_request_t;

typedef struct fm_udp_extant_info {
	unsigned int		src_port;
	unsigned int		dst_port;
} fm_udp_extant_info_t;

static fm_socket_t *	fm_udp_create_bsd_socket(fm_protocol_t *proto, int af);
static fm_socket_t *	fm_udp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target);
static fm_extant_t *	fm_udp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_udp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);

static fm_udp_request_t *fm_udp_probe_get_request(const fm_probe_t *probe);
static void		fm_udp_probe_set_request(fm_probe_t *probe, fm_udp_request_t *udp);

/* Global extant map for all UDP related stuff */
static fm_extant_map_t fm_udp_extant_map = FM_EXTANT_MAP_INIT;

static struct fm_protocol	fm_udp_bsdsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "udp",
	.id		= FM_PROTO_UDP,

	.supported_parameters =
			  FM_PARAM_TYPE_PORT_MASK |
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK |
			  FM_FEATURE_SOCKET_SHARING_MASK |
			  FM_FEATURE_STATUS_CALLBACK_MASK,

	.create_socket	= fm_udp_create_bsd_socket,
	.create_host_shared_socket = fm_udp_create_shared_socket,
	.locate_error	= fm_udp_locate_error,
	.locate_response= fm_udp_locate_response,
};

FM_PROTOCOL_REGISTER(fm_udp_bsdsock_ops);

/*
 * Regular UDP sock dgram sockets.
 * In the error case, the packet the kernel will give us does *not* include any headers
 */
static fm_socket_t *
fm_udp_create_bsd_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;

	sock = fm_socket_create(af, SOCK_DGRAM, 0, proto);
	if (sock) {
		fm_socket_enable_ttl(sock);
		fm_socket_enable_tos(sock);

		fm_socket_attach_extant_map(sock, &fm_udp_extant_map);
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
 * Regular dgram sockets do not provide headers; synthesize them
 */
static fm_packet_parser_t *
fm_udp_create_dummy_data_parser(void)
{
	static fm_packet_parser_t *fake = NULL;

	if (fake == NULL) {
		fake = fm_packet_parser_alloc();

		fm_packet_parser_add_layer(fake, FM_PROTO_IP);
		fm_packet_parser_add_layer(fake, FM_PROTO_UDP);
	}

	return fake;
}

static fm_packet_parser_t *
fm_udp_create_dummy_error_parser(void)
{
	static fm_packet_parser_t *fake = NULL;

	if (fake == NULL) {
		fake = fm_packet_parser_alloc();

		fm_packet_parser_add_layer(fake, FM_PROTO_IP);
		fm_packet_parser_add_layer(fake, FM_PROTO_ICMP);
		fm_packet_parser_add_layer(fake, FM_PROTO_IP);
		fm_packet_parser_add_layer(fake, FM_PROTO_UDP);
	}

	return fake;
}

static fm_parsed_pkt_t *
fm_udp_synthesize_headers(fm_pkt_t *pkt)
{
	fm_packet_parser_t *parser;

	if (pkt->info.ee == NULL)
		parser = fm_udp_create_dummy_data_parser();
	else
		parser = fm_udp_create_dummy_error_parser();

	return fm_packet_synthetic_parse(parser, pkt);
}

/*
 * UDP action
 */
static void
fm_udp_request_free(fm_udp_request_t *udp)
{
	if (udp->sock != NULL && !udp->sock_is_shared)
		fm_socket_free(udp->sock);

	udp->sock = NULL;
	free(udp);
}

static fm_udp_request_t *
fm_udp_request_alloc(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
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

	if (udp->params.retries == 0)
		udp->params.retries = fm_global.udp.retries;
	udp->total_retries = udp->params.retries;

	udp->family = target->address.ss_family;
	udp->host_address = target->address;
	if (!fm_address_set_port(&udp->host_address, params->port)) {
		fm_udp_request_free(udp);
		return NULL;
	}

	return udp;
}

static void
fm_udp_request_set_socket(fm_udp_request_t *udp, fm_socket_t *sock)
{
	fm_address_t local_addr;

	udp->sock = sock;
	udp->sock_is_shared = true;
	udp->src_port = 0;

	fm_socket_enable_recverr(sock);

	if (fm_socket_get_local_address(sock, &local_addr))
		udp->src_port = fm_address_get_port(&local_addr);
}

static void
fm_udp_request_set_service(fm_udp_request_t *udp, fm_service_probe_t *service_probe)
{
	unsigned int npackets;

	if (service_probe == NULL || (npackets = service_probe->npackets) == 0) {
		udp->service_probe = NULL;
		return;
	}

	udp->service_probe = service_probe;
	udp->total_retries = udp->params.retries * npackets;
}

/*
 * Track extant UDP requests.
 * We currently do not track individual packets and their response(s), we just
 * record the fact that we *did* send to a specific port.
 * We do not even distinguish by the source port used on our end.
 */
static void
fm_udp_extant_info_build(const fm_udp_request_t *udp, fm_udp_extant_info_t *extant_info)
{
	extant_info->src_port = udp->src_port;
	extant_info->dst_port = udp->params.port;
}

static fm_extant_t *
fm_udp_locate_common(fm_pkt_t *pkt, unsigned short src_port, unsigned short dst_port, hlist_iterator_t *iter)
{
	fm_host_asset_t *host;
	fm_extant_t *extant;

	host = fm_host_asset_get_active(&pkt->peer_addr);
	if (host == NULL)
		return NULL;

	while ((extant = fm_extant_iterator_match(iter, pkt->family, IPPROTO_UDP)) != NULL) {
		const fm_udp_extant_info_t *info = (fm_udp_extant_info_t *) (extant + 1);

		if (extant->host == host
		 && info->dst_port == dst_port
		 && (src_port == 0 || info->src_port == src_port))
			return extant;
	}

	return NULL;
}

static fm_extant_t *
fm_udp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	fm_parsed_pkt_t *cooked;
	fm_parsed_hdr_t *hdr;
	fm_extant_t *extant;
	bool unreachable;

	if ((cooked = pkt->parsed) == NULL
	 && (cooked = fm_udp_synthesize_headers(pkt)) == NULL)
		return NULL;

	/* First, check the ICMP error header - does it tell us the port is unreachable? */
	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_ICMP)) == NULL)
		return NULL;
	unreachable = fm_icmp_header_is_host_unreachable(&hdr->icmp);

	/* Then, look at the enclosed UDP header */
	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_UDP)) == NULL)
		return NULL;

	extant = fm_udp_locate_common(pkt, hdr->udp.src_port, hdr->udp.dst_port, iter);

	/* If ICMP says the net/host/port is unreachable, mark the port resource as closed. */
	if (extant != NULL && extant->host && unreachable)
		fm_host_asset_update_port_state(extant->host, FM_PROTO_UDP, hdr->udp.dst_port, FM_ASSET_STATE_CLOSED);

	return extant;
}

static fm_extant_t *
fm_udp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	fm_parsed_pkt_t *cooked;
	fm_parsed_hdr_t *hdr;
	fm_extant_t *extant;

	if ((cooked = pkt->parsed) == NULL
	 && (cooked = fm_udp_synthesize_headers(pkt)) == NULL)
		return NULL;

	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_UDP)) == NULL)
		return NULL;

	extant = fm_udp_locate_common(pkt, hdr->udp.dst_port, hdr->udp.src_port, iter);

	if (extant != NULL && extant->host)
		fm_host_asset_update_port_state(extant->host, FM_PROTO_UDP, hdr->udp.src_port, FM_ASSET_STATE_OPEN);

	return extant;
}

/*
 * UDP port probes using standard BSD sockets
 */

/*
 * See if we have a probe packet
 */
static const fm_buffer_t *
fm_udp_request_next_service_probe(fm_udp_request_t *udp)
{
	unsigned int index = udp->service_index;
	const fm_buffer_t *payload;

	if (udp->service_probe == NULL)
		return NULL;

	payload = udp->service_probe->packets[index++];
	if (fm_buffer_available(payload) == 0) {
		fm_log_warning("udp port %u: service probe %u has empty packet", udp->params.port, index - 1);
		payload = NULL;
	}

	udp->service_index = index % udp->service_probe->npackets;
	return payload;
}

static fm_pkt_t *
fm_udp_build_packet(fm_address_t *dstaddr, unsigned int port, const fm_buffer_t *payload)
{
	fm_pkt_t *pkt;

	pkt = fm_pkt_alloc(dstaddr->ss_family, 0);
	pkt->peer_addr = *dstaddr;

	/* If we have a service probe payload, send a (copy) of that packet, else
	 * send a single NUL byte as payload */
	if (payload != NULL) {
		unsigned int len = fm_buffer_available(payload);

		pkt->payload = fm_buffer_alloc(len);
		fm_buffer_append(pkt->payload, fm_buffer_head(payload), len);
	} else {
		pkt->payload = fm_buffer_alloc(16);
		fm_buffer_append(pkt->payload, "", 1);
	}

	return pkt;
}

static fm_error_t
fm_udp_request_schedule(fm_udp_request_t *udp, fm_time_t *expires)
{
	if (udp->total_retries == 0)
		return FM_TIMED_OUT;

	/* After sending the last probe, we wait until the full timeout has expired.
	 * For any earlier probe, we wait for the specified packet spacing */
	if (udp->total_retries == 1)
		*expires = fm_time_now() + 1e-3 * fm_global.udp.timeout;
	else
		*expires = fm_time_now() + 1e-3 * fm_global.udp.packet_spacing;
	return 0;
}

/*
 * Send the udp request.
 * The probe argument is only here because we need to notify it when done.
 */
static fm_error_t
fm_udp_request_send(fm_udp_request_t *udp, fm_extant_t **extant_ret)
{
	fm_udp_extant_info_t extant_info;
	fm_socket_t *sock;
	fm_pkt_t *pkt;
	const fm_buffer_t *payload;

	if ((sock = udp->sock) != NULL) {
		/* pass */
	} else if (udp->use_connected_socket) {
		fm_address_t local_addr;

		udp->sock = fm_udp_create_connected_socket(udp->proto, &udp->host_address);
		sock = udp->sock;

		if (!fm_socket_get_local_address(sock, &local_addr)) {
			fm_log_warning("UDP: unable to get local address after connect: %m");
		} else {
			udp->src_port = fm_address_get_port(&local_addr);
		}
	} else {
		sock = fm_protocol_create_host_shared_socket(udp->proto, udp->target);
	}

	if (sock == NULL) {
		fm_log_error("Unable to create UDP socket for %s: %m",
				fm_address_format(&udp->host_address));
		return FM_SEND_ERROR;
	}

	payload = fm_udp_request_next_service_probe(udp);

	pkt = fm_udp_build_packet(&udp->host_address, udp->params.port, payload);

	/* apply ttl, tos etc */
	fm_pkt_apply_probe_params(pkt, &udp->params, udp->proto->supported_parameters);

	if (!fm_socket_send_pkt_and_burn(sock, pkt)) {
		fm_log_error("Unable to send UDP packet: %m");
		return FM_SEND_ERROR;
	}

	fm_udp_extant_info_build(udp, &extant_info);
	*extant_ret = fm_socket_add_extant(sock, udp->target->host_asset,
			udp->family, IPPROTO_UDP, &extant_info, sizeof(extant_info));

	assert(*extant_ret);

	udp->total_retries -= 1;

	/* update the asset state */
	fm_target_update_port_state(udp->target, FM_PROTO_UDP, udp->params.port, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

/*
 * Probe destructor
 */
static void
fm_udp_port_probe_destroy(fm_probe_t *probe)
{
	fm_udp_request_t *udp = fm_udp_probe_get_request(probe);

	if (udp != NULL) {
		fm_udp_request_free(udp);
		fm_udp_probe_set_request(probe, NULL);
	}

	fm_extant_map_forget_probe(&fm_udp_extant_map, probe);
}

/*
 * Check whether we're clear to send. If so, set the probe timer
 */
static fm_error_t
fm_udp_port_probe_schedule(fm_probe_t *probe)
{
	fm_udp_request_t *udp = fm_udp_probe_get_request(probe);

	return fm_udp_request_schedule(udp, &probe->job.expires);
}

/*
 * Send the probe.
 */
static fm_error_t
fm_udp_port_probe_send(fm_probe_t *probe)
{
	fm_udp_request_t *udp = fm_udp_probe_get_request(probe);
	fm_extant_t *extant = NULL;
	fm_error_t error;

	error = fm_udp_request_send(udp, &extant);
	if (extant != NULL)
		extant->probe = probe;

	return error;
}

static fm_error_t
fm_udp_port_probe_set_socket(fm_probe_t *probe, fm_socket_t *sock)
{
	fm_udp_request_t *udp = fm_udp_probe_get_request(probe);

	if (udp == NULL)
		return FM_NOT_SUPPORTED;

	fm_udp_request_set_socket(udp, sock);
	return 0;
}

static fm_error_t
fm_udp_port_probe_set_service(fm_probe_t *probe, fm_service_probe_t *service_probe)
{
	fm_udp_request_t *udp = fm_udp_probe_get_request(probe);

	if (udp == NULL)
		return FM_NOT_SUPPORTED;

	fm_udp_request_set_service(udp, service_probe);
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
struct fm_udp_port_probe {
	fm_probe_t		base;
	fm_udp_request_t *	udp;
};

static struct fm_probe_ops fm_udp_port_probe_ops = {
	.obj_size	= sizeof(struct fm_udp_port_probe),
	.name 		= "udp",

	.destroy	= fm_udp_port_probe_destroy,
	.schedule	= fm_udp_port_probe_schedule,
	.send		= fm_udp_port_probe_send,
	.set_socket	= fm_udp_port_probe_set_socket,
	.set_service	= fm_udp_port_probe_set_service,
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
fm_udp_create_parameterized_probe(fm_probe_class_t *pclass, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_protocol_t *proto = pclass->proto;
	fm_udp_request_t *udp;
	fm_probe_t *probe;
	char name[32];

	assert(proto && proto->id == FM_PROTO_UDP);

	udp = fm_udp_request_alloc(proto, target, params, extra_params);
	if (udp == NULL)
		return NULL;

	snprintf(name, sizeof(name), "udp/port=%u,ttl=%u", params->port, params->ttl);
	probe = fm_probe_alloc(name, &fm_udp_port_probe_ops, target);

	fm_udp_probe_set_request(probe, udp);

	/* UDP services may be slow to respond. */
	probe->rtt_application_bias = fm_global.udp.application_delay;

	fm_log_debug("Created UDP socket probe for %s\n", fm_address_format(&udp->host_address));
	return probe;
}

static struct fm_probe_class fm_udp_port_probe_class = {
	.name		= "udp",
	.proto_id	= FM_PROTO_UDP,
	.modes		= FM_PROBE_MODE_TOPO|FM_PROBE_MODE_HOST|FM_PROBE_MODE_PORT,
	.features	= FM_FEATURE_SERVICE_PROBES_MASK,
	.create_probe	= fm_udp_create_parameterized_probe,
};

FM_PROBE_CLASS_REGISTER(fm_udp_port_probe_class)
