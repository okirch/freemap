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
#include "target.h"
#include "socket.h"
#include "services.h"
#include "probe_private.h"
#include "logging.h"
#include "buffer.h"

typedef struct fm_udp_control {
	fm_protocol_t *		proto;

	fm_socket_t *		sock;
	bool			sock_is_shared;

	fm_probe_params_t	params;

	fm_ip_header_info_t	ip_info;
	fm_udp_header_info_t	udp_info;

	/* total_retries reflects the complete # of packets we're supposed to
	 * send, accounting for service probes with multiple packets. */
	unsigned int		total_retries;

	/* Set of packages we're supposed to use in probing the port */
	unsigned int		service_index;
	fm_service_probe_t *	service_probe;
} fm_udp_control_t;

typedef struct fm_udp_extant_info {
	unsigned int		src_port;
	unsigned int		dst_port;
} fm_udp_extant_info_t;

static fm_socket_t *	fm_udp_create_socket(fm_protocol_t *proto, int af);
static fm_extant_t *	fm_udp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_udp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);

/* Global pool for UDP sockets */
static fm_socket_pool_t	*fm_udp_socket_pool = NULL;

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

	.create_socket	= fm_udp_create_socket,
	.locate_error	= fm_udp_locate_error,
	.locate_response= fm_udp_locate_response,
};

FM_PROTOCOL_REGISTER(fm_udp_bsdsock_ops);

/*
 * Regular UDP sock dgram sockets.
 * In the error case, the packet the kernel will give us does *not* include any headers
 */
static fm_socket_t *
fm_udp_create_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;

	sock = fm_socket_create(af, SOCK_RAW, IPPROTO_UDP, proto);
	if (sock) {
		fm_socket_enable_recverr(sock);
		fm_socket_enable_hdrincl(sock);

		if (af == AF_INET) {
			fm_socket_install_data_parser(sock, FM_PROTO_IP);
			fm_socket_install_error_parser(sock, FM_PROTO_IP);
		}
		fm_socket_install_data_parser(sock, FM_PROTO_UDP);
		fm_socket_install_error_parser(sock, FM_PROTO_UDP);

		fm_socket_attach_extant_map(sock, &fm_udp_extant_map);
	}
	return sock;
}

static fm_socket_t *
fm_udp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target)
{
	fm_address_t bind_address;

	/* Pick adequate source address to use when talking to this target. */
	if (!fm_target_get_local_bind_address(target, &bind_address)) {
		fm_log_error("%s: cannot determine source address", target->id);
		return NULL;
	}

	/* make sure the port number is 0 */
	fm_address_set_port(&bind_address, 0);

	return fm_socket_pool_get_socket(fm_udp_socket_pool, &bind_address);
}

/*
 * UDP action
 */
static void
fm_udp_control_free(fm_udp_control_t *udp)
{
	if (udp->sock != NULL && !udp->sock_is_shared)
		fm_socket_free(udp->sock);

	udp->sock = NULL;
	free(udp);
}

static fm_udp_control_t *
fm_udp_control_alloc(fm_protocol_t *proto, const fm_probe_params_t *params)
{
	fm_udp_control_t *udp;
	uint16_t src_port;

	udp = calloc(1, sizeof(*udp));
	udp->proto = proto;
	udp->params = *params;

	if (udp->params.retries == 0)
		udp->params.retries = fm_global.udp.retries;
	udp->total_retries = udp->params.retries;

	if (fm_udp_socket_pool == NULL)
		fm_udp_socket_pool = fm_socket_pool_create(proto, SOCK_DGRAM);

	src_port = fm_port_reserve(FM_PROTO_UDP);

	udp->ip_info.ipproto = IPPROTO_UDP;
	udp->ip_info.ttl = 64;
	udp->ip_info.tos = 0;

	udp->udp_info.src_port = src_port;

	/* The default application data */
	udp->udp_info.payload.data = "ABCDEFGHIJKLMNOPabcdefghijklmnop";
	udp->udp_info.payload.len = 32;

	return udp;
}

static bool
fm_udp_control_init_target(const fm_udp_control_t *udp, fm_target_control_t *target_control, fm_target_t *target)
{
	const fm_address_t *addr = &target->address;
	fm_socket_t *sock = NULL;

	sock = fm_udp_create_shared_socket(udp->proto, target);
	if (sock == NULL)
		return false;

	target_control->family = addr->family;
	target_control->target = target;
	target_control->dst_addr = *addr;
	target_control->sock = sock;
	target_control->sock_is_shared = true;

	target_control->ip_info = udp->ip_info;
	target_control->ip_info.dst_addr = *addr;

	fm_target_get_local_bind_address(target, &target_control->ip_info.src_addr);

	return true;
}

/*
 * Track extant UDP requests.
 * We currently do not track individual packets and their response(s), we just
 * record the fact that we *did* send to a specific port.
 */
static void
fm_udp_extant_info_build(const fm_udp_control_t *udp, uint16_t dst_port, fm_udp_extant_info_t *extant_info)
{
	extant_info->src_port = udp->udp_info.src_port;
	extant_info->dst_port = dst_port;
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
		 && (info->src_port == 0 || info->src_port == src_port))
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

	if ((cooked = pkt->parsed) == NULL)
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

	if ((cooked = pkt->parsed) == NULL)
		return NULL;

	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_UDP)) == NULL)
		return NULL;

	extant = fm_udp_locate_common(pkt, hdr->udp.dst_port, hdr->udp.src_port, iter);

	if (extant != NULL && extant->host)
		fm_host_asset_update_port_state(extant->host, FM_PROTO_UDP, hdr->udp.src_port, FM_ASSET_STATE_OPEN);

	return extant;
}

/*
 * Build the packet.
 */
static fm_pkt_t *
fm_udp_build_packet(const fm_udp_control_t *udp, fm_target_control_t *target_control,
		const fm_ip_header_info_t *ip_info,
		const fm_udp_header_info_t *udp_info)
{
	fm_pkt_t *pkt;

	pkt = fm_pkt_alloc(target_control->family, 128);
	pkt->peer_addr = target_control->dst_addr;

	if (!fm_raw_packet_add_ip_header(pkt->payload, ip_info, fm_udp_compute_len(udp_info))
	 || !fm_raw_packet_add_udp_header(pkt->payload, ip_info, udp_info))
		goto failed;

	/* On raw sockets, the port field is supposed to be either 0 or contain the transport
	 * protocol (IPPROTO_TCP in our case). Note, it seems that this is only enforced for
	 * IPv6; the manpages say that this behavior "got lost" for IPv4 some time in Linux 2.2. */
	fm_address_set_port(&pkt->peer_addr, IPPROTO_UDP);

	return pkt;

failed:
	fm_pkt_free(pkt);
	return NULL;
}

/*
 * Send the udp request.
 * The probe argument is only here because we need to notify it when done.
 */
static fm_error_t
fm_udp_request_send(const fm_udp_control_t *udp, fm_target_control_t *target_control, int param_type, int param_value,
		const fm_buffer_t *application_payload,
		fm_extant_t **extant_ret)
{
	fm_udp_extant_info_t extant_info;
	const fm_udp_header_info_t *udp_info;
	const fm_ip_header_info_t *ip_info;
	fm_target_t *target = target_control->target;
	fm_socket_t *sock;
	fm_pkt_t *pkt;

	ip_info = fm_ip_header_info_finalize(&target_control->ip_info, param_type, param_value);
	udp_info = fm_udp_header_info_finalize(&udp->udp_info, param_type, param_value, application_payload);

	sock = target_control->sock;
	if (sock == NULL) {
		fm_log_error("Unable to create UDP socket for %s: %m", target->id);
		return FM_SEND_ERROR;
	}

	pkt = fm_udp_build_packet(udp, target_control, ip_info, udp_info);

	if (!fm_socket_send_pkt_and_burn(sock, pkt)) {
		fm_log_error("Unable to send UDP packet: %m");
		return FM_SEND_ERROR;
	}

	fm_udp_extant_info_build(udp, udp_info->dst_port, &extant_info);
	*extant_ret = fm_socket_add_extant(sock, target->host_asset,
			target_control->family, IPPROTO_UDP, &extant_info, sizeof(extant_info));

	assert(*extant_ret);

	/* update the asset state */
	fm_target_update_port_state(target, FM_PROTO_UDP, udp_info->dst_port, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

/*
 * New multiprobe implementation
 */
static bool
fm_udp_multiprobe_add_target(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_target_t *target)
{
	const fm_udp_control_t *udp = multiprobe->control;

	return fm_udp_control_init_target(udp, &host_task->control, target);
}

static fm_error_t
fm_udp_multiprobe_transmit(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
		int param_type, int param_value,
		const fm_buffer_t *application_payload,
		fm_extant_t **extant_ret, double *timeout_ret)
{
	const fm_udp_control_t *udp = multiprobe->control;

	return fm_udp_request_send(udp, &host_task->control,
			param_type, param_value,
			application_payload, extant_ret);
}

static void
fm_udp_multiprobe_destroy(fm_multiprobe_t *multiprobe)
{
	fm_udp_control_t *icmp = multiprobe->control;

	multiprobe->control = NULL;
	fm_udp_control_free(icmp);
}

static fm_multiprobe_ops_t	fm_udp_multiprobe_ops = {
	.add_target		= fm_udp_multiprobe_add_target,
	.transmit		= fm_udp_multiprobe_transmit,
	.destroy		= fm_udp_multiprobe_destroy,
};

static bool
fm_udp_configure_probe(const fm_probe_class_t *pclass, fm_multiprobe_t *multiprobe, const fm_string_array_t *extra_string_args)
{
	fm_udp_control_t *udp;

	if (multiprobe->control != NULL) {
		fm_log_error("cannot reconfigure probe %s", multiprobe->name);
		return false;
	}

	/* Set the default timings and retries */
	multiprobe->timings.packet_spacing = fm_global.udp.packet_spacing * 1e-3;
	multiprobe->timings.timeout = fm_global.udp.timeout * 1e-3;
	if (multiprobe->params.retries == 0)
		multiprobe->params.retries = fm_global.udp.retries;

	if (extra_string_args && extra_string_args->count != 0) {
		fm_log_error("%s: found unsupported extra parameters", multiprobe->name);
		return false;
	}

	udp = fm_udp_control_alloc(pclass->proto, &multiprobe->params);
	if (udp == NULL)
		return false;

	multiprobe->ops = &fm_udp_multiprobe_ops;
	multiprobe->control = udp;
	return true;
}

static struct fm_probe_class fm_udp_port_probe_class = {
	.name		= "udp",
	.proto_id	= FM_PROTO_UDP,
	.modes		= FM_PROBE_MODE_TOPO|FM_PROBE_MODE_HOST|FM_PROBE_MODE_PORT,
	.features	= FM_FEATURE_SERVICE_PROBES_MASK,
	.configure	= fm_udp_configure_probe,
};

FM_PROBE_CLASS_REGISTER(fm_udp_port_probe_class)
