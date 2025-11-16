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
 * Simple TCP scanning functions
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <linux/errqueue.h>
#include <netinet/tcp.h>

#include "scanner.h"
#include "protocols.h"
#include "target.h"
#include "socket.h"
#include "rawpacket.h"
#include "buffer.h"

typedef struct fm_tcp_extra_params {
	unsigned char		flags;
	uint32_t		sequence;
	uint32_t		ack;
} fm_tcp_extra_params_t;

typedef struct fm_tcp_control {
	fm_protocol_t *		proto;

	/* This is used primarily for connected sockets and
	 * for traceroute */
	unsigned int		src_port;

	fm_probe_params_t	params;
	fm_tcp_extra_params_t	extra_params;
} fm_tcp_control_t;

typedef struct tcp_extant_info {
	unsigned int		src_port;
	unsigned int		dst_port;
} fm_tcp_extant_info_t;


static fm_socket_t *	fm_tcp_create_socket(fm_protocol_t *proto, int af);
static fm_socket_t *	fm_tcp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target);
static bool		fm_tcp_connecton_established(fm_protocol_t *proto, fm_pkt_t *);
static fm_extant_t *	fm_tcp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_tcp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);

/* Global extant map for all TCP related stuff */
static fm_extant_map_t	fm_tcp_extant_map = FM_EXTANT_MAP_INIT;

static struct fm_protocol	fm_tcp_sock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "tcp",
	.id		= FM_PROTO_TCP,

	.supported_parameters = 
			  FM_PARAM_TYPE_PORT_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK |
			  FM_FEATURE_STATUS_CALLBACK_MASK,

	.create_socket	= fm_tcp_create_socket,
	.create_host_shared_socket = fm_tcp_create_shared_socket,
	.locate_error	= fm_tcp_locate_error,
	.locate_response= fm_tcp_locate_response,
	.connection_established = fm_tcp_connecton_established,
};

FM_PROTOCOL_REGISTER(fm_tcp_sock_ops);

static fm_socket_t *
fm_tcp_create_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;

	sock = fm_socket_create(af, SOCK_RAW, IPPROTO_TCP, proto);
	if (sock != NULL) {
		fm_socket_enable_recverr(sock);
		fm_socket_enable_hdrincl(sock);

		/* Duh, raw tcp6 sockets do not include the IP header in incoming packets :-( */
		if (af == AF_INET)
			fm_socket_install_data_parser(sock, FM_PROTO_IP);
		fm_socket_install_data_parser(sock, FM_PROTO_TCP);

#if 0
		/* It's a raw socket, so the ICMP message will be parsed by the kernel. */
		fm_socket_install_error_parser(sock, FM_PROTO_IP);
		fm_socket_install_error_parser(sock, FM_PROTO_ICMP);
#endif

		/* Duh, raw tcp6 sockets do not include the IP header in incoming packets :-( */
		if (af == AF_INET)
			fm_socket_install_error_parser(sock, FM_PROTO_IP);
		fm_socket_install_error_parser(sock, FM_PROTO_TCP);

		fm_socket_attach_extant_map(sock, &fm_tcp_extant_map);
	}
	return sock;
}

static fm_socket_t *
fm_tcp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target)
{
	const fm_address_t *dst_address = &target->address;
	fm_address_t bind_address;
	fm_socket_t *sock = NULL;

	sock = fm_protocol_create_socket(proto, dst_address->ss_family);

	/* The following code is not used yet. We will use that eg for
	 * allocating source ports from a given range.
	 * Before we get there, we would have to implement something like a port pool
	 */
	if (1) {
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
	target->tcp_sock = sock;

	return sock;

failed:
	fm_socket_free(sock);
	return NULL;
}

/*
 * TCP action
 */
static void
fm_tcp_control_free(fm_tcp_control_t *tcp)
{
	free(tcp);
}

static inline uint32_t
fm_tcp_generate_sequence(void)
{
	static uint32_t global_seq;
	uint32_t seq;

	if (global_seq == 0)
		global_seq = random() & ~0xFF;

	seq = global_seq;
	global_seq += 0x100;
	return seq;
}

static fm_tcp_control_t *
fm_tcp_control_alloc(fm_protocol_t *proto, const fm_probe_params_t *params, const fm_tcp_extra_params_t *extra_params)
{
	fm_tcp_control_t *tcp;

	tcp = calloc(1, sizeof(*tcp));
	tcp->proto = proto;
	tcp->params = *params;

	if (tcp->params.retries == 0)
		tcp->params.retries = fm_global.tcp.retries;

	if (extra_params != NULL)
		tcp->extra_params = *extra_params;
	
	if (tcp->extra_params.flags == 0)
		tcp->extra_params.flags = TH_SYN;
	if (tcp->extra_params.sequence == 0)
		tcp->extra_params.sequence = fm_tcp_generate_sequence();
	tcp->extra_params.ack = tcp->extra_params.sequence + 0x80;

	return tcp;
}

static bool
fm_tcp_control_init_target(fm_tcp_control_t *tcp, fm_target_control_t *target_control, fm_target_t *target)
{
	const fm_address_t *addr = &target->address;
	fm_socket_t *sock = NULL;

	/* For the time being, we create a single raw socket per target host */
	sock = fm_protocol_create_host_shared_socket(tcp->proto, target);
	if (sock == NULL) {
		fm_log_error("could not create shared TCP socket for %s", target->id);
		return false;
	}

	target_control->family = addr->ss_family;
	target_control->target = target;
	target_control->address = *addr;
	target_control->sock = sock;

	if (!fm_socket_get_local_address(target_control->sock, &target_control->local_address))
		fm_log_warning("TCP: unable to get local address: %m");

	return true;
}

/*
 * Track extant TCP requests.
 * We currently do not track individual packets and their response(s), we just
 * record the fact that we *did* send to a specific port.
 * We do not even distinguish by the source port used on our end.
 */
static void
fm_tcp_extant_info_build(fm_tcp_control_t *tcp, uint16_t src_port, uint16_t dst_port, fm_tcp_extant_info_t *extant_info)
{
	extant_info->src_port = src_port;
	extant_info->dst_port = dst_port;
}

static fm_extant_t *
fm_tcp_locate_common(fm_pkt_t *pkt, unsigned short src_port, unsigned short dst_port, hlist_iterator_t *iter)
{
	fm_host_asset_t *host;
	fm_extant_t *extant;

	host = fm_host_asset_get_active(&pkt->peer_addr);
	if (host == NULL)
		return NULL;

	while ((extant = fm_extant_iterator_match(iter, pkt->family, IPPROTO_TCP)) != NULL) {
		const struct tcp_extant_info *info = (struct tcp_extant_info *) (extant + 1);

		if (extant->host == host
		 && info->dst_port == dst_port
		 && (src_port == 0 || info->src_port == src_port))
			return extant;
	}

	return NULL;
}

static fm_extant_t *
fm_tcp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	fm_parsed_pkt_t *cooked;
	fm_parsed_hdr_t *hdr;
	fm_extant_t *extant;
	int icmp_type;
	bool unreachable;

	if ((cooked = pkt->parsed) == NULL)
		return NULL;

	/* First, check the ICMP error header - does it tell us the port is unreachable? */
	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_ICMP)) == NULL)
		return NULL;

	unreachable = fm_icmp_header_is_host_unreachable(&hdr->icmp);
	icmp_type = hdr->icmp.type;

	/* Then, look at the enclosed TCP header */
	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_TCP)) == NULL)
		return NULL;

	fm_log_debug("TCP: %s:%u -> %s:%u received ICMP error %u",
			fm_address_format(&pkt->peer_addr), hdr->tcp.src_port,
			fm_address_format(&pkt->local_addr), hdr->tcp.dst_port,
			icmp_type);

	extant = fm_tcp_locate_common(pkt, hdr->tcp.src_port, hdr->tcp.dst_port, iter);

	/* If ICMP says the net/host/port is unreachable, mark the port resource as closed. */
	if (extant != NULL && extant->host && unreachable)
		fm_host_asset_update_port_state(extant->host, FM_PROTO_TCP, hdr->tcp.dst_port, FM_ASSET_STATE_CLOSED);

	return extant;
}

static fm_extant_t *
fm_tcp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	fm_parsed_pkt_t *cooked;
	fm_parsed_hdr_t *hdr;
	fm_extant_t *extant;

	if ((cooked = pkt->parsed) == NULL
	 || (hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_TCP)) == NULL)
		return NULL;

	fm_log_debug("TCP: %s:%u -> %s:%u received response, flags=0x%x",
			fm_address_format(&pkt->peer_addr), hdr->tcp.src_port,
			fm_address_format(&pkt->local_addr), hdr->tcp.dst_port,
			hdr->tcp.flags);

	extant = fm_tcp_locate_common(pkt, hdr->tcp.dst_port, hdr->tcp.src_port, iter);

	if (extant != NULL && extant->host) {
		if (hdr->tcp.flags & TH_RST)
			fm_host_asset_update_port_state(extant->host, FM_PROTO_TCP, hdr->tcp.src_port, FM_ASSET_STATE_CLOSED);
		else if (hdr->tcp.flags & TH_ACK)
			fm_host_asset_update_port_state(extant->host, FM_PROTO_TCP, hdr->tcp.src_port, FM_ASSET_STATE_OPEN);
	}

	return extant;
}

/*
 * Callback from socket layer to indicate the connection has been established.
 * We only get here for stream sockets
 */
static bool
fm_tcp_connecton_established(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	unsigned int src_port, dst_port;
	hlist_iterator_t iter;
	fm_extant_t *extant;

	src_port = fm_address_get_port(&pkt->peer_addr);
	dst_port = fm_address_get_port(&pkt->local_addr);

	fm_extant_iterator_init(&iter, &fm_tcp_extant_map.pending);

	extant = fm_tcp_locate_common(pkt, dst_port, src_port, &iter);
	if (extant != NULL) {
		fm_host_asset_update_port_state(extant->host, FM_PROTO_TCP, src_port, FM_ASSET_STATE_OPEN);
		fm_extant_received_reply(extant, NULL);
		fm_extant_free(extant);
	}

	return true;
}

static fm_pkt_t *
fm_tcp_build_raw_packet(fm_tcp_control_t *tcp, uint16_t dst_port, fm_target_control_t *target_control,
		const fm_probe_params_t *params)
{
	fm_tcp_header_info_t hdrinfo;
	fm_address_t dst_addr;
	fm_buffer_t *payload;
	fm_pkt_t *pkt;

	memset(&hdrinfo, 0, sizeof(hdrinfo));
	hdrinfo.flags = tcp->extra_params.flags;
	hdrinfo.seq = tcp->extra_params.sequence;

	if (hdrinfo.flags & TH_ACK)
		hdrinfo.ack_seq = tcp->extra_params.ack;
	hdrinfo.mtu = 576;

	/* Build the dest addr with port */
	dst_addr = target_control->address;
	fm_address_set_port(&dst_addr, dst_port);

	payload = fm_buffer_alloc(128);

	if (!fm_raw_packet_add_network_header(payload, &target_control->local_address, &dst_addr,
					IPPROTO_TCP, params->ttl, params->tos,
					20 /* standard TCP header length */))
		goto failed;

	if (!fm_raw_packet_add_tcp_header(payload, &target_control->local_address, &dst_addr, &hdrinfo, 0))
		goto failed;

	pkt = fm_pkt_alloc(target_control->family, 0);
	pkt->payload = payload;
	pkt->peer_addr = target_control->address;

	/* On raw sockets, the port field is supposed to be either 0 or contain the transport
	 * protocol (IPPROTO_TCP in our case). Note, it seems that this is only enforced for
	 * IPv6; the manpages say that this behavior "got lost" for IPv4 some time in Linux 2.2. */
	fm_address_set_port(&pkt->peer_addr, IPPROTO_TCP);

	return pkt;

failed:
	fm_buffer_free(payload);
	return NULL;
}

static fm_error_t
fm_tcp_request_send(fm_tcp_control_t *tcp, fm_target_control_t *target_control, int param_type, int param_value, fm_extant_t **extant_ret)
{
	fm_tcp_extant_info_t extant_info;
	fm_probe_params_t param_copy;
	uint16_t src_port, dst_port;

	if (target_control->sock == NULL) {
		target_control->sock = fm_protocol_create_socket(tcp->proto, target_control->family);
		if (target_control->sock == NULL) {
			fm_log_error("Unable to create TCP socket for %s: %m",
					fm_address_format(&target_control->address));
			return FM_SEND_ERROR;
		}

		if (!fm_socket_connect(target_control->sock, &target_control->address)) {
			fm_log_error("Unable to connect TCP socket for %s: %m",
					fm_address_format(&target_control->address));
			return FM_SEND_ERROR;
		}

		if (!fm_socket_get_local_address(target_control->sock, &target_control->local_address)) {
			fm_log_warning("TCP: unable to get local address after connect: %m");
		}

		fm_log_debug("Created TCP connection %s -> %s",
					fm_address_format(&target_control->local_address),
					fm_address_format(&target_control->address));
	}

	param_copy = tcp->params;
	src_port = fm_address_get_port(&target_control->local_address);
	dst_port = tcp->params.port;
	if (param_type == FM_PARAM_TYPE_PORT)
		dst_port = param_value;
	else if (param_type == FM_PARAM_TYPE_TTL)
		param_copy.ttl = param_value;
	else if (param_type == FM_PARAM_TYPE_TOS)
		param_copy.tos = param_value;

	{
		/* build the TCP packet and transmit */
		fm_pkt_t *pkt;

		if (!(pkt = fm_tcp_build_raw_packet(tcp, dst_port, target_control, &param_copy)))
			return FM_SEND_ERROR;

		if (!fm_socket_send_pkt_and_burn(target_control->sock, pkt))
			return FM_SEND_ERROR;
	}

	fm_tcp_extant_info_build(tcp, src_port, dst_port, &extant_info);
	*extant_ret = fm_socket_add_extant(target_control->sock, target_control->target->host_asset,
				target_control->family, IPPROTO_TCP, &extant_info, sizeof(extant_info));

	/* update the asset state */
	fm_target_update_port_state(target_control->target, FM_PROTO_TCP, dst_port, FM_ASSET_STATE_PROBE_SENT);

	tcp->params.retries -= 1;

	return 0;
}

/*
 * New multiprobe implementation
 */
static bool
fm_tcp_multiprobe_add_target(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_target_t *target)
{
	fm_tcp_control_t *tcp = multiprobe->control;

	return fm_tcp_control_init_target(tcp, &host_task->control, target);
}

static fm_error_t
fm_tcp_multiprobe_transmit(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
		int param_type, int param_value,
		fm_extant_t **extant_ret, double *timeout_ret)
{
	fm_tcp_control_t *tcp = multiprobe->control;

	return fm_tcp_request_send(tcp, &host_task->control,
			param_type, param_value, extant_ret);
}

static void
fm_tcp_multiprobe_destroy(fm_multiprobe_t *multiprobe)
{
	fm_tcp_control_t *icmp = multiprobe->control;

	multiprobe->control = NULL;
	fm_tcp_control_free(icmp);
}

static fm_multiprobe_ops_t	fm_tcp_multiprobe_ops = {
	.add_target		= fm_tcp_multiprobe_add_target,
	.transmit		= fm_tcp_multiprobe_transmit,
	.destroy		= fm_tcp_multiprobe_destroy,
};

static bool
fm_tcp_configure_probe(const fm_probe_class_t *pclass, fm_multiprobe_t *multiprobe, const void *extra_params)
{
	fm_tcp_control_t *tcp;

	if (multiprobe->control != NULL) {
		fm_log_error("cannot reconfigure probe %s", multiprobe->name);
		return false;
	}

	/* Set the default timings and retries */
	multiprobe->timings.packet_spacing = fm_global.tcp.packet_spacing * 1e-3;
	multiprobe->timings.timeout = fm_global.tcp.timeout * 1e-3;
	if (multiprobe->params.retries == 0)
		multiprobe->params.retries = fm_global.tcp.retries;

	tcp = fm_tcp_control_alloc(pclass->proto, &multiprobe->params, extra_params);
	if (tcp == NULL)
		return false;

	multiprobe->ops = &fm_tcp_multiprobe_ops;
	multiprobe->control = tcp;
	return true;
}

static struct fm_probe_class	fm_tcp_port_probe_class = {
	.name		= "tcp",
	.proto_id	= FM_PROTO_TCP,
	.modes		= FM_PROBE_MODE_TOPO|FM_PROBE_MODE_HOST|FM_PROBE_MODE_PORT,
	.configure	= fm_tcp_configure_probe,
};

FM_PROBE_CLASS_REGISTER(fm_tcp_port_probe_class)
