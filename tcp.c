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
#include "target.h" /* for fm_probe_t */
#include "socket.h"
#include "rawpacket.h"
#include "buffer.h"

typedef struct fm_tcp_extra_params {
	unsigned char		flags;
	uint32_t		sequence;
	uint32_t		ack;
} fm_tcp_extra_params_t;

typedef struct fm_tcp_request {
	fm_protocol_t *		proto;
	fm_target_t *		target;
	fm_socket_t *		sock;

	int			family;
	fm_address_t		host_address;
	fm_address_t		local_address;
	fm_csum_hdr_t *		csum_header;

	/* This is used primarily for connected sockets and
	 * for traceroute */
	unsigned int		src_port;

	fm_probe_params_t	params;
	fm_tcp_extra_params_t	extra_params;
} fm_tcp_request_t;

typedef struct tcp_extant_info {
	unsigned int		src_port;
	unsigned int		dst_port;
} fm_tcp_extant_info_t;


static fm_socket_t *	fm_tcp_create_bsd_socket(fm_protocol_t *proto, int af);
static fm_socket_t *	fm_tcp_create_raw_socket(fm_protocol_t *proto, int af);
static bool		fm_tcp_connecton_established(fm_protocol_t *proto, fm_pkt_t *);
static fm_extant_t *	fm_tcp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_tcp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);

static fm_tcp_request_t *fm_tcp_probe_get_request(const fm_probe_t *probe);
static void		fm_tcp_probe_set_request(fm_probe_t *probe, fm_tcp_request_t *tcp);

/* Global extant map for all TCP related stuff */
static fm_extant_map_t	fm_tcp_extant_map = FM_EXTANT_MAP_INIT;

static struct fm_protocol	fm_tcp_bsdsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "tcp",
	.id		= FM_PROTO_TCP,

	.supported_parameters = 
			  FM_PARAM_TYPE_PORT_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK |
			  FM_FEATURE_STATUS_CALLBACK_MASK,

	.create_socket	= fm_tcp_create_bsd_socket,
	.locate_error	= fm_tcp_locate_error,
	.locate_response= fm_tcp_locate_response,
	.connection_established = fm_tcp_connecton_established,
};

FM_PROTOCOL_REGISTER(fm_tcp_bsdsock_ops);

static struct fm_protocol	fm_tcp_rawsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "tcp-raw",
	.id		= FM_PROTO_TCP,
	.require_raw	= true,

	.supported_parameters = 
			  FM_PARAM_TYPE_PORT_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK |
			  FM_FEATURE_STATUS_CALLBACK_MASK,

	.create_socket	= fm_tcp_create_raw_socket,
	.locate_error	= fm_tcp_locate_error,
	.locate_response= fm_tcp_locate_response,
	.connection_established = fm_tcp_connecton_established,
};

FM_PROTOCOL_REGISTER(fm_tcp_rawsock_ops);

static fm_socket_t *
fm_tcp_create_bsd_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;

	sock = fm_socket_create(af, SOCK_STREAM, 0, proto);
	if (sock != NULL) {
		fm_socket_install_data_parser(sock, FM_PROTO_TCP);

		fm_socket_install_error_parser(sock, FM_PROTO_ICMP);
		fm_socket_install_error_parser(sock, FM_PROTO_IP);
		fm_socket_install_error_parser(sock, FM_PROTO_TCP);

		fm_socket_attach_extant_map(sock, &fm_tcp_extant_map);
	}
	return sock;
}

static fm_socket_t *
fm_tcp_create_raw_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;

	sock = fm_socket_create(af, SOCK_RAW, IPPROTO_TCP, proto);
	if (sock != NULL) {
		fm_socket_enable_recverr(sock);

		/* Raw sockets always include the IP header, else it's the same as above. */
		fm_socket_install_data_parser(sock, FM_PROTO_IP);
		fm_socket_install_data_parser(sock, FM_PROTO_TCP);

		fm_socket_install_error_parser(sock, FM_PROTO_IP);
		fm_socket_install_error_parser(sock, FM_PROTO_ICMP);
		fm_socket_install_error_parser(sock, FM_PROTO_IP);
		fm_socket_install_error_parser(sock, FM_PROTO_TCP);

		fm_socket_attach_extant_map(sock, &fm_tcp_extant_map);
	}
	return sock;
}

/*
 * TCP action
 */
static void
fm_tcp_request_free(fm_tcp_request_t *tcp)
{
	if (tcp->sock != NULL) {
		fm_socket_free(tcp->sock);
		tcp->sock = NULL;
	}
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

static fm_tcp_request_t *
fm_tcp_request_alloc(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const fm_tcp_extra_params_t *extra_params)
{
	fm_tcp_request_t *tcp;

	if (params->port == 0) {
		fm_log_error("%s: trying to create a tcp request without destination port");
		return NULL;
	}


	tcp = calloc(1, sizeof(*tcp));
	tcp->proto = proto;
	tcp->target = target;
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

	tcp->family = target->address.ss_family;
	tcp->host_address = target->address;
	if (!fm_address_set_port(&tcp->host_address, params->port)) {
		fm_tcp_request_free(tcp);
		return NULL;
	}

	return tcp;
}

/*
 * Track extant TCP requests.
 * We currently do not track individual packets and their response(s), we just
 * record the fact that we *did* send to a specific port.
 * We do not even distinguish by the source port used on our end.
 */
static void
fm_tcp_extant_info_build(fm_tcp_request_t *tcp, fm_tcp_extant_info_t *extant_info)
{
	extant_info->src_port = tcp->src_port;
	extant_info->dst_port = tcp->params.port;
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
	bool unreachable;

	if ((cooked = pkt->parsed) == NULL)
		return NULL;

	/* First, check the ICMP error header - does it tell us the port is unreachable? */
	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_ICMP)) == NULL)
		return NULL;
	unreachable = fm_icmp_header_is_host_unreachable(&hdr->icmp);

	/* Then, look at the enclosed TCP header */
	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_TCP)) == NULL)
		return NULL;

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
fm_tcp_build_raw_packet(fm_tcp_request_t *tcp)
{
	fm_tcp_header_info_t hdrinfo;
	void *tcp_hdr_addr;
	fm_buffer_t *payload;
	fm_pkt_t *pkt;

	memset(&hdrinfo, 0, sizeof(hdrinfo));
	hdrinfo.flags = tcp->extra_params.flags;
	hdrinfo.seq = tcp->extra_params.sequence;

	if (hdrinfo.flags & TH_ACK)
		hdrinfo.ack_seq = tcp->extra_params.ack;
	hdrinfo.mtu = 576;

	payload = fm_buffer_alloc(128);
	tcp_hdr_addr = (void *) fm_buffer_head(payload);

	if (!fm_raw_packet_add_tcp_header(payload, &tcp->local_address, &tcp->host_address, &hdrinfo, 0))
		return NULL;

	/* Prepare the checksum pseudo header */
	if (tcp->csum_header == NULL && tcp->family == AF_INET6) {
		tcp->csum_header = fm_ipv6_checksum_header(&tcp->local_address, &tcp->host_address, IPPROTO_TCP);
		if (tcp->csum_header == NULL) {
			fm_log_error("refusing to create TCP checksum header for %s -> %s",
					fm_address_format(&tcp->local_address),
					fm_address_format(&tcp->host_address));
			return NULL;
		}
		tcp->csum_header->checksum.offset = 16;
		tcp->csum_header->checksum.width = 2;
	}

	if (tcp->csum_header != NULL
	 && !fm_raw_packet_csum(tcp->csum_header, tcp_hdr_addr, fm_buffer_len(payload, tcp_hdr_addr))) {
		fm_log_fatal("got my wires crossed in the tcp checksum thing");
	}

	pkt = fm_pkt_alloc(tcp->family, 0);
	pkt->payload = payload;
	pkt->peer_addr = tcp->host_address;
	fm_address_set_port(&pkt->peer_addr, 0);
	return pkt;
}

static fm_error_t
fm_tcp_request_schedule(fm_tcp_request_t *tcp, fm_time_t *expires)
{
	if (tcp->params.retries == 0)
		return FM_TIMED_OUT;

	/* After sending the last probe, we wait until the full timeout has expired.
	 * For any earlier probe, we wait for the specified packet spacing */
	if (tcp->params.retries == 1)
		*expires = fm_time_now() + 1e-3 * fm_global.tcp.timeout;
	else
		*expires = fm_time_now() + 1e-3 * fm_global.tcp.packet_spacing;
	return 0;
}

static fm_error_t
fm_tcp_request_send(fm_tcp_request_t *tcp, fm_extant_t **extant_ret)
{
	fm_tcp_extant_info_t extant_info;

	if (tcp->sock != NULL && tcp->sock->type == SOCK_STREAM) {
		fm_socket_free(tcp->sock);
		tcp->sock = NULL;
	}

	if (tcp->sock == NULL) {
		tcp->sock = fm_protocol_create_socket(tcp->proto, tcp->host_address.ss_family);
		if (tcp->sock == NULL) {
			fm_log_error("Unable to create TCP socket for %s: %m",
					fm_address_format(&tcp->host_address));
			return FM_SEND_ERROR;
		}

		if (!fm_socket_connect(tcp->sock, &tcp->host_address)) {
			fm_log_error("Unable to connect TCP socket for %s: %m",
					fm_address_format(&tcp->host_address));
			return FM_SEND_ERROR;
		}

		if (!fm_socket_get_local_address(tcp->sock, &tcp->local_address)) {
			fm_log_warning("TCP: unable to get local address after connect: %m");
		} else {
			tcp->src_port = fm_address_get_port(&tcp->local_address);
		}

		fm_log_debug("Created TCP connection %s -> %s",
					fm_address_format(&tcp->local_address),
					fm_address_format(&tcp->host_address));
	}

	if (tcp->sock->type == SOCK_RAW) {
		/* build the TCP packet and transmit */
		fm_pkt_t *pkt;

		if (!(pkt = fm_tcp_build_raw_packet(tcp)))
			return FM_SEND_ERROR;

		/* apply ttl, tos etc */
		fm_pkt_apply_probe_params(pkt, &tcp->params, tcp->proto->supported_parameters);

		if (!fm_socket_send_pkt_and_burn(tcp->sock, pkt))
			return FM_SEND_ERROR;
	}

	fm_tcp_extant_info_build(tcp, &extant_info);
	*extant_ret = fm_socket_add_extant(tcp->sock, tcp->target->host_asset,
				tcp->family, IPPROTO_TCP, &extant_info, sizeof(extant_info));

	/* update the asset state */
	fm_target_update_port_state(tcp->target, FM_PROTO_TCP, tcp->params.port, FM_ASSET_STATE_PROBE_SENT);

	tcp->params.retries -= 1;

	return 0;
}

/*
 * TCP port probes using standard BSD sockets
 */
struct fm_tcp_port_probe {
	fm_probe_t		base;
	fm_tcp_request_t *	tcp;
};

static void
fm_tcp_port_probe_destroy(fm_probe_t *probe)
{
	fm_tcp_request_t *tcp = fm_tcp_probe_get_request(probe);

	if (tcp != NULL) {
		fm_tcp_request_free(tcp);
		fm_tcp_probe_set_request(probe, NULL);
	}

	fm_extant_map_forget_probe(&fm_tcp_extant_map, probe);
}

/*
 * Check whether we're clear to send. If so, set the probe timer
 */
static fm_error_t
fm_tcp_port_probe_schedule(fm_probe_t *probe)
{
	fm_tcp_request_t *tcp = fm_tcp_probe_get_request(probe);

	return fm_tcp_request_schedule(tcp, &probe->job.expires);
}

/*
 * Transmit a packet
 */
static fm_error_t
fm_tcp_port_probe_send(fm_probe_t *probe)
{
	fm_tcp_request_t *tcp = fm_tcp_probe_get_request(probe);
	fm_extant_t *extant = NULL;
	fm_error_t error;

	error = fm_tcp_request_send(tcp, &extant);
	if (extant != NULL)
		extant->probe = probe;

	return error;
}

static struct fm_probe_ops fm_tcp_port_probe_ops = {
	.obj_size	= sizeof(struct fm_tcp_port_probe),
	.name 		= "tcp",

	.destroy	= fm_tcp_port_probe_destroy,
	.schedule	= fm_tcp_port_probe_schedule,
	.send		= fm_tcp_port_probe_send,
};

static fm_tcp_request_t *
fm_tcp_probe_get_request(const fm_probe_t *probe)
{
	return ((struct fm_tcp_port_probe *) probe)->tcp;
}

static void
fm_tcp_probe_set_request(fm_probe_t *probe, fm_tcp_request_t *tcp)
{
	((struct fm_tcp_port_probe *) probe)->tcp = tcp;
}

static fm_probe_t *
fm_tcp_create_parameterized_probe(fm_probe_class_t *pclass, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_protocol_t *proto = pclass->proto;
	fm_tcp_request_t *tcp;
	fm_probe_t *probe;
	char name[32];

	assert(proto && proto->id == FM_PROTO_TCP);

	if (!(tcp = fm_tcp_request_alloc(proto, target, params, extra_params)))
		return NULL;

	snprintf(name, sizeof(name), "tcp/%u", params->port);
	probe = fm_probe_alloc(name, &fm_tcp_port_probe_ops, target);

	fm_tcp_probe_set_request(probe, tcp);

	/* TCP services may take up to .5 sec for the queued TCP connection to be accepted. */
	probe->rtt_application_bias = fm_global.tcp.application_delay;

	fm_log_debug("Created TCP socket probe for %s\n", fm_address_format(&tcp->host_address));
	return probe;
}

static struct fm_probe_class	fm_tcp_port_probe_class = {
	.name		= "tcp",
	.proto_id	= FM_PROTO_TCP,
	.modes		= FM_PROBE_MODE_TOPO|FM_PROBE_MODE_HOST|FM_PROBE_MODE_PORT,
	.create_probe	= fm_tcp_create_parameterized_probe,
};

FM_PROBE_CLASS_REGISTER(fm_tcp_port_probe_class)
