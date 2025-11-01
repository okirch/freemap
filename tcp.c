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
	fm_probe_params_t	params;
	fm_tcp_extra_params_t	extra_params;
} fm_tcp_request_t;

typedef struct tcp_extant_info {
	unsigned int		port;
} fm_tcp_extant_info_t;


static fm_socket_t *	fm_tcp_create_bsd_socket(fm_protocol_t *proto, int af);
static fm_socket_t *	fm_tcp_create_raw_socket(fm_protocol_t *proto, int af);
static bool		fm_tcp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt);
static bool		fm_tcp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt);
static bool		fm_tcp_connecton_established(fm_protocol_t *proto, const fm_address_t *);

static fm_tcp_request_t *fm_tcp_probe_get_request(const fm_probe_t *probe);
static void		fm_tcp_probe_set_request(fm_probe_t *probe, fm_tcp_request_t *tcp);

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
	.process_packet = fm_tcp_process_packet,
	.process_error	= fm_tcp_process_error,
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

	.process_packet = fm_tcp_process_packet,
	.process_error	= fm_tcp_process_error,
	.create_socket	= fm_tcp_create_raw_socket,
	.connection_established = fm_tcp_connecton_established,
};

FM_PROTOCOL_REGISTER(fm_tcp_rawsock_ops);

static fm_socket_t *
fm_tcp_create_bsd_socket(fm_protocol_t *proto, int af)
{
	return fm_socket_create(af, SOCK_STREAM, 0, proto);
}

static fm_socket_t *
fm_tcp_create_raw_socket(fm_protocol_t *proto, int af)
{
	return fm_socket_create(af, SOCK_RAW, IPPROTO_TCP, proto);
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
	extant_info->port = tcp->params.port;
}

static fm_extant_t *
fm_tcp_locate_probe(int af, const fm_address_t *target_addr, fm_asset_state_t state)
{
	fm_target_t *target;
	unsigned short port;
	hlist_iterator_t iter;
	fm_extant_t *extant;

	target = fm_target_pool_find(target_addr);
	if (target == NULL)
		return NULL;

	port = fm_address_get_port(target_addr);

	/* update the asset */
	fm_target_update_port_state(target, FM_PROTO_TCP, port, state);

	fm_extant_iterator_init(&iter, &target->expecting);
	while ((extant = fm_extant_iterator_match(&iter, af, IPPROTO_TCP)) != NULL) {
		const struct tcp_extant_info *info = (struct tcp_extant_info *) (extant + 1);

		if (info->port == port)
			return extant;
	}

	return extant;
}

/*
 * Handle TCP reply packet
 */
static bool
fm_tcp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_asset_state_t state = FM_ASSET_STATE_UNDEF;
	fm_extant_t *extant;
	fm_ip_header_info_t ip;
	fm_tcp_header_info_t tcp_info;

	if (!fm_raw_packet_pull_ip_hdr(pkt, &ip))
		return false;

	fm_log_debug("%s: packet %s -> %s; proto %d",
			proto->name,
			fm_address_format(&ip.src_addr),
			fm_address_format(&ip.dst_addr),
			ip.ipproto);

	if (ip.ipproto != IPPROTO_TCP) {
		/* do we get icmp packets here? */
		fm_log_warning("%s: weird, unexpected ipproto %d", __func__, ip.ipproto);
		return false;
	}

	if (!fm_raw_packet_pull_tcp_header(pkt->payload, &tcp_info)) {
		fm_log_debug("%s: short or truncated TCP packet", proto->name);
		return false;
	}

	fm_log_debug("   tcp hdr %d -> %d: flags=0x%x seq 0x%x ack 0x%x",
			tcp_info.src_port,
			tcp_info.dst_port,
			tcp_info.flags,
			tcp_info.seq,
			tcp_info.ack_seq);

	if (tcp_info.flags & TH_RST)
		state = FM_ASSET_STATE_CLOSED;
	else
	if (tcp_info.flags & TH_ACK)
		state = FM_ASSET_STATE_OPEN;
	/* else weird */

	if (state == FM_ASSET_STATE_UNDEF) {
		fm_log_debug("don't know what to think of this packet");
		return false;
	}

	extant = fm_tcp_locate_probe(pkt->family, &pkt->peer_addr, state);
	if (extant != NULL) {
		fm_extant_received_reply(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

static bool
fm_tcp_connecton_established(fm_protocol_t *proto, const fm_address_t *target_addr)
{
	fm_extant_t *extant;

	extant = fm_tcp_locate_probe(target_addr->ss_family, target_addr, FM_ASSET_STATE_OPEN);
	if (extant != NULL) {
		fm_extant_received_reply(extant, NULL);
		fm_extant_free(extant);
	}

	return true;
}

static bool
fm_tcp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant;

	extant = fm_tcp_locate_probe(pkt->family, &pkt->peer_addr, FM_ASSET_STATE_CLOSED);
	if (extant != NULL) {
		fm_extant_received_error(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

static fm_pkt_t *
fm_tcp_build_raw_packet(fm_tcp_request_t *tcp)
{
	fm_tcp_header_info_t hdrinfo;
	fm_pkt_t *pkt;

	memset(&hdrinfo, 0, sizeof(hdrinfo));
	hdrinfo.flags = tcp->extra_params.flags;
	hdrinfo.seq = tcp->extra_params.sequence;

	if (hdrinfo.flags)
		hdrinfo.ack_seq = tcp->extra_params.ack;
	hdrinfo.mtu = 576;

	pkt = fm_pkt_alloc(tcp->family, 128);
	if (!fm_raw_packet_add_tcp_header(pkt->payload, &tcp->local_address, &tcp->host_address, &hdrinfo, 0))
		return NULL;

	pkt->peer_addr = tcp->host_address;
	return pkt;
}

static fm_error_t
fm_tcp_request_schedule(fm_tcp_request_t *tcp, struct timeval *expires)
{
	if (tcp->params.retries == 0)
		return FM_TIMED_OUT;

	/* After sending the last probe, we wait until the full timeout has expired.
	 * For any earlier probe, we wait for the specified packet spacing */
	if (tcp->params.retries == 1)
		fm_timestamp_set_timeout(expires, fm_global.tcp.timeout);
	else
		fm_timestamp_set_timeout(expires, fm_global.tcp.packet_spacing);
	return 0;
}

static fm_error_t
fm_tcp_request_send(fm_tcp_request_t *tcp, fm_tcp_extant_info_t *extant_info)
{
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

		if (tcp->sock->type == SOCK_RAW)
			fm_socket_enable_recverr(tcp->sock);

		if (!fm_socket_connect(tcp->sock, &tcp->host_address)) {
			fm_log_error("Unable to connect TCP socket for %s: %m",
					fm_address_format(&tcp->host_address));
			return FM_SEND_ERROR;
		}

		fm_socket_get_local_address(tcp->sock, &tcp->local_address);
		fm_log_debug("Created TCP connection %s -> %s",
					fm_address_format(&tcp->local_address),
					fm_address_format(&tcp->host_address));

	}

	if (tcp->sock->type == SOCK_RAW) {
		/* build the TCP packet and transmit */
		fm_pkt_t *pkt;

		if (!(pkt = fm_tcp_build_raw_packet(tcp)))
			return FM_SEND_ERROR;

		if (!fm_socket_send_pkt_and_burn(tcp->sock, pkt))
			return FM_SEND_ERROR;
	}

	fm_tcp_extant_info_build(tcp, extant_info);

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
}

/*
 * Check whether we're clear to send. If so, set the probe timer
 */
static fm_error_t
fm_tcp_port_probe_schedule(fm_probe_t *probe)
{
	fm_tcp_request_t *tcp = fm_tcp_probe_get_request(probe);

	return fm_tcp_request_schedule(tcp, &probe->expires);
}

/*
 * Transmit a packet
 */
static fm_error_t
fm_tcp_port_probe_send(fm_probe_t *probe)
{
	fm_tcp_request_t *tcp = fm_tcp_probe_get_request(probe);
	fm_tcp_extant_info_t extant_info;
	fm_error_t error;

	error = fm_tcp_request_send(tcp, &extant_info);
	if (error == 0)
		fm_extant_alloc(probe, tcp->family, IPPROTO_TCP, &extant_info, sizeof(extant_info));

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
