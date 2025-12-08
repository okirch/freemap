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
#include "probe_private.h"
#include "logging.h"
#include "buffer.h"

typedef struct fm_tcp_extra_params {
	unsigned char		flags;
	uint32_t		sequence;
	uint32_t		ack;
} fm_tcp_extra_params_t;

typedef struct fm_tcp_control {
	fm_protocol_t *		proto;

	fm_ip_header_info_t	ip_info;
	fm_tcp_header_info_t	tcp_info;
} fm_tcp_control_t;

typedef struct tcp_extant_info {
	unsigned char		sent_flags;
	uint16_t		src_port;
	uint16_t		dst_port;
} fm_tcp_extant_info_t;


static fm_socket_t *	fm_tcp_create_socket(fm_protocol_t *proto, int af, const fm_address_t *bind_addr);
static fm_extant_t *	fm_tcp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_tcp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);

/* Global pool for TCP sockets */
static fm_socket_pool_t	*fm_tcp_socket_pool = NULL;

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
	.locate_error	= fm_tcp_locate_error,
	.locate_response= fm_tcp_locate_response,
};

FM_PROTOCOL_REGISTER(fm_tcp_sock_ops);

static fm_socket_t *
fm_tcp_create_socket(fm_protocol_t *proto, int af, const fm_address_t *bind_addr)
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
	fm_address_t bind_address;
	fm_socket_t *sock = NULL;

	/* Pick adequate source address to use when talking to this target. */
	if (!fm_target_get_local_bind_address(target, &bind_address)) {
		fm_log_error("%s: cannot determine source address", target->id);
		return NULL;
	}

	/* make sure the port number is 0 */
	fm_address_set_port(&bind_address, 0);

	sock = fm_socket_pool_get_socket(fm_tcp_socket_pool, &bind_address);
	if (sock == NULL)
		return NULL;

	return sock;
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
fm_tcp_control_alloc(fm_protocol_t *proto)
{
	fm_tcp_control_t *tcp;
	uint16_t src_port;

	tcp = calloc(1, sizeof(*tcp));
	tcp->proto = proto;

	if (fm_tcp_socket_pool == NULL)
		fm_tcp_socket_pool = fm_socket_pool_create(proto, SOCK_RAW);

	src_port = fm_port_reserve(FM_PROTO_TCP);

	tcp->ip_info.ipproto = IPPROTO_TCP;
	tcp->ip_info.ttl = 64;
	tcp->ip_info.tos = 0;

	tcp->tcp_info.flags = TH_SYN;
	tcp->tcp_info.seq = fm_tcp_generate_sequence();
	tcp->tcp_info.ack_seq = tcp->tcp_info.seq + 0x80;
	tcp->tcp_info.src_port = src_port;
	tcp->tcp_info.mtu = 576;

	return tcp;
}

/*
 * Initialize protocol-specific part of target control.
 * When we get here, most of the generic members have already been set.
 */
static bool
fm_tcp_control_init_target(const fm_tcp_control_t *tcp, fm_target_control_t *target_control, fm_target_t *target)
{
	fm_socket_t *sock = NULL;

	sock = fm_tcp_create_shared_socket(tcp->proto, target);
	if (sock == NULL)
		return false;

	target_control->sock = sock;

	target_control->ip_info = tcp->ip_info;
	target_control->ip_info.src_addr = target_control->src_addr;
	target_control->ip_info.dst_addr = target_control->dst_addr;

	return true;
}

/*
 * Track extant TCP requests.
 */
static void
fm_tcp_extant_info_build(const fm_tcp_header_info_t *tcp_info, fm_tcp_extant_info_t *extant_info)
{
	extant_info->sent_flags = tcp_info->flags;
	extant_info->src_port = tcp_info->src_port;
	extant_info->dst_port = tcp_info->dst_port;
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
		const struct tcp_extant_info *info = (struct tcp_extant_info *) (extant + 1);

		/* beware - responses are only indicative of port state if the original request was
		 * a regular SYN packet.
		 * Everything else should just elicit an RST packet, indicating that we can
		 * talk to the host's TCP stack. */
		if (info->sent_flags == TH_SYN) {
			if (hdr->tcp.flags & TH_RST)
				fm_host_asset_update_port_state(extant->host, FM_PROTO_TCP, hdr->tcp.src_port, FM_ASSET_STATE_CLOSED);
			else if (hdr->tcp.flags & TH_ACK)
				fm_host_asset_update_port_state(extant->host, FM_PROTO_TCP, hdr->tcp.src_port, FM_ASSET_STATE_OPEN);
		}

		fm_host_asset_update_state(extant->host, FM_ASSET_STATE_OPEN);
	}

	return extant;
}

static fm_pkt_t *
fm_tcp_build_raw_packet(const fm_tcp_control_t *tcp, fm_target_control_t *target_control,
		const fm_ip_header_info_t *ip_info,
		const fm_tcp_header_info_t *tcp_info)
{
	fm_pkt_t *pkt;

	pkt = fm_pkt_alloc(target_control->family, 128);
	fm_pkt_set_peer_address_raw(pkt, &target_control->dst_addr, IPPROTO_TCP);

	if (!fm_raw_packet_add_ip_header(pkt->payload, ip_info, fm_tcp_compute_len(tcp_info))
	 || !fm_raw_packet_add_tcp_header(pkt->payload, ip_info, tcp_info)) {
		fm_pkt_free(pkt);
		return NULL;
	}

	return pkt;
}

static fm_error_t
fm_tcp_request_send(const fm_tcp_control_t *tcp, fm_target_control_t *target_control, int param_type, int param_value, fm_extant_t **extant_ret)
{
	fm_tcp_extant_info_t extant_info;
	const fm_tcp_header_info_t *tcp_info;
	const fm_ip_header_info_t *ip_info;

	ip_info = fm_ip_header_info_finalize(&target_control->ip_info, param_type, param_value);
	tcp_info = fm_tcp_header_info_finalize(&tcp->tcp_info, param_type, param_value);

	{
		/* build the TCP packet and transmit */
		fm_pkt_t *pkt;
		fm_error_t err;

		if (!(pkt = fm_tcp_build_raw_packet(tcp, target_control, ip_info, tcp_info)))
			return FM_SEND_ERROR;

		err = fm_socket_send_pkt_and_burn(target_control->sock, pkt);
		if (err < 0)
			return err;
	}

	fm_tcp_extant_info_build(tcp_info, &extant_info);
	*extant_ret = fm_socket_add_extant(target_control->sock, target_control->target->host_asset,
				target_control->family, IPPROTO_TCP, &extant_info, sizeof(extant_info));

	/* update the asset state */
	fm_target_update_port_state(target_control->target, FM_PROTO_TCP, tcp_info->dst_port, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

/*
 * New multiprobe implementation
 */
static bool
fm_tcp_multiprobe_add_target(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_target_t *target)
{
	const fm_tcp_control_t *tcp = multiprobe->control;

	return fm_tcp_control_init_target(tcp, &host_task->control, target);
}

static fm_error_t
fm_tcp_multiprobe_transmit(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
		int param_type, int param_value,
		const fm_buffer_t *application_payload,
		fm_extant_t **extant_ret, double *timeout_ret)
{
	const fm_tcp_control_t *tcp = multiprobe->control;

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
fm_tcp_configure_probe(const fm_probe_class_t *pclass, fm_multiprobe_t *multiprobe, const fm_string_array_t *extra_args)
{
	fm_tcp_control_t *tcp;
	unsigned int i;

	if (multiprobe->control != NULL) {
		fm_log_error("cannot reconfigure probe %s", multiprobe->name);
		return false;
	}

	/* Set the default timings and retries */
	multiprobe->timings.packet_spacing = fm_global.tcp.packet_spacing * 1e-3;
	multiprobe->timings.timeout = fm_global.tcp.timeout * 1e-3;
	if (multiprobe->params.retries == 0)
		multiprobe->params.retries = fm_global.tcp.retries;

	tcp = fm_tcp_control_alloc(pclass->proto);
	if (tcp == NULL)
		return false;

	/* process extra_args if given */
	for (i = 0; i < extra_args->count; ++i) {
		const char *arg = extra_args->entries[i];

		if (!strncmp(arg, "tcp-", 4) && fm_tcp_process_config_arg(&tcp->tcp_info, arg))
			continue;

		if (!strncmp(arg, "ip-", 4) && fm_ip_process_config_arg(&tcp->ip_info, arg))
			continue;

		fm_log_error("%s: unsupported or invalid option %s", multiprobe->name, arg);
		return false;
	}

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
