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
 * Simple ICMP reachability functions
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "scanner.h"
#include "protocols.h"
#include "target.h"
#include "buffer.h"
#include "utils.h"
#include "icmp.h"
#include "rawpacket.h"
#include "socket.h"
#include "logging.h"

static fm_socket_t *	fm_icmp_create_socket(fm_protocol_t *proto, int ipproto);
static fm_socket_t *	fm_icmp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target);

static fm_socket_t *	fm_icmp_create_connected_socket(fm_protocol_t *proto, const fm_address_t *addr);
static int		fm_icmp_protocol_for_family(int af);
static void		fm_icmp_request_build_extant_info(fm_icmp_extant_info_t *info, int v4_request_type, int v4_response_type, int id, int seq);
static fm_extant_t *	fm_icmp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_icmp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static bool		fm_icmp_process_extra_parameters(const fm_string_array_t *extra_args, fm_icmp_extra_params_t *extra_params);

/* Global extant map for all ICMP related stuff */
static fm_extant_map_t	fm_icmp_extant_map = FM_EXTANT_MAP_INIT;

static struct fm_protocol	fm_icmp_sock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "icmp",
	.id		= FM_PROTO_ICMP,

	.supported_parameters =
			  FM_PARAM_TYPE_PORT_MASK |	/* we use the port parameter to seq the icmp_id */
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK |
			  FM_FEATURE_STATUS_CALLBACK_MASK,

	.create_socket	= fm_icmp_create_socket,
	.create_host_shared_socket = fm_icmp_create_shared_socket,

	.locate_error	= fm_icmp_locate_error,
	.locate_response= fm_icmp_locate_response,
};

FM_PROTOCOL_REGISTER(fm_icmp_sock_ops);

/*
 * Create a DGRAM socket and connect it.
 * Used for PF_PACKET sockets only
 */
static fm_socket_t *
fm_icmp_create_connected_socket(fm_protocol_t *proto, const fm_address_t *addr)
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

static fm_extant_t *
fm_icmp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	fm_parsed_pkt_t *cooked;
	fm_parsed_hdr_t *hdr;
	fm_host_asset_t *host;
	fm_extant_t *extant;

	if ((cooked = pkt->parsed) == NULL
	 || (hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_ICMP)) == NULL)
		return NULL;

	/* Note, host can also be NULL. This happens with discovery probes, for instance. */
	host = fm_host_asset_get_active(&pkt->peer_addr);

	/* this should go to packet.c */
	if (fm_debug_level) {
		if (pkt->family == AF_INET)
			fm_log_debug("ICMPv4: message with type=%d, code=%d from %s", 
					hdr->icmp.v4_type, hdr->icmp.v4_code,
					fm_address_format(&pkt->peer_addr));
		else
			fm_log_debug("ICMPv6: message with v4-equivalent type=%d, code=%d from %s", 
					hdr->icmp.v4_type, hdr->icmp.v4_code,
					fm_address_format(&pkt->peer_addr));
	}

        while ((extant = fm_extant_iterator_match(iter, pkt->family, IPPROTO_ICMP)) != NULL) {
		fm_icmp_extant_info_t *ei = (fm_icmp_extant_info_t *) (extant + 1);

		if (extant->host != host)
			continue;

		if (ei->match.v4_request_type == hdr->icmp.v4_type
		 && (ei->match.id < 0 || ei->match.id == hdr->icmp.id)
		 && ei->match.seq == hdr->icmp.seq)
			return extant;
        }

	return NULL;
}

static fm_extant_t *
fm_icmp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	fm_parsed_pkt_t *cooked;
	fm_parsed_hdr_t *hdr;
	fm_host_asset_t *host;
	fm_extant_t *extant;

	if ((cooked = pkt->parsed) == NULL
	 || (hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_ICMP)) == NULL)
		return NULL;

	/* Note, host can also be NULL. This happens with discovery probes, for instance. */
	host = fm_host_asset_get_active(&pkt->peer_addr);

	/* this should go to packet.c */
	if (fm_debug_level) {
		if (pkt->family == AF_INET)
			fm_log_debug("ICMPv4: message with type=%d, code=%d, seq=0x%x, id=0x%x from %s", 
					hdr->icmp.v4_type, hdr->icmp.v4_code,
					hdr->icmp.seq, hdr->icmp.id,
					fm_address_format(&pkt->peer_addr));
		else
			fm_log_debug("ICMPv6: message with v4-equivalent type=%d, code=%d, seq=0x%x, id=0x%x from %s", 
					hdr->icmp.v4_type, hdr->icmp.v4_code,
					hdr->icmp.seq, hdr->icmp.id,
					fm_address_format(&pkt->peer_addr));
	}

        while ((extant = fm_extant_iterator_match(iter, pkt->family, IPPROTO_ICMP)) != NULL) {
		fm_icmp_extant_info_t *ei = (fm_icmp_extant_info_t *) (extant + 1);

		if (extant->host != host)
			continue;

		if (ei->match.v4_response_type == hdr->icmp.v4_type
		 && (ei->match.id < 0 || ei->match.id == hdr->icmp.id)
		 && ei->match.seq == hdr->icmp.seq)
			return extant;
        }

	return NULL;
}

/*
 * SOCK_RAW sockets
 */
static fm_socket_t *
fm_icmp_create_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;
	int ipproto;

	/* This should not fail; the caller should have taken care of this check already */
	ipproto = fm_icmp_protocol_for_family(af);
	if (ipproto < 0)
		return NULL;

	sock = fm_socket_create(af, SOCK_RAW, ipproto, proto);
	if (sock != NULL) {
		fm_socket_enable_ttl(sock);
		fm_socket_enable_tos(sock);

		/* PF_RAW sockets will always give us the IPv4 header.
		 * Funnily, IPv6 packets always come with the header stripped. */
		if (af == AF_INET)
			fm_socket_install_data_parser(sock, FM_PROTO_IP);
		fm_socket_install_data_parser(sock, FM_PROTO_ICMP);

		fm_socket_attach_extant_map(sock, &fm_icmp_extant_map);
	}
	return sock;
}

static fm_socket_t *
fm_icmp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target)
{
	const fm_address_t *addr = &target->address;
	fm_socket_t **sharedp;

	if (addr->ss_family == AF_INET)
		sharedp = &target->raw_icmp4_sock;
	else if (addr->ss_family == AF_INET6)
		sharedp = &target->raw_icmp4_sock;
	else
		return NULL;

	if (*sharedp == NULL)
		*sharedp = fm_icmp_create_connected_socket(proto, addr);

	return *sharedp;
}

/*
 * Choose the ICMP type to use.
 * As we don't know how long the type_name string passed as argument will be valid,
 * we replace it with a const string.
 */
static bool
fm_icmp_extra_params_set_type(fm_icmp_extra_params_t *params, const char *type_name)
{
	params->ipv4.send_type = -1;
	params->ipv4.response_type = -1;
	params->ipv6.send_type = -1;
	params->ipv6.response_type = -1;

	if (!strcasecmp(type_name, "echo")) {
		params->type_name = "echo";
		params->ipv4.send_type = ICMP_ECHO;
		params->ipv4.response_type = ICMP_ECHOREPLY;
		params->ipv6.send_type = ICMP6_ECHO_REQUEST;
		params->ipv6.response_type = ICMP6_ECHO_REPLY;
	} else if (!strcasecmp(type_name, "timestamp")) {
		params->type_name = "timestamp";
		params->ipv4.send_type = ICMP_TIMESTAMP;
		params->ipv4.response_type = ICMP_TIMESTAMPREPLY;
	} else if (!strcasecmp(type_name, "info")) {
		params->type_name = "info";
		params->ipv4.send_type = ICMP_INFO_REQUEST;
		params->ipv4.response_type = ICMP_INFO_REPLY;
	} else {
		return false;
	}

	return true;
}

/*
 * Create an ICMP request block
 */
fm_icmp_control_t *
fm_icmp_control_alloc(fm_protocol_t *proto, const fm_probe_params_t *params, const fm_icmp_extra_params_t *extra_params)
{
	fm_icmp_control_t *icmp;

	icmp = calloc(1, sizeof(*icmp));
	icmp->proto = proto;
	icmp->params = *params;

	if (extra_params != NULL)
		icmp->extra_params = *extra_params;

	if (icmp->params.retries == 0)
		icmp->params.retries = fm_global.icmp.retries;

	icmp->extra_params.ident = 0x5678;

	if (icmp->extra_params.type_name == NULL)
		fm_icmp_extra_params_set_type(&icmp->extra_params, "echo");


	return icmp;
}

static fm_socket_t *
fm_icmp_create_packet_socket(fm_icmp_control_t *icmp, const fm_interface_t *nic, int family)
{
	fm_address_t lladdr;
	fm_socket_t *sock;
	int llproto;

	if (!fm_interface_get_lladdr(nic, (struct sockaddr_ll *) &lladdr)
	 || !fm_address_link_update_upper_protocol(&lladdr, family))
		return NULL;

	/* Extract the llproto from the sockaddr. Note, this is in network byte order, which
	 * is exactly what socket(PF_PACKET, ...) expects as the protocol argument */
	llproto = fm_address_to_link(&lladdr)->sll_protocol;

	sock = fm_socket_create(PF_PACKET, SOCK_DGRAM, llproto, icmp->proto);

	fm_socket_install_data_parser(sock, FM_PROTO_IP);
	fm_socket_install_data_parser(sock, FM_PROTO_ICMP);

	fm_socket_attach_extant_map(sock, &fm_icmp_extant_map);

        if (!fm_socket_bind(sock, &lladdr)) {
                fm_log_error("Cannot bind raw socket to address %s: %m", fm_address_format(&lladdr));
                fm_socket_free(sock);
                return NULL;
        }

	return sock;
}

static void
fm_icmp_control_free(fm_icmp_control_t *icmp)
{
	if (icmp->sock != NULL && !icmp->sock_is_shared)
		fm_socket_free(icmp->sock);
	icmp->sock = NULL;

	free(icmp);
}

static bool
fm_icmp_request_init_target(const fm_icmp_control_t *icmp, fm_target_control_t *target_control, fm_target_t *target)
{
	const fm_address_t *addr = &target->address;
	fm_socket_t *sock = NULL;

	/* For the time being, we create a single raw socket per target host */
	sock = fm_protocol_create_host_shared_socket(icmp->proto, target);
	if (sock == NULL)
		return false;

	target_control->family = addr->ss_family;
	target_control->target = target;
	target_control->address = *addr;
	target_control->sock = sock;

	if (target_control->family == AF_INET6) {
		fm_ipv6_transport_csum_partial(&target_control->icmp.csum,
						&target_control->target->local_bind_address,
						&target_control->address,
						IPPROTO_ICMPV6);
	}

	return true;
}

/*
 * Set the shared socket (for traceroute)
 */
static int
fm_icmp_protocol_for_family(int af)
{
	switch (af) {
	case AF_INET:
		return IPPROTO_ICMP;

	case AF_INET6:
		return IPPROTO_ICMPV6;

	default:
		return -1;
	}
}

/*
 * raw icmp6
 */
static fm_pkt_t *
fm_icmp_request_build_packet(const fm_icmp_control_t *icmp, fm_target_control_t *host,
				const fm_icmp_extra_params_t *send_params,
				fm_icmp_extant_info_t *extant_info)
{
	fm_pkt_t *pkt = fm_pkt_alloc(host->family, 0);
	fm_csum_partial_t *csum = NULL, _csum;
	fm_buffer_t *bp, *raw;

	if ((raw = host->icmp.packet_header) != NULL) {
		bp = fm_buffer_alloc(16 + fm_buffer_available(raw));
		fm_buffer_append(bp, fm_buffer_head(raw), fm_buffer_available(raw));

		_csum = host->icmp.csum;
		csum = &_csum;
	} else {
		bp = fm_buffer_alloc(16);
	}

	pkt->payload = bp;

	pkt->peer_addr = host->address;
	if (host->family == AF_INET) {
		struct icmp *icmph;

		icmph = fm_buffer_push(bp, 8);
		icmph->icmp_type = send_params->ipv4.send_type;
		icmph->icmp_code = 0;
		icmph->icmp_cksum = 0;
		icmph->icmp_id = htons(send_params->ident);
		icmph->icmp_seq = htons(send_params->sequence);

		icmph->icmp_cksum = in_csum(icmph, 8);
        } else if (host->family == AF_INET6) {
		struct icmp6_hdr *icmph;

		icmph = fm_buffer_push(bp, 8);
		icmph->icmp6_type = send_params->ipv6.send_type;
		icmph->icmp6_code = 0;
		icmph->icmp6_cksum = 0;
		icmph->icmp6_id = htons(send_params->ident);
		icmph->icmp6_seq = htons(send_params->sequence);

		if (csum != NULL) {
			/* Add the length field to the IPv6 pseudo header */
			fm_csum_partial_u16(csum, 8);

			/* Add the ICMP header for checksumming */
			fm_csum_partial_update(csum, icmph, 8);

			icmph->icmp6_cksum = fm_csum_fold(csum);
		}
        }

	/* Now construct the extant match.
	 * To make things a bit simpler, the ICMPv6 header parsing code provides the v4 equivalent
	 * type/code where possible, so that we do not have to distinguish between v4 and v6 in the
	 * matching code.
	 */
	fm_icmp_request_build_extant_info(extant_info,
			send_params->ipv4.send_type,
			send_params->ipv4.response_type,
			icmp->kernel_trashes_id? -1 : send_params->ident,
			send_params->sequence);

	/* apply ttl, tos etc */
	fm_pkt_apply_probe_params(pkt, &icmp->params, icmp->proto->supported_parameters);

	return pkt;
}

/*
 * Build the response match
 */
static void
fm_icmp_request_build_extant_info(fm_icmp_extant_info_t *info, int v4_request_type, int v4_response_type, int id, int seq)
{
	info->match.v4_request_type = v4_request_type;
	info->match.v4_response_type = v4_response_type;
	info->match.seq = seq;
	info->match.id = id;
}

/*
 * Send the icmp request.
 * The probe argument is only here because we need to notify it when done.
 */
static fm_error_t
fm_icmp_request_send(const fm_icmp_control_t *icmp, fm_target_control_t *host,
				int param_type, unsigned int param_value,
				fm_extant_t **extant_ret)
{
	static unsigned int global_icmp_seq = 1;
	fm_icmp_extra_params_t send_params;
	fm_icmp_extant_info_t extant_info;
	fm_socket_t *sock;
	fm_pkt_t *pkt;

	if ((sock = icmp->sock) == NULL
	 && (sock = host->sock) == NULL) {
		fm_log_error("%s: you promised me a socket but there ain't none", __func__);
		return FM_SEND_ERROR;
	}

	/* Copy the param block so that we can modify it */
	send_params = icmp->extra_params;

	send_params.ttl = icmp->params.ttl;
	send_params.tos = icmp->params.tos;

	/* If the TTL parameter is set, this is probably traceroute, and we need to
	 * have a way to match error packets against the actual request.
	 * With PF_PACKET sockets, we can actually choose the icmp_id, but with SOCK_RAW,
	 * the kernel will overwrite what we try to send.
	 * Fudge a sequence number that is a combination of retry and ttl.
	 */
	if (param_type == FM_PARAM_TYPE_TTL) {
		send_params.sequence = (param_value << 8) | host->icmp.retries++;
		send_params.ttl = param_value;
	} else {
		send_params.sequence = global_icmp_seq++;
	}

	pkt = fm_icmp_request_build_packet(icmp, host, &send_params, &extant_info);

	fm_log_debug("ICMP: create extant with response type=%d, seq=0x%x, id=0x%x from %s", 
			extant_info.match.v4_response_type,
			extant_info.match.seq, extant_info.match.id,
			fm_address_format(&pkt->peer_addr));

	if (!fm_socket_send_pkt_and_burn(sock, pkt)) {
		fm_log_error("Unable to send ICMP packet: %m");
		return FM_SEND_ERROR;
	}

	if (host->target != NULL) {
		fm_host_asset_t *asset = host->target->host_asset;

		*extant_ret = fm_socket_add_extant(sock, asset, host->family, IPPROTO_ICMP, &extant_info, sizeof(extant_info));
	} else {
		*extant_ret = fm_socket_add_extant(sock, NULL, host->family, IPPROTO_ICMP, &extant_info, sizeof(extant_info));
	}

	if (*extant_ret && icmp->extants_are_multi_shot)
		(*extant_ret)->single_shot = false;

	/* update the asset state */
	if (host->target != NULL)
		fm_target_update_host_state(host->target, FM_PROTO_ICMP, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

static bool
fm_icmp_process_extra_parameters(const fm_string_array_t *extra_args, fm_icmp_extra_params_t *extra_params)
{
	const char *type_name = NULL;
	unsigned int i;

	extra_params = calloc(1, sizeof(*extra_params));

	for (i = 0; i < extra_args->count; ++i) {
		const char *arg = extra_args->entries[i];

		if (fm_parse_string_argument(arg, "type", &type_name)) {
			/* pass */
		} else {
			fm_log_error("Cannot create ICMP host probe: invalid argument \"%s\"", arg);
			return false;
		}
	}

	if (type_name == NULL)
		type_name = "echo";

	if (!fm_icmp_extra_params_set_type(extra_params, type_name)) {
		fm_log_error("ICMP type %s not supported\n", type_name);
		return false;
	}

	return true;

}

/*
 * New multiprobe implementation
 */
static bool
fm_icmp_multiprobe_add_target(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_target_t *target)
{
	const fm_icmp_control_t *icmp = multiprobe->control;

	return fm_icmp_request_init_target(icmp, &host_task->control, target);
}

static bool
fm_icmp_multiprobe_add_broadcast(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
						const fm_interface_t *nic,
						const fm_address_t *src_link_addr,
						const fm_address_t *dst_link_addr,
						const fm_address_t *src_network_addr,
						const fm_address_t *dst_network_addr)

{
	fm_target_control_t *target_control = &host_task->control;
	fm_icmp_control_t *icmp = multiprobe->control;
	fm_socket_t *sock;

	if (target_control->family != AF_INET6) {
		fm_log_error("ICMP broadcast currently implemented for IPv6 only");
		return false;
	}

	if (!(sock = fm_icmp_create_packet_socket(icmp, nic, target_control->family)))
		return false;

	target_control->local_address = *src_link_addr;
	target_control->address = *dst_link_addr;
	target_control->sock = sock;

	target_control->icmp.packet_header = fm_buffer_alloc(128);
	fm_raw_packet_add_ipv6_header(target_control->icmp.packet_header, src_network_addr, dst_network_addr,
			IPPROTO_ICMPV6, icmp->params.ttl, icmp->params.tos, 
			sizeof(struct icmp6_hdr));

	fm_ipv6_transport_csum_partial(&target_control->icmp.csum, src_network_addr, dst_network_addr, IPPROTO_ICMPV6);

	/* Normally, extants are destroyed after the first response; we want them to
	 * stay around so that we see *all* responses */
	icmp->extants_are_multi_shot = true;

	return true;
}

static fm_error_t
fm_icmp_multiprobe_transmit(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
		int param_type, int param_value,
		fm_extant_t **extant_ret, double *timeout_ret)
{
	const fm_icmp_control_t *icmp = multiprobe->control;

	return fm_icmp_request_send(icmp, &host_task->control, param_type, param_value, extant_ret);
}

void
fm_icmp_multiprobe_destroy_target(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task)
{
	fm_target_control_t *target_control = &host_task->control;

	if (target_control->icmp.packet_header != NULL) {
		fm_buffer_free(target_control->icmp.packet_header);
		target_control->icmp.packet_header = NULL;
	}
}

static void
fm_icmp_multiprobe_destroy(fm_multiprobe_t *multiprobe)
{
	fm_icmp_control_t *icmp = multiprobe->control;

	multiprobe->control = NULL;
	fm_icmp_control_free(icmp);
}

static fm_multiprobe_ops_t	fm_icmp_multiprobe_ops = {
	.add_target		= fm_icmp_multiprobe_add_target,
	.add_broadcast		= fm_icmp_multiprobe_add_broadcast,
	.transmit		= fm_icmp_multiprobe_transmit,
	.destroy		= fm_icmp_multiprobe_destroy,
	.destroy_host		= fm_icmp_multiprobe_destroy_target,
};

static bool
fm_icmp_configure_probe(const fm_probe_class_t *pclass, fm_multiprobe_t *multiprobe, const fm_string_array_t *extra_string_args)
{
	fm_icmp_extra_params_t parsed_extra_params, *extra_params = NULL;
	fm_icmp_control_t *icmp;

	if (multiprobe->control != NULL) {
		fm_log_error("cannot reconfigure probe %s", multiprobe->name);
		return false;
	}

	/* Set the default timings and retries */
	multiprobe->timings.packet_spacing = fm_global.icmp.packet_spacing * 1e-3;
	multiprobe->timings.timeout = fm_global.icmp.timeout * 1e-3;
	if (multiprobe->params.retries == 0)
		multiprobe->params.retries = fm_global.icmp.retries;

	if (extra_string_args && extra_string_args->count != 0) {
		memset(&parsed_extra_params, 0, sizeof(parsed_extra_params));
		if (fm_icmp_process_extra_parameters(extra_string_args, &parsed_extra_params)) {
			fm_log_warning("ICMP: failed to parse all protocol-specific parameters");
			return false;
		}

		extra_params = &parsed_extra_params;
	}

	icmp = fm_icmp_control_alloc(pclass->proto, &multiprobe->params, extra_params);
	if (icmp == NULL)
		return false;

	multiprobe->ops = &fm_icmp_multiprobe_ops;
	multiprobe->control = icmp;
	return true;
}

static struct fm_probe_class fm_icmp_host_probe_class = {
	.name		= "icmp",
	.proto_id	= FM_PROTO_ICMP,
	.modes		= FM_PROBE_MODE_TOPO|FM_PROBE_MODE_HOST|FM_PROBE_MODE_BCAST,
	.configure	= fm_icmp_configure_probe,
};

FM_PROBE_CLASS_REGISTER(fm_icmp_host_probe_class)
