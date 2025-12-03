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
#include "probe_private.h"
#include "socket.h"
#include "logging.h"

static fm_socket_t *	fm_icmp_create_socket(fm_protocol_t *proto, int ipproto);

static int		fm_icmp_protocol_for_family(int af);
static void		fm_icmp_request_build_extant_info(fm_icmp_extant_info_t *info, int v4_request_type, int v4_response_type, int id, int seq);
static fm_extant_t *	fm_icmp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_icmp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static bool		fm_icmp_process_extra_parameters(const fm_string_array_t *extra_args, fm_icmp_extra_params_t *extra_params);

/* Global pool for ICMP sockets */
static fm_socket_pool_t	*fm_icmp_socket_pool = NULL;

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

	.locate_error	= fm_icmp_locate_error,
	.locate_response= fm_icmp_locate_response,
};

FM_PROTOCOL_REGISTER(fm_icmp_sock_ops);

/*
 * Track extant ICMP requests.
 */
static void
fm_icmp_extant_info_build(const fm_icmp_control_t *icmp, const fm_icmp_header_info_t *icmp_info, fm_icmp_extant_info_t *extant_info)
{
	fm_icmp_msg_type_t *response_type;

	/* This is a quick operation, and we've checked earlier that this returns non-NULL */
	response_type = fm_icmp_msg_type_get_reply(icmp_info->msg_type);

	/* Now construct the extant match. */
	fm_icmp_request_build_extant_info(extant_info,
			icmp_info->msg_type->v4_type,
			response_type->v4_code,
			icmp_info->id,
			icmp_info->seq);

	fm_log_debug("ICMP: create extant with response type=%d, seq=0x%x, id=0x%x", 
			extant_info->match.v4_response_type,
			extant_info->match.seq, extant_info->match.id);
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
	if (host != NULL)
		fm_host_asset_update_state(host, FM_ASSET_STATE_OPEN);

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
		fm_socket_enable_hdrincl(sock);

		fm_socket_install_data_parser(sock, FM_PROTO_IP);
		fm_socket_install_data_parser(sock, FM_PROTO_ICMP);

		fm_socket_attach_extant_map(sock, &fm_icmp_extant_map);
	}
	return sock;
}

static fm_socket_t *
fm_icmp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target)
{
	fm_address_t bind_address;

	/* Pick adequate source address to use when talking to this target. */
	if (!fm_target_get_local_bind_address(target, &bind_address)) {
		fm_log_error("%s: cannot determine source address", target->id);
		return NULL;
	}

	/* make sure the port number is 0 */
	fm_address_set_port(&bind_address, 0);

	return fm_socket_pool_get_socket(fm_icmp_socket_pool, &bind_address);
}

/*
 * Create an ICMP request block
 */
fm_icmp_control_t *
fm_icmp_control_alloc(fm_protocol_t *proto, const fm_probe_params_t *params)
{
	fm_icmp_control_t *icmp;

	icmp = calloc(1, sizeof(*icmp));
	icmp->proto = proto;
	icmp->params = *params;

	/* No IP settings at this level */

	icmp->icmp_info.seq = 0;
	icmp->icmp_info.id = 0x5678;

	/* Default to echo request/reply */
	if (!fm_icmp_process_config_arg(&icmp->icmp_info, "icmp-type=echo"))
		return NULL;

	if (fm_icmp_socket_pool == NULL)
		fm_icmp_socket_pool = fm_socket_pool_create(proto, SOCK_RAW);

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

	sock = fm_icmp_create_shared_socket(icmp->proto, target);
	if (sock == NULL)
		return false;

	target_control->family = addr->family;
	target_control->target = target;
	target_control->dst_addr = *addr;
	target_control->sock = sock;
	target_control->sock_is_shared = true;

	if (target_control->family == AF_INET6) {
		/* nix this, too: */
		fm_ipv6_transport_csum_partial(&target_control->icmp.csum,
						&target_control->src_addr,
						&target_control->dst_addr,
						IPPROTO_ICMPV6);
	}

	target_control->ip_info = icmp->ip_info;
	target_control->ip_info.ipproto = fm_icmp_protocol_for_family(target_control->family);
	target_control->ip_info.dst_addr = *addr;

	fm_target_get_local_bind_address(target, &target_control->ip_info.src_addr);

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
 * Build the actual packet.
 */
static fm_pkt_t *
fm_icmp_request_build_packet(const fm_icmp_control_t *icmp, fm_target_control_t *target_control,
				const fm_ip_header_info_t *ip_info,
				fm_icmp_header_info_t *icmp_info)
{
	fm_pkt_t *pkt;

	pkt = fm_pkt_alloc(target_control->family, fm_ip_compute_len(ip_info) + fm_icmp_compute_len(icmp_info));
	pkt->peer_addr = ip_info->dst_addr;

	if (!fm_raw_packet_add_ip_header(pkt->payload, ip_info, fm_icmp_compute_len(icmp_info))
	 || !fm_raw_packet_add_icmp_header(pkt->payload, ip_info, icmp_info)) {
		fm_pkt_free(pkt);
		return NULL;
	}

	/* On raw sockets, the port field is supposed to be either 0 or contain the transport
         * protocol (IPPROTO_TCP in our case). Note, it seems that this is only enforced for
         * IPv6; the manpages say that this behavior "got lost" for IPv4 some time in Linux 2.2. */
        fm_address_set_port(&pkt->peer_addr, IPPROTO_UDP);

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
fm_icmp_request_send(const fm_icmp_control_t *icmp, fm_target_control_t *target_control,
				int param_type, unsigned int param_value,
				fm_extant_t **extant_ret)
{
	static unsigned int global_icmp_seq = 1;
	const fm_ip_header_info_t *ip_info;
	fm_icmp_header_info_t *icmp_info;
	fm_icmp_extant_info_t extant_info;
	fm_socket_t *sock;
	fm_pkt_t *pkt;

	if ((sock = icmp->sock) == NULL
	 && (sock = target_control->sock) == NULL) {
		fm_log_error("%s: you promised me a socket but there ain't none", __func__);
		return FM_SEND_ERROR;
	}

	ip_info = fm_ip_header_info_finalize(&target_control->ip_info, param_type, param_value);

	icmp_info = fm_icmp_header_info_finalize(&icmp->icmp_info, param_type, param_value, NULL);

	/* If the TTL parameter is set, this is probably traceroute, and we need to
	 * have a way to match error packets against the actual request.
	 * With PF_PACKET sockets, we can actually choose the icmp_id, but with SOCK_RAW,
	 * the kernel will overwrite what we try to send.
	 * Fudge a sequence number that is a combination of retry and ttl.
	 */
	if (param_type == FM_PARAM_TYPE_TTL) {
		icmp_info->seq = (param_value << 8) | target_control->icmp.retries++;
	} else {
		icmp_info->seq = global_icmp_seq++;
	}

	pkt = fm_icmp_request_build_packet(icmp, target_control, ip_info, icmp_info);

	if (!fm_socket_send_pkt_and_burn(sock, pkt)) {
		fm_log_error("Unable to send ICMP packet: %m");
		return FM_SEND_ERROR;
	}

	fm_icmp_extant_info_build(icmp, icmp_info, &extant_info);
	if (target_control->target != NULL) {
		fm_host_asset_t *asset = target_control->target->host_asset;

		*extant_ret = fm_socket_add_extant(sock, asset, target_control->family, IPPROTO_ICMP, &extant_info, sizeof(extant_info));
	} else {
		*extant_ret = fm_socket_add_extant(sock, NULL, target_control->family, IPPROTO_ICMP, &extant_info, sizeof(extant_info));
	}

	if (*extant_ret && icmp->extants_are_multi_shot)
		(*extant_ret)->single_shot = false;

	/* update the asset state */
	if (target_control->target != NULL)
		fm_target_update_host_state(target_control->target, FM_PROTO_ICMP, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

static bool
fm_icmp_process_extra_parameters(const fm_string_array_t *extra_args, fm_icmp_extra_params_t *extra_params)
{
#if 0 /* this will change */
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
#endif

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

	target_control->src_addr = *src_link_addr;
	target_control->dst_addr = *dst_link_addr;
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
		const fm_buffer_t *payload,
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
fm_icmp_configure_probe(const fm_probe_class_t *pclass, fm_multiprobe_t *multiprobe, const fm_string_array_t *extra_args)
{
	fm_icmp_extra_params_t parsed_extra_params, *extra_params = NULL;
	fm_icmp_control_t *icmp;
	unsigned int i;

	if (multiprobe->control != NULL) {
		fm_log_error("cannot reconfigure probe %s", multiprobe->name);
		return false;
	}

	/* Set the default timings and retries */
	multiprobe->timings.packet_spacing = fm_global.icmp.packet_spacing * 1e-3;
	multiprobe->timings.timeout = fm_global.icmp.timeout * 1e-3;
	if (multiprobe->params.retries == 0)
		multiprobe->params.retries = fm_global.icmp.retries;

	icmp = fm_icmp_control_alloc(pclass->proto, &multiprobe->params);
	if (icmp == NULL)
		return false;

	/* process extra_args if given */
	for (i = 0; i < extra_args->count; ++i) {
		const char *arg = extra_args->entries[i];

		if (!strncmp(arg, "icmp-", 4) && fm_icmp_process_config_arg(&icmp->icmp_info, arg))
			continue;

		if (!strncmp(arg, "ip-", 4) && fm_ip_process_config_arg(&icmp->ip_info, arg))
			continue;

		fm_log_error("%s: unsupported or invalid option %s", multiprobe->name, arg);
		return false;
	}

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
