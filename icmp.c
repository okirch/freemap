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
#include "target.h" /* for fm_probe_t */
#include "buffer.h"
#include "utils.h"
#include "icmp.h"
#include "rawpacket.h"
#include "socket.h"

static fm_socket_t *	fm_icmp_create_socket(fm_protocol_t *proto, int ipproto);
static fm_socket_t *	fm_icmp_create_shared_socket(fm_protocol_t *proto, fm_target_t *target);

static fm_socket_t *	fm_icmp_create_connected_socket(fm_protocol_t *proto, const fm_address_t *addr);
static int		fm_icmp_protocol_for_family(int af);
static void		fm_icmp_request_build_extant_info(fm_icmp_extant_info_t *info, int v4_request_type, int v4_response_type, int id, int seq);
static fm_extant_t *	fm_icmp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_icmp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);

static fm_icmp_request_t *fm_icmp_probe_get_request(const fm_probe_t *probe);
static void		fm_icmp_probe_set_request(fm_probe_t *probe, fm_icmp_request_t *icmp);

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

static bool
fm_icmp_control_install_packet_socket(fm_icmp_control_t *icmp, const fm_interface_t *nic, int family)
{
	fm_address_t lladdr;
	fm_socket_t *sock;
	int llproto;

	if (!fm_interface_get_lladdr(nic, (struct sockaddr_ll *) &lladdr)
	 || !fm_address_link_update_upper_protocol(&lladdr, family))
		return false;

	/* Extract the llproto from the sockaddr. Note, this is in network byte order, which
	 * is exactly what socket(PF_PACKET, ...) expects as the protocol argument */
	llproto = fm_address_to_link(&lladdr)->sll_protocol;

	sock = fm_socket_create(PF_PACKET, SOCK_DGRAM, llproto, icmp->proto);
        fm_socket_install_data_parser(sock, FM_PROTO_ICMP);

        if (!fm_socket_bind(sock, &lladdr)) {
                fm_log_error("Cannot bind raw socket to address %s: %m", fm_address_format(&lladdr));
                fm_socket_free(sock);
                return false;
        }

	icmp->sock = sock;
	return true;
}

static void
fm_icmp_control_free(fm_icmp_control_t *icmp)
{
	if (icmp->sock != NULL && !icmp->sock_is_shared)
		fm_socket_free(icmp->sock);
	icmp->sock = NULL;

	free(icmp);
}

static fm_icmp_request_t *
fm_icmp_request_alloc(fm_protocol_t *proto, const fm_probe_params_t *params, const fm_icmp_extra_params_t *extra_params)
{
	fm_icmp_request_t *req;

	req = calloc(1, sizeof(*req));
	req->control = fm_icmp_control_alloc(proto, params, extra_params);
	return req;
}

static bool
fm_icmp_request_init_target(fm_icmp_control_t *icmp, fm_target_control_t *target_control, fm_target_t *target)
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

	return true;
}

static bool
fm_icmp_request_set_target(fm_icmp_request_t *req, fm_target_t *target)
{
	return fm_icmp_request_init_target(req->control, &req->target_control, target);
}

static bool
fm_icmp_request_set_broadcast(fm_icmp_request_t *req, int af, const fm_interface_t *nic, const fm_address_t *net_src_addr)
{
	fm_icmp_control_t *icmp = req->control;
	fm_address_t network_broadcast;
	struct sockaddr_ll lladdr, llbcast;
	fm_socket_t *sock;
	fm_target_control_t *target_control;

	/* Note, for IPv6 over ethernet, the get_llbroadcast function will actually return the
	 * all-nodes MAC multicast address 33:33:00:00:00:01.
	 * I wonder what this does for IPv4... */
	if (!fm_interface_get_lladdr(nic, &lladdr)
	 || !fm_interface_get_llbroadcast(nic, &llbcast))
		return false;

	if (af == AF_INET) {
		fm_address_set_ipv4_local_broadcast(&network_broadcast);
		lladdr.sll_protocol = htons(ETH_P_IP);
		llbcast.sll_protocol = htons(ETH_P_IP);
	} else if (af == AF_INET6) {
		fm_address_set_ipv6_all_hosts_multicast(&network_broadcast);
		lladdr.sll_protocol = htons(ETH_P_IPV6);
		llbcast.sll_protocol = htons(ETH_P_IPV6);
	} else {
		return false;
	}

	if (af != AF_INET6) {
		fm_log_error("ICMP broadcast currently implemented for IPv6 only");
		return false;
	}

	/* get a PF_PACKET socket */
	sock = fm_raw_socket_get((fm_address_t *) &lladdr, icmp->proto, SOCK_DGRAM);
	if (sock == NULL)
		return false;

	target_control = &req->target_control;
	target_control->family = af;
	target_control->address = network_broadcast;

	icmp->sock = sock;
	icmp->sock_is_shared = true;

	icmp->packet_header = fm_buffer_alloc(128);
	fm_raw_packet_add_ipv6_header(icmp->packet_header, net_src_addr, &network_broadcast, 
			IPPROTO_ICMPV6, icmp->params.ttl, icmp->params.tos, 
			sizeof(struct icmp6_hdr));

	icmp->csum_header = fm_ipv6_checksum_header(net_src_addr, &network_broadcast, IPPROTO_ICMPV6);
	icmp->csum_header->checksum.offset = 2;
	icmp->csum_header->checksum.width = 2;

	/* Normally, extants are destroyed after the first response; we want them to
	 * stay around so that we see *all* responses */
	icmp->extants_are_multi_shot = true;

	return icmp;
}

/*
 * Free an existing request
 */
static void
fm_icmp_request_free(fm_icmp_request_t *req)
{
	fm_target_control_destroy(&req->target_control);
	fm_icmp_control_free(req->control);
	free(req);
}

/*
 * Set the shared socket (for traceroute)
 */
static void
fm_icmp_control_set_socket(fm_icmp_control_t *icmp, fm_socket_t *sock)
{
	icmp->sock = sock;
	icmp->sock_is_shared = true;
}

/*
 * Do the scheduling
 */
static fm_error_t
fm_icmp_control_schedule(fm_icmp_control_t *icmp, fm_time_t *expires)
{
	if (icmp->params.retries == 0)
		return FM_TIMED_OUT;

	/* After sending the last probe, we wait until the full timeout has expired.
	 * For any earlier probe, we wait for the specified packet spacing */
	if (icmp->params.retries == 1)
		*expires = fm_time_now() + 1e-3 * fm_global.icmp.timeout;
	else
		*expires = fm_time_now() + 1e-3 * fm_global.icmp.packet_spacing;
	return 0;
}

static inline bool
fm_icmp_instantiate_params(struct icmp_params *params, fm_target_t *target)
{
	/* params->host_address = target->address; */

	params->ipproto = fm_icmp_protocol_for_family(target->address.ss_family);
	if (params->ipproto < 0) {
		fm_log_error("Cannot create ICMP probe for %s", fm_address_format(&target->address));
		return false;
	}

	/* params->ident = 0x1234; */
	return true;
}

int
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
fm_icmp_request_build_packet(fm_icmp_control_t *icmp, fm_target_control_t *host,
				const fm_icmp_extra_params_t *send_params,
				fm_icmp_extant_info_t *extant_info)
{
	fm_pkt_t *pkt = fm_pkt_alloc(host->family, 0);
	fm_buffer_t *bp, *raw;
	fm_csum_hdr_t *csum_header;

	if ((raw = host->icmp.packet_header) != NULL) {
		bp = fm_buffer_alloc(16 + fm_buffer_available(raw));
		fm_buffer_append(bp, fm_buffer_head(raw), fm_buffer_available(raw));
	} else {
		bp = fm_buffer_alloc(16);
	}

	csum_header = host->icmp.csum_header;

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

		if (csum_header != NULL
		 && !fm_raw_packet_csum(csum_header, icmph, 8)) {
			fm_log_fatal("got my wires crossed in the icmpv6 checksum thing");
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
fm_icmp_request_send(fm_icmp_control_t *icmp, fm_target_control_t *host,
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
	 * With SOCK_PACKET, we can actually choose the icmp_id, but with SOCK_RAW,
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

	/* FIXME: this is wrong */
	icmp->params.retries -= 1;

	/* update the asset state */
	if (host->target != NULL)
		fm_target_update_host_state(host->target, FM_PROTO_ICMP, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

/*
 * The ICMP host probe
 */
struct fm_icmp_host_probe {
	fm_probe_t		base;
	fm_icmp_request_t *	icmp;

	void			(*discovery_callback)(const fm_address_t *, void *);
	void *			user_data;
};

/*
 * Check whether we're clear to send. If so, set the probe timer
 */
static fm_error_t
fm_icmp_host_probe_schedule(fm_probe_t *probe)
{
	fm_icmp_request_t *req = fm_icmp_probe_get_request(probe);

	if (req == NULL)
		return FM_NOT_SUPPORTED;

	return fm_icmp_control_schedule(req->control, &probe->job.expires);
}


/*
 * Send the probe.
 */
static fm_error_t
fm_icmp_host_probe_send(fm_probe_t *probe)
{
	fm_icmp_request_t *req = fm_icmp_probe_get_request(probe);
	fm_extant_t *extant = NULL;
	fm_error_t error;

	error = fm_icmp_request_send(req->control, &req->target_control, &extant);
	if (extant != NULL)
		extant->probe = probe;

	return error;
}

static fm_error_t
fm_icmp_host_probe_set_socket(fm_probe_t *probe, fm_socket_t *sock)
{
	fm_icmp_request_t *icmp = fm_icmp_probe_get_request(probe);

	if (icmp == NULL)
		return FM_NOT_SUPPORTED;

	fm_icmp_control_set_socket(icmp->control, sock);
	return 0;
}

static bool
fm_icmp_host_probe_data_tap(const fm_probe_t *probe, const fm_pkt_t *pkt, double rtt, void *user_data)
{
	const struct sock_extended_err *ee;

	if ((ee = pkt->info.ee) == NULL) {
		/* We received a response. The host is reachable */
		fm_log_debug("%s: have a response, done", probe->name);
		return false;
	} else
	if (pkt->family == AF_INET && ee->ee_origin == SO_EE_ORIGIN_ICMP) {
		if (ee->ee_type == ICMP_DEST_UNREACH) {
			fm_log_debug("%s: received ICMP unreachable", fm_probe_name(probe));
			return false;
		} else {
			fm_log_debug("%s ignoring icmp packet with type %d.%d",
					fm_address_format(&pkt->peer_addr),
					ee->ee_type, ee->ee_code);
		}
	}

	/* by default, keep going */
	return true;
}

static bool
fm_icmp_discovery_data_tap(const fm_probe_t *probe, const fm_pkt_t *pkt, double rtt, void *user_data)
{
	const struct sock_extended_err *ee;

	if ((ee = pkt->info.ee) == NULL) {
		struct fm_icmp_host_probe *icmp_probe = (struct fm_icmp_host_probe *) probe;

		/* FIXME: link-local addresses need the interface index in the sockaddr.
		 * Add it. */
		fm_log_debug("%s: DISCOVERED %s", probe->name, fm_address_format(&pkt->peer_addr));
		icmp_probe->discovery_callback(&pkt->peer_addr, icmp_probe->user_data);
	}

	/* keep going */
	return true;
}

static void
fm_icmp_host_probe_set_discovery_callback(fm_probe_t *probe,
				void (*callback)(const fm_address_t *, void *user_data), void *user_data)
{
	struct fm_icmp_host_probe *icmp_probe = (struct fm_icmp_host_probe *) probe;

	icmp_probe->discovery_callback = callback;
	icmp_probe->user_data = user_data;

	fm_probe_install_status_callback(probe, fm_icmp_discovery_data_tap, NULL);
}


static void
fm_icmp_host_probe_destroy(fm_probe_t *probe)
{
	fm_icmp_probe_set_request(probe, NULL);
	fm_extant_map_forget_probe(&fm_icmp_extant_map, probe);
}

static struct fm_probe_ops fm_icmp_host_probe_ops = {
	.obj_size	= sizeof(struct fm_icmp_host_probe),
	.name 		= "icmp",

	.default_timeout= 1000,	/* FM_ICMP_RESPONSE_TIMEOUT */

	.destroy	= fm_icmp_host_probe_destroy,
	.schedule	= fm_icmp_host_probe_schedule,
	.send		= fm_icmp_host_probe_send,
	.set_socket	= fm_icmp_host_probe_set_socket,
};

static fm_icmp_request_t *
fm_icmp_probe_get_request(const fm_probe_t *probe)
{
	if (probe->ops != &fm_icmp_host_probe_ops)
		return NULL;

	return ((struct fm_icmp_host_probe *) probe)->icmp;
}

static void
fm_icmp_probe_set_request(fm_probe_t *probe, fm_icmp_request_t *icmp)
{
	struct fm_icmp_host_probe *icmp_probe;

	if (probe->ops != &fm_icmp_host_probe_ops)
		return;

	icmp_probe = (struct fm_icmp_host_probe *) probe;
	if (icmp_probe->icmp != NULL)
		fm_icmp_request_free(icmp_probe->icmp);
	icmp_probe->icmp = icmp;
}

static void *
fm_icmp_process_extra_parameters(const fm_probe_class_t *pclass, const fm_string_array_t *extra_args)
{
	fm_icmp_extra_params_t *extra_params;
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
		free(extra_params);
		return NULL;
	}

	return extra_params;

}


static fm_probe_t *
fm_icmp_create_host_probe(fm_probe_class_t *pclass, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_protocol_t *proto = pclass->proto;
	fm_icmp_request_t *req;
	fm_icmp_control_t *icmp;
	fm_probe_t *probe;
	char name[32];

	assert(proto && proto->id == FM_PROTO_ICMP);

	req = fm_icmp_request_alloc(proto, params, extra_params);
	if (req == NULL)
		return NULL;

	icmp = req->control;
	if (!fm_icmp_request_set_target(req, target)) {
		fm_icmp_request_free(req);
		return NULL;
	}

	snprintf(name, sizeof(name), "icmp/%s/%04x", icmp->extra_params.type_name, icmp->icmp.seq);
	probe = fm_probe_alloc(name, &fm_icmp_host_probe_ops, target);

	fm_icmp_probe_set_request(probe, req);

	fm_probe_install_status_callback(probe, fm_icmp_host_probe_data_tap, NULL);

	fm_log_debug("Created ICMP socket probe for %s\n", target->id);
	return probe;
}

/*
 * New multiprobe implementation
 */
static bool
fm_icmp_multiprobe_add_target(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_target_t *target)
{
	fm_icmp_control_t *icmp = multiprobe->control;

	return fm_icmp_request_init_target(icmp, &host_task->control, target);
}

static bool
fm_icmp_multiprobe_add_broadcast(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
                                                const fm_address_t *src_link_addr,
                                                const fm_address_t *dst_link_addr,
                                                const fm_address_t *src_network_addr,
                                                const fm_address_t *dst_network_addr)

{
	fm_target_control_t *target_control = &host_task->control;
	fm_icmp_control_t *icmp = multiprobe->control;

	if (target_control->family != AF_INET6) {
		fm_log_error("ICMP broadcast currently implemented for IPv6 only");
		return false;
	}


	target_control->local_address = *src_link_addr;
	target_control->address = *dst_link_addr;

	target_control->icmp.packet_header = fm_buffer_alloc(128);
	fm_raw_packet_add_ipv6_header(target_control->icmp.packet_header, src_network_addr, dst_network_addr,
			IPPROTO_ICMPV6, icmp->params.ttl, icmp->params.tos, 
			sizeof(struct icmp6_hdr));

	target_control->icmp.csum_header = fm_ipv6_checksum_header(src_network_addr, dst_network_addr, IPPROTO_ICMPV6);
	target_control->icmp.csum_header->checksum.offset = 2;
	target_control->icmp.csum_header->checksum.width = 2;

	/* Normally, extants are destroyed after the first response; we want them to
	 * stay around so that we see *all* responses */
	icmp->extants_are_multi_shot = true;

	return false;
}

static fm_error_t
fm_icmp_multiprobe_transmit(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
		int param_type, int param_value,
		fm_extant_t **extant_ret, double *timeout_ret)
{
	fm_icmp_control_t *icmp = multiprobe->control;

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
	if (target_control->icmp.csum_header != NULL) {
		free(target_control->icmp.csum_header);
		target_control->icmp.csum_header = NULL;
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
fm_icmp_configure_probe(const fm_probe_class_t *pclass, fm_multiprobe_t *multiprobe, const void *extra_params)
{
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
	.modes		= FM_PROBE_MODE_TOPO|FM_PROBE_MODE_HOST,
	.process_extra_parameters = fm_icmp_process_extra_parameters,
	.configure	= fm_icmp_configure_probe,
};

FM_PROBE_CLASS_REGISTER(fm_icmp_host_probe_class)

/*
 * ICMPv6 broadcast probes can be used to discover hosts on the local network
 *
 * FIXME: we may want to send some gratuitous ARP/ND_ADVERT messages before we
 * do the broadcast...
 */
fm_multiprobe_t *
fm_icmp_create_broadcast_probe(fm_protocol_t *proto, int family, const fm_interface_t *nic,
				const fm_address_t *net_src_addr,
				void (*callback)(const fm_pkt_t *, void *user_data), void *user_data,
				const fm_probe_params_t *params, const void *extra_params)
{
	fm_multiprobe_t *multiprobe;
	fm_icmp_control_t *icmp;

	fm_log_debug("Creating ICMP broadcast probe for %s, srcaddr=%s",
			fm_interface_get_name(nic), fm_address_format(net_src_addr));

	assert(proto && proto->id == FM_PROTO_ICMP);
	assert(net_src_addr->ss_family == family);

	multiprobe = fm_multiprobe_alloc(FM_PROBE_MODE_HOST, "broadcast-ping");
	if (!fm_multiprobe_configure(multiprobe, &fm_icmp_host_probe_class, params, extra_params))
		return NULL;

	icmp = multiprobe->control;

	/* install a PF_PACKET socket */
	if (!fm_icmp_control_install_packet_socket(icmp, nic, family))
		goto failed;

	if (!fm_multiprobe_add_link_level_broadcast(multiprobe, family, nic, net_src_addr))
		goto failed;

	fm_socket_install_data_tap(icmp->sock, callback, user_data);

	fm_log_debug("Created ICMP discovery probe for %s\n", fm_interface_get_name(nic));
	return multiprobe;

failed:
	fm_multiprobe_free(multiprobe);
	return NULL;
}
