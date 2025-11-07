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

static fm_socket_t *	fm_icmp_create_bsd_socket(fm_protocol_t *proto, int ipproto);
static bool		fm_icmp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt);
static bool		fm_icmp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt);
static fm_socket_t *	fm_icmp_create_raw_socket(fm_protocol_t *proto, int ipproto);
static fm_socket_t *	fm_icmp_create_shared_raw_socket(fm_protocol_t *proto, fm_target_t *target);

static fm_socket_t *	fm_icmp_create_connected_socket(fm_protocol_t *proto, const fm_address_t *addr);
static int		fm_icmp_protocol_for_family(int af);
static void		fm_icmp_request_build_extant_info(fm_icmp_extant_info_t *info, const void *raw, size_t len);
static fm_extant_t *	fm_icmp_locate_probe(const struct sockaddr_storage *target_addr, fm_pkt_t *pkt, bool is_response, bool ignore_id);

static fm_icmp_request_t *fm_icmp_probe_get_request(const fm_probe_t *probe);
static void		fm_icmp_probe_set_request(fm_probe_t *probe, fm_icmp_request_t *icmp);

/* This is for ICMP discovery probes */
static fm_extant_list_t	global_extant_list;

static struct fm_protocol	fm_icmp_bsdsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "icmp",
	.id		= FM_PROTO_ICMP,

	.supported_parameters =
			  FM_PARAM_TYPE_PORT_MASK |	/* we use the port parameter to seq the icmp_id */
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK |
			  FM_FEATURE_STATUS_CALLBACK_MASK,

	.create_socket	= fm_icmp_create_bsd_socket,
	.process_packet	= fm_icmp_process_packet,
	.process_error	= fm_icmp_process_error,
};

static struct fm_protocol	fm_icmp_rawsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "icmp-raw",
	.id		= FM_PROTO_ICMP,
	.require_raw	= true,

	.supported_parameters =
			  FM_PARAM_TYPE_PORT_MASK |	/* we use the port parameter to seq the icmp_id */
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK |
			  FM_FEATURE_STATUS_CALLBACK_MASK,

	.create_socket	= fm_icmp_create_raw_socket,
	.create_host_shared_socket = fm_icmp_create_shared_raw_socket,
	.process_packet	= fm_icmp_process_packet,
	.process_error	= fm_icmp_process_error,
};


FM_PROTOCOL_REGISTER(fm_icmp_bsdsock_ops);
FM_PROTOCOL_REGISTER(fm_icmp_rawsock_ops);

static fm_socket_t *
fm_icmp_create_bsd_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;
	int ipproto;

	/* This should not fail; the caller should have taken care of this check already */
	ipproto = fm_icmp_protocol_for_family(af);
	if (ipproto < 0)
		return NULL;

	sock = fm_socket_create(af, SOCK_DGRAM, ipproto, proto);
	if (sock != NULL) {
		fm_socket_enable_ttl(sock);
		fm_socket_enable_tos(sock);
	}
	return sock;
}

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


static bool
fm_icmp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant = NULL;
	bool ignore_id = false;

	/* When using PF_PACKET sockets, we do receive raw IP packets.
	 * Massage the packet by stripping off the IP header and adjusting
	 * the packet.
	 */
	if (pkt->family == AF_PACKET) {
		fm_ip_header_info_t ip;
		int ifindex = 0;

		/* Pull the IP header. This will also update pkt->family, depending
		 * on the ETH_P_* type */
		if (!fm_raw_packet_pull_ip_hdr(pkt, &ip))
			return false;

		if (pkt->peer_addr.ss_family == AF_PACKET)
			ifindex = ((struct sockaddr_ll *) &pkt->peer_addr)->sll_ifindex;

		if (pkt->family == AF_INET6)
			fm_address_ipv6_update_scope_id(&ip.src_addr, ifindex);

		fm_local_neighbor_cache_update(&ip.src_addr, &pkt->peer_addr);

		pkt->peer_addr = ip.src_addr;
	}

	fm_host_asset_update_state_by_address(&pkt->peer_addr, FM_PROTO_ICMP, FM_ASSET_STATE_OPEN);

	if (proto == &fm_icmp_bsdsock_ops) {
		/* When using dgram/icmp sockets, the kernel will overwrite the icmp sequence
		 * number that we picked. So ignore that in our search for a matching
		 * probe */
		ignore_id = true;
	} else
	if (pkt->family == AF_INET) {
		fm_ip_header_info_t ip;

		/* PF_RAW sockets will always give us the IPv4 header.
		 * Funnily, IPv6 packets always come with the header stripped. */
		if (!fm_raw_packet_pull_ip_hdr(pkt, &ip)) {
			fm_log_debug("%s: bad IP header", proto->name);
			return false;
		}

		if (ip.ipproto != IPPROTO_ICMP)  {
			fm_log_debug("%s: %s -> %s: unexpected protocol %d", __func__,
					fm_address_format(&ip.src_addr),
					fm_address_format(&ip.dst_addr),
					ip.ipproto);
			return false;
		}
	} else
	if (pkt->family == AF_INET6) {
		/* Nothing to be done for now */
	}

	extant = fm_icmp_locate_probe(&pkt->peer_addr, pkt, true, ignore_id);
	if (extant != NULL) {
		/* Mark the probe as successful, and update the RTT estimate */
		fm_extant_received_reply(extant, pkt);

		/* For regular host probes, we could now free the extant.
		 * However, for discovery probes, there will be any number of
		 * responses, and we want to catch them all.
		 * So we just leave the extant untouched.
		 */
		/* fm_extant_free(extant); */
	}

	return true;
}

bool
fm_icmp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	const struct sock_extended_err *ee;
	fm_extant_t *extant = NULL;
	bool ignore_id = false;

	/* fm_print_hexdump(pkt->data, pkt->len); */

	if (proto == &fm_icmp_bsdsock_ops) {
		/* When using dgram/icmp sockets, the kernel will overwrite the icmp sequence
		 * number that we picked. So ignore that in our search for a matching
		 * probe */
		ignore_id = true;
	}

	if ((ee = pkt->info.ee) == NULL)
		return false;

	if (pkt->family == AF_INET && ee->ee_origin == SO_EE_ORIGIN_ICMP) {
		fm_log_debug("%s received ICMP error type %d code %d\n",
				fm_address_format(&pkt->peer_addr),
				ee->ee_type, ee->ee_code);

		/* update asset state right away */
		if (ee->ee_type == ICMP_DEST_UNREACH)
			fm_host_asset_update_state_by_address(&pkt->peer_addr, FM_PROTO_ICMP, FM_ASSET_STATE_CLOSED);
		if (pkt->info.offender != NULL)
			fm_host_asset_update_state_by_address(pkt->info.offender, FM_PROTO_ICMP, FM_ASSET_STATE_OPEN);

		/* The errqueue stuff is a bit non-intuitive at times. When receiving an
		 * ICMP packet, the "from" address is the IP we originally sent the packet
		 * to, and the offender is the address of the host that generated the
		 * ICMP packet. */
		extant = fm_icmp_locate_probe(&pkt->peer_addr, pkt, false, ignore_id);
	}

	if (extant != NULL) {
		/* Mark the probe as failed, and update the RTT estimate */
		fm_extant_received_error(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

/*
 * SOCK_RAW sockets
 */
static fm_socket_t *
fm_icmp_create_raw_socket(fm_protocol_t *proto, int af)
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
	}
	return sock;
}

static fm_socket_t *
fm_icmp_create_shared_raw_socket(fm_protocol_t *proto, fm_target_t *target)
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
fm_icmp_request_t *
fm_icmp_request_alloc_common(fm_protocol_t *proto, int family, const fm_address_t *dst_addr, const fm_probe_params_t *params, const fm_icmp_extra_params_t *extra_params)
{
	static unsigned int global_icmp_seq = 1;
	fm_icmp_request_t *icmp;

	icmp = calloc(1, sizeof(*icmp));
	icmp->proto = proto;
	icmp->params = *params;

	if (extra_params != NULL)
		icmp->extra_params = *extra_params;

	if (icmp->params.retries == 0)
		icmp->params.retries = fm_global.icmp.retries;

	icmp->icmp.ident = 0x5678;

	/* If the TTL parameter is set, this is probably traceroute, and we need to
	 * have a way to match error packets against the actual request.
	 * With SOCK_PACKET, we can actually choose the icmp_id, but with SOCK_RAW,
	 * the kernel will overwrite what we try to send.
	 * Fudge a sequence number that is a combination of retry and ttl.
	 */
	if (icmp->params.ttl != 0)
		icmp->icmp.seq = (icmp->params.ttl << 8);
	else
		icmp->icmp.seq = global_icmp_seq++;

	if (icmp->extra_params.type_name == NULL)
		fm_icmp_extra_params_set_type(&icmp->extra_params, "echo");

	icmp->family = family;
	icmp->host_address = *dst_addr;

	return icmp;
}

static fm_icmp_request_t *
fm_icmp_request_alloc(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const fm_icmp_extra_params_t *extra_params)
{
	const fm_address_t *addr = &target->address;
	fm_icmp_request_t *icmp;

	icmp = fm_icmp_request_alloc_common(proto, addr->ss_family, addr, params, extra_params);
	if (icmp != NULL)
		icmp->target = target;
	return icmp;
}

static fm_icmp_request_t *
fm_icmp_broadcast_request_alloc(fm_protocol_t *proto, int af, const fm_interface_t *nic,
				const fm_address_t *net_src_addr,
				const fm_probe_params_t *params, const fm_icmp_extra_params_t *extra_params)
{
	fm_address_t network_broadcast;
	struct sockaddr_ll lladdr, llbcast;
	fm_icmp_request_t *icmp;
	fm_socket_t *sock;

	/* Note, for IPv6 over ethernet, the get_llbroadcast function will actually return the
	 * all-nodes MAC multicast address 33:33:00:00:00:01.
	 * I wonder what this does for IPv4... */
	if (!fm_interface_get_lladdr(nic, &lladdr)
	 || !fm_interface_get_llbroadcast(nic, &llbcast))
		return NULL;

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

	sock = fm_raw_socket_get((fm_address_t *) &lladdr, proto, SOCK_DGRAM);
	if (sock == NULL)
		return NULL;

	icmp = fm_icmp_request_alloc_common(proto, af, (fm_address_t *) &llbcast, params, extra_params);

	icmp->sock = sock;
	icmp->sock_is_shared = true;

	icmp->packet_header = fm_buffer_alloc(128);
	fm_raw_packet_add_ipv6_header(icmp->packet_header, net_src_addr, &network_broadcast, 
			IPPROTO_ICMPV6, params->ttl, params->tos, 
			sizeof(struct icmp6_hdr));

	assert(icmp->family == AF_INET6);
	icmp->csum_header = fm_ipv6_checksum_header(net_src_addr, &network_broadcast, IPPROTO_ICMPV6);
	icmp->csum_header->checksum.offset = 2;
	icmp->csum_header->checksum.width = 2;

	return icmp;
}

/*
 * Free an existing request
 */
static void
fm_icmp_request_free(fm_icmp_request_t *icmp)
{
	if (icmp->sock != NULL && !icmp->sock_is_shared)
		fm_socket_free(icmp->sock);
	icmp->sock = NULL;

	if (icmp->packet_header != NULL)
		fm_buffer_free(icmp->packet_header);

	free(icmp);
}

/*
 * Set the shared socket (for traceroute)
 */
static void
fm_icmp_request_set_socket(fm_icmp_request_t *icmp, fm_socket_t *sock)
{
	icmp->sock = sock;
	icmp->sock_is_shared = true;
}

/*
 * Do the scheduling
 */
static fm_error_t
fm_icmp_request_schedule(fm_icmp_request_t *icmp, fm_time_t *expires)
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
fm_icmp_request_build_packet(fm_icmp_request_t *icmp, fm_icmp_extant_info_t *extant_info)
{
	fm_pkt_t *pkt = fm_pkt_alloc(icmp->family, 0);
	fm_buffer_t *bp, *raw;

	if ((raw = icmp->packet_header) != NULL) {
		bp = fm_buffer_alloc(16 + fm_buffer_available(raw));
		fm_buffer_append(bp, fm_buffer_head(raw), fm_buffer_available(raw));
	} else {
		bp = fm_buffer_alloc(16);
	}

	pkt->payload = bp;

	pkt->peer_addr = icmp->host_address;
	if (icmp->family == AF_INET) {
		struct icmp *icmph;

		icmph = fm_buffer_push(bp, 8);
		icmph->icmp_type = icmp->extra_params.ipv4.send_type;
		icmph->icmp_code = 0;
		icmph->icmp_cksum = 0;
		icmph->icmp_id = htons(icmp->icmp.ident);
		icmph->icmp_seq = htons(icmp->icmp.seq);

		icmph->icmp_cksum = in_csum(icmph, sizeof(*icmph));

		fm_icmp_request_build_extant_info(extant_info, icmph, 8);
		extant_info->expect_hdr.icmp4.icmp_type = icmp->extra_params.ipv4.response_type;
        } else if (icmp->family == AF_INET6) {
		struct icmp6_hdr *icmph;

		icmph = fm_buffer_push(bp, 8);
		icmph->icmp6_type = icmp->extra_params.ipv6.send_type;
		icmph->icmp6_code = 0;
		icmph->icmp6_cksum = 0;
		icmph->icmp6_id = htons(icmp->icmp.ident);
		icmph->icmp6_seq = htons(icmp->icmp.seq);

		if (icmp->csum_header != NULL
		 && !fm_raw_packet_csum(icmp->csum_header, icmph, 8)) {
			fm_log_fatal("got my wires crossed in the icmpv6 checksum thing");
		}

		fm_icmp_request_build_extant_info(extant_info, icmph, 8);
		extant_info->expect_hdr.icmp6.icmp6_type = icmp->extra_params.ipv6.response_type;
        }

	/* apply ttl, tos etc */
	fm_pkt_apply_probe_params(pkt, &icmp->params, icmp->proto->supported_parameters);

	icmp->icmp.seq += 1;

	return pkt;
}

/*
 * Build the response match
 */
static void
fm_icmp_request_build_extant_info(fm_icmp_extant_info_t *info, const void *raw, size_t len)
{
	if (len > sizeof(info->sent_hdr.raw))
		len = sizeof(info->sent_hdr.raw);
	memcpy(info->sent_hdr.raw, raw, len);
	info->sent_hdr.len = len;

	/* The response we expect is exactly what we sent, just with the response type */
	info->expect_hdr = info->sent_hdr;
}

fm_extant_t *
fm_icmp4_locate_probe(hlist_iterator_t *iter, fm_pkt_t *pkt, bool is_response, bool ignore_id)
{
	const struct icmp *icmph;
	fm_extant_t *extant;

	if (!(icmph = fm_pkt_pull(pkt, sizeof(*icmph))))
		return NULL;

	if (fm_debug_level) {
		fm_log_debug("ICMPv4: message type=%d, code=%d from %s", 
				icmph->icmp_type, icmph->icmp_code,
				fm_address_format(&pkt->peer_addr));
	}

        while ((extant = fm_extant_iterator_match(iter, AF_INET, IPPROTO_ICMP)) != NULL) {
		fm_icmp_extant_info_t *ei = (fm_icmp_extant_info_t *) (extant + 1);
		const struct icmp *match = is_response? &ei->expect_hdr.icmp4 : &ei->sent_hdr.icmp4;

		if (!ignore_id && match->icmp_id != icmph->icmp_id)
			continue;

		if (match->icmp_type == icmph->icmp_type
		 && match->icmp_seq == icmph->icmp_seq)
			return extant;
        }

	return NULL;
}

static fm_extant_t *
fm_icmp6_locate_probe(hlist_iterator_t *iter, fm_pkt_t *pkt, bool is_response, bool ignore_id)
{
	const struct icmp6_hdr *icmph;
	fm_extant_t *extant;

	if (!(icmph = fm_pkt_pull(pkt, sizeof(*icmph))))
		return NULL;

	if (fm_debug_level) {
		fm_log_debug("ICMPv6: message type=%d, code=%d from %s", 
				icmph->icmp6_type, icmph->icmp6_code,
				fm_address_format(&pkt->peer_addr));
	}

        while ((extant = fm_extant_iterator_match(iter, AF_INET6, IPPROTO_ICMPV6)) != NULL) {
		fm_icmp_extant_info_t *ei = (fm_icmp_extant_info_t *) (extant + 1);
		const struct icmp6_hdr *match = is_response? &ei->expect_hdr.icmp6 : &ei->sent_hdr.icmp6;

		if (!ignore_id && match->icmp6_id != icmph->icmp6_id)
			continue;

		if (match->icmp6_type == icmph->icmp6_type
		 && match->icmp6_seq == icmph->icmp6_seq)
			return extant;
        }

	return NULL;
}

static fm_extant_t *
fm_icmp_locate_probe_on_list(fm_extant_list_t *awaiters, fm_pkt_t *pkt, bool is_response, bool ignore_id)
{
	hlist_iterator_t iter;

        fm_extant_iterator_init(&iter, awaiters);
	if (pkt->family == AF_INET)
		return fm_icmp4_locate_probe(&iter, pkt, is_response, ignore_id);
	if (pkt->family == AF_INET6)
		return fm_icmp6_locate_probe(&iter, pkt, is_response, ignore_id);

	return NULL;
}

fm_extant_t *
fm_icmp_locate_probe(const struct sockaddr_storage *target_addr, fm_pkt_t *pkt, bool is_response, bool ignore_id)
{
	fm_target_t *target;

	if (pkt->family != target_addr->ss_family)
		return NULL;

	if (global_extant_list.hlist.first != NULL) {
		fm_extant_t *extant = NULL;

		extant = fm_icmp_locate_probe_on_list(&global_extant_list, pkt, is_response, ignore_id);
		if (extant != NULL)
			return extant;
	}

	target = fm_target_pool_find(target_addr);
	if (target == NULL)
		return NULL;

	return fm_icmp_locate_probe_on_list(&target->expecting, pkt, is_response, ignore_id);
}

/*
 * Send the icmp request.
 * The probe argument is only here because we need to notify it when done.
 */
static fm_error_t
fm_icmp_request_send(fm_icmp_request_t *icmp, fm_icmp_extant_info_t *extant_info)
{
	fm_socket_t *sock;
	fm_pkt_t *pkt;

	if ((sock = icmp->sock) != NULL) {
		/* pass */
	} else if (icmp->target != NULL) {
		/* When using raw sockets, create a single ICMP socket per target host */
		sock = fm_protocol_create_host_shared_socket(icmp->proto, icmp->target);
	}

	if (sock == NULL) {
		icmp->sock = fm_icmp_create_connected_socket(icmp->proto, &icmp->host_address);
		if (icmp->sock == NULL) {
			fm_log_error("Unable to create ICMP socket for %s: %m",
					fm_address_format(&icmp->host_address));
			return FM_SEND_ERROR;
		}

		sock = icmp->sock;
	}

	pkt = fm_icmp_request_build_packet(icmp, extant_info);

	if (!fm_socket_send_pkt_and_burn(sock, pkt)) {
		fm_log_error("Unable to send ICMP packet: %m");
		return FM_SEND_ERROR;
	}

	icmp->params.retries -= 1;

	/* update the asset state */
	if (icmp->target != NULL)
		fm_target_update_host_state(icmp->target, FM_PROTO_ICMP, FM_ASSET_STATE_PROBE_SENT);

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
	fm_icmp_request_t *icmp = fm_icmp_probe_get_request(probe);

	if (icmp == NULL)
		return FM_NOT_SUPPORTED;

	return fm_icmp_request_schedule(icmp, &probe->job.expires);
}


/*
 * Send the probe.
 */
static fm_error_t
fm_icmp_host_probe_send(fm_probe_t *probe)
{
	fm_icmp_request_t *icmp = fm_icmp_probe_get_request(probe);
	fm_icmp_extant_info_t extant_info;
	fm_error_t error;

	error = fm_icmp_request_send(icmp, &extant_info);
	if (error != 0) {
		/* no send, nothing to wait for */
	} else
	if (icmp->target != NULL) {
		fm_extant_alloc(probe, icmp->family, icmp->icmp.ipproto, &extant_info, sizeof(extant_info));
	} else {
		fm_extant_alloc_list(probe, icmp->family, icmp->icmp.ipproto, &extant_info, sizeof(extant_info), &global_extant_list);
	}

	return error;
}

static fm_error_t
fm_icmp_host_probe_set_socket(fm_probe_t *probe, fm_socket_t *sock)
{
	fm_icmp_request_t *icmp = fm_icmp_probe_get_request(probe);

	if (icmp == NULL)
		return FM_NOT_SUPPORTED;

	fm_icmp_request_set_socket(icmp, sock);
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
	fm_icmp_request_t *icmp;
	fm_probe_t *probe;
	char name[32];

	assert(proto && proto->id == FM_PROTO_ICMP);

	icmp = fm_icmp_request_alloc(proto, target, params, extra_params);
	if (icmp == NULL)
		return NULL;

	snprintf(name, sizeof(name), "icmp/%s/%04x", icmp->extra_params.type_name, icmp->icmp.seq);
	probe = fm_probe_alloc(name, &fm_icmp_host_probe_ops, target);

	fm_icmp_probe_set_request(probe, icmp);

	fm_probe_install_status_callback(probe, fm_icmp_host_probe_data_tap, NULL);

	fm_log_debug("Created ICMP socket probe for %s\n", fm_address_format(&icmp->host_address));
	return probe;
}

static struct fm_probe_class fm_icmp_host_probe_class = {
	.name		= "icmp",
	.proto_id	= FM_PROTO_ICMP,
	.modes		= FM_PROBE_MODE_TOPO|FM_PROBE_MODE_HOST,
	.process_extra_parameters = fm_icmp_process_extra_parameters,
	.create_probe	= fm_icmp_create_host_probe,
};

FM_PROBE_CLASS_REGISTER(fm_icmp_host_probe_class)


/*
 * ICMPv6 broadcast probes can be used to discover hosts on the local network
 *
 * FIXME: we may want to send some gratuitous ARP/ND_ADVERT messages before we
 * do the broadcast...
 */
fm_probe_t *
fm_icmp_create_broadcast_probe(fm_protocol_t *proto, int family, const fm_interface_t *nic,
				const fm_address_t *net_src_addr,
				void (*callback)(const fm_address_t *, void *user_data), void *user_data,
				const fm_probe_params_t *params, const void *extra_params)
{
	fm_icmp_request_t *icmp;
	fm_probe_t *probe;
	char name[32];

	fm_log_debug("Creating ICMP broadcast probe for %s, srcaddr=%s",
			fm_interface_get_name(nic), fm_address_format(net_src_addr));

	assert(proto && proto->id == FM_PROTO_ICMP);

	icmp = fm_icmp_broadcast_request_alloc(proto, family, nic, net_src_addr, params, extra_params);
	if (icmp == NULL)
		return NULL;

	snprintf(name, sizeof(name), "icmp-bcast/%s/%04x", icmp->extra_params.type_name, icmp->icmp.seq);
	probe = fm_probe_alloc(name, &fm_icmp_host_probe_ops, NULL);

	fm_icmp_probe_set_request(probe, icmp);

	fm_icmp_host_probe_set_discovery_callback(probe, callback, user_data);

	fm_log_debug("Created ICMP discovery probe for %s\n", fm_interface_get_name(nic));
	return probe;
}
