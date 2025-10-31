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
 * Scanning IP protocols
 */

#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "scanner.h"
#include "protocols.h"
#include "wellknown.h"
#include "target.h" /* for fm_probe_t */
#include "socket.h"
#include "buffer.h"
#include "utils.h"

static fm_socket_t *	fm_ipproto_create_socket(fm_protocol_t *proto, int ipproto);
static bool		fm_ipproto_process_error(fm_protocol_t *proto, fm_pkt_t *pkt);
static fm_probe_t *	fm_ipproto_create_parameterized_probe(fm_protocol_t *, fm_target_t *, const fm_probe_params_t *params, const void *extra_params);

static struct fm_protocol_ops	fm_ipproto_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "ipproto",
	.require_raw	= true,

	.create_socket	= fm_ipproto_create_socket,
	/* We do not expect to receive a response, so no response handler for now */
	.process_error	= fm_ipproto_process_error,

	.create_parameterized_probe = fm_ipproto_create_parameterized_probe,
};

FM_PROTOCOL_REGISTER(fm_ipproto_ops);

static fm_socket_t *
fm_ipproto_create_socket(fm_protocol_t *proto, int ipproto)
{
	return NULL;
}

static fm_socket_t *
fm_rawip_create_socket(fm_protocol_t *proto, const fm_address_t *addr)
{
	fm_address_t lladdr = *addr;
	fm_socket_t *sock;

	if (lladdr.ss_family != AF_PACKET)
		return NULL;

	((struct sockaddr_ll *) &lladdr)->sll_protocol = htons(ETH_P_IP);

	sock = fm_raw_socket_get(&lladdr, proto, SOCK_RAW);
	if (sock == NULL)
		return NULL;

	fm_socket_enable_recverr(sock);

	return sock;
}

/*
 * Track extant IP proto requests.
 * We currently do not track individual packets and their response(s), we just
 * record the fact that we *did* send to a specific port.
 * We do not even distinguish by the source port used on our end.
 */
struct ipproto_extant_info {
	unsigned int		proto;
};

static bool
fm_ipproto_expect_response(fm_probe_t *probe, int af, unsigned int proto)
{
	fm_extant_alloc(probe, af, proto, NULL, 0);
	return true;
}

static fm_extant_t *
fm_ipproto_locate_probe(fm_protocol_t *proto, fm_pkt_t *pkt, fm_asset_state_t state)
{
	fm_target_t *target;
	hlist_iterator_t iter;
	int ipproto;

	ipproto = 5;

	target = fm_target_pool_find(&pkt->peer_addr);
	if (target == NULL)
		return NULL;

	fm_target_update_host_state(target, FM_PROTO_IP, state);

	fm_extant_iterator_init(&iter, &target->expecting);
	return fm_extant_iterator_match(&iter, pkt->family, ipproto);
}

static bool
fm_ipproto_process_error(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant;

	extant = fm_ipproto_locate_probe(proto, pkt, FM_ASSET_STATE_CLOSED);
	if (extant != NULL) {
		fm_extant_received_error(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

/*
 * ipproto probes
 */
struct fm_ipproto_port_probe {
	fm_probe_t	base;

	fm_socket_t *	sock;
	unsigned int	send_retries;

	fm_ip_info_t	ip;
	fm_routing_info_t rtinfo;
};

static void
fm_ipproto_port_probe_destroy(fm_probe_t *probe)
{
	struct fm_ipproto_port_probe *ipproto = (struct fm_ipproto_port_probe *) probe;

	if (ipproto->sock != NULL) {
		fm_socket_free(ipproto->sock);
		ipproto->sock = NULL;
	}
}

/* this should live elsewhere */
bool
fm_raw_packet_add_link_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr)
{
	const struct sockaddr_ll *src_lladdr, *dst_lladdr;
	bool ok = false;

	if (!(src_lladdr = fm_address_to_link_const(src_addr))) {
		fm_log_error("%s: invalid source address", __func__);
	} else
	if (!(dst_lladdr = fm_address_to_link_const(dst_addr))) {
		fm_log_error("%s: invalid dest address", __func__);
	} else
	if (dst_lladdr->sll_ifindex != src_lladdr->sll_ifindex) {
		fm_log_error("%s: incompatible nic", __func__);
	} else
	if (dst_lladdr->sll_hatype != src_lladdr->sll_hatype) {
		fm_log_error("%s: incompatible link layer protocol", __func__);
	} else {
		ok = true;
	}

	if (!ok)
		return false;

	fm_log_debug("%s: hatype=%u", __func__, dst_lladdr->sll_hatype);
	if (dst_lladdr->sll_hatype == ARPHRD_ETHER) {
		unsigned char *eth = fm_buffer_push(bp, 2 * ETH_ALEN + 2);
		uint16_t eth_proto = htons(ETH_P_IP);

		memcpy(eth, src_lladdr->sll_addr, ETH_ALEN);
		memcpy(eth + ETH_ALEN, dst_lladdr->sll_addr, ETH_ALEN);
		memcpy(eth + 2 * ETH_ALEN, &eth_proto, 2);
	}

	return true;
}

/* this should live elsewhere */
bool
fm_raw_packet_add_ipv4_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
				int ipproto, unsigned int ttl, unsigned int tos,
				unsigned int transport_len)
{
	const struct sockaddr_in *src_inaddr, *dst_inaddr;
	struct iphdr *ip;
	bool ok = false;

	if (!(src_inaddr = fm_address_to_ipv4_const(src_addr))) {
		fm_log_error("%s: invalid source address", __func__);
	} else
	if (!(dst_inaddr = fm_address_to_ipv4_const(dst_addr))) {
		fm_log_error("%s: invalid dest address", __func__);
	} else {
		ok = true;
	}

	if (!ok)
		return false;

	ip = fm_buffer_push(bp, sizeof(*ip));
	memset(ip, 0, sizeof(*ip));

	ip->version = 4;
	ip->ihl = 5;
	ip->protocol = ipproto;
	ip->ttl = ttl;
	ip->tos = tos;
	ip->frag_off = htons(IP_DF);
	ip->tot_len = htons(sizeof(*ip) + transport_len);

	ip->saddr = src_inaddr->sin_addr.s_addr;
	ip->daddr = dst_inaddr->sin_addr.s_addr;

	ip->check = in_csum(ip, sizeof(*ip));

	return true;
}

bool
fm_raw_packet_add_network_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
				int ipproto, unsigned int ttl, unsigned int tos,
				unsigned int transport_len)
{
	if (src_addr->ss_family != dst_addr->ss_family) {
		fm_log_error("%s: incompatible network protocols", __func__);
		return false;
	}

	if (dst_addr->ss_family == AF_INET)
		return fm_raw_packet_add_ipv4_header(bp, src_addr, dst_addr, ipproto, ttl, tos, transport_len);

#ifdef notyet
	if (dst_addr->ss_family == AF_INET6)
		return fm_raw_packet_add_ipv6_header(bp, src_addr, dst_addr, ipproto, ttl, tos, transport_len);
#endif

	fm_log_error("%s: unsupported network protocol %u", __func__, dst_addr->ss_family);
	return false;
}

static fm_buffer_t *
fm_ipproto_build_proto_probe(fm_routing_info_t *rtinfo, int ipproto)
{
	fm_buffer_t *bp;

	if (rtinfo->dst.network_address.ss_family != AF_INET)
		return NULL;

	/* should be plenty */
	bp = fm_buffer_alloc(1500);

	if (!fm_raw_packet_add_link_header(bp, &rtinfo->src.link_address, &rtinfo->nh.link_address)
	 || !fm_raw_packet_add_network_header(bp, &rtinfo->src.network_address, &rtinfo->nh.network_address,
		 	ipproto, 64, 0,
			44)) {
		fm_buffer_free(bp);
		return NULL;
	}

	/* put random trash into payload, we don't care */
	memset(fm_buffer_push(bp, 44), 0, 44);

	return bp;
}

static fm_error_t
fm_ipproto_port_probe_send(fm_probe_t *probe)
{
	struct fm_ipproto_port_probe *ipprobe = (struct fm_ipproto_port_probe *) probe;
	fm_routing_info_t *rtinfo = &ipprobe->rtinfo;
	fm_ip_info_t *ip = &ipprobe->ip;
	fm_socket_t *sock;
	fm_buffer_t *bp;

	if (rtinfo->nh.link_address.ss_family == AF_UNSPEC) {
		fm_log_error("%s: neighbor discovery failed",
				fm_address_format(&ip->dst_addr));
		return FM_SEND_ERROR;
	}

	sock = fm_rawip_create_socket(probe->proto, &rtinfo->nh.link_address);
	if (sock == NULL) {
		fm_log_error("Unable to create packet socket for %s: %m",
				fm_address_format(&ip->dst_addr));
		return FM_SEND_ERROR;
	}

	if (!(bp = fm_ipproto_build_proto_probe(rtinfo, ip->ipproto))) {
		fm_log_error("Unable to build IP proto probe");
		return FM_SEND_ERROR;
	}

	if (fm_debug_level) {
		struct sockaddr_ll *lladdr = fm_address_to_link(&rtinfo->nh.link_address);
		const fm_interface_t *nic;

		assert(lladdr != NULL);
		nic = fm_interface_by_index(lladdr->sll_ifindex);
		fm_log_debug("About to send raw packet via %s", fm_interface_get_name(nic));
		fm_print_hexdump(bp->data, bp->wpos);
	}

	if (!fm_socket_send(sock, &rtinfo->nh.link_address, bp->data, bp->wpos)) {
		fm_log_error("Unable to send IP proto probe: %m");
		return FM_SEND_ERROR;
	}

	fm_ipproto_expect_response(probe, rtinfo->dst.network_address.ss_family, ip->ipproto);

	/* update the asset state */
	fm_target_update_host_state(probe->target, FM_PROTO_IP, FM_ASSET_STATE_PROBE_SENT);

	ipprobe->send_retries -= 1;

	return 0;
}

/*
 * This is called when we time out.
 * We record the port as HEISENBERG
 */
static fm_error_t
fm_ipproto_port_probe_schedule(fm_probe_t *probe)
{
	struct fm_ipproto_port_probe *ipproto = (struct fm_ipproto_port_probe *) probe;

	if (ipproto->send_retries == 0)
		return FM_TIMED_OUT;

	fm_timestamp_set_timeout(&probe->expires, 1000);
	return false;
}

/*
 * Event handling callback
 */
static bool
fm_ipproto_event_handler(fm_probe_t *probe, fm_event_t event)
{
	struct fm_ipproto_port_probe *ipproto = (struct fm_ipproto_port_probe *) probe;

	if (event != FM_EVENT_ID_NEIGHBOR_CACHE)
		return false;

	/* This does not do another full routing lookup, it just checks
	 * whether the neighbor discovery completed.
	 * NB, discovery may have failed, and we need to check for that in
	 * the send() function.
	 */
	return fm_routing_lookup_complete(&ipproto->rtinfo);
}

static struct fm_probe_ops fm_ipproto_port_probe_ops = {
	.obj_size	= sizeof(struct fm_ipproto_port_probe),
	.name 		= "ipproto",

	.destroy	= fm_ipproto_port_probe_destroy,
	.send		= fm_ipproto_port_probe_send,
	.schedule	= fm_ipproto_port_probe_schedule,
};

static fm_probe_t *
fm_ipproto_create_parameterized_probe(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	struct fm_ipproto_port_probe *probe;
	fm_routing_info_t rtinfo;
	fm_event_t wait_event = FM_EVENT_ID_NONE;
	unsigned int ipproto = params->port;
	char name[32];

	if (target->address.ss_family != AF_INET) {
		fm_log_error("Cannot implement %s probe for %s: not supported",
				proto->ops->name, fm_address_format(&target->address));
		return NULL;
	}

	memset(&rtinfo, 0, sizeof(rtinfo));

	rtinfo.dst.network_address = target->address;
	if (!fm_routing_lookup(&rtinfo))
		return NULL;

	if (rtinfo.incomplete_neighbor_entry) {
		if (!fm_neighbor_initiate_discovery(rtinfo.incomplete_neighbor_entry)) {
			fm_log_error("%s: neighbor discovery failed", fm_address_format(&target->address));
			return NULL;
		}
		wait_event = FM_EVENT_ID_NEIGHBOR_CACHE;
	}

	snprintf(name, sizeof(name), "ipproto/%u", ipproto);

	probe = (struct fm_ipproto_port_probe *) fm_probe_alloc(name, &fm_ipproto_port_probe_ops, proto, target);

	probe->rtinfo = rtinfo;

	probe->ip.src_addr = target->local_bind_address;
	probe->ip.dst_addr = target->address;
	probe->ip.ipproto = ipproto;
	probe->send_retries = 3;

	probe->sock = NULL;

	fm_log_debug("Created IP proto probe for %s/proto %u\n", fm_address_format(&target->address), ipproto);

	if (wait_event != FM_EVENT_ID_NONE)
		fm_probe_wait_for_event(&probe->base, fm_ipproto_event_handler, wait_event);

	return &probe->base;
}

