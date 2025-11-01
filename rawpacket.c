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

#include "rawpacket.h"
#include "addresses.h"
#include "buffer.h"
#include "utils.h"


/*
 * Add link-level header to raw packet
 */
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

/*
 * Add IPv4 header to raw packet
 */
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

/*
 * Add network header to packet
 */
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

