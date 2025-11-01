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
#include <netinet/tcp.h>
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

/*
 * Perform TCP checksum
 */
static bool
fm_raw_packet_tcp_checksum(const fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr, struct tcphdr *th)
{
	fm_buffer_t *csum = fm_buffer_alloc(128);
	unsigned int len = th->th_off << 2;

	if (src_addr->ss_family == AF_INET && dst_addr->ss_family == AF_INET) {
		if (!fm_buffer_append(csum, &((struct sockaddr_in *) src_addr)->sin_addr, 4)
		 || !fm_buffer_append(csum, &((struct sockaddr_in *) dst_addr)->sin_addr, 4))
			goto failed;
	} else
	if (src_addr->ss_family == AF_INET6 && dst_addr->ss_family == AF_INET6) {
		if (!fm_buffer_append(csum, &((struct sockaddr_in6 *) src_addr)->sin6_addr, 16)
		 || !fm_buffer_append(csum, &((struct sockaddr_in6 *) dst_addr)->sin6_addr, 16))
			goto failed;
	}

	if (!fm_buffer_put16(csum, htons(len))
	 || !fm_buffer_put16(csum, htons(IPPROTO_TCP))
	 || !fm_buffer_append(csum, th, len))
		goto failed;

	th->th_sum = in_csum(fm_buffer_head(csum), fm_buffer_available(csum));
	fm_buffer_free(csum);

	return true;

failed:
	fm_buffer_free(csum);
	return false;
}

/*
 * Add TCP header to packet
 */
bool
fm_raw_packet_add_tcp_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
					fm_tcp_header_info_t *tcp_info, unsigned int payload_len)
{
	struct tcphdr *th;
	uint16_t window;
	unsigned int len;

	if (src_addr->ss_family == AF_INET && dst_addr->ss_family == AF_INET) {
		tcp_info->src_port = ((struct sockaddr_in *) src_addr)->sin_port;
		tcp_info->dst_port = ((struct sockaddr_in *) dst_addr)->sin_port;
	} else
	if (src_addr->ss_family == AF_INET6 && dst_addr->ss_family == AF_INET6) {
		tcp_info->src_port = ((struct sockaddr_in6 *) src_addr)->sin6_port;
		tcp_info->dst_port = ((struct sockaddr_in6 *) dst_addr)->sin6_port;
	} else
		return false;

	th = fm_buffer_push(bp, sizeof(*th));
	memset(th, 0, sizeof(*th));

	th->th_sport = tcp_info->src_port;
	th->th_dport = tcp_info->dst_port;

	th->th_seq = tcp_info->seq;
	th->th_ack = tcp_info->ack_seq;
	th->th_flags = tcp_info->flags;

	window = tcp_info->window;
	if (window == 0)
		window = tcp_info->mss? : tcp_info->mtu;
	if (window == 0)
		window = 6000;
	th->th_win = htons(window);

	/* Maybe add a couple of TCP options here */

	/* Set the length */
	len = fm_buffer_len(bp, th);
	if (len & 3)
		return false;

	th->th_off = len >> 2;
	th->th_sum = 0;

	/* Then do the checksum */
	fm_raw_packet_tcp_checksum(bp, src_addr, dst_addr, th);

	return true;
}

bool
fm_raw_packet_pull_tcp_header(fm_buffer_t *bp, fm_tcp_header_info_t *tcp_info)
{
	struct tcphdr *th;

	if (!(th = fm_buffer_peek(bp, sizeof(*th))))
		return false;

	if (!fm_buffer_pull(bp, th->th_off << 2))
		return false;

	tcp_info->src_port = ntohs(th->th_sport);
	tcp_info->dst_port = ntohs(th->th_dport);
	tcp_info->seq = th->th_seq;
	tcp_info->ack_seq = th->th_ack;
	tcp_info->flags = th->th_flags;
	tcp_info->window = htons(th->th_win);

	return true;
}
