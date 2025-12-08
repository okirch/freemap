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
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "rawpacket.h"
#include "addresses.h"
#include "buffer.h"
#include "logging.h"
#include "utils.h"


/*
 * This is called when we prepare the target_control data when adding
 * a new target to a probe.
 */
void
fm_ip_header_info_apply_defaults(fm_ip_header_info_t *ip, int family)
{
	if (ip->ttl == 0) {
		if (family == AF_INET)
			ip->ttl = fm_global.ipv4.ttl;
		else if (family == AF_INET6)
			ip->ttl = fm_global.ipv6.ttl;
	}
	if (ip->tos == 0) {
		if (family == AF_INET)
			ip->tos = fm_global.ipv4.tos;
		else if (family == AF_INET6)
			ip->tos = fm_global.ipv6.tos;
	}
}

/* These functions can be used to apply parameters before sending a packet.
 * If the parameter is applicable, returns a pointer to a local (static) copy with the parameter applied.
 * If the parameter is not applicable, just returns the pointer that was passed in.
 */
const fm_ip_header_info_t *
fm_ip_header_info_finalize(const fm_ip_header_info_t *ip, int param_type, int param_value)
{
	static fm_ip_header_info_t copy;

	if (param_type == FM_PARAM_TYPE_TTL) {
		copy = *ip;
		copy.ttl = param_value;
		return &copy;
	}
	if (param_type == FM_PARAM_TYPE_TOS) {
		copy = *ip;
		copy.tos = param_value;
		return &copy;
	}

	return ip;
}

const fm_tcp_header_info_t *
fm_tcp_header_info_finalize(const fm_tcp_header_info_t *tcp, int param_type, int param_value)
{
	static fm_tcp_header_info_t copy;

	if (param_type == FM_PARAM_TYPE_PORT) {
		copy = *tcp;
		copy.dst_port = param_value;
		return &copy;
	}

	return tcp;
}

unsigned int
fm_tcp_compute_len(const fm_tcp_header_info_t *tcp)
{
	/* We don't do any TCP options yet, so it'll be just 20 bytes for the standard 
	 * header + the payload */
	return 20 + tcp->payload.len;
}

unsigned int
fm_ip_compute_len(const fm_ip_header_info_t *ip)
{
	if (ip->dst_addr.family == AF_INET)
		return 20; /* no options yet */

	if (ip->dst_addr.family == AF_INET6)
		return 40; /* option headers yet */

	fm_log_fatal("%s: bad address family", __func__);
	return 1024;
}

const fm_udp_header_info_t *
fm_udp_header_info_finalize(const fm_udp_header_info_t *udp, int param_type, int param_value, const fm_buffer_t *payload)
{
	static fm_udp_header_info_t copy;

	copy = *udp;

	if (payload) {
		copy.payload.len = fm_buffer_available(payload);
		copy.payload.data = fm_buffer_head(payload);
	}

	if (param_type == FM_PARAM_TYPE_PORT)
		copy.dst_port = param_value;

	return &copy;
}

fm_icmp_header_info_t *
fm_icmp_header_info_finalize(const fm_icmp_header_info_t *icmp, int param_type, int param_value, const fm_buffer_t *payload)
{
	static fm_icmp_header_info_t copy;

	copy = *icmp;

	if (payload) {
		copy.payload.len = fm_buffer_available(payload);
		copy.payload.data = fm_buffer_head(payload);
	}

	return &copy;
}

unsigned int
fm_udp_compute_len(const fm_udp_header_info_t *udp)
{
	return 8 + udp->payload.len;
}

unsigned int
fm_icmp_compute_len(const fm_icmp_header_info_t *icmp)
{
	return 8 + icmp->payload.len;
}

/*
 * Process extra args at protocol level
 */
bool
fm_ip_process_config_arg(fm_ip_header_info_t *ip, const char *arg)
{
	if (fm_parse_numeric_argument(arg, "ip-ttl", &ip->ttl)
	 || fm_parse_numeric_argument(arg, "ip-tos", &ip->tos))
		return true;
	return false;
}

bool
fm_tcp_process_config_arg(fm_tcp_header_info_t *tcp, const char *arg)
{
	unsigned int nvalue;

	if (fm_parse_numeric_argument(arg, "tcp-dst-port", &nvalue)) {
		tcp->dst_port = nvalue;
		return true;
	}

	if (fm_parse_numeric_argument(arg, "tcp-mss", &nvalue)) {
		tcp->mss = nvalue;
		return true;
	}

	if (!strncmp(arg, "tcp-flags=", 10)) {
		char *svalue, *next;
		int flags = 0;

		for (svalue = strdupa(arg + 10); svalue; svalue = next) {
			if ((next = strchr(svalue, ',')) != NULL)
				*next++ = '\0';

			if (!strcmp(svalue, "syn"))
				flags |= TH_SYN;
			else if (!strcmp(svalue, "ack"))
				flags |= TH_ACK;
			else if (!strcmp(svalue, "rst"))
				flags |= TH_RST;
			else if (!strcmp(svalue, "fin"))
				flags |= TH_FIN;
			else if (!strcmp(svalue, "push"))
				flags |= TH_PUSH;
			else if (!strcmp(svalue, "none"))
				flags = 0;
			else
				return false;
		}

		tcp->flags = flags;
		return true;
	}

	if (!strncmp(arg, "tcp-options=", 12)) {
		char *svalue, *next;
		int option_mask = 0;

		for (svalue = strdupa(arg + 12); svalue; svalue = next) {
			if ((next = strchr(svalue, ',')) != NULL)
				*next++ = '\0';

			if (!strcmp(svalue, "maxseg"))
				option_mask |= (1 << TCPOPT_MAXSEG);
			if (!strcmp(svalue, "wscale"))
				option_mask |= (1 << TCPOPT_WINDOW);
			else if (!strcmp(svalue, "sack-permitted"))
				option_mask |= (1 << TCPOPT_SACK_PERMITTED);
			else if (!strcmp(svalue, "timestamp"))
				option_mask |= (1 << TCPOPT_TIMESTAMP);
			else if (!strcmp(svalue, "none"))
				option_mask = 0;
			else
				return false;
		}

		if (option_mask)
			fm_log_warning("TCP: sending of TCP options not yet implemented");

		tcp->option_mask = option_mask;
		return true;
	}

	return false;
}

bool
fm_udp_process_config_arg(fm_udp_header_info_t *udp, const char *arg)
{
	unsigned int port;

	if (fm_parse_numeric_argument(arg, "udp-dst-port", &port)) {
		udp->dst_port = port;
		return true;
	}

	return false;
}

bool
fm_icmp_process_config_arg(fm_icmp_header_info_t *icmp, const char *arg)
{
	unsigned int ival;
	const char  *sval;

	if (fm_parse_numeric_argument(arg, "icmp-id", &ival)) {
		icmp->id = ival;
		return true;
	}

	if (fm_parse_string_argument(arg, "icmp-type", &sval)) {
		fm_icmp_msg_type_t *msg_type;
		char type_name[64];

		snprintf(type_name, sizeof(type_name), "%s-request", sval);
		if ((msg_type = fm_icmp_msg_type_by_name(type_name)) == NULL) {
			fm_log_error("ICMP: cannot configure probe type %s: no ICMP message type called \"%s\"", sval, type_name);
			return false;
		}

		if (!fm_icmp_msg_type_get_reply(msg_type)) {
			fm_log_error("ICMP: cannot configure probe type %s: message type \"%s\" has no corresponding reply type", sval, type_name);
			return false;
		}

		icmp->msg_type = msg_type;
		return true;
	}

	return false;
}

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

	if (ttl == 0)
		ttl = fm_global.ipv4.ttl;
	if (tos == 0)
		tos = fm_global.ipv4.tos;

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
 * Add IPv6 header to raw packet
 */
bool
fm_raw_packet_add_ipv6_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
				int ipproto, unsigned int ttl, unsigned int tos,
				unsigned int transport_len)
{
	const struct sockaddr_in6 *src_inaddr, *dst_inaddr;
	uint32_t flow_label = random() & 0xFFFFF;
	struct ip6_hdr *ip;
	bool ok = false;

	if (!(src_inaddr = fm_address_to_ipv6_const(src_addr))) {
		fm_log_error("%s: invalid source address", __func__);
	} else
	if (!(dst_inaddr = fm_address_to_ipv6_const(dst_addr))) {
		fm_log_error("%s: invalid dest address", __func__);
	} else {
		ok = true;
	}

	if (ttl == 0)
		ttl = fm_global.ipv6.ttl;
	if (tos == 0)
		tos = fm_global.ipv6.tos; /* well, traffic class */

	if (!ok)
		return false;

	ip = fm_buffer_push(bp, sizeof(*ip));
	memset(ip, 0, sizeof(*ip));

	ip->ip6_flow = htonl(0x60000000 | ((tos & 0xFF) << 20) | flow_label);
	ip->ip6_nxt = ipproto;
	ip->ip6_hlim = ttl;
	ip->ip6_plen = htons(transport_len);

	ip->ip6_src = src_inaddr->sin6_addr;
	ip->ip6_dst = dst_inaddr->sin6_addr;

	return true;
}

/*
 * IP header analysis
 */
bool
fm_raw_packet_pull_eth_hdr(fm_pkt_t *pkt, fm_eth_header_info_t *info)
{
	fm_buffer_t *bp = pkt->payload;
	const struct ether_header *eth;

	eth = (const struct ether_header *) fm_buffer_peek(bp, sizeof(struct ether_header));
	if (eth == NULL)
		return false;

	memcpy(&info->dst_addr, &eth->ether_dhost, ETH_ALEN);
	memcpy(&info->src_addr, &eth->ether_shost, ETH_ALEN);
	info->eth_proto = ntohs(eth->ether_type);

	switch (info->eth_proto) {
	case ETHERTYPE_IP:
		info->next_proto = FM_PROTO_IP;
		break;

	case ETHERTYPE_IPV6:
		info->next_proto = FM_PROTO_IPV6;
		break;

	case ETHERTYPE_ARP:
		info->next_proto = FM_PROTO_ARP;
		break;

	default:
		info->next_proto = FM_PROTO_NONE;
		break;
	}

	return true;
}

static bool
fm_raw_packet_pull_ipv4_hdr(fm_buffer_t *bp, fm_ip_header_info_t *info)
{
	const struct iphdr *ip = (const struct iphdr *) fm_buffer_peek(bp, sizeof(struct iphdr));
	unsigned int hlen;

	if (ip == NULL)
		return false;

	hlen = ip->ihl << 2;
	if (hlen < 20 || !fm_buffer_pull(bp, hlen))
		return false;

	if (ip->version != 4)
		return false;

	fm_address_set_ipv4(&info->src_addr, ip->saddr);
	fm_address_set_ipv4(&info->dst_addr, ip->daddr);
	info->ipproto = ip->protocol;
	info->ttl = ip->ttl;

	return true;
}

static bool
fm_raw_packet_pull_ipv6_extension(fm_buffer_t *bp, fm_ip_header_info_t *info)
{
	struct fm_ip_extension_hdr *ext;
	unsigned char *raw;

	if (info->num_ext_headers >= FM_IP_MAX_EXTENSIONS)
		return false;

	switch (info->ipproto) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_DSTOPTS:
	case IPPROTO_MH:
	case 143: /* segment routing */
		break;
	default:
		return false;
	}

	if (!(raw = fm_buffer_peek(bp, 8))
	 || !(raw = fm_buffer_pull(bp, raw[1] + 8)))
		return false;

	ext = &info->ext_header[info->num_ext_headers++];
	ext->ipproto = info->ipproto;
	ext->data = raw + 2;
	ext->len = raw[1] + 8 - 2;

	info->ipproto = raw[0];

	return true;
}

static bool
fm_raw_packet_pull_ipv6_hdr(fm_buffer_t *bp, fm_ip_header_info_t *info)
{
	const struct ip6_hdr *ip = (const struct ip6_hdr *) fm_buffer_pull(bp, sizeof(struct ip6_hdr));

	if (ip == NULL)
		return false;

	if ((ip->ip6_vfc & 0xF0) != 0x60)
		return false;

	/* We do not yet unwrap all those next headers; we expect the transport header to follow
	 * the IPv6 header right away. */
	info->ipproto = ip->ip6_nxt;
	info->ttl = ip->ip6_hops;

	fm_address_set_ipv6(&info->src_addr, &ip->ip6_src);
	fm_address_set_ipv6(&info->dst_addr, &ip->ip6_dst);

	while (fm_raw_packet_pull_ipv6_extension(bp, info))
		;

	return true;
}

bool
fm_raw_packet_pull_ip_hdr(fm_pkt_t *pkt, fm_ip_header_info_t *info)
{
	if (pkt->family == AF_PACKET) {
		const struct sockaddr_ll *sll = (struct sockaddr_ll *) &pkt->peer_addr;

		if (sll->sll_protocol == htons(ETH_P_IP))
			pkt->family = AF_INET;
		else if (sll->sll_protocol == htons(ETH_P_IPV6))
			pkt->family = AF_INET6;
	}

	if (pkt->family == AF_INET)
		return fm_raw_packet_pull_ipv4_hdr(pkt->payload, info);
	if (pkt->family == AF_INET6)
		return fm_raw_packet_pull_ipv6_hdr(pkt->payload, info);

	return false;
}

/*
 * Compute the part of the header checksum that we already know.
 * Since addition is commutative, we can update this partial checksum with the
 * length value at any time.
 */
bool
fm_ipv6_transport_csum_partial(fm_csum_partial_t *cp, const fm_address_t *src_addr, const fm_address_t *dst_addr, unsigned int next_header)
{
	const struct sockaddr_in6 *six;

	cp->value = 0;

	if (!(six = fm_address_to_ipv6_const(src_addr)))
		return false;
	fm_csum_partial_update(cp, &six->sin6_addr, 16);

	if (!(six = fm_address_to_ipv6_const(dst_addr)))
		return false;
	fm_csum_partial_update(cp, &six->sin6_addr, 16);

	fm_csum_partial_u16(cp, next_header);

	return true;
}

bool
fm_ipv4_transport_csum_partial(fm_csum_partial_t *cp, const fm_address_t *src_addr, const fm_address_t *dst_addr, unsigned int next_header)
{
	const struct sockaddr_in *sin;

	cp->value = 0;

	if (!(sin = fm_address_to_ipv4_const(src_addr)))
		return false;
	fm_csum_partial_update(cp, &sin->sin_addr, 4);

	if (!(sin = fm_address_to_ipv4_const(dst_addr)))
		return false;
	fm_csum_partial_update(cp, &sin->sin_addr, 4);

	fm_csum_partial_u16(cp, next_header);

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
	if (src_addr->family != dst_addr->family) {
		fm_log_error("%s: incompatible src/dst address", __func__);
		return false;
	}

	if (dst_addr->family == AF_INET)
		return fm_raw_packet_add_ipv4_header(bp, src_addr, dst_addr, ipproto, ttl, tos, transport_len);

	if (dst_addr->family == AF_INET6)
		return fm_raw_packet_add_ipv6_header(bp, src_addr, dst_addr, ipproto, ttl, tos, transport_len);

	fm_log_error("%s: unsupported network protocol %u", __func__, dst_addr->family);
	return false;
}

bool
fm_raw_packet_add_ip_header(fm_buffer_t *bp, const fm_ip_header_info_t *ip, unsigned int transport_len)
{
	return fm_raw_packet_add_network_header(bp, &ip->src_addr, &ip->dst_addr, ip->ipproto, ip->ttl, ip->tos, transport_len);
}

/*
 * Perform TCP checksum
 */
static bool
fm_raw_packet_tcp_checksum(const fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr, struct tcphdr *th)
{
	fm_csum_partial_t csum = { 0 };
	unsigned int len = th->th_off << 2;

	th->th_sum = 0;

	if (dst_addr->family == AF_INET) {
		if (!fm_ipv4_transport_csum_partial(&csum, src_addr, dst_addr, IPPROTO_TCP))
			return false;
	} else 
	if (dst_addr->family == AF_INET6) {
		if (!fm_ipv6_transport_csum_partial(&csum, src_addr, dst_addr, IPPROTO_TCP))
			return false;
	} else 
		return false;

	fm_csum_partial_u16(&csum, len);
	fm_csum_partial_update(&csum, th, len);

	th->th_sum = fm_csum_fold(&csum);
	return true;
}

/*
 * Perform UDP checksum
 */
static bool
fm_raw_packet_udp_checksum(const fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr, struct udphdr *uh)
{
	fm_csum_partial_t csum = { 0 };
	unsigned int len = ntohs(uh->uh_ulen);

	uh->uh_sum = 0;

	if (dst_addr->family == AF_INET) {
		if (!fm_ipv4_transport_csum_partial(&csum, src_addr, dst_addr, IPPROTO_UDP))
			return false;
	} else 
	if (dst_addr->family == AF_INET6) {
		if (!fm_ipv6_transport_csum_partial(&csum, src_addr, dst_addr, IPPROTO_UDP))
			return false;
	} else 
		return false;

	fm_csum_partial_u16(&csum, len);
	fm_csum_partial_update(&csum, uh, len);

	uh->uh_sum = fm_csum_fold(&csum);
	return true;
}

/*
 * Add TCP header to packet
 */
bool
fm_raw_packet_add_tcp_header(fm_buffer_t *bp, const fm_ip_header_info_t *ip_info, const fm_tcp_header_info_t *tcp_info)
{
	struct tcphdr *th;
	uint16_t window;
	unsigned int len;

	assert(tcp_info->src_port != 0);
	assert(tcp_info->dst_port != 0);

	th = fm_buffer_push(bp, sizeof(*th));
	memset(th, 0, sizeof(*th));

	th->th_sport = htons(tcp_info->src_port);
	th->th_dport = htons(tcp_info->dst_port);

	th->th_seq = tcp_info->seq;
	th->th_ack = (tcp_info->flags & TH_ACK)? tcp_info->ack_seq : 0;
	th->th_flags = tcp_info->flags;

	window = tcp_info->window;
	if (window == 0)
		window = tcp_info->mss? : tcp_info->mtu;
	if (window == 0)
		window = 6000;
	th->th_win = htons(window);

	/* Maybe add a couple of TCP options here */
	if (tcp_info->option_mask) {
		/* TBD */
	}

	/* Add the payload */
	if (tcp_info->payload.len
	 && !fm_buffer_append(bp, tcp_info->payload.data, tcp_info->payload.len))
		return false;

	/* Set the length */
	len = fm_buffer_len(bp, th);
	if (len & 3)
		return false;

	th->th_off = len >> 2;
	th->th_sum = 0;

	/* Then do the checksum */
	fm_raw_packet_tcp_checksum(bp, &ip_info->src_addr, &ip_info->dst_addr, th);

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

/*
 * Add UDP header to packet
 */
bool
fm_raw_packet_add_udp_header(fm_buffer_t *bp, const fm_ip_header_info_t *ip_info,
					const fm_udp_header_info_t *udp_info)
{
	struct udphdr *uh;

	assert(udp_info->src_port != 0);
	assert(udp_info->dst_port != 0);

	uh = fm_buffer_push(bp, sizeof(*uh));
	memset(uh, 0, sizeof(*uh));

	uh->uh_sport = htons(udp_info->src_port);
	uh->uh_dport = htons(udp_info->dst_port);

	uh->uh_ulen = htons(8 + udp_info->payload.len);
	uh->uh_sum = 0;

	if (!fm_buffer_append(bp, udp_info->payload.data, udp_info->payload.len))
		return false;

	/* Then do the checksum */
	fm_raw_packet_udp_checksum(bp, &ip_info->src_addr, &ip_info->dst_addr, uh);

	return true;
}

bool
fm_raw_packet_pull_udp_header(fm_buffer_t *bp, fm_udp_header_info_t *udp_info)
{
	struct udphdr *uh;
	unsigned int len;

	if (!(uh = fm_buffer_pull(bp, sizeof(*uh))))
		return false;

	udp_info->src_port = ntohs(uh->uh_sport);
	udp_info->dst_port = ntohs(uh->uh_dport);

	len = ntohs(uh->uh_ulen);
	fm_buffer_truncate(bp, len);
	return true;
}

/*
 * I don't want to distinguish between v4 and v6 in upper layer code,
 * so what we'll do here is translate ICMPv6 code/type combinations
 * to what resembles them most closely in v4.
 *
 * The list of types is far from complete; this omits source quench and redirect, as well as
 * a zoo of bizarre unreachable codes.
 */
static fm_icmp_msg_type_t	fm_icmp_msg_type[] = {
	{ "net-unreach",	ICMP_DEST_UNREACH, ICMP_NET_UNREACH, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE, .with_error = true },
	{ "host-unreach",	ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADDR, .with_error = true },
	{ "port-unreach",	ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT, .with_error = true },
	{ "proto-unreach",	ICMP_DEST_UNREACH, ICMP_PROT_UNREACH, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_NEXTHEADER, .with_error = true },
	{ "frag-needed",	ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, ICMP6_PACKET_TOO_BIG, -1, .with_error = true },
	{ "ttl-exceeded",	ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, .with_error = true },
	{ "fragtime-exceeded",	ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_REASSEMBLY, .with_error = true },
	{ "param-problem",	ICMP_PARAMETERPROB, 0, ICMP6_PARAM_PROB, 0, .with_error = true },

	/* Order is crucial for the following set of message types. If a msgtype has the .is_request flag set,
	 * we expect the response type to be the one immediately following. */
	{ "echo-request",	ICMP_ECHO, 0, ICMP6_ECHO_REQUEST, 0, .with_seq_id = true, .is_request = true },
	{ "echo-reply",		ICMP_ECHOREPLY, 0, ICMP6_ECHO_REPLY, 0, .with_seq_id = true },
	{ "timestamp-request",	ICMP_TIMESTAMP, 0, -1, 0, .with_seq_id = true, .is_request = true },
	{ "timestamp-reply",	ICMP_TIMESTAMPREPLY, 0, -1, 0, .with_seq_id = true },
	{ "info-request",	ICMP_INFO_REQUEST, 0, -1, 0, .with_seq_id = true, .is_request = true },
	{ "info-reply",		ICMP_INFO_REPLY, 0, -1, 0, .with_seq_id = true },

	{ NULL }
};

static fm_icmp_msg_type_t *
fm_icmp_msg_type_get_v4(unsigned int type, unsigned int code)
{
	fm_icmp_msg_type_t *info;

	for (info = fm_icmp_msg_type; info->desc != NULL; ++info) {
		if (info->v4_type == type && (info->v4_code < 0 || info->v4_code == code))
			return info;
	}

	return NULL;
}

static fm_icmp_msg_type_t *
fm_icmp_msg_type_get_v6(unsigned int type, unsigned int code)
{
	fm_icmp_msg_type_t *info;

	for (info = fm_icmp_msg_type; info->desc != NULL; ++info) {
		if (info->v6_type == type && (info->v6_code < 0 || info->v6_code == code))
			return info;
	}

	return NULL;
}

fm_icmp_msg_type_t *
fm_icmp_msg_type_get_reply(fm_icmp_msg_type_t *req)
{
	if (!req->is_request)
		return NULL;

	/* See comment about ordering in fm_icmp_msg_type[] table above */
	return req + 1;

}

/*
 * This should be used by the icmp probing code to translate strings like "echo" into the corresponding
 * request and reply types. Simply call this function with "foo-request" and "foo-reply" for
 * foo in "echo", "timestamp", etc.
 */
fm_icmp_msg_type_t *
fm_icmp_msg_type_by_name(const char *name)
{
	fm_icmp_msg_type_t *info;

	for (info = fm_icmp_msg_type; info->desc != NULL; ++info) {
		if (!strcmp(info->desc, name))
			return info;
	}
	return NULL;
}

bool
fm_raw_packet_pull_icmp_header(fm_buffer_t *bp, fm_icmp_header_info_t *icmp_info)
{
	struct icmp *ih;

	if (!(ih = fm_buffer_pull(bp, 8)))
		return false;

	icmp_info->type = ih->icmp_type;
	icmp_info->code = ih->icmp_code;

	icmp_info->v4_type = ih->icmp_type;
	icmp_info->v4_code = ih->icmp_code;

	icmp_info->msg_type = fm_icmp_msg_type_get_v4(ih->icmp_type, ih->icmp_code);

	if (icmp_info->msg_type != NULL) {
		icmp_info->include_error_pkt = icmp_info->msg_type->with_error;

		if (icmp_info->msg_type->with_seq_id) {
			icmp_info->seq = ntohs(ih->icmp_seq);
			icmp_info->id = ntohs(ih->icmp_id);
		}
	}

	return true;
}

void
fm_raw_packet_map_icmpv6_codes(fm_icmp_header_info_t *icmp_info, unsigned int type, unsigned int code)
{
	icmp_info->msg_type = fm_icmp_msg_type_get_v6(type, code);
	if (icmp_info->msg_type != NULL) {
		icmp_info->v4_type = icmp_info->msg_type->v4_type;
		icmp_info->v4_code = icmp_info->msg_type->v4_code;
	} else {
		icmp_info->v4_type = 0xFF;
		icmp_info->v4_code = 0xFF;
	}
}

bool
fm_raw_packet_pull_icmpv6_header(fm_buffer_t *bp, fm_icmp_header_info_t *icmp_info)
{
	struct icmp6_hdr *ih;

	if (!(ih = fm_buffer_pull(bp, 8)))
		return false;

	icmp_info->type = ih->icmp6_type;
	icmp_info->code = ih->icmp6_code;

	fm_raw_packet_map_icmpv6_codes(icmp_info, ih->icmp6_type, ih->icmp6_code);

	if (!(ih->icmp6_type & ICMP6_INFOMSG_MASK)) {
		icmp_info->include_error_pkt = true;
	} else {
		icmp_info->seq = ntohs(ih->icmp6_seq);
		icmp_info->id = ntohs(ih->icmp6_id);
	}

	return true;
}

/*
 * Add an ICMP header (IPv4/v6 agnostic)
 */
bool
fm_raw_packet_add_icmp_header(fm_buffer_t *bp, const fm_ip_header_info_t *ip_info, const fm_icmp_header_info_t *icmp_info)
{
	fm_icmp_msg_type_t *msg_type;
	unsigned int hdrlen = 8, datalen = 0;

	if ((msg_type = icmp_info->msg_type) == NULL)
		return false;

	datalen = icmp_info->payload.len;

	if (ip_info->ipproto == IPPROTO_ICMP) {
		struct icmp *icmph;

		icmph = fm_buffer_push(bp, hdrlen);
		icmph->icmp_type = msg_type->v4_type;
		icmph->icmp_code = msg_type->v4_code >= 0? msg_type->v4_code : 0;
		icmph->icmp_cksum = 0;
		if (msg_type->with_seq_id) {
			icmph->icmp_id = htons(icmp_info->id);
			icmph->icmp_seq = htons(icmp_info->seq);
		} else {
			icmph->icmp_id = 0;
			icmph->icmp_seq = 0;
		}

		if (datalen != 0) {
			if (!fm_buffer_append(bp, icmp_info->payload.data, datalen))
				return false;
			hdrlen += datalen;
		}

		icmph->icmp_cksum = in_csum(icmph, hdrlen);
	} else
	if (ip_info->ipproto == IPPROTO_ICMPV6) {
		fm_csum_partial_t csum = { 0 };
		struct icmp6_hdr *icmph;

		icmph = fm_buffer_push(bp, hdrlen);
		icmph->icmp6_type = msg_type->v6_type;
		icmph->icmp6_code = msg_type->v6_code >= 0? msg_type->v6_code : 0;
		icmph->icmp6_cksum = 0;
		if (msg_type->with_seq_id) {
			icmph->icmp6_id = htons(icmp_info->id);
			icmph->icmp6_seq = htons(icmp_info->seq);
		} else {
			icmph->icmp6_id = 0;
			icmph->icmp6_seq = 0;
		}

		if (datalen != 0) {
			if (!fm_buffer_append(bp, icmp_info->payload.data, datalen))
				return false;
			hdrlen += datalen;
		}

		if (!fm_ipv6_transport_csum_partial(&csum, &ip_info->src_addr, &ip_info->dst_addr, IPPROTO_ICMPV6))
			return false;

		/* Add the length field to the IPv6 pseudo header */
		fm_csum_partial_u16(&csum, hdrlen);

		/* Add the ICMP header for checksumming */
		fm_csum_partial_update(&csum, icmph, hdrlen);

		icmph->icmp6_cksum = fm_csum_fold(&csum);
	} else {
		return false;
	}

	return true;
}


/*
 * Check whether an ICMP error marks the resource as unreachable.
 */
bool
fm_icmp_header_is_host_unreachable(const fm_icmp_header_info_t *icmp_info)
{
	if (icmp_info->v4_type != ICMP_DEST_UNREACH
	 || icmp_info->v4_code == ICMP_FRAG_NEEDED)
		return false;

	return true;
}

bool
fm_icmp_header_is_proto_unreachable(const fm_icmp_header_info_t *icmp_info)
{
	if (icmp_info->v4_type != ICMP_DEST_UNREACH
	 || icmp_info->v4_code == ICMP_PROT_UNREACH)
		return false;

	return true;
}

bool
fm_raw_packet_pull_arp_header(fm_buffer_t *bp, fm_arp_header_info_t *arp_info)
{
	struct arphdr *ah;
	unsigned char *addr;

	if (!(ah = fm_buffer_pull(bp, sizeof(*ah))))
		return false;

	arp_info->op = ntohs(ah->ar_op);
	arp_info->hwtype = ntohs(ah->ar_hrd);
	arp_info->nwtype = ntohs(ah->ar_pro);

	if (!(addr = fm_buffer_pull(bp, ah->ar_hln)))
		return false;
	if (ah->ar_hln == ETH_ALEN)
		memcpy(arp_info->src_hwaddr, addr, ETH_ALEN);

	if (!(addr = fm_buffer_pull(bp, ah->ar_pln)))
		return false;
	if (ah->ar_pln == 4)
		memcpy(&arp_info->src_ipaddr, addr, 4);

	if (!(addr = fm_buffer_pull(bp, ah->ar_hln)))
		return false;
	if (ah->ar_hln == ETH_ALEN)
		memcpy(arp_info->dst_hwaddr, addr, ETH_ALEN);

	if (!(addr = fm_buffer_pull(bp, ah->ar_pln)))
		return false;
	if (ah->ar_pln == 4)
		memcpy(&arp_info->dst_ipaddr, addr, 4);

	return true;
}
