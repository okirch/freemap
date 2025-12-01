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
#include <linux/errqueue.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "packet.h"
#include "rawpacket.h"
#include "addresses.h"
#include "logging.h"
#include "buffer.h"

#undef FM_DEBUG_PACKET_PARSER

#define INFO_ALIGN(size)	(((size) + 7) & ~7)
#define COMMON_SIZE		offsetof(fm_parsed_hdr_t, data)
#define INFO_SIZE(member)	INFO_ALIGN(COMMON_SIZE + sizeof(((fm_parsed_hdr_t *) 0)->member))

static bool			fm_proto_eth_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);
static bool			fm_proto_ip_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);
static bool			fm_proto_arp_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);
static bool			fm_proto_icmp_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);
static bool			fm_proto_tcp_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);
static bool			fm_proto_udp_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);

static void			fm_proto_eth_display(const fm_pkt_t *, const fm_parsed_hdr_t *);
static void			fm_proto_arp_display(const fm_pkt_t *, const fm_parsed_hdr_t *);
static void			fm_proto_ip_display(const fm_pkt_t *, const fm_parsed_hdr_t *);
static void			fm_proto_tcp_display(const fm_pkt_t *, const fm_parsed_hdr_t *);
static void			fm_proto_udp_display(const fm_pkt_t *, const fm_parsed_hdr_t *);
static void			fm_proto_icmp_display(const fm_pkt_t *, const fm_parsed_hdr_t *);

static fm_protocol_handler_t	fm_protocol_handlers[] = {
	{ FM_PROTO_IP,		INFO_SIZE(ip),		fm_proto_ip_display,	fm_proto_ip_dissect	},
	{ FM_PROTO_IPV6,	INFO_SIZE(ip),		fm_proto_ip_display,	fm_proto_ip_dissect	},
	{ FM_PROTO_ARP,		INFO_SIZE(arp),		fm_proto_arp_display,	fm_proto_arp_dissect	},
	{ FM_PROTO_TCP,		INFO_SIZE(tcp),		fm_proto_tcp_display,	fm_proto_tcp_dissect	},
	{ FM_PROTO_UDP,		INFO_SIZE(udp),		fm_proto_udp_display,	fm_proto_udp_dissect	},
	{ FM_PROTO_ICMP,	INFO_SIZE(icmp),	fm_proto_icmp_display,	fm_proto_icmp_dissect	},
	{ FM_LINK_PROTO_ETHER,	INFO_SIZE(eth),		fm_proto_eth_display,	fm_proto_eth_dissect	},
	{ FM_PROTO_NONE }
};

#define debugmsg	fm_debug_packet

static fm_protocol_handler_t *
fm_packet_parser_select(int proto_id)
{
	fm_protocol_handler_t *h;

	for (h = fm_protocol_handlers; h->proto_id != FM_PROTO_NONE; h++) {
		if (h->proto_id == proto_id)
			return h;
	}

	return NULL;
}

fm_packet_parser_t *
fm_packet_parser_alloc(void)
{
	fm_packet_parser_t *parser;

	parser = calloc(1, sizeof(*parser));
	return parser;
}

bool
fm_packet_parser_add_layer(fm_packet_parser_t *parser, int proto_id)
{
	fm_protocol_handler_t *h;

	if (parser->num_handlers >= FM_PARSED_PACKET_MAX_PROTOS)
		return false;

	/* The IP header parsing code handles both v4 and v6 transparently,
	 * so we map both to the same proto id. */
	if (proto_id == FM_PROTO_IPV6)
		proto_id = FM_PROTO_IP;

	if (!(h = fm_packet_parser_select(proto_id)))
		return false;

	parser->recv_alloc += h->recv_alloc;
	parser->handler[parser->num_handlers++] = h;
	return true;
}

static fm_parsed_pkt_t *
fm_parsed_pkt_alloc(fm_packet_parser_t *parser)
{
	fm_parsed_pkt_t *pkt;
	unsigned int header_space = parser->recv_alloc, allocated;
	unsigned int k;
	unsigned char *headers;

	pkt = calloc(1, sizeof(*pkt) + header_space);

	headers = (unsigned char *) (pkt + 1);
	allocated = 0;

	for (k = 0; k < parser->num_handlers; ++k) {
		fm_protocol_handler_t *h = parser->handler[k];
		fm_parsed_hdr_t *hdr;

		assert(header_space - allocated >= h->recv_alloc);

		hdr = (fm_parsed_hdr_t *) (headers + allocated);
		hdr->proto_id = h->proto_id;

		pkt->headers[k] = hdr;
		allocated += h->recv_alloc;
	}

	pkt->num_headers = k;
	return pkt;
}

void
fm_parsed_pkt_free(fm_parsed_pkt_t *cooked)
{
	free(cooked);
}

/*
 * Inspect a single protocol layer
 */
static bool
fm_parsed_hdr_inspect(fm_protocol_handler_t *h, fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	fm_buffer_t *payload = pkt->payload;

	hdr->raw.data = fm_buffer_head(payload);
	hdr->raw.tot_len = fm_buffer_available(payload);

	if (!h->dissect(pkt, hdr, next_proto)) {
		debugmsg("  failed to parse %s header (%u bytes)",
				fm_protocol_id_to_string(h->proto_id),
				fm_buffer_available(payload));
		return false;
	}

	hdr->raw.hdr_len = hdr->raw.tot_len - fm_buffer_available(payload);

	if (fm_debug_facilities & FM_DEBUG_FACILITY_PACKET) {
		if (h->display)
			h->display(pkt, hdr);
		else
			debugmsg("  parsed %s header, next proto %s",
					fm_protocol_id_to_string(h->proto_id),
					fm_protocol_id_to_string(*next_proto));
	}

	return true;
}

/*
 * Parse a packet, given an explicit stack of protocols we expect to see.
 * If we see something different, we punt.
 */
fm_parsed_pkt_t *
fm_packet_parser_inspect(fm_packet_parser_t *parser, fm_pkt_t *pkt)
{
	fm_parsed_pkt_t *cooked;
	unsigned int k, next_proto;

	assert(parser->num_handlers);

	/* If debug facility data is enabled, no need to print the packet a second
	 * time. */
	if ((fm_debug_facilities & (FM_DEBUG_FACILITY_PACKET|FM_DEBUG_FACILITY_DATA)) == FM_DEBUG_FACILITY_PACKET
	 && fm_debug_level > 1)
		fm_buffer_dump(pkt->payload, __func__);

	if (!(cooked = fm_parsed_pkt_alloc(parser)))
		return NULL;

	next_proto = parser->handler[0]->proto_id;
	for (k = 0; k < parser->num_handlers; ++k) {
		fm_protocol_handler_t *h = parser->handler[k];

		debugmsg("  about to parse %s header, %u bytes left",
				fm_protocol_id_to_string(h->proto_id),
				fm_buffer_available(pkt->payload));

		if (next_proto != h->proto_id)
			goto trash;

		if (!fm_parsed_hdr_inspect(h, pkt, cooked->headers[k], &next_proto))
			goto trash;
	}

	pkt->parsed = cooked;
	debugmsg("  success.");
	return cooked;

trash:
	debugmsg("  failed.");
	free(cooked);
	return NULL;
}

/*
 * Parse a packet, detecting the next layer as we go.
 */
fm_parsed_pkt_t *
fm_packet_parser_inspect_any(fm_pkt_t *pkt, unsigned int next_proto)
{
	unsigned int header_space, allocated;
	fm_parsed_pkt_t *cooked;
	unsigned char *headers;
	unsigned int k;

	/* Allocate space for at least 5 headers */
	header_space = 5 * sizeof(fm_parsed_hdr_t);

	/* If debug facility data is enabled, no need to print the packet a second
	 * time. */
	if ((fm_debug_facilities & (FM_DEBUG_FACILITY_PACKET|FM_DEBUG_FACILITY_DATA)) == FM_DEBUG_FACILITY_PACKET
	 && fm_debug_level > 1)
		fm_buffer_dump(pkt->payload, __func__);

	cooked = calloc(1, sizeof(*cooked) + header_space);
	headers = (unsigned char *) (cooked + 1);
	allocated = 0;

	for (k = 0; k < FM_PARSED_PACKET_MAX_PROTOS; ++k) {
		fm_protocol_handler_t *h;
		fm_parsed_hdr_t *hdr;

		h = fm_packet_parser_select(next_proto);
		if (h == NULL)
			break;

		if (header_space - allocated < h->recv_alloc)
			break;

		hdr = (fm_parsed_hdr_t *) (headers + allocated);
		hdr->proto_id = next_proto;

		cooked->headers[k] = hdr;
		allocated += h->recv_alloc;

		cooked->num_headers = k + 1;

		if (!fm_parsed_hdr_inspect(h, pkt, cooked->headers[k], &next_proto))
			goto trash;
	}

	pkt->parsed = cooked;
	debugmsg("  success.");
	return cooked;

trash:
	debugmsg("  failed.");
	free(cooked);
	return NULL;
}

fm_parsed_hdr_t *
fm_parsed_packet_find_next(fm_parsed_pkt_t *cooked, unsigned int proto_id)
{
	unsigned int k;

	if (cooked == NULL)
		return NULL;

	/* The IP header parsing code handles both v4 and v6 transparently,
	 * so we map both to the same proto id. */
	if (proto_id == FM_PROTO_IPV6)
		proto_id = FM_PROTO_IP;

	k = cooked->next_header;
	while (k < cooked->num_headers) {
		fm_parsed_hdr_t *hdr = cooked->headers[k++];

		if (hdr->proto_id == proto_id) {
			cooked->next_header = k;
			return hdr;
		}
	}

	return NULL;
}

fm_parsed_hdr_t *
fm_parsed_packet_next_header(fm_parsed_pkt_t *cooked)
{
	unsigned int k = cooked->next_header;

	if (k >= cooked->num_headers)
		return NULL;

	cooked->next_header += 1;
	return cooked->headers[k];
}

bool
fm_proto_eth_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (!fm_raw_packet_pull_eth_hdr(pkt, &hdr->eth))
		return false;

	*next_proto = hdr->eth.next_proto;
	return true;
}

void
fm_proto_eth_display(const fm_pkt_t *pkt, const fm_parsed_hdr_t *hdr)
{
	const fm_eth_header_info_t *info = &hdr->eth;

	fm_log_debug("  eth %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x; next proto=%s",
			info->src_addr[0], info->src_addr[1], info->src_addr[2],
			info->src_addr[3], info->src_addr[4], info->src_addr[5],
			info->dst_addr[0], info->dst_addr[1], info->dst_addr[2],
			info->dst_addr[3], info->dst_addr[4], info->dst_addr[5],
			fm_protocol_id_to_string(info->next_proto));
}

bool
fm_proto_ip_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	/* This will also update pkt->family, depending on the ETH_P_* type */
	if (!fm_raw_packet_pull_ip_hdr(pkt, &hdr->ip))
		return false;

	/* When using PF_PACKET sockets, the addresses on the packet will be an AF_PACKET
	 * address.
	 * Replace these with the IP addrs.
	 */
	if (pkt->peer_addr.family == AF_PACKET) {
		int ifindex = ((struct sockaddr_ll *) &pkt->peer_addr)->sll_ifindex;

		if (pkt->family == AF_INET6)
			fm_address_ipv6_update_scope_id(&hdr->ip.src_addr, ifindex);

		/* Is it efficient to do this all the time? */
		fm_local_neighbor_cache_update(&hdr->ip.src_addr, &pkt->peer_addr);

		pkt->peer_addr = hdr->ip.src_addr;
		pkt->local_addr = hdr->ip.dst_addr;
	}

	switch (hdr->ip.ipproto) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		*next_proto = FM_PROTO_ICMP; break;
	case IPPROTO_TCP:
		*next_proto = FM_PROTO_TCP; break;
	case IPPROTO_UDP:
		*next_proto = FM_PROTO_UDP; break;
	default:
		*next_proto = FM_PROTO_NONE; break;
	}

	return true;
}

void
fm_proto_ip_display(const fm_pkt_t *pkt, const fm_parsed_hdr_t *hdr)
{
	const fm_ip_header_info_t *info = &hdr->ip;
	unsigned int k;

	fm_log_debug("  ip %s -> %s, ttl=%u, next_proto=%s",
			fm_address_format(&info->src_addr),
			fm_address_format(&info->dst_addr),
			info->ttl,
			fm_protocol_id_to_string(info->ipproto));

	for (k = 0; k < info->num_ext_headers; ++k) {
		const struct fm_ip_extension_hdr *ext = &info->ext_header[k];

		fm_log_debug("    ext hdr proto=%d len=%u", ext->ipproto, ext->len);
	}
}

bool
fm_proto_arp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (!fm_raw_packet_pull_arp_header(pkt->payload, &hdr->arp))
		return false;

	*next_proto = FM_PROTO_NONE;
	return true;
}

void
fm_proto_arp_display(const fm_pkt_t *pkg, const fm_parsed_hdr_t *hdr)
{
	const fm_arp_header_info_t *info = &hdr->arp;

	if (info->op == ARPOP_REQUEST)
		fm_log_debug("  arp request: who-has %s tell %s",
				inet_ntoa(info->dst_ipaddr),
				inet_ntoa(info->src_ipaddr));
	else if (info->op == ARPOP_REPLY)
		fm_log_debug("  arp request: %s is at %02x:%02x:%02x:%02x:%02x:%02x",
				inet_ntoa(info->src_ipaddr),
				info->src_hwaddr[0], info->src_hwaddr[1], info->src_hwaddr[2],
				info->src_hwaddr[3], info->src_hwaddr[4], info->src_hwaddr[5]);
	else
		fm_log_debug("  arp message %u: dst=%s src=%s",
				info->op,
				inet_ntoa(info->dst_ipaddr),
				inet_ntoa(info->src_ipaddr));
}

bool
fm_proto_tcp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (!fm_raw_packet_pull_tcp_header(pkt->payload, &hdr->tcp))
		return false;

	*next_proto = FM_PROTO_NONE;
	return true;
}

void
fm_proto_tcp_display(const fm_pkt_t *pkt, const fm_parsed_hdr_t *hdr)
{
	const fm_tcp_header_info_t *info = &hdr->tcp;

	fm_log_debug("  tcp %u -> %u, flags=0x%x", 
			info->src_port, info->dst_port, info->flags);
}

bool
fm_proto_udp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (!fm_raw_packet_pull_udp_header(pkt->payload, &hdr->udp))
		return false;

	*next_proto = FM_PROTO_NONE;
	return true;
}

void
fm_proto_udp_display(const fm_pkt_t *pkt, const fm_parsed_hdr_t *hdr)
{
	const fm_udp_header_info_t *info = &hdr->udp;

	fm_log_debug("  udp %u -> %u", 
			info->src_port, info->dst_port);
}

bool
fm_proto_icmp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (pkt->family == AF_INET) {
		if (!fm_raw_packet_pull_icmp_header(pkt->payload, &hdr->icmp))
			return false;
	} else
	if (pkt->family == AF_INET6) {
		if (!fm_raw_packet_pull_icmpv6_header(pkt->payload, &hdr->icmp))
			return false;
	} else
		return false;

	/* If it's an error code, this will be followed by an IP packet, else nothing
	 */
	if (hdr->icmp.include_error_pkt)
		*next_proto = FM_PROTO_IP;
	else
		*next_proto = FM_PROTO_NONE;

	return true;
}

void
fm_proto_icmp_display(const fm_pkt_t *pkt, const fm_parsed_hdr_t *hdr)
{
	const fm_icmp_header_info_t *info = &hdr->icmp;

	fm_log_debug("  icmp type %u/code %u",
			info->type, info->code);
}

/*
 * "Fake" header handlers that just extract the accessible bits and pieces from
 * data provided by the socket layer.
 */
fm_parsed_pkt_t *
fm_packet_synthetic_parse(fm_packet_parser_t *parser, fm_pkt_t *pkt)
{
	struct sock_extended_err *ee = pkt->info.ee;
	fm_parsed_pkt_t *cooked = fm_parsed_pkt_alloc(parser);
	fm_protocol_handler_t *h;
	fm_parsed_hdr_t *hdr, *iphdr;
	unsigned int layer = 0;

	if (pkt->family != AF_INET && pkt->family != AF_INET6)
		goto trash;

	if (layer >= parser->num_handlers)
		goto done;

	h = parser->handler[layer];
	if (h->proto_id != FM_PROTO_IP)
		goto trash;

	hdr = cooked->headers[layer];
	if (ee != NULL) {
		/* error case */
		if (ee->ee_origin == SO_EE_ORIGIN_ICMP)
			hdr->ip.ipproto = IPPROTO_ICMP;
		else if (ee->ee_origin == SO_EE_ORIGIN_ICMP6)
			hdr->ip.ipproto = IPPROTO_ICMPV6;
		else
			goto trash;

		hdr->ip.dst_addr = pkt->peer_addr;
		hdr->ip.src_addr = *(pkt->info.offender);

		if (++layer >= parser->num_handlers)
			goto done;

		h = parser->handler[layer];
		if (h->proto_id != FM_PROTO_ICMP)
			goto trash;

		hdr = cooked->headers[layer];
		if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
			hdr->icmp.type = ee->ee_type;
			hdr->icmp.code = ee->ee_code;
			hdr->icmp.v4_type = ee->ee_type;
			hdr->icmp.v4_code = ee->ee_code;
		} else
		if (pkt->info.ee->ee_origin == SO_EE_ORIGIN_ICMP6) {
			hdr->icmp.type = ee->ee_type;
			hdr->icmp.code = ee->ee_code;
			fm_raw_packet_map_icmpv6_codes(&hdr->icmp, ee->ee_type, ee->ee_code);
		}

		if (++layer >= parser->num_handlers)
			goto done;
	}

	h = parser->handler[layer];
	if (h->proto_id != FM_PROTO_IP)
		goto trash;

	hdr = cooked->headers[layer];
	hdr->ip.src_addr = pkt->peer_addr;
	hdr->ip.dst_addr = pkt->local_addr;
	hdr->ip.ipproto = 0;
	iphdr = hdr;

	if (++layer >= parser->num_handlers)
		goto done;

	h = parser->handler[layer];
	hdr = cooked->headers[layer];
	if (h->proto_id == FM_PROTO_UDP) {
		iphdr->ip.ipproto = IPPROTO_UDP;

		if (ee == NULL) {
			hdr->udp.src_port = fm_address_get_port(&pkt->peer_addr);
			hdr->udp.dst_port = fm_address_get_port(&pkt->local_addr);
		} else {
			hdr->udp.dst_port = fm_address_get_port(&pkt->peer_addr);
			hdr->udp.src_port = fm_address_get_port(&pkt->local_addr);
		}
	} else
		goto trash;

	if (++layer < parser->num_handlers)
		goto trash;

done:
	pkt->parsed = cooked;
	debugmsg("success.");
	return cooked;

trash:
	free(cooked);
	return NULL;
}

bool
fm_proto_fake_ip_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	hdr->ip.src_addr = pkt->peer_addr;
	hdr->ip.dst_addr = pkt->local_addr;

	/* really nasty */
	hdr->ip.ipproto = (hdr + 1)->proto_id;
	return true;
}

bool
fm_proto_fake_icmp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	struct sock_extended_err *ee;

	if ((ee = pkt->info.ee) == NULL)
		return false;

	if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
		hdr->icmp.type = ee->ee_type;
		hdr->icmp.code = ee->ee_code;
		hdr->icmp.v4_type = ee->ee_type;
		hdr->icmp.v4_code = ee->ee_code;
	} else
	if (pkt->info.ee->ee_origin == SO_EE_ORIGIN_ICMP6) {
		hdr->icmp.type = ee->ee_type;
		hdr->icmp.code = ee->ee_code;
		fm_raw_packet_map_icmpv6_codes(&hdr->icmp, ee->ee_type, ee->ee_code);
	} else
		return false;

	return true;
}

bool
fm_proto_fake_tcp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	return false;
}

bool
fm_proto_fake_udp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	hdr->udp.src_port = fm_address_get_port(&pkt->peer_addr);
	hdr->udp.dst_port = fm_address_get_port(&pkt->local_addr);
	return false;
}

