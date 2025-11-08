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
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "packet.h"
#include "rawpacket.h"
#include "buffer.h"

#undef FM_DEBUG_PACKET_PARSER

#define INFO_ALIGN(size)	(((size) + 7) & ~7)
#define COMMON_SIZE		offsetof(fm_parsed_hdr_t, data)
#define INFO_SIZE(member)	INFO_ALIGN(COMMON_SIZE + sizeof(((fm_parsed_hdr_t *) 0)->member))

static bool			fm_proto_ip_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);
static bool			fm_proto_arp_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);
static bool			fm_proto_icmp_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);
static bool			fm_proto_tcp_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);
static bool			fm_proto_udp_dissect(fm_pkt_t *, fm_parsed_hdr_t *, unsigned int *);

static fm_protocol_handler_t	fm_protocol_handlers[] = {
	{ FM_PROTO_IP,		INFO_SIZE(ip),		NULL,	fm_proto_ip_dissect	},
	{ FM_PROTO_IPV6,	INFO_SIZE(ip),		NULL,	fm_proto_ip_dissect	},
	{ FM_PROTO_ARP,		INFO_SIZE(arp),		NULL,	fm_proto_arp_dissect	},
	{ FM_PROTO_TCP,		INFO_SIZE(tcp),		NULL,	fm_proto_tcp_dissect	},
	{ FM_PROTO_UDP,		INFO_SIZE(udp),		NULL,	fm_proto_udp_dissect	},
	{ FM_PROTO_ICMP,	INFO_SIZE(icmp),	NULL,	fm_proto_icmp_dissect	},
	{ FM_PROTO_NONE }
};

#ifdef FM_DEBUG_PACKET_PARSER
# define debugmsg	fm_log_debug
#else
# define debugmsg(fmt ...) do { } while (0)
#endif

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
	}

	pkt->num_headers = k;
	return pkt;
}

void
fm_parsed_pkt_free(fm_parsed_pkt_t *cooked)
{
	free(cooked);
}

fm_parsed_pkt_t *
fm_packet_parser_inspect(fm_packet_parser_t *parser, fm_pkt_t *pkt)
{
	fm_parsed_pkt_t *cooked;
	unsigned int k, next_proto;

	assert(parser->num_handlers);

#ifdef FM_DEBUG_PACKET_PARSER
	fm_buffer_dump(pkt->payload, __func__);
#endif

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

		if (!h->dissect(pkt, cooked->headers[k], &next_proto))
			goto trash;

		debugmsg("  parsed %s header, next proto %s",
				fm_protocol_id_to_string(h->proto_id),
				fm_protocol_id_to_string(next_proto));
	}

	pkt->parsed = cooked;
	debugmsg("success.");
	return cooked;

trash:
	debugmsg("failed.");
	free(cooked);
	return NULL;
}

fm_parsed_hdr_t *
fm_parsed_packet_find_next(fm_parsed_pkt_t *cooked, unsigned int proto_id)
{
	unsigned int k = cooked->next_header;

	/* The IP header parsing code handles both v4 and v6 transparently,
	 * so we map both to the same proto id. */
	if (proto_id == FM_PROTO_IPV6)
		proto_id = FM_PROTO_IP;

	while (k < cooked->num_headers) {
		fm_parsed_hdr_t *hdr = cooked->headers[k++];

		if (hdr->proto_id == proto_id) {
			cooked->next_header = k;
			return hdr;
		}
	}

	return NULL;
}

bool
fm_proto_ip_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (!fm_raw_packet_pull_ip_hdr(pkt, &hdr->ip))
		return false;

	*next_proto = hdr->ip.ipproto;
	return true;
}

bool
fm_proto_arp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (!fm_raw_packet_pull_arp_header(pkt->payload, &hdr->arp))
		return false;

	*next_proto = FM_PROTO_NONE;
	return true;
}

bool
fm_proto_tcp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (!fm_raw_packet_pull_tcp_header(pkt->payload, &hdr->tcp))
		return false;

	*next_proto = FM_PROTO_NONE;
	return true;
}

bool
fm_proto_udp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (!fm_raw_packet_pull_udp_header(pkt->payload, &hdr->udp))
		return false;

	*next_proto = FM_PROTO_NONE;
	return true;
}

bool
fm_proto_icmp_dissect(fm_pkt_t *pkt, fm_parsed_hdr_t *hdr, unsigned int *next_proto)
{
	if (!fm_raw_packet_pull_icmp_header(pkt->payload, &hdr->icmp))
		return false;

	/* If it's an error code, this will be followed by an IP packet */

	*next_proto = FM_PROTO_NONE;
	return true;
}
