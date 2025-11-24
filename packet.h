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

#ifndef FREEMAP_PACKET_H
#define FREEMAP_PACKET_H

#include <stdint.h>
#include "freemap.h"

#define FM_PARSED_PACKET_MAX_PROTOS 8

struct fm_parsed_hdr;

typedef const struct fm_protocol_handler {
	int			proto_id;
	unsigned int		recv_alloc;
	void			(*display)(const fm_pkt_t *, const struct fm_parsed_hdr *);
	bool			(*dissect)(fm_pkt_t *, struct fm_parsed_hdr *, unsigned int *);
} fm_protocol_handler_t;

typedef struct fm_packet_parser {
	unsigned int		recv_alloc;

	unsigned int		num_handlers;
	fm_protocol_handler_t *	handler[FM_PARSED_PACKET_MAX_PROTOS];
} fm_packet_parser_t;

extern fm_packet_parser_t *	fm_packet_parser_alloc(void);
extern bool			fm_packet_parser_add_layer(fm_packet_parser_t *, int proto_id);
extern fm_pkt_t *		fm_packet_parser_allocate(const fm_packet_parser_t *, int, unsigned int);
extern fm_parsed_pkt_t *	fm_packet_parser_inspect(fm_packet_parser_t *, fm_pkt_t *);
extern fm_parsed_pkt_t *	fm_packet_parser_inspect_any(fm_pkt_t *pkt, unsigned int next_proto);
extern fm_parsed_pkt_t *	fm_packet_synthetic_parse(fm_packet_parser_t *parser, fm_pkt_t *pkt);
extern struct fm_parsed_hdr *	fm_parsed_packet_find_next(fm_parsed_pkt_t *, unsigned int proto_id);
extern struct fm_parsed_hdr *	fm_parsed_packet_next_header(fm_parsed_pkt_t *);

#endif /* FREEMAP_PACKET_H */
