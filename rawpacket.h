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

#ifndef FREEMAP_RAWPACKET_H
#define FREEMAP_RAWPACKET_H

#include <stdint.h>
#include "freemap.h"

typedef struct fm_tcp_header_info {
	unsigned char		flags;
	uint32_t		seq;
	uint32_t		ack_seq;
	uint32_t		window;
	uint16_t		mss;
	uint16_t		mtu;

	bool			opt_maxseg,
				opt_timestamps,
				opt_sack,
				opt_wscale;

	/* internal use only: */
	uint16_t		src_port;
	uint16_t		dst_port;

} fm_tcp_header_info_t;

extern bool		fm_raw_packet_add_link_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr);
extern bool		fm_raw_packet_add_ipv4_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
					int ipproto, unsigned int ttl, unsigned int tos,
					unsigned int transport_len);
extern bool		fm_raw_packet_add_network_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
					int ipproto, unsigned int ttl, unsigned int tos,
					unsigned int transport_len);
extern bool		fm_raw_packet_add_tcp_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
					fm_tcp_header_info_t *, unsigned int payload_len);
extern bool		fm_raw_packet_pull_tcp_header(fm_buffer_t *bp, fm_tcp_header_info_t *tcp);


static inline uint16_t
in_csum(const void *data, size_t noctets)
{
        const uint16_t *p = (const uint16_t *) data;
        size_t nwords = noctets / 2;
        uint32_t csum = 0;
        uint16_t res;

        while (nwords--)
		csum += *p++;

        if (noctets & 0x1)
		csum += htons (*((unsigned char *) p) << 8);

        csum = (csum >> 16) + (csum & 0xffff);
        csum += (csum >> 16);

        res = ~csum;
        if (!res)
		res = ~0;

        return res;
}


#endif /* FREEMAP_RAWPACKET_H */
