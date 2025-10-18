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
 */

#ifndef FREEMAP_PROTOCOLS_H
#define FREEMAP_PROTOCOLS_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "freemap.h"
#include "protocols.h"

struct fm_protocol {
	const struct fm_protocol_ops *ops;
};

struct fm_protocol_ops {
	size_t		obj_size;
	const char *	name;

	int		id; /* FM_PROTO_* */

	void		(*destroy)(fm_protocol_t *);

	fm_scan_action_t *(*create_host_probe_action)(fm_protocol_t *, const fm_string_array_t *args);

	fm_socket_t *	(*create_host_shared_socket)(fm_protocol_t *, fm_target_t *);

	fm_socket_t *	(*create_socket)(fm_protocol_t *, int af);
	bool		(*process_packet)(fm_protocol_t *, fm_pkt_t *);
	bool		(*process_error)(fm_protocol_t *, fm_pkt_t *);
	bool		(*connection_established)(fm_protocol_t *, const fm_address_t *);

	fm_probe_t *	(*create_host_probe)(fm_protocol_t *, fm_target_t *, unsigned int retries);
	fm_probe_t *	(*create_port_probe)(fm_protocol_t *, fm_target_t *, uint16_t);
};

struct fm_protocol_engine {
	fm_protocol_t *	icmp;
	fm_protocol_t *	udp;
	fm_protocol_t *	tcp;
};

extern fm_protocol_engine_t *fm_protocol_engine_create_default(void);

/* regular unprivileged socket */
extern fm_protocol_t *	fm_tcp_bsdsock_create(void);
extern fm_protocol_t *	fm_udp_bsdsock_create(void);
extern fm_protocol_t *	fm_icmp_bsdsock_create(void);
extern fm_protocol_t *	fm_icmp_rawsock_create(void);

extern fm_protocol_t *	fm_protocol_create(const struct fm_protocol_ops *ops);
extern fm_socket_t *	fm_protocol_create_socket(fm_protocol_t *, int af);
extern fm_probe_t *	fm_protocol_create_host_probe(fm_protocol_t *, fm_target_t *, unsigned int);
extern fm_probe_t *	fm_protocol_create_port_probe(fm_protocol_t *, fm_target_t *, uint16_t);
extern fm_socket_t *	fm_protocol_create_host_shared_socket(fm_protocol_t *proto, fm_target_t *target);

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

/*
 * Utility functions for packet parsing
 */
static inline const void *
fm_pkt_peek(const fm_pkt_t *pkt, unsigned int wanted)
{
	unsigned int avail = pkt->len - pkt->rpos;

	if (avail < wanted)
		return NULL;
	return pkt->data + pkt->rpos;
}

static inline const void *
fm_pkt_pull(fm_pkt_t *pkt, unsigned int wanted)
{
	const void *p;

	if ((p = fm_pkt_peek(pkt, wanted)) != NULL)
		pkt->rpos += wanted;
	return p;
}

/*
 * IP header information
 */
typedef struct fm_ip_info {
	fm_address_t		src_addr, dst_addr;
	int			ipproto;
} fm_ip_info_t;


extern bool		fm_pkt_pull_ip_hdr(fm_pkt_t *pkt, fm_ip_info_t *info);

#endif /* FREEMAP_PROTOCOLS_H */

