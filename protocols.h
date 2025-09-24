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

struct fm_protocol_engine {
	const struct fm_protocol_ops *ops;
};

struct fm_protocol_ops {
	size_t		obj_size;
	const char *	name;

	void		(*destroy)(fm_protocol_engine_t *);
	fm_probe_t *	(*create_host_probe)(fm_protocol_engine_t *, fm_target_t *, unsigned int retries);
	fm_probe_t *	(*create_port_probe)(fm_protocol_engine_t *, fm_target_t *, uint16_t);
};

extern fm_protocol_engine_t *fm_protocol_engine_create(const struct fm_protocol_ops *ops);
extern fm_probe_t *	fm_protocol_engine_create_host_probe(fm_protocol_engine_t *, fm_target_t *, unsigned int);
extern fm_probe_t *	fm_protocol_engine_create_port_probe(fm_protocol_engine_t *, fm_target_t *, uint16_t);


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



#endif /* FREEMAP_PROTOCOLS_H */

