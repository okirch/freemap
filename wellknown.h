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

#ifndef FREEMAP_WELLKNOWN_H
#define FREEMAP_WELLKNOWN_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "freemap.h"
#include "protocols.h"

typedef struct fm_probe_packet {
	const void *		data;
	unsigned int		len;
} fm_probe_packet_t;

struct fm_wellknown_service {
	const char *		id;

	/* keep it simple for now. */
	fm_probe_packet_t *	probe_packet;
};


extern fm_wellknown_service_t	unknown_rpc_service;
extern fm_wellknown_service_t	portmap_rpc_service;
extern fm_wellknown_service_t	dns_service;
extern fm_wellknown_service_t	mdns_service;

#endif /* FREEMAP_WELLKNOWN_H */


