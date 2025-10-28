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

#ifndef FREEMAP_ROUTING_H
#define FREEMAP_ROUTING_H

#include "freemap.h"

typedef struct fm_route {
	int			family;
	unsigned int		type;		/* RTN_UNICAST and friends */
	unsigned int		priority;

	unsigned int		oif;
	const fm_interface_t *	interface;

	struct fm_route_prefix {
		unsigned int	prefix_len;
		fm_address_t	addr;
		unsigned char	raw_mask[16];
	} src, dst;

	fm_address_t		pref_src_addr;
	fm_address_t		gateway;
} fm_route_t;

typedef struct fm_routing_cache {
	int			family;
	unsigned int		nroutes;
	fm_route_t **		entries;
} fm_routing_cache_t;

#endif /* FREEMAP_ROUTING_H */
