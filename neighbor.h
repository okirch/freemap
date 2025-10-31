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

#ifndef FREEMAP_NEIGHBOR_H
#define FREEMAP_NEIGHBOR_H

#include "freemap.h"

enum {
	FM_NEIGHBOR_LARVAL,
	FM_NEIGHBOR_VALID,
	FM_NEIGHBOR_INVALID,
};

struct fm_neighbor {
	int			state;

	fm_address_t		network_address;
	fm_address_t		link_address;

	fm_completion_t *	pending_probe;
};

typedef struct fm_neighbor_array {
	unsigned int		count;
	fm_neighbor_t **	elements;
} fm_neighbor_array_t;

struct fm_neighbor_cache {
	int			ifindex;
	fm_neighbor_array_t	neighbors;
};

extern fm_neighbor_cache_t *	fm_neighbor_cache_create(int ifindex);
extern fm_neighbor_t *		fm_neighbor_cache_find_entry(fm_neighbor_cache_t *, const fm_address_t *, bool);
extern bool			fm_neighbor_cache_update(fm_neighbor_cache_t *cache, const fm_address_t *network_address, const struct sockaddr_ll *link_address);

extern void			fm_neighbor_array_append(fm_neighbor_array_t *array, fm_neighbor_t *neigh);
extern void			fm_neighbor_array_destroy(fm_neighbor_array_t *array);

#endif /* FREEMAP_NEIGHBOR_H */
