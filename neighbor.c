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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <linux/if_packet.h>

#include "freemap.h"
#include "neighbor.h"
#include "utils.h"

typedef struct fm_completion	fm_completion_t;

static void
fm_neighbor_free(fm_neighbor_t *neigh)
{
	assert(neigh->pending_probe == NULL);
	free(neigh);
}

void
fm_neighbor_array_append(fm_neighbor_array_t *array, fm_neighbor_t *neigh)
{
	maybe_realloc_array(array->elements, array->count, 16);
	array->elements[array->count++] = neigh;
}

void
fm_neighbor_array_destroy(fm_neighbor_array_t *array)
{
	while (array->count)
		fm_neighbor_free(array->elements[--(array->count)]);

	if (array->elements)
		free(array->elements);
}

fm_neighbor_t *
fm_neighbor_create(const fm_address_t *net_addr)
{
	fm_neighbor_t *neigh;

	neigh = calloc(1, sizeof(*neigh));
	neigh->state = FM_NEIGHBOR_LARVAL;
	neigh->network_address = *net_addr;
	return neigh;
}

fm_neighbor_cache_t *
fm_neighbor_cache_create(int ifindex)
{
	fm_neighbor_cache_t *cache;

	cache = calloc(1, sizeof(*cache));
	cache->ifindex = ifindex;
	return cache;
}

fm_neighbor_t *
fm_neighbor_cache_find_entry(fm_neighbor_cache_t *cache, const fm_address_t *addr, bool create)
{
	fm_neighbor_t *neigh = NULL;
	unsigned int i;

	for (i = 0; i < cache->neighbors.count; ++i) {
		neigh = cache->neighbors.elements[i];
		if (fm_address_equal(&neigh->network_address, addr, false))
			break;
	}

	if (neigh == NULL && create) {
		neigh = fm_neighbor_create(addr);
		fm_neighbor_array_append(&cache->neighbors, neigh);
	}

	return neigh;
}

bool
fm_neighbor_cache_update(fm_neighbor_cache_t *cache, const fm_address_t *network_address, const struct sockaddr_ll *link_address)
{
	fm_neighbor_t *neigh;

	if (link_address != NULL) {
		if (link_address->sll_family != AF_PACKET || link_address->sll_ifindex != cache->ifindex) {
			fm_log_error("%s: link address for %s has wrong ifindex %u", __func__,
					fm_address_format(network_address),
					link_address->sll_ifindex);
			return false;
		}
	}

	neigh = fm_neighbor_cache_find_entry(cache, network_address, true);
	assert(neigh != NULL);

	if (link_address != NULL) {
		memcpy(&neigh->link_address, link_address, sizeof(*link_address));
		neigh->state = FM_NEIGHBOR_VALID;
	} else if (neigh->state == FM_NEIGHBOR_LARVAL)
		neigh->state = FM_NEIGHBOR_INVALID;

	/* TBD: inform any probes that were waiting for this to be resolved */

	return true;
}

