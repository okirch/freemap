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
#include "protocols.h"
#include "target.h" /* for fm_target_pool_find */
#include "logging.h"
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

bool
fm_neighbor_get_link_address(const fm_neighbor_t *neigh, fm_address_t *link_address)
{
	if (neigh->state == FM_NEIGHBOR_LARVAL)
		return false;

	*link_address = neigh->link_address;
	return true;
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

	/* inform any probes that were waiting for this to be resolved */
	fm_event_post(FM_EVENT_ID_NEIGHBOR_CACHE);

	fm_host_asset_update_link_address_by_address(network_address, (const fm_address_t *) link_address);
	return true;
}

/*
 * Neighbor discovery
 */
static bool
fm_neighbor_initiate_arp(const fm_address_t *network_address)
{
	fm_target_t *target;
	fm_protocol_t *proto;

#if 0
	/* Obsolete, this function no longer exists. */
	target = fm_target_pool_find(network_address);
#else
	/* We should not rely on our ability to access a target handle for this address.
	 * Instead, fm_arp_discover() needs to be rewritten to accept an address */
	target = NULL;
#endif
	if (target == NULL) {
		/* We need to handle the case of local routers which may not be a scan target */
		fm_log_error("%s: not a scan target", fm_address_format(network_address));
		return false;
	}

	proto = fm_protocol_by_name("arp");
	if (proto == NULL) {
		fm_log_error("ARP protocol not available (possibly due to insufficient privilege)");
		return false;
	}

	if (!fm_arp_discover(proto, target, 0)) {
		fm_log_error("%s: unable to create ARP probe", fm_address_format(network_address));
		return false;
	}

	return true;
}

static bool
fm_neighbor_initiate_ipv6_ndisc(const fm_address_t *network_address)
{
	fm_log_error("%s: not yet implemented", __func__);
	return false;
}

bool
fm_neighbor_initiate_discovery(fm_neighbor_t *neigh)
{
	/* Why did you call me? Now you have to go the long way round... */
	if (neigh->state == FM_NEIGHBOR_VALID) {
		fm_log_warning("A fool is searching for gold.");
		fm_event_post(FM_EVENT_ID_NEIGHBOR_CACHE);
		return true;
	}

	if (neigh->network_address.ss_family == AF_INET)
		return fm_neighbor_initiate_arp(&neigh->network_address);

	if (neigh->network_address.ss_family == AF_INET6)
		return fm_neighbor_initiate_ipv6_ndisc(&neigh->network_address);

	return false;
}
