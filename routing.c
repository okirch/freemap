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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>

#include "freemap.h"
#include "addresses.h"
#include "routing.h"
#include "neighbor.h"
#include "buffer.h"
#include "utils.h"

static fm_routing_cache_t *fm_routing_cache_ipv4;
static fm_routing_cache_t *fm_routing_cache_ipv6;

static void		fm_route_show(fm_route_t *r);

fm_route_t *
fm_route_alloc(int af, int type)
{
	fm_route_t *route;

	route = calloc(1, sizeof(*route));
	route->family = af;
	route->type = type;
	return route;
}

void
fm_route_free(fm_route_t *route)
{
	free(route);
}

fm_routing_cache_t *
fm_routing_cache_alloc(int af)
{
	fm_routing_cache_t *cache;

	cache = calloc(1, sizeof(*cache));
	cache->family = af;
	return cache;
}

fm_routing_cache_t *
fm_routing_cache_for_family(int af)
{
	fm_routing_cache_t **cachep;

	if (af == AF_INET)
		cachep = &fm_routing_cache_ipv4;
	else if (af == AF_INET6)
		cachep = &fm_routing_cache_ipv6;
	else
		return NULL;

	if (*cachep == NULL)
		*cachep = fm_routing_cache_alloc(af);
	return *cachep;
}

void
fm_routing_cache_free(fm_routing_cache_t *cache)
{
	if (cache->entries) {
		unsigned int i;

		for (i = 0; i < cache->nroutes; ++i)
			fm_route_free(cache->entries[i]);

		free(cache->entries);
	}

	memset(cache, 9, sizeof(*cache));
	free(cache);
}

void
fm_routing_cache_add(fm_routing_cache_t *cache, fm_route_t *route)
{
	assert(route->family == cache->family);

	maybe_realloc_array(cache->entries, cache->nroutes, 16);
	cache->entries[cache->nroutes++] = route;
}

/*
 * Sort the rtcache from most specific to least
 */
static inline int
rt_type_to_prio(int type)
{
	/* put unicast and local routes first */
	if (type == RTN_UNICAST || type == RTN_LOCAL)
		return 0;
	return 1;
}

static int
rtcache_entry_cmp(const void *a, const void *b)
{
	fm_route_t *rta = *(fm_route_t **) a;
	fm_route_t *rtb = *(fm_route_t **) b;
	int diff;

	/* put unicast and local routes before mcast, anycast etc */
	diff = rt_type_to_prio(rta->type) - rt_type_to_prio(rtb->type);

	/* put longer prefix before shorter */
	if (diff == 0)
		diff = -(rta->dst.prefix_len - rtb->dst.prefix_len);

	/* put higher priority before shorter */
	if (diff == 0)
		diff = -(rta->priority - rtb->priority);

	return diff;
}

static void
fm_routing_cache_sort(fm_routing_cache_t *cache)
{
	qsort(cache->entries, cache->nroutes, sizeof(cache->entries[0]), rtcache_entry_cmp);
}

static void
fm_routing_cache_attach_interfaces(fm_routing_cache_t *rtcache)
{
	for (unsigned int i = 0; i < rtcache->nroutes; ++i) {
		fm_route_t *route = rtcache->entries[i];

		if (route->interface == NULL
		 && (route->interface = fm_interface_by_index(route->oif)) == NULL)
			fm_log_error("Unable to find NIC for ifindex %d\n", route->oif);
	}
}

void
fm_routing_cache_dump(fm_routing_cache_t *cache)
{
	printf("Routing cache for %s addresses\n", fm_addrfamily_name(cache->family));
	for (unsigned int i = 0; i < cache->nroutes; ++i) {
		fm_route_show(cache->entries[i]);
	}
	printf("\n");
}

static const char *
address_format(const struct sockaddr_storage *ap)
{
	static char extra[128];
	if (ap->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *) ap;

		return inet_ntoa(sin->sin_addr);
	} else
	if (ap->ss_family == AF_INET6) {
		const struct sockaddr_in6 *six = (const struct sockaddr_in6 *) ap;

		return inet_ntop(AF_INET6, &six->sin6_addr, extra, sizeof(extra));
	}

	return "BAD";
}

static const char *
route_prefix_format(struct sockaddr_storage *addr, unsigned int pfxlen)
{
	static char abuf[128];

	if (pfxlen == 0)
		return "default";

	snprintf(abuf, sizeof(abuf), "%s/%u", address_format(addr), pfxlen);
	return abuf;
}

static const char *
route_type_name(int type)
{
	static char buffer[16];

	switch (type) {
	case RTN_UNICAST:
		return "unicast";
	case RTN_LOCAL:
		return "local";
	case RTN_BROADCAST:
		return "bcast";
	case RTN_ANYCAST:
		return "anycast";
	case RTN_MULTICAST:
		return "mcast";
	}

	snprintf(buffer, sizeof(buffer), "rt%u", type);
	return buffer;
}

void
fm_route_show(fm_route_t *r)
{
	printf("%-10s ", route_type_name(r->type));
	printf("%-25s", route_prefix_format(&r->dst.addr, r->dst.prefix_len));
	if (r->gateway.ss_family != AF_UNSPEC)
		printf(" via %s", address_format(&r->gateway));
	if (r->priority)
		printf(" priority %u", r->priority);
	if (r->interface)
		printf(" dev %s", fm_interface_get_name(r->interface));
	else if (r->oif)
		printf(" oif %u", r->oif);
	if (r->pref_src_addr.ss_family != AF_UNSPEC)
		printf(" prefsrc %s", address_format(&r->pref_src_addr));
	printf("\n");
}

/*
 * Routing table lookup
 */
fm_route_t *
fm_routing_for_address(const fm_address_t *addr)
{
	fm_routing_cache_t *rtcache;
	const unsigned char *raw_addr1;
	const unsigned char *raw_addr2;
	unsigned int i, k, addr_bits, noctets;

	if ((rtcache = fm_routing_cache_for_family(addr->ss_family)) == NULL)
		return NULL;

	raw_addr1 = fm_address_get_raw_addr(addr, &addr_bits);
	if (raw_addr1 == NULL)
		return NULL;

	noctets = addr_bits / 8;

	for (i = 0; i < rtcache->nroutes; ++i) {
		fm_route_t *route = rtcache->entries[i];
		int xor = 0;

		assert(route->family == addr->ss_family);

		/* we could also cache the route's raw dst addr */
		raw_addr2 = fm_address_get_raw_addr(&route->dst.addr, NULL);
		for (k = 0; k < noctets && xor == 0; ++k)
			xor = route->dst.raw_mask[k] & (raw_addr1[k] ^ raw_addr2[k]);

		if (xor == 0)
			return route;
	}

	return NULL;
}

/*
 * Given an IP destination, fill in source address and the lladdrs.
 */

bool
fm_routing_lookup(fm_routing_info_t *info)
{
	fm_route_t *route;
	fm_neighbor_t *neigh;

	if (!(route = fm_routing_for_address(&info->dst.network_address))) {
		fm_log_error("%s: no route to host", fm_address_format(&info->dst.link_address));
		return false;
	}

	info->src.network_address = route->pref_src_addr;

	if (route->interface == NULL) {
		fm_log_error("%s: no interface for route", fm_address_format(&info->dst.link_address));
		return false;
	}

	if (!fm_interface_get_lladdr(route->interface, (struct sockaddr_ll *) &info->src.link_address)) {
		fm_log_error("%s: no interface has no lladdr", fm_address_format(&info->dst.link_address));
		return false;
	}

	if (route->gateway.ss_family == AF_UNSPEC) {
		info->nh.network_address = info->dst.network_address;
	} else {
		info->nh.network_address = route->gateway;
	}

	/* FIXME: if the interface is eg a tunnel or some point-to-point link, we
	 * won't have to do any neighbor lookup */

	/* We need the link-layer address for the next hop */
	neigh = fm_interface_get_neighbor(route->interface, &info->nh.network_address, true);
	assert(neigh);

	if (neigh->state == FM_NEIGHBOR_LARVAL) {
		/* tell the caller that we're still waiting for neighbor resolution */
		info->incomplete_neighbor_entry = neigh;
	} else
	if (neigh->state == FM_NEIGHBOR_VALID) {
		info->nh.link_address = neigh->link_address;
	} else {
		/* negative entry; nothing we can do here */
		return false;
	}

	return true;
}

/*
 * We get here to check whether neighbor discovery is complete.
 * This returns true even if the decision was negative, so the
 * caller needs to check rtinfo->nh.link_address if it's valid.
 */
bool
fm_routing_lookup_complete(fm_routing_info_t *rtinfo)
{
	const fm_neighbor_t *neigh;

	neigh = rtinfo->incomplete_neighbor_entry;

	/* This should not disappear, but better make it robust */
	if (neigh == NULL)
		return true;

	if (!fm_neighbor_get_link_address(neigh, &rtinfo->nh.link_address))
		return false;

	rtinfo->incomplete_neighbor_entry = NULL;
	return true;
}

/*
 * Route discovery.
 * Most of the actual work happens in netlink.c
 */
static void
refresh_routing_cache(int af)
{
	if (netlink_build_routing_cache(af)) {
		fm_routing_cache_t *rtcache = fm_routing_cache_for_family(af);

		if (rtcache != NULL) {
			fm_routing_cache_attach_interfaces(rtcache);
			fm_routing_cache_sort(rtcache);

			if (fm_debug_level > 1)
				fm_routing_cache_dump(rtcache);
		} else {
			fm_log_debug("It seems that we do not have any %s routes",
					fm_addrfamily_name(af));
		}
	}
}

void
fm_routing_discover(void)
{
	fm_log_debug("About to dump net devices\n");
	netlink_build_device_cache();

	fm_log_debug("About to dump addresses\n");
	netlink_build_address_cache();

	if (fm_routing_cache_ipv4 == NULL)
		refresh_routing_cache(AF_INET);

	if (fm_routing_cache_ipv6 == NULL)
		refresh_routing_cache(AF_INET6);
}
