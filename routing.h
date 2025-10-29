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

#include <linux/if_packet.h>
#include "freemap.h"

struct fm_interface {
	struct hlist		link;
	char *			name;

	unsigned int		ifflags;
	unsigned int		operstate;
	unsigned int		linkmode;
	unsigned int		carrier;

	int			ifindex;
	struct sockaddr_ll	lladdr;
	struct sockaddr_ll	llbcast;

	fm_neighbor_cache_t *	neighbor_cache;
};

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

extern fm_interface_t *		fm_interface_alloc(int ifindex, int hatype);
extern fm_address_prefix_t *	fm_local_address_prefix_create(const fm_address_t *local_address, unsigned int pfxlen, int ifindex);

extern fm_route_t *		fm_route_alloc(int af, int type);
extern void			fm_route_free(fm_route_t *route);
extern fm_routing_cache_t *	fm_routing_cache_for_family(int af);
extern void			fm_routing_cache_add(fm_routing_cache_t *cache, fm_route_t *route);

extern bool			netlink_build_device_cache(void);
extern bool			netlink_build_address_cache(void);
extern bool			netlink_build_routing_cache(int af);


#endif /* FREEMAP_ROUTING_H */
