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

#ifndef FREEMAP_FAKENET_H
#define FREEMAP_FAKENET_H

#include "freemap.h"
#include "addresses.h"
#include "lists.h"

typedef struct fm_fake_network_config {
	char *			address;
	char *			router;
} fm_fake_network_config_t;

typedef struct fm_fake_router_config {
	char *			name;
	char *			address;
	char *			prev_name;
} fm_fake_router_config_t;


typedef struct fm_fake_router	fm_fake_router_t;
struct fm_fake_router {
	fm_address_t		ipv4_address;
	fm_address_t		ipv6_address;
	fm_fake_router_t *	prev;

	unsigned int		ttl;
	unsigned int		label;		/* used for loop detection only */

	fm_fake_router_config_t	config;
};

typedef struct fm_fake_network {
	fm_address_prefix_t	prefix;
	fm_fake_router_t *	router;

	fm_fake_network_config_t config;
} fm_fake_network_t;

typedef struct fm_fake_router_array {
	unsigned int		count;
	fm_fake_router_t **	entries;
} fm_fake_router_array_t;

typedef struct fm_fake_network_array {
	unsigned int		count;
	fm_fake_network_t **	entries;
} fm_fake_network_array_t;

typedef struct fm_fake_address_pool {
	struct hlist		link;

	int			family;

	unsigned int		pfxlen;
	unsigned int		addrbits;
	unsigned int		shift;
	unsigned int		next_value;
	unsigned int		max_value;
	unsigned char		raw_addr[16];
} fm_fake_address_pool_t;

typedef struct fm_fake_config {
	fm_string_array_t	addresses;
	fm_string_array_t	backbone_pool;

	fm_fake_router_t *	egress_router;

	fm_fake_router_array_t	routers;
	fm_fake_network_array_t	networks;

	struct hlist_head	bpool;
} fm_fake_config_t;

typedef struct fm_tunnel {
	char *			ifname;
	int			fd;
	int			ifindex;

	fm_address_t		ipv4_address;
	fm_address_t		ipv6_address;
} fm_tunnel_t;

#endif /* FREEMAP_FAKENET_H */
