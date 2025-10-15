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

#ifndef FREEMAP_NETWORK_H
#define FREEMAP_NETWORK_H

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "freemap.h"
#include "lists.h"
#include "addresses.h"

/*
 * The gateway and network objects are used for rate limiting
 * and RTT estimation
 */
struct fm_network {
	unsigned int		netid;
	fm_address_t		addr;
	unsigned int		prefixlen;

	fm_gateway_t *		last_hop;
};

struct fm_gateway {
	struct hlist		link;
	fm_address_t		addr;
};


extern fm_gateway_t *	fm_gateway_alloc(const fm_address_t *);

static inline bool
fm_gateway_is_unknown(const fm_gateway_t *gw)
{
	return gw->addr.ss_family == AF_UNSPEC;
}

#endif /* FREEMAP_NETWORK_H */

