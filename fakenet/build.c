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

#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>

#include "fakenet.h"
#include "scanner.h"
#include "commands.h"
#include "protocols.h"
#include "socket.h"
#include "routing.h"
#include "packet.h"
#include "buffer.h"
#include "filefmt.h"
#include "logging.h"

/*
 * Primitives
 */
fm_fake_router_t *
fm_fake_router_alloc(const char *name, fm_fake_router_array_t *array)
{
	fm_fake_router_t *router;

	router = calloc(1, sizeof(*router));
	if (name)
		router->config.name = strdup(name);

	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = router;

	return router;
}

fm_address_t *
fm_fake_router_addr(fm_fake_router_t *router, int family)
{
	if (family == AF_INET)
		return &router->ipv4_address;
	if (family == AF_INET6)
		return &router->ipv6_address;
	return NULL;
}

bool
fm_fake_router_has_address(fm_fake_router_t *router, int family)
{
	const fm_address_t *addr;

	if (!(addr = fm_fake_router_addr(router, family)))
		return false;
	return addr->family == family;
}

const fm_address_t *
fm_fake_router_get_address(fm_fake_router_t *router, int family)
{
	return fm_fake_router_addr(router, family);
}

bool
fm_fake_router_set_address(fm_fake_router_t *router, int family, const fm_address_t *new_addr)
{
	if (new_addr->family != family)
		return false;

	if (family == AF_INET)
		router->ipv4_address = *new_addr;
	else if (family == AF_INET6)
		router->ipv6_address = *new_addr;
	else
		return false;
	return true;
}

fm_fake_network_t *
fm_fake_network_alloc(fm_fake_network_array_t *array)
{
	fm_fake_network_t *network;

	network = calloc(1, sizeof(*network));

	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = network;

	return network;
}

/*
 * Follow the chain of routers
 */
static fm_fake_router_t *
fm_fake_router_build_chain(const fm_fake_config_t *config, const char *name, unsigned int label)
{
	unsigned int i;

	for (i = 0; i < config->routers.count; ++i) {
		fm_fake_router_t *router = config->routers.entries[i];

		if (router->config.name && !strcmp(router->config.name, name)) {
			if (router->label == label) {
				fm_log_error("seems we have a routing loop involving %s", name);
				return NULL;
			}

			if (router->label != 0)
				return router; /* we've handled this one before */

			router->label = label;

			if (router->config.prev_name == NULL) {
				fm_log_error("router %s does not have a previous hop", router->config.name);
			} else if (router->prev == NULL) {
				router->prev = fm_fake_router_build_chain(config, router->config.prev_name, label);
				if (router->prev == NULL)
					return NULL; /* hard error */

				router->ttl = router->prev->ttl + 1;
			}

			return router;
		}
	}

	fm_log_error("router %s not found", name);
	return NULL;
}

/*
 * Manage a pool of addresses we can use for routers (and maybe other entities).
 */
static fm_fake_address_pool_t *
fm_fake_address_pool_alloc(const fm_address_prefix_t *prefix)
{
	fm_fake_address_pool_t *pool;
	const unsigned char *raw_addr;
	unsigned int nbits, value_bits;

	if (!(raw_addr = fm_address_get_raw_addr(&prefix->address, &nbits))
	 || nbits > 128
	 || prefix->pfxlen >= nbits)
		return NULL;

	pool = calloc(1, sizeof(*pool));
	pool->family = prefix->address.family;
	pool->pfxlen = prefix->pfxlen;
	pool->addrbits = nbits;
	pool->shift = 0;
	memcpy(pool->raw_addr, raw_addr, nbits / 8);

	if (prefix->address.family == AF_INET6) {
		if (prefix->pfxlen >= 64)
			return NULL;
		value_bits = 64 - prefix->pfxlen;
		pool->shift = 64;

		memset(pool->raw_addr + 8, 0, 8);
		pool->raw_addr[15] = 0x1;
	} else {
		value_bits = nbits - prefix->pfxlen;
		pool->shift = 0;
	}

	if (value_bits > 16)
		value_bits = 16;
	pool->max_value = (1 << value_bits) - 1;

	return pool;
}

static bool
fm_fake_address_pool_get_next(fm_fake_address_pool_t *pool, fm_address_t *addr)
{
	unsigned char raw_addr[16];
	unsigned int k;
	uint32_t value;

	if (pool->next_value >= pool->max_value)
		return false;

	/* For now, hand out addresses consecutively. Alternative
	 * strategies might involve 4-bit subnets or similar */
	value = pool->next_value++;

	memcpy(raw_addr, pool->raw_addr, pool->addrbits / 8);

	k = (pool->addrbits - pool->shift) / 8;
	raw_addr[--k] |= value & 0xFF;

	value >>= 8;
	raw_addr[--k] |= value & 0xFF;

	fm_address_set_raw_addr(addr, pool->family, raw_addr, pool->addrbits / 8);

	return true;
}

static bool
fm_fake_network_create_backbone_pools(const fm_string_array_t *array, struct hlist_head *head)
{
	hlist_insertion_iterator_t tail;
	unsigned int i;

	hlist_insertion_iterator_init(&tail, head);
	for (i = 0; i < array->count; ++i) {
		const char *addrstring = array->entries[i];
		fm_address_prefix_t prefix;
		fm_fake_address_pool_t *pool;

		if (!fm_address_prefix_parse(addrstring, &prefix)) {
			fm_log_error("Unable to parse backbone pool prefix %s", addrstring);
			continue;
		}

		if ((pool = fm_fake_address_pool_alloc(&prefix)) == NULL)
			continue;

		hlist_insertion_iterator_insert_and_advance(&tail, &pool->link);
	}

	return true;
}

/*
 * Make sure router has a suitable address assigned
 */
static bool
fm_fake_router_assign_addresses(fm_fake_router_t *router, int family, struct hlist_head *pool_head)
{
	fm_address_t new_addr;

	while (router && !fm_fake_router_has_address(router, family)) {
		fm_fake_address_pool_t *pool;
		hlist_iterator_t iter;
		bool found = false;

		hlist_iterator_init(&iter, pool_head);
		while (!found && (pool = hlist_iterator_next(&iter)) != NULL) {
			if (pool->family == family)
				found = fm_fake_address_pool_get_next(pool, &new_addr);
		}

		if (!found)
			return false;

		fm_log_debug("router %s assign address %s", router->config.name, fm_address_format(&new_addr));
		fm_fake_router_set_address(router, family, &new_addr);

		router = router->prev;
	}

	return true;
}

/*
 * Given the configuration setup, try to build the network in-memory
 */
bool
fm_fake_network_set_egress(fm_fake_config_t *config, const fm_tunnel_t *tunnel)
{
	fm_fake_router_t *router;

	if (config->egress_router != NULL)
		return true;

	router = fm_fake_router_alloc("egress", &config->routers);
	router->ipv4_address = tunnel->ipv4_address;
	router->ipv6_address = tunnel->ipv6_address;
	router->label = 1;
	router->ttl = 1;

	config->egress_router = router;
	return true;
}

/*
 * Given the configuration setup, try to build the network in-memory
 */
bool
fm_fake_network_build(fm_fake_config_t *config)
{
	unsigned int i, router_label = 16;
	bool ok = true;

	config->egress_router = fm_fake_router_alloc("egress", &config->routers);
	config->egress_router->label = router_label++;
	config->egress_router->ttl = 1;

	if (!fm_fake_network_create_backbone_pools(&config->backbone_pool, &config->bpool))
		return false;

	for (i = 0; i < config->networks.count; ++i) {
		fm_fake_network_t *net = config->networks.entries[i];

		/* can't happen */
		assert(net->config.address != NULL);

		if (!fm_address_prefix_parse(net->config.address, &net->prefix)) {
			fm_log_error("network %s: cannot parse prefix", net->config.address);
			ok = false;
			continue;
		}

		if (net->config.router == NULL) {
			fm_log_error("network %s: no router specified", net->config.address);
			continue;
		}

		net->router = fm_fake_router_build_chain(config, net->config.router, router_label++);
		if (net->router == NULL) {
			ok = false;
			continue;
		}

		fm_fake_router_assign_addresses(net->router, net->prefix.address.family, &config->bpool);

		{
			fm_fake_router_t *router;

			fm_log_debug("network %s", net->config.address);
			for (router = net->router; router; router = router->prev) {
				const fm_address_t *addr = fm_fake_router_get_address(router, net->prefix.address.family);

				fm_log_debug("  %u %s; addr=%s", router->ttl, router->config.name, 
						fm_address_format(addr));
			}
		}

	}

	return ok;
}
