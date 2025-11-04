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

#include <sys/socket.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include "addresses.h"
#include "network.h"

extern const fm_address_prefix_t *	fm_local_prefix_for_address(const fm_address_t *);

#define NEW_ADDRESS_ENUMERATOR(_typename) \
	((struct _typename *) fm_address_enumerator_alloc(&_typename ## _ops))


/*
 * Common address handling functions
 */
fm_address_enumerator_t *
fm_address_enumerator_alloc(const struct fm_address_enumerator_ops *ops)
{
	static unsigned int allocator_id = 1;
	fm_address_enumerator_t *agen;

	assert(sizeof(*agen) <= ops->obj_size);

	agen = calloc(1, ops->obj_size);
	agen->ops = ops;
	agen->id = allocator_id++;

	agen->unknown_gateway = fm_gateway_alloc(NULL);

	return agen;
}

void
fm_address_enumerator_restart(fm_address_enumerator_t *agen, int stage)
{
	assert(agen->ops != NULL);

	agen->ops->restart(agen, stage);
}

void
fm_address_enumerator_destroy(fm_address_enumerator_t *agen)
{
	assert(agen->ops != NULL);

	if (agen->ops->destroy != NULL)
		agen->ops->destroy(agen);
	memset(agen, 0, agen->ops->obj_size);
	free(agen);
}

const char *
fm_address_enumerator_name(const fm_address_enumerator_t *agen)
{
	return agen->ops->name;
}

bool
fm_address_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	assert(agen->ops != NULL);
	assert(agen->ops->get_one_address != NULL);

	return agen->ops->get_one_address(agen, ret);
}

void
fm_address_enumerator_array_append(fm_address_enumerator_array_t *array, fm_address_enumerator_t *agen)
{
	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = agen;
}

static bool
fm_try_parse_cidr(const char *addr_string, struct sockaddr_storage *ss, unsigned int *nbits)
{
	char *addr_copy, *slash, *end;
	bool ok = false;

	addr_copy = strdup(addr_string);
	if (addr_copy == NULL)
		return false;

	if ((slash = strchr(addr_copy, '/')) == NULL)
		goto out;

	*slash++ = '\0';
	if (!fm_address_parse(addr_copy, ss))
		goto out;

	*nbits = strtoul(slash, &end, 0);
	if (*end)
		goto out;

	if (*nbits > fm_addrfamily_max_addrbits(ss->ss_family))
		goto out;

	ok = true;
out:
	free(addr_copy);
	return ok;
}

/*
 * The "simple" enumerator that is initialized with a single address
 */
struct fm_simple_address_enumerator {
	fm_address_enumerator_t base;

	unsigned int		next;
	fm_address_array_t	addrs;
};

static bool
fm_simple_address_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	struct fm_simple_address_enumerator *simple = (struct fm_simple_address_enumerator *) agen;

	if (simple->next >= simple->addrs.count)
		return false;
	*ret = simple->addrs.elements[simple->next++];
	return true;
}

static void
fm_simple_address_enumerator_restart(fm_address_enumerator_t *agen, int stage)
{
	struct fm_simple_address_enumerator *simple = (struct fm_simple_address_enumerator *) agen;

	simple->next = 0;
}

static const struct fm_address_enumerator_ops fm_simple_address_enumerator_ops = {
	.obj_size	= sizeof(struct fm_simple_address_enumerator),
	.name		= "simple",
	.destroy	= NULL,
	.get_one_address= fm_simple_address_enumerator_get_one,
	.restart	= fm_simple_address_enumerator_restart,
};

/*
 * Note, when hostname resolution is supported, this function will return a list of
 * generators rather than a single one.
 */
fm_address_enumerator_t *
fm_create_simple_address_enumerator(const char *addr_string)
{
	struct fm_simple_address_enumerator *simple;

	simple = NEW_ADDRESS_ENUMERATOR(fm_simple_address_enumerator);

	if (!fm_address_resolve(addr_string, &simple->addrs)) {
		free(simple);
		return NULL;
	}

	return &simple->base;
}

/*
 * Enumeration of local IPv6 networks
 */
static fm_address_enumerator_t *
fm_local_ipv6_address_enumerator(const char *device, const fm_address_t *addr, unsigned int pfxlen)
{
	fm_log_error("%s: not yet implemented", __func__);
	return NULL;
}

/*
 * The "cidr" enumerator that iterates over a CIDR block.
 */
struct fm_ipv4_network_enumerator {
	fm_address_enumerator_t base;

	int		stride;

	uint32_t	ipv4_net;
	unsigned int	prefixlen;

	/* these should not exceed the size of an IPv4 address */
	uint32_t	next_host;
	uint32_t	last_host;
};

bool
fm_ipv4_network_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	struct fm_ipv4_network_enumerator *sagen = (struct fm_ipv4_network_enumerator *) agen;
	struct sockaddr_in *sin;
	uint32_t addr;

	if (sagen->next_host > sagen->last_host || sagen->next_host == 0)
		return false;

	if (sagen->stride <= 1) {
		addr = sagen->ipv4_net | sagen->next_host++;
	} else {
		/* For now, pick any address from the block.
		 * If we want to do better, we could probe the first and the last
		 * one from each block, and compare their last_hop. If they
		 * differ, then we should split the subnet and repeat. */

		addr = sagen->ipv4_net | (sagen->next_host + 1);
		sagen->next_host += sagen->stride;
	}

	memset(ret, 0, sizeof(*ret));

	sin = (struct sockaddr_in *) ret;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(addr);

	return true;
}

static void
fm_ipv4_network_enumerator_restart(fm_address_enumerator_t *agen, int stage)
{
	struct fm_ipv4_network_enumerator *ngen = (struct fm_ipv4_network_enumerator *) agen;

	ngen->next_host = 0;
	if (stage == FM_SCAN_STAGE_TOPO) {
		ngen->stride = 1;
	} else {
		ngen->stride = 256;	/* hard-coded for now */
	}
}

static const struct fm_address_enumerator_ops fm_ipv4_network_enumerator_ops = {
	.obj_size	= sizeof(struct fm_ipv4_network_enumerator),
	.name		= "ipv4-net",
	.destroy	= NULL,
	.get_one_address= fm_ipv4_network_enumerator_get_one,
	.restart	= fm_ipv4_network_enumerator_restart,
};

static fm_address_enumerator_t *
fm_ipv4_network_enumerator(const fm_address_t *addr, unsigned int pfxlen)
{
	struct fm_ipv4_network_enumerator *sagen;

	assert(addr->ss_family == AF_INET);

	sagen = NEW_ADDRESS_ENUMERATOR(fm_ipv4_network_enumerator);
	sagen->ipv4_net = ntohl(((struct sockaddr_in *) addr)->sin_addr.s_addr);
	sagen->prefixlen = pfxlen;
	sagen->next_host = 1;
	sagen->last_host = 0xFFFFFFFF >> pfxlen;

	/* Clear the network's host part */
	sagen->ipv4_net &= ~(sagen->last_host);
	return &sagen->base;
}

/*
 * Note, when hostname resolution is supported, this function will return a list of
 * generators rather than a single one.
 */
fm_address_enumerator_t *
fm_create_cidr_address_enumerator(const char *addr_string)
{
	struct sockaddr_storage ss;
	unsigned int cidr_bits, host_bits;

	if (!fm_try_parse_cidr(addr_string, &ss, &cidr_bits)) {
		/* TBD: resolve hostname, apply opts to filter which addresses to use */
		return NULL;
	}

	if (!fm_address_generator_address_eligible(&ss))
		return NULL;

	host_bits = fm_addrfamily_max_addrbits(ss.ss_family);
	if (host_bits == 0)
		return NULL;

	if (cidr_bits > host_bits) {
		fm_log_error("%s: network size of %lu bits bigger than address size", addr_string, cidr_bits);
		return NULL;
	}
	host_bits -= cidr_bits;

	if (ss.ss_family == AF_INET6) {
		const fm_address_prefix_t *local_prefix;

		local_prefix = fm_local_prefix_for_address(&ss);
		if (local_prefix == NULL || cidr_bits < local_prefix->pfxlen) {
			fm_log_error("%s: remote network enumeration not supported for IPv6", addr_string);
			return NULL;
		}

		return fm_local_ipv6_address_enumerator(local_prefix->ifname, &ss, cidr_bits);
	}

	if (ss.ss_family == AF_INET) {
		/* This limit is somewhat arbitrary and we need to increase it, at least for
		 * local networks. */
		if (host_bits > 8) {
			fm_log_error("%s: IPv4 address enumeration limited to /24 networks", addr_string);
			return NULL;
		}

		return fm_ipv4_network_enumerator(&ss, cidr_bits);
	}

	return NULL;
}
