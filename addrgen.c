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
#include "protocols.h"
#include "probe.h"
#include "assets.h"
#include "logging.h"

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

fm_error_t
fm_address_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	assert(agen->ops != NULL);
	assert(agen->ops->get_one_address != NULL);

	return agen->ops->get_one_address(agen, ret);
}

fm_error_t
fm_address_enumerator_add(fm_address_enumerator_t *agen, const fm_address_t *new_addr)
{
	assert(agen->ops != NULL);

	if (agen->ops->add_address == NULL)
		return FM_NOT_SUPPORTED;

	agen->ops->add_address(agen, new_addr);
	return 0;
}

void
fm_address_enumerator_array_append(fm_address_enumerator_array_t *array, fm_address_enumerator_t *agen)
{
	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = agen;
}

void
fm_address_enumerator_array_remove_shallow(fm_address_enumerator_array_t *array, unsigned int index)
{
	if (index >= array->count)
		return;

	while (index + 1 < array->count) {
		array->entries[index] = array->entries[index + 1];
		++index;
	}
	array->entries[index] = NULL;
	array->count -= 1;
}

void
fm_address_enumerator_array_destroy_shallow(fm_address_enumerator_array_t *array)
{
	if (array->entries)
		free(array->entries);
	memset(array, 0, sizeof(*array));
}

/*
 * Check whether a given address is eligible for scanning, based on the
 * constraints given by the user.
 */
bool
fm_address_generator_address_eligible_state(const fm_address_t *address, int asset_state)
{
	if (asset_state > FM_ASSET_STATE_UNDEF
	 && !fm_host_asset_get_state_by_address(address, FM_PROTO_NONE))
		return false;
	 
	if (fm_global.address_generation.only_family == AF_UNSPEC)
		return true;	/* no restrictions */

	if (fm_global.address_generation.only_family == address->ss_family)
		return true;	/* it's a match */

	return false;
}

bool
fm_address_generator_address_eligible(const fm_address_t *address)
{
	if (fm_global.address_generation.try_all)
		return fm_address_generator_address_eligible_state(address, FM_ASSET_STATE_UNDEF);

	return fm_address_generator_address_eligible_state(address, FM_ASSET_STATE_OPEN);
}

bool
fm_address_generator_address_eligible_any_state(const fm_address_t *address)
{
	return fm_address_generator_address_eligible_state(address, FM_ASSET_STATE_UNDEF);
}

/*
 * Parse a prefix in add/len notation
 */
static bool
fm_try_parse_cidr(const char *addr_string, fm_address_t *addr, unsigned int *nbits)
{
	char *addr_copy, *slash, *end;
	bool ok = false;

	addr_copy = strdup(addr_string);
	if (addr_copy == NULL)
		return false;

	if ((slash = strchr(addr_copy, '/')) == NULL)
		goto out;

	*slash++ = '\0';
	if (!fm_address_parse(addr_copy, addr))
		goto out;

	*nbits = strtoul(slash, &end, 0);
	if (*end)
		goto out;

	if (*nbits > fm_addrfamily_max_addrbits(addr->ss_family))
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

static fm_error_t
fm_simple_address_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	struct fm_simple_address_enumerator *simple = (struct fm_simple_address_enumerator *) agen;

	if (simple->next >= simple->addrs.count)
		return FM_SEND_ERROR;

	*ret = simple->addrs.elements[simple->next++];
	return 0;
}

static void
fm_simple_address_enumerator_add_address(fm_address_enumerator_t *agen, const fm_address_t *new_addr)
{
	struct fm_simple_address_enumerator *simple = (struct fm_simple_address_enumerator *) agen;

	if (fm_address_generator_address_eligible_any_state(new_addr)) {
		fm_address_array_append_unique(&simple->addrs, new_addr);

		/* Record in the asset database that this address is reachable.
		 * This may fail, eg if there's a problem mapping the asset file into memory.
		 * Silently ignore those kinds of failure */
		fm_host_asset_update_state_by_address(new_addr, FM_PROTO_NONE, FM_ASSET_STATE_OPEN);
	}
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
	.add_address	= fm_simple_address_enumerator_add_address,
	.restart	= fm_simple_address_enumerator_restart,
};

/*
 * Note, when hostname resolution is supported, this function will return a list of
 * generators rather than a single one.
 */
bool
fm_create_simple_address_enumerator(const char *addr_string, fm_target_manager_t *target_manager)
{
	struct fm_simple_address_enumerator *simple;

	simple = NEW_ADDRESS_ENUMERATOR(fm_simple_address_enumerator);

	if (!fm_address_resolve(addr_string, &simple->addrs)) {
		free(simple);
		return false;
	}

	fm_target_manager_add_address_generator(target_manager, &simple->base);
	return true;
}

static struct fm_simple_address_enumerator *
fm_create_simple_address_enumerator_empty(void)
{
	return NEW_ADDRESS_ENUMERATOR(fm_simple_address_enumerator);
}

/*
 * Enumeration of local IPv6 networks
 * This relies on the output of a previous discovery scan, as it's hardly practical to enumerate an entire IPv6 prefix.
 */
static fm_address_enumerator_t *
fm_ipv6_network_enumerator(const fm_address_prefix_t *prefix, unsigned int pfxlen)
{
	struct fm_simple_address_enumerator *simple;
	fm_host_asset_iterator_t iter;
	fm_host_asset_t *host_asset;
	const unsigned char *raw_addr1;
	const unsigned char *raw_addr2;
	const unsigned char *raw_mask;
	unsigned int addr_bits, noctets, k;

	/* Allow the user to be more restrictive if they really want to */
	if (pfxlen < prefix->pfxlen)
		pfxlen = prefix->pfxlen;

	fm_log_debug("Trying to add all known addresses for prefix %s/%u on device %s",
			fm_address_format(&prefix->address), pfxlen, prefix->ifname);

	simple = fm_create_simple_address_enumerator_empty();

	/* Load the asset tables */
	fm_host_asset_cache_prime();

	raw_addr1 = fm_address_get_raw_addr(&prefix->address, &addr_bits);
	if (raw_addr1 == NULL)
		return false;

	raw_mask = prefix->raw_mask;

	assert(pfxlen <= addr_bits);
	noctets = (pfxlen + 7) / 8;

	/* This is a bit brute force because we loop over all assets of the given address family.
	 * With a large DB, this means we visit a lot of assets we are not interested in.
	 * Doing this more efficiently requires some smarts inside the asset iterator,
	 * which I'm not keen on doing right now. */
	fm_host_asset_iterator_init_family(&iter, prefix->address.ss_family);
	while ((host_asset = fm_host_asset_iterator_next(&iter)) != NULL) {
		const fm_address_t *host_addr = &host_asset->address;
		unsigned char xor = 0;

		assert(host_addr->ss_family == prefix->address.ss_family);

		if (!fm_address_generator_address_eligible_any_state(host_addr))
			continue;

		if (!(raw_addr2 = fm_address_get_raw_addr(host_addr, NULL)))
			continue;

		for (k = 0; k < noctets && xor == 0; ++k)
			xor = raw_mask[k] & (raw_addr1[k] ^ raw_addr2[k]);

		if (xor != 0)
			continue; /* does not match prefix */

		if (!fm_host_asset_hot_map(host_asset))
			continue; /* can't map the asset into memory */

		if (fm_host_asset_get_state(host_asset) != FM_ASSET_STATE_OPEN)
			continue; /* host not reachable */

		fm_address_array_append(&simple->addrs, host_addr);
	}

	return &simple->base;
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

fm_error_t
fm_ipv4_network_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	struct fm_ipv4_network_enumerator *sagen = (struct fm_ipv4_network_enumerator *) agen;
	struct sockaddr_in *sin;
	uint32_t addr;

	if (sagen->next_host > sagen->last_host || sagen->next_host == 0)
		return FM_SEND_ERROR;

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

	return 0;
}

static void
fm_ipv4_network_enumerator_restart(fm_address_enumerator_t *agen, int stage)
{
	struct fm_ipv4_network_enumerator *ngen = (struct fm_ipv4_network_enumerator *) agen;

	ngen->next_host = 1;
	if (stage == FM_SCAN_STAGE_TOPO) {
		ngen->stride = 256;	/* hard-coded for now */
	} else {
		ngen->stride = 1;
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
bool
fm_create_cidr_address_enumerator(const char *addr_string, fm_target_manager_t *target_manager)
{
	fm_address_t addr;
	unsigned int cidr_bits, host_bits;
	fm_address_enumerator_t *agen = NULL;

	if (!fm_try_parse_cidr(addr_string, &addr, &cidr_bits)) {
		/* TBD: resolve hostname, apply opts to filter which addresses to use */
		return false;
	}

	if (!fm_address_generator_address_eligible_any_state(&addr))
		return false;

	host_bits = fm_addrfamily_max_addrbits(addr.ss_family);
	if (host_bits == 0)
		return false;

	if (cidr_bits > host_bits) {
		fm_log_error("%s: network size of %lu bits bigger than address size", addr_string, cidr_bits);
		return false;
	}
	host_bits -= cidr_bits;

	if (addr.ss_family == AF_INET6) {
		const fm_address_prefix_t *local_prefix;

		local_prefix = fm_local_prefix_for_address(&addr);
		if (local_prefix == NULL || cidr_bits < local_prefix->pfxlen) {
			fm_log_error("%s: remote network enumeration not supported for IPv6", addr_string);
			return false;
		}

		agen = fm_ipv6_network_enumerator(local_prefix, cidr_bits);
	} else
	if (addr.ss_family == AF_INET) {
		/* This limit is somewhat arbitrary and we need to increase it, at least for
		 * local networks. */
		if (host_bits > 8) {
			fm_log_error("%s: IPv4 address enumeration limited to /24 networks", addr_string);
			return false;
		}

		agen = fm_ipv4_network_enumerator(&addr, cidr_bits);
	}

	if (agen == NULL)
		return false;

	fm_target_manager_add_address_generator(target_manager, agen);
	return true;
}

/*
 * Address enumerator into which a discovery scan can feed its results
 */
fm_address_enumerator_t *
fm_address_enumerator_new_discovery(void)
{
	struct fm_simple_address_enumerator *simple;

	simple = fm_create_simple_address_enumerator_empty();

	return &simple->base;
}

/*
 * Address enumerator for local interfaces.
 *
 * Without --all-addresses, this will use only those addresses that have been discovered in a
 * previous discovery probe. For IPv6, it will select only one prefix, preferring a globally
 * routable prefix over a link-local fe80:: prefix.
 *
 * With --all-addresses, this will generate all addresses for each of the network prefixes
 * attached to the interface. As that is not possible (reasonable) for IPv6, we print a
 * warning instead, telling users to run a discovery probe first.
 */
bool
fm_create_local_address_enumerator(const char *ifname, fm_target_manager_t *target_manager)
{
	fm_address_prefix_array_t prefix_array = { 0 };
	struct fm_simple_address_enumerator *simple = NULL;
	const fm_interface_t *nic;
	const fm_address_prefix_t *ipv6_discovery_prefix = NULL;
	unsigned int i, old_count, num_created = 0;
	bool warn_ipv6_no_discovery = false;

	if (!(nic = fm_interface_by_name(ifname))) {
		fm_log_error("Cannot generate local address generator for interface %s: unknown interface", ifname);
		return false;
	}

	fm_interface_get_local_prefixes(nic, &prefix_array);

	old_count = fm_target_manager_get_generator_count(target_manager);
	for (i = 0; i < prefix_array.count; ++i) {
		const fm_address_prefix_t *prefix = &prefix_array.elements[i];
		const fm_address_t *tgt_addr = NULL;
		fm_address_enumerator_t *child = NULL;

		/* The prefix address may not have a host asset, and we
		 * have probably never set its asset state... */
		if (!fm_address_generator_address_eligible_any_state(&prefix->address))
			continue;

		if (fm_interface_is_loopback(nic)) {
			/* Bravely talking to myself. Hullo, self... */
			tgt_addr = &prefix->source_addr;
		} else
		if (prefix->address.ss_family == AF_INET) {
			if (prefix->pfxlen == 32) {
				tgt_addr = &prefix->address;
			} else {
				child = fm_ipv4_network_enumerator(&prefix->address, prefix->pfxlen);
			}
		} else
		if (prefix->address.ss_family == AF_INET6) {
			if (prefix->pfxlen == 128) {
				tgt_addr = &prefix->address;
			} else if (fm_global.address_generation.try_all) {
				warn_ipv6_no_discovery = true;
			} else {
				if (ipv6_discovery_prefix == NULL || fm_address_is_ipv6_link_local(&ipv6_discovery_prefix->address))
					ipv6_discovery_prefix = prefix;
			}
		} else {
			/* silently ignore anything else (for those of you still on Netware IPX, I pity you) */
		}

		if (tgt_addr != NULL) {
			if (simple == NULL) {
				simple = fm_create_simple_address_enumerator_empty();
				fm_target_manager_add_address_generator(target_manager, &simple->base);
			}

			fm_address_array_append(&simple->addrs, tgt_addr);
		}

		if (child != NULL)
			fm_target_manager_add_address_generator(target_manager, child);
	}

	if (warn_ipv6_no_discovery) {
		fm_log_warning("You have asked to inspect all IPv6 addresses on %s.", ifname);
		fm_log_warning("To achieve this, please run a discovery probe first, like this:");
		fm_log_warning("  freemap discovery-scan %%%s", ifname);
		fm_log_warning("Then, re-run this probe command without the --all-addresses option");
	}

	if (ipv6_discovery_prefix != NULL) {
		fm_address_enumerator_t *child;

		child = fm_ipv6_network_enumerator(ipv6_discovery_prefix, ipv6_discovery_prefix->pfxlen);
		if (child != NULL)
			fm_target_manager_add_address_generator(target_manager, child);
	}

	num_created = fm_target_manager_get_generator_count(target_manager) - old_count;
	if (num_created == 0)
		fm_log_warning("Empty local address generator for interface %s: no local prefixes found", ifname);

	fm_address_prefix_array_destroy(&prefix_array);
	return true;
}
