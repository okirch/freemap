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
fm_address_generator_address_eligible(const fm_address_t *address)
{
	if (fm_global.address_generation.only_family == AF_UNSPEC)
		return true;	/* no restrictions */

	if (fm_global.address_generation.only_family == address->ss_family)
		return true;	/* it's a match */

	return false;
}

/*
 * Parse a prefix in add/len notation
 */
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
	struct sockaddr_storage ss;
	unsigned int cidr_bits, host_bits;
	fm_address_enumerator_t *agen = NULL;

	if (!fm_try_parse_cidr(addr_string, &ss, &cidr_bits)) {
		/* TBD: resolve hostname, apply opts to filter which addresses to use */
		return false;
	}

	if (!fm_address_generator_address_eligible(&ss))
		return false;

	host_bits = fm_addrfamily_max_addrbits(ss.ss_family);
	if (host_bits == 0)
		return false;

	if (cidr_bits > host_bits) {
		fm_log_error("%s: network size of %lu bits bigger than address size", addr_string, cidr_bits);
		return false;
	}
	host_bits -= cidr_bits;

	if (ss.ss_family == AF_INET6) {
		const fm_address_prefix_t *local_prefix;

		local_prefix = fm_local_prefix_for_address(&ss);
		if (local_prefix == NULL || cidr_bits < local_prefix->pfxlen) {
			fm_log_error("%s: remote network enumeration not supported for IPv6", addr_string);
			return false;
		}

		agen = fm_local_ipv6_address_enumerator(local_prefix->ifname, &ss, cidr_bits);
	} else
	if (ss.ss_family == AF_INET) {
		/* This limit is somewhat arbitrary and we need to increase it, at least for
		 * local networks. */
		if (host_bits > 8) {
			fm_log_error("%s: IPv4 address enumeration limited to /24 networks", addr_string);
			return false;
		}

		agen = fm_ipv4_network_enumerator(&ss, cidr_bits);
	}

	if (agen == NULL)
		return false;

	fm_target_manager_add_address_generator(target_manager, agen);
	return true;
}

/*
 * Address generator that tries to discover hosts on a local network, typically using
 * something like icmp broadcasts
 */
struct fm_local_discovery_enumerator {
	fm_address_enumerator_t base;

	fm_job_t *		pending;
	fm_completion_t *	completion;

	unsigned int		index;
	fm_address_array_t	found;
};

static fm_error_t
fm_local_discovery_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	struct fm_local_discovery_enumerator *disco = (struct fm_local_discovery_enumerator *) agen;

	if (disco->index < disco->found.count) {
		*ret = disco->found.elements[disco->index++];
		return 0;
	}

	/* The discovery job is done; no more new addresses. */
	if (disco->pending == 0)
		return FM_SEND_ERROR;

	return FM_TRY_AGAIN;
}

static void
fm_local_discovery_enumerator_restart(fm_address_enumerator_t *agen, int stage)
{
	struct fm_local_discovery_enumerator *disco = (struct fm_local_discovery_enumerator *) agen;

	disco->index = 0;
}

static void
fm_local_discovery_job_callback(const fm_job_t *job, void *user_data)
{
	struct fm_local_discovery_enumerator *disco = user_data;

	if (disco->pending != job)
		return;

	fm_log_debug("local address discovery job is complete");

	fm_completion_free(disco->completion);
	disco->pending = NULL;
	disco->completion = NULL;
}

static void
fm_local_discovery_info_callback(const fm_pkt_t *pkt, void *user_data)
{
	struct fm_local_discovery_enumerator *disco = user_data;
	const fm_address_t *new_addr;

	if (pkt->info.ee != NULL)
		return;

	new_addr = &pkt->peer_addr;
	if (fm_address_generator_address_eligible(new_addr))
		fm_address_array_append_unique(&disco->found, new_addr);
}

static void
fm_local_discovery_enumerator_add_address(fm_address_enumerator_t *agen, const fm_address_t *new_addr)
{
	struct fm_local_discovery_enumerator *disco = (struct fm_local_discovery_enumerator *) agen;

	if (fm_address_generator_address_eligible(new_addr)) {
		fm_address_array_append_unique(&disco->found, new_addr);

		/* Record in the asset database that this address is reachable.
		 * This may fail, eg if there's a problem mapping the asset file into memory.
		 * Silently ignore those kinds of failure */
		fm_host_asset_update_state_by_address(new_addr, FM_PROTO_NONE, FM_ASSET_STATE_OPEN);
	}
}

static const struct fm_address_enumerator_ops fm_local_discovery_enumerator_ops = {
	.obj_size	= sizeof(struct fm_local_discovery_enumerator),
	.name		= "icmp-discovery",
	.destroy	= NULL,
	.get_one_address= fm_local_discovery_enumerator_get_one,
	.add_address	= fm_local_discovery_enumerator_add_address,
	.restart	= fm_local_discovery_enumerator_restart,
};

fm_address_enumerator_t *
fm_address_enumerator_new_discovery(void)
{
	struct fm_local_discovery_enumerator *disco;

	disco = NEW_ADDRESS_ENUMERATOR(fm_local_discovery_enumerator);

	return &disco->base;
}

static fm_address_enumerator_t *
fm_local_discovery_enumerator_create(const fm_interface_t *nic, int family, const fm_address_t *src_addr)
{
	struct fm_local_discovery_enumerator *disco;
	fm_probe_params_t probe_params = { 0 };
	fm_protocol_t *proto;
	fm_multiprobe_t *multiprobe;

	disco = NEW_ADDRESS_ENUMERATOR(fm_local_discovery_enumerator);

	proto = fm_protocol_by_id(FM_PROTO_ICMP);
	probe_params.retries = 3;
	probe_params.ttl = 1;

	multiprobe = fm_icmp_create_broadcast_probe(proto, family, nic, src_addr,
					fm_local_discovery_info_callback, disco,
					&probe_params, NULL);
	if (multiprobe == NULL) {
		free(disco);
		return NULL;
	}

	disco->pending = &multiprobe->job;
	disco->completion = fm_job_wait_for_completion(&multiprobe->job, fm_local_discovery_job_callback, disco);

	fm_job_run(&multiprobe->job, NULL);

	return &disco->base;
}


/*
 * Local address enumerator
 */
static void
fm_local_address_enumerator_add_single_address(struct fm_simple_address_enumerator **simple_p, const fm_address_t *addr, fm_target_manager_t *target_manager)
{
	struct fm_simple_address_enumerator *simple = *simple_p;

	if (simple == NULL) {
		*simple_p = simple = fm_create_simple_address_enumerator_empty();
		fm_target_manager_add_address_generator(target_manager, &simple->base);
	}

	fm_address_array_append(&simple->addrs, addr);
}

static bool
fm_local_address_enumerator_add_discovery(const fm_interface_t *nic, const fm_address_prefix_t *prefix, fm_target_manager_t *target_manager)
{
	static bool complained = false;
	fm_address_enumerator_t *child = NULL;
	int family;

	family = prefix->address.ss_family;

	child = fm_local_discovery_enumerator_create(nic, family, &prefix->source_addr);
	if (child == NULL) {
		if (!complained) {
			fm_log_error("%s: trying to perform address discovery, but I lack privileges", 
					fm_interface_get_name(nic));
			complained = true;
		}
		return false;
	}

	fm_target_manager_add_address_generator(target_manager, child);
	return true;
}

bool
fm_create_local_address_enumerator(const char *ifname, fm_target_manager_t *target_manager)
{
	fm_address_prefix_array_t prefix_array = { 0 };
	struct fm_simple_address_enumerator *simple = NULL;
	const fm_interface_t *nic;
	const fm_address_prefix_t *ipv6_discovery_prefix = NULL;
	unsigned int i, old_count, num_created = 0;

	if (!(nic = fm_interface_by_name(ifname))) {
		fm_log_error("Cannot generate local address generator for interface %s: unknown interface", ifname);
		return false;
	}

	fm_interface_get_local_prefixes(nic, &prefix_array);

	old_count = fm_target_manager_get_generator_count(target_manager);
	for (i = 0; i < prefix_array.count; ++i) {
		const fm_address_prefix_t *prefix = &prefix_array.elements[i];
		const fm_address_t *tgt_addr = &prefix->address;
		fm_address_enumerator_t *child = NULL;

		if (!fm_address_generator_address_eligible(&prefix->address))
			continue;

		if (fm_interface_is_loopback(nic)) {
			/* Bravely talking to myself. Hullo, self... */
			fm_local_address_enumerator_add_single_address(&simple, &prefix->source_addr, target_manager);
			continue;
		}

		if (prefix->address.ss_family == AF_INET) {
			if (prefix->pfxlen == 32)
				fm_local_address_enumerator_add_single_address(&simple, tgt_addr, target_manager);
			else
				child = fm_ipv4_network_enumerator(tgt_addr, prefix->pfxlen);
		} else
		if (prefix->address.ss_family == AF_INET6) {
			if (prefix->pfxlen == 128) {
				fm_local_address_enumerator_add_single_address(&simple, tgt_addr, target_manager);
			} else if (fm_global.address_generation.try_all) {
				fm_local_address_enumerator_add_discovery(nic, prefix, target_manager);
			} else {
				if (ipv6_discovery_prefix == NULL || fm_address_is_ipv6_link_local(&ipv6_discovery_prefix->address))
					ipv6_discovery_prefix = prefix;
			}
		} else {
			/* silently ignore anything else (for those of you still on Netware IPX, I pity you) */
		}

		if (child != NULL) {
			fm_target_manager_add_address_generator(target_manager, child);
			num_created += 1;
		}
	}

	if (ipv6_discovery_prefix != NULL)
		fm_local_address_enumerator_add_discovery(nic, ipv6_discovery_prefix, target_manager);

	num_created = fm_target_manager_get_generator_count(target_manager) - old_count;
	if (num_created == 0)
		fm_log_warning("Empty local address generator for interface %s: no local prefixes", ifname);

	fm_address_prefix_array_destroy(&prefix_array);
	return true;
}
