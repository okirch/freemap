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

#include <string.h>
#include <stdio.h>
#include "addresses.h"
#include "network.h"

typedef struct fm_netbucket	fm_netbucket_t;

static fm_network_t *		fm_network_alloc(const fm_address_t *, unsigned int prefixlen);
static fm_gateway_t *		fm_network_choose_gateway(fm_netbucket_t *h);

/* For the time being, assume a very simplistic model
 * where subnet masks are a multiple of 16
 */
#define SUBNET_CHUNK		16

struct fm_netbucket {
	fm_gateway_t *		gateway;

	union {
		fm_netbucket_t *	hash[SUBNET_CHUNK];
		fm_network_t *		subnet[SUBNET_CHUNK];
	};
};

typedef struct fm_nethash_table {
	int			family;
	unsigned int		addr_bits;
	unsigned int		host_bits;

	fm_netbucket_t		buckets;
} fm_nethash_table_t;

static fm_nethash_table_t	fm_network_hash_ipv4 = {
	.family	= AF_INET,
	.addr_bits = 32,
	.host_bits = 8,
};
static fm_nethash_table_t	fm_network_hash_ipv6 = {
	.family	= AF_INET6,
	.addr_bits = 128,
	.host_bits = 64,
};

/*
 * network hash table mgmt
 */
static fm_netbucket_t *
fm_netbucket_alloc(void)
{
	return (fm_netbucket_t *) calloc(1, sizeof(fm_netbucket_t));
}

static inline unsigned int
get_addr_bits(const unsigned char *raw_addr, unsigned int off)
{
	unsigned char octet = raw_addr[off / 8];

	if (off % 8)
		octet >>= (off % 8);

	return octet & (SUBNET_CHUNK - 1);
}

static fm_network_t *
fm_network_hash_lookup(fm_nethash_table_t *t, const fm_address_t *addr)
{
	const unsigned char *raw_addr;
	fm_netbucket_t *h;
	unsigned int addr_bits, net_bits;
	unsigned int index;
	unsigned int off;
	fm_network_t *net;

	raw_addr = fm_address_get_raw_addr(addr, &addr_bits);
	if (raw_addr == NULL)
		return NULL;

	assert(addr_bits == t->addr_bits);

	net_bits = addr_bits - t->host_bits;
	assert((addr_bits % SUBNET_CHUNK) == 0);

	h = &t->buckets;
	for (off = 0; off + SUBNET_CHUNK < net_bits; off += SUBNET_CHUNK) {
		fm_netbucket_t *next;

		index = get_addr_bits(raw_addr, off);
		if ((next = h->hash[index]) == NULL) {
			next = fm_netbucket_alloc();
			h->hash[index] = next;
		}

		off += SUBNET_CHUNK;
		h = next;
	}

	index = get_addr_bits(raw_addr, off);
	if ((net = h->subnet[index]) == NULL) {
		net = fm_network_alloc(addr, off);
		h->subnet[index] = net;

		net->last_hop = fm_network_choose_gateway(h);
	}

	return net;
}

fm_network_t *
fm_network_for_host(const fm_address_t *addr)
{
	switch (addr->ss_family) {
	case AF_INET:
		return fm_network_hash_lookup(&fm_network_hash_ipv4, addr);

	case AF_INET6:
		return fm_network_hash_lookup(&fm_network_hash_ipv6, addr);
	}

	return NULL;
}

static fm_network_t *
fm_network_alloc(const fm_address_t *addr, unsigned int pfxlen)
{
	static unsigned int netid = 1;
	fm_network_t *net;

	net = calloc(1, sizeof(*net));

	net->netid = netid++;
	net->addr = *addr;
	net->prefixlen = pfxlen;
	return net;
}

void
fm_network_get_rtt_estimator(fm_network_t *net, fm_protocol_t *proto)
{
}

/*
 * The "gateway" behind which a target is located can't be determined
 * unless we perform TTL probing a la traceroute. Which, however,
 * will stress the intermediate gateways a lot, and result in ICMP
 * error suppression and probe timeouts.
 *
 * The approach we take is:
 *  - for new networks, we use the "unknown default gateway" which
 *    provides a very pessimistic view of the ICMP rate available.
 *  - If we receive a positive response, we create a dummy gateway
 *    (without really knowning its address) and install this for
 *    all subnets of this /24 range
 *  - if we receive an ICMP_UNREACH or similar error, we create
 *    a gateway object for this address, and install it for the
 *    target's network, and also as the default for the /24 range.
 */
static fm_gateway_t *
fm_network_choose_gateway(fm_netbucket_t *h)
{
	fm_gateway_t *gw = NULL;
	unsigned int i;

	if (h->gateway != NULL)
		return h->gateway;

	for (i = 0; i < SUBNET_CHUNK && gw == NULL; ++i) {
		fm_network_t *neigh = h->subnet[i];

		if (neigh != NULL && neigh->last_hop && !fm_gateway_is_unknown(neigh->last_hop))
			return neigh->last_hop;
	}

	return NULL;
}

fm_gateway_t *
fm_gateway_alloc(const fm_address_t *addr)
{
	fm_gateway_t *gw;

	gw = calloc(1, sizeof(*gw));

	if (addr != NULL)
		gw->addr = *addr;

	return gw;
}
