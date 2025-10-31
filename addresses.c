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
fm_address_enumerator_destroy(fm_address_enumerator_t *agen)
{
	assert(agen->ops != NULL);

	fm_address_enumerator_list_remove(agen);
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


/*
 * Miscellaneous address related helper functions
 */
static bool
fm_try_parse_ipv4_address(const char *addr_string, struct sockaddr_in *sin)
{
	memset(sin, 0, sizeof(*sin));
	if (inet_pton(AF_INET, addr_string, &sin->sin_addr) <= 0)
		return false;
	sin->sin_family = AF_INET;
	return true;
}

static bool
fm_try_parse_ipv6_address(const char *addr_string, struct sockaddr_in6 *six)
{
	memset(six, 0, sizeof(*six));
	if (inet_pton(AF_INET6, addr_string, &six->sin6_addr) <= 0)
		return false;
	six->sin6_family = AF_INET6;
	return true;
}

static bool
fm_try_parse_address(const char *addr_string, struct sockaddr_storage *ss)
{
	return fm_try_parse_ipv4_address(addr_string, (struct sockaddr_in *) ss)
	    || fm_try_parse_ipv6_address(addr_string, (struct sockaddr_in6 *) ss);
}

static unsigned char *
fm_get_raw_addr(int af, struct sockaddr_storage *ss, unsigned int *nbits)
{
	switch (af) {
	case AF_INET:
		if (nbits)
			*nbits = 32;
		return (unsigned char *) &((struct sockaddr_in *) ss)->sin_addr;

	case AF_INET6:
		if (nbits)
			*nbits = 128;
		return (unsigned char *) &((struct sockaddr_in6 *) ss)->sin6_addr;

	case AF_PACKET:
		if (nbits)
			*nbits = 8 * ((struct sockaddr_ll *) ss)->sll_halen;
		return (unsigned char *) ((struct sockaddr_ll *) ss)->sll_addr;
	}

	return NULL;
}

unsigned short
fm_address_get_port(const struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *) ss)->sin_port);

	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *) ss)->sin6_port);

	case AF_PACKET:
		return 0;
	}

	return 0;

}

bool
fm_address_set_port(struct sockaddr_storage *ss, unsigned short port)
{
	switch (ss->ss_family) {
	case AF_INET:
		((struct sockaddr_in *) ss)->sin_port = htons(port);
		break;

	case AF_INET6:
		((struct sockaddr_in6 *) ss)->sin6_port = htons(port);
		break;

	default:
		return false;
	}

	return true;

}

const unsigned char *
fm_address_get_raw_addr(const struct sockaddr_storage *ss, unsigned int *nbits)
{
	return fm_get_raw_addr(ss->ss_family, (struct sockaddr_storage *) ss, nbits);
}

void
fm_address_set_ipv4(struct sockaddr_storage *ss, u_int32_t raw_addr)
{
	memset(ss, 0, sizeof(*ss));
	ss->ss_family = AF_INET;
	((struct sockaddr_in *) ss)->sin_addr.s_addr = raw_addr;
}

bool
fm_address_get_ipv4(const fm_address_t *addr, u_int32_t *ip_addr)
{
	if (addr->ss_family != AF_INET)
		return false;

	*ip_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
	return true;
}

void
fm_address_set_ipv6(struct sockaddr_storage *ss, const struct in6_addr *raw_addr)
{
	memset(ss, 0, sizeof(*ss));
	ss->ss_family = AF_INET6;
	((struct sockaddr_in6 *) ss)->sin6_addr = *raw_addr;
}

bool
fm_address_get_ipv6(const fm_address_t *addr, struct in6_addr *raw_addr)
{
	if (addr->ss_family != AF_INET6)
		return false;

	*raw_addr = ((struct sockaddr_in6 *) addr)->sin6_addr;
	return true;
}

unsigned int
fm_addrfamily_sockaddr_size(int family)
{
	switch (family) {
	case AF_PACKET:
		return sizeof(struct sockaddr_ll);

	case AF_INET:
		return sizeof(struct sockaddr_in);

	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	}

	return 0;
}

const char *
fm_addrfamily_name(int family)
{
	switch (family) {
	case AF_PACKET:
		return "link-level";

	case AF_INET:
		return "ipv4";

	case AF_INET6:
		return "ipv6";
	}

	return "unknown";
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
	if (!fm_try_parse_address(addr_copy, ss))
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

const char *
fm_address_format(const fm_address_t *ap)
{
	static char	abuf[4][128];
	static unsigned int aindex;
	unsigned int index, port;
	const unsigned char *raw_addr;

	index = aindex;
	aindex = (aindex + 1) % 4;

	if (!(raw_addr = fm_address_get_raw_addr(ap, NULL))) {
		snprintf(abuf[index], sizeof(abuf[index]), "<unsupported address family %d>", ap->ss_family);
		return abuf[index];
	}

	if (ap->ss_family == AF_PACKET) {
		const struct sockaddr_ll *sll = (const struct sockaddr_ll *) ap;
		const char *arp_type;
		char *wbuf;
		unsigned int wlen, wpos = 0;
		unsigned int i;

		wbuf = abuf[index];
		wlen = sizeof(abuf[index]);

		arp_type = fm_arp_type_to_string(sll->sll_hatype);
		snprintf(wbuf + wpos, wlen - wpos, "%s", arp_type);
		wpos += strlen(wbuf + wpos);

		if (sll->sll_halen != 0 && sll->sll_halen <= 8) {
			for (i = 0; i < sll->sll_halen; i++) {
				if (wpos + 2 < wlen) {
					wbuf[wpos++] = (i == 0)? '/' : ':';
					wbuf[wpos] = '\0';
				}
				snprintf(wbuf + wpos, wlen - wpos, "%02x", sll->sll_addr[i]);
				wpos += strlen(wbuf + wpos);
			}
		}

		if (sll->sll_ifindex > 0) {
			snprintf(wbuf + wpos, wlen - wpos, "%%if%d", sll->sll_ifindex);
			wpos += strlen(wbuf + wpos);
		}

		return wbuf;
	}

	port = fm_address_get_port(ap);
	if (port == 0) {
		return inet_ntop(ap->ss_family, raw_addr, abuf[index], sizeof(abuf[index]));
	} else {
		char tmpbuf[128];

		if (!inet_ntop(ap->ss_family, raw_addr, tmpbuf, sizeof(tmpbuf)))
			return NULL;

		if (ap->ss_family == AF_INET6)
			snprintf(abuf[index], sizeof(abuf[index]), "[%s]:%u", tmpbuf, port);
		else
			snprintf(abuf[index], sizeof(abuf[index]), "%s:%u", tmpbuf, port);
		return abuf[index];
	}
}

bool
fm_address_equal(const fm_address_t *a, const fm_address_t *b, bool with_port)
{
	if (a->ss_family != b->ss_family)
		return false;

	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *sina = (const struct sockaddr_in *) a;
		const struct sockaddr_in *sinb = (const struct sockaddr_in *) b;

		if (with_port && sina->sin_port != sinb->sin_port)
			return false;

		return sina->sin_addr.s_addr == sinb->sin_addr.s_addr;
	} else
	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sixa = (const struct sockaddr_in6 *) a;
		const struct sockaddr_in6 *sixb = (const struct sockaddr_in6 *) b;

		if (with_port && sixa->sin6_port != sixb->sin6_port)
			return false;

		return !memcmp(&sixa->sin6_addr, &sixb->sin6_addr, 16);
	}

	return false;
}

/*
 * Helper functions for hostname resolution
 */
static bool
fm_address_resolve(const char *hostname, fm_address_array_t *array)
{
	struct addrinfo hints, *result = NULL, *pos;
	fm_address_t address;
	int err;

	if (fm_try_parse_address(hostname, &address)) {
		if (!fm_address_generator_address_eligible(&address)) {
			fm_log_warning("Ignoring address %s because it's from the wrong family", hostname);
			return true;
		}

		fm_address_array_append(array, &address);
		return true;
	}

	memset(&hints, 0, sizeof(hints));

	/* only resolve addresses of a given family */
	hints.ai_family = fm_global.address_generation.only_family;

	err = getaddrinfo(hostname, NULL, &hints, &result);

	if (err < 0) {
		fm_log_error("Unable to resolve \"%s\": %s", hostname, gai_strerror(err));
		return false;
	}

	for (pos = result; pos; pos = pos->ai_next) {
		if (pos->ai_addrlen > sizeof(address))
			continue;
		memset(&address, 0, sizeof(address));
		memcpy(&address, pos->ai_addr, pos->ai_addrlen);

		fm_address_array_append(array, &address);
	}

	freeaddrinfo(result);
	return true;
}

/*
 * The "simple" enumerator that is initialized with a single address
 */
struct fm_simple_address_enumerator {
	fm_address_enumerator_t base;

	struct sockaddr_storage	addr;
};

static bool		fm_simple_address_enumerator_get_one(fm_address_enumerator_t *, fm_address_t *);

static const struct fm_address_enumerator_ops fm_simple_address_enumerator_ops = {
	.obj_size	= sizeof(struct fm_simple_address_enumerator),
	.name		= "simple",
	.destroy	= NULL,
	.get_one_address= fm_simple_address_enumerator_get_one,
};

static fm_address_enumerator_t *fm_create_simple_address_enumerator_work(const char *addr_string, const fm_address_t *addr);

#define NEW_ADDRESS_ENUMERATOR(_typename) \
	((struct _typename *) fm_address_enumerator_alloc(&_typename ## _ops))

/*
 * Note, when hostname resolution is supported, this function will return a list of
 * generators rather than a single one.
 */
fm_address_enumerator_t *
fm_create_simple_address_enumerator(const char *addr_string)
{
	fm_address_array_t addrs = { 0 };
	fm_address_enumerator_t *result = NULL;
	unsigned int i;

	if (!fm_address_resolve(addr_string, &addrs))
		return NULL;

	for (i = 0; i < addrs.count; ++i) {
		fm_address_t *addr = &addrs.elements[i];
		fm_address_enumerator_t *agen;

		agen = fm_create_simple_address_enumerator_work(fm_address_format(addr), addr);
		if (agen != NULL) {
			result = agen;

			if (!fm_global.address_generation.try_all)
				break;
		}
	}

	fm_address_array_destroy(&addrs);

	return result;
}

static fm_address_enumerator_t *
fm_create_simple_address_enumerator_work(const char *addr_string, const fm_address_t *addr)
{
	struct fm_simple_address_enumerator *sagen;

	sagen = NEW_ADDRESS_ENUMERATOR(fm_simple_address_enumerator);
	sagen->addr = *addr;

	return &sagen->base;
}

bool
fm_simple_address_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	struct fm_simple_address_enumerator *sagen = (struct fm_simple_address_enumerator *) agen;
	if (sagen->addr.ss_family == AF_UNSPEC)
		return false;

	*ret = sagen->addr;
	sagen->addr.ss_family = AF_UNSPEC;

	return true;
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

	uint32_t	ipv4_net;
	unsigned int	prefixlen;

	/* these should not exceed the size of an IPv4 address */
	uint32_t	next_host;
	uint32_t	last_host;
};

static bool		fm_ipv4_network_enumerator_get_one(fm_address_enumerator_t *, fm_address_t *);

static const struct fm_address_enumerator_ops fm_ipv4_network_enumerator_ops = {
	.obj_size	= sizeof(struct fm_ipv4_network_enumerator),
	.name		= "ipv4-net",
	.destroy	= NULL,
	.get_one_address= fm_ipv4_network_enumerator_get_one,
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

bool
fm_ipv4_network_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	struct fm_ipv4_network_enumerator *sagen = (struct fm_ipv4_network_enumerator *) agen;
	struct sockaddr_in *sin;
	uint32_t addr;

	if (sagen->next_host > sagen->last_host || sagen->next_host == 0)
		return false;

	addr = sagen->ipv4_net | sagen->next_host++;

	memset(ret, 0, sizeof(*ret));

	sin = (struct sockaddr_in *) ret;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(addr);

	return true;
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
