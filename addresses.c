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

#include <net/if.h>
#include <ifaddrs.h>

#include "addresses.h"
#include "network.h"

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

static inline unsigned int
fm_addrfamily_max_addrbits(int af)
{
	switch (af) {
	case AF_INET:
		return 32;
	case AF_INET6:
		return 128;
	}

	return 0;
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

unsigned int
fm_addrfamily_sockaddr_size(int family)
{
	switch (family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);

	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	}

	return 0;
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

static bool
fm_address_clear_host_bits(struct sockaddr_storage *ss, unsigned int cidr_bits)
{
	unsigned int host_bits, addr_bits, addr_octets, pos;
	unsigned char *raw_addr;

	if (!(raw_addr = fm_get_raw_addr(ss->ss_family, ss, &addr_bits)))
		return false;

	if (cidr_bits > addr_bits)
		return false;

	if (addr_bits & 7)
		return false;
	addr_octets = addr_bits / 8;

	host_bits = addr_bits - cidr_bits;

	for (pos = addr_octets; pos--; host_bits -= 8) {
		if (host_bits < 8) {
			raw_addr[pos] &= 0xff << host_bits;
			break;
		}
		raw_addr[pos] = 0;
	}

	return true;
}

static bool
fm_address_combine_net_host(struct sockaddr_storage *ret,
		const struct sockaddr_storage *cidr_net,
		uint32_t host)
{
	unsigned char *raw_host_addr;
	unsigned int addr_bits, i;

	*ret = *cidr_net;

	if (!(raw_host_addr = fm_get_raw_addr(ret->ss_family, ret, &addr_bits)))
		return false;

	if (addr_bits > 32) {
		unsigned int skip = (addr_bits - 32) / 8;

		raw_host_addr += skip;
	}

	for (i = 0; i < 4; ++i)
		raw_host_addr[i] |= 0xFF & (host >> (24 - 8 * i));

	return true;
}

const char *
fm_address_format(const fm_address_t *ap)
{
	static char	abuf[4][128];
	static unsigned int aindex;
	unsigned int port;

	const unsigned char *raw_addr;
	unsigned int nbits, index;

	if (!(raw_addr = fm_address_get_raw_addr(ap, &nbits)))
		return "<unsupported address family>";

	index = aindex;
	aindex = (aindex + 1) % 4;

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

#define NEW_ADDRESS_ENUMERATOR(_typename) \
	((struct _typename *) fm_address_enumerator_alloc(&_typename ## _ops))

/*
 * Note, when hostname resolution is supported, this function will return a list of
 * generators rather than a single one.
 */
fm_address_enumerator_t *
fm_create_simple_address_enumerator(const char *addr_string, const fm_addr_gen_options_t *opts)
{
	struct sockaddr_storage ss;
	struct fm_simple_address_enumerator *sagen;

	if (!fm_try_parse_address(addr_string, &ss))
		return NULL;

	if (opts != NULL && opts->only_family && opts->only_family != ss.ss_family)
		return NULL;

	sagen = NEW_ADDRESS_ENUMERATOR(fm_simple_address_enumerator);
	sagen->addr = ss;

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
 * The "cidr" enumerator that iterates over a CIDR block.
 */
struct fm_cidr_address_enumerator {
	fm_address_enumerator_t base;

	struct sockaddr_storage	cidr_net;
	unsigned int	cidr_bits;

	/* these should not exceed the size of an IPv4 address */
	uint32_t	next_host;
	uint32_t	last_host;
};

static bool		fm_cidr_address_enumerator_get_one(fm_address_enumerator_t *, fm_address_t *);

static const struct fm_address_enumerator_ops fm_cidr_address_enumerator_ops = {
	.obj_size	= sizeof(struct fm_cidr_address_enumerator),
	.name		= "cidr",
	.destroy	= NULL,
	.get_one_address= fm_cidr_address_enumerator_get_one,
};

#define NEW_ADDRESS_ENUMERATOR(_typename) \
	((struct _typename *) fm_address_enumerator_alloc(&_typename ## _ops))

fm_address_enumerator_t *
fm_create_cidr_address_enumerator(const char *addr_string, const fm_addr_gen_options_t *opts)
{
	struct sockaddr_storage ss;
	struct fm_cidr_address_enumerator *sagen;
	unsigned int cidr_bits, host_bits;

	if (!fm_try_parse_cidr(addr_string, &ss, &cidr_bits)) {
		/* TBD: resolve hostname, apply opts to filter which addresses to use */
		return NULL;
	}

	if (opts != NULL && opts->only_family && opts->only_family != ss.ss_family)
		return NULL;

	host_bits = fm_addrfamily_max_addrbits(ss.ss_family);
	if (host_bits == 0)
		return NULL;

	if (cidr_bits > host_bits) {
		fm_log_error("%s: network size of %lu bits bigger than address size", addr_string, cidr_bits);
		return NULL;
	}
	host_bits -= cidr_bits;

	if (host_bits >= 8 * sizeof(sagen->last_host)) {
		fm_log_error("%s: network size of %lu bits exceeds my capacity", addr_string, cidr_bits);
		return NULL;
	}

	fm_address_clear_host_bits(&ss, cidr_bits);

	sagen = NEW_ADDRESS_ENUMERATOR(fm_cidr_address_enumerator);
	sagen->cidr_net = ss;
	sagen->cidr_bits = cidr_bits;
	sagen->next_host = 1;
	sagen->last_host = (1 << host_bits) - 1;

	return &sagen->base;
}

bool
fm_cidr_address_enumerator_get_one(fm_address_enumerator_t *agen, fm_address_t *ret)
{
	struct fm_cidr_address_enumerator *sagen = (struct fm_cidr_address_enumerator *) agen;

	if (sagen->next_host > sagen->last_host || sagen->next_host == 0)
		return false;

	fm_address_combine_net_host(ret, &sagen->cidr_net, sagen->next_host);
	sagen->next_host += 1;

	return true;
}

/*
 * addr prefix lists
 */
fm_address_prefix_t *
fm_address_prefix_array_append(fm_address_prefix_array_t *array, const fm_address_t *addr, unsigned int pfxlen)
{
	fm_address_prefix_t *entry;

	if ((array->count % 8) == 0) 
		array->elements = realloc(array->elements, (array->count + 8) * sizeof(array->elements[0]));

	entry = &array->elements[array->count++];
	memset(entry, 0, sizeof(*entry));

	entry->address = *addr;
	entry->pfxlen = pfxlen;

	return entry;
}

/*
 * Discovery of local addresses
 */
static fm_address_prefix_array_t	fm_local_address_prefixes;

static inline unsigned int
fm_mask_to_prefix(const struct sockaddr *mask)
{
	const unsigned char *raw_mask;
	unsigned int pfxlen = 0, addr_bits;

	if (mask == NULL)
		return 0;

	raw_mask = fm_get_raw_addr(mask->sa_family, (struct sockaddr_storage *) mask, &addr_bits);
	if (raw_mask == 0)
		return 0;

	for (pfxlen = 0; pfxlen < addr_bits; pfxlen += 8) {
		unsigned char octet = *raw_mask++;

		if (octet == 0xFF)
			continue;

		while (octet & 0x80) {
			octet <<= 1;
			pfxlen++;
		}
		break;
	}

	return pfxlen;
}

static inline bool
fm_prefix_to_mask(int af, unsigned int pfxlen, unsigned char *mask, unsigned int size)
{
	unsigned int addr_bits, noctets;

	addr_bits = fm_addrfamily_max_addrbits(af);
	if (addr_bits == 0)
		return false;

	if (pfxlen > addr_bits)
		return false;

	noctets = addr_bits / 8;
	if (noctets > size)
		return false;

	memset(mask, 0, size);

	while (pfxlen) {
		if (pfxlen < 8) {
			*mask++ = (0xFF00 >> pfxlen);
			break;
		}

		*mask++ = 0xFF;
		pfxlen -= 8;
	}

	return true;
}

void
fm_address_discover_local(void)
{
	struct ifaddrs *head, *ifa;

	if (getifaddrs(&head) < 0)
		fm_log_fatal("getifaddrs: %m");

	fm_log_debug("Discovering local interfaces and addresses");

	for (ifa = head; ifa; ifa = ifa->ifa_next) {
		fm_address_prefix_t *entry;
		const char *state = "down";
		unsigned int pfxlen = 0;

		if (ifa->ifa_flags & IFF_LOOPBACK)
			state = "loop";
		else
		if (ifa->ifa_flags & IFF_UP)
			state = "up";

		if (ifa->ifa_flags & IFF_POINTOPOINT) {
			/* skip for now */
			continue;
		}

		pfxlen = fm_mask_to_prefix(ifa->ifa_netmask);

		/* The loopback "network" is really just a single address */
		if (ifa->ifa_flags & IFF_LOOPBACK)
			pfxlen = fm_addrfamily_max_addrbits(ifa->ifa_addr->sa_family);

		fm_log_debug("  %-8s %4s %s/%u\n", ifa->ifa_name, state,
				fm_address_format((fm_address_t *) ifa->ifa_addr), pfxlen);

		entry = fm_address_prefix_array_append(&fm_local_address_prefixes,
					(fm_address_t *) ifa->ifa_addr, pfxlen);

		entry->device = strdup(ifa->ifa_name);
		entry->source_addr = *(fm_address_t *) ifa->ifa_addr;

		fm_prefix_to_mask(ifa->ifa_addr->sa_family, pfxlen, entry->raw_mask, sizeof(entry->raw_mask));
	}

	freeifaddrs(head);
}

