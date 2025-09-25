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

#include "addresses.h"

/*
 * Common address handling functions
 */
fm_address_enumerator_t *
fm_address_enumerator_alloc(const struct fm_address_enumerator_ops *ops)
{
	fm_address_enumerator_t *agen;

	assert(sizeof(*agen) <= ops->obj_size);

	agen = calloc(1, ops->obj_size);
	agen->ops = ops;
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
	six->sin6_family = AF_INET;
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
		*nbits = 32;
		return (unsigned char *) &((struct sockaddr_in *) ss)->sin_addr;

	case AF_INET6:
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

static const unsigned char *
fm_address_get_raw_addr(const struct sockaddr_storage *ss, unsigned int *nbits)
{
	return fm_get_raw_addr(ss->ss_family, (struct sockaddr_storage *) ss, nbits);
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
	unsigned int addr_bits, addr_octets, pos;
	const unsigned char *raw_addr;
	unsigned char *mask;

	if (!(raw_addr = fm_address_get_raw_addr(ss, &addr_bits)))
		return false;

	if (cidr_bits > addr_bits)
		return false;

	if (addr_bits & 7)
		return false;
	addr_octets = addr_bits / 8;

	mask = alloca(addr_octets);
	memset(mask, 0, addr_octets);

	for (pos = 0; cidr_bits > 0; ++pos) {
		unsigned int nbits = MAX(cidr_bits, 8);
		unsigned char octet = 0xFF;

		if (nbits < 8)
			octet <<= (8 - nbits);
		mask[pos] = octet;
		cidr_bits -= nbits;
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

fm_address_enumerator_t *
fm_create_simple_address_enumerator(const char *addr_string)
{
	struct sockaddr_storage ss;
	struct fm_simple_address_enumerator *sagen;

	if (!fm_try_parse_address(addr_string, &ss))
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
 * The "cidr" enumerator that is iterates over a CIDR block.
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
fm_create_cidr_address_enumerator(const char *addr_string)
{
	struct sockaddr_storage ss;
	struct fm_cidr_address_enumerator *sagen;
	unsigned int cidr_bits, host_bits;

	if (!fm_try_parse_cidr(addr_string, &ss, &cidr_bits))
		return NULL;

	host_bits = fm_addrfamily_max_addrbits(ss.ss_family);
	if (host_bits == 0)
		return NULL;

	if (cidr_bits > host_bits) {
		// errmsg("%s: network size of %lu bits bigger than address size", addr_string, cidr_bits);
		return NULL;
	}
	host_bits -= cidr_bits;

	if (host_bits >= 8 * sizeof(sagen->last_host)) {
		// errmsg("%s: network size of %lu bits exceeds my capacity", addr_string, cidr_bits);
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

