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
#include <linux/if_packet.h>

#include "addresses.h"
#include "network.h"

extern const fm_address_prefix_t *	fm_address_find_local_prefix(const fm_address_t *);

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

const char *
fm_address_format(const fm_address_t *ap)
{
	static char	abuf[4][128];
	static unsigned int aindex;
	unsigned int index, port;
	const unsigned char *raw_addr;

	if (!(raw_addr = fm_address_get_raw_addr(ap, NULL)))
		return "<unsupported address family>";

	index = aindex;
	aindex = (aindex + 1) % 4;

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

#define NEW_ADDRESS_ENUMERATOR(_typename) \
	((struct _typename *) fm_address_enumerator_alloc(&_typename ## _ops))

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
fm_create_cidr_address_enumerator(const char *addr_string, const fm_addr_gen_options_t *opts)
{
	struct sockaddr_storage ss;
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

	if (ss.ss_family == AF_INET6) {
		const fm_address_prefix_t *local_prefix;

		local_prefix = fm_address_find_local_prefix(&ss);
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
	unsigned int i;

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

		if (ifa->ifa_netmask) {
			pfxlen = fm_mask_to_prefix(ifa->ifa_netmask);

			/* The loopback "network" is really just a single address */
			if (ifa->ifa_flags & IFF_LOOPBACK)
				pfxlen = fm_addrfamily_max_addrbits(ifa->ifa_addr->sa_family);

			fm_log_debug("  %-8s %4s %s/%u\n", ifa->ifa_name, state,
					fm_address_format((fm_address_t *) ifa->ifa_addr), pfxlen);
		} else {
			fm_log_debug("  %-8s %4s %s\n", ifa->ifa_name, state,
					fm_address_format((fm_address_t *) ifa->ifa_addr));
		}

		if (ifa->ifa_addr->sa_family == AF_PACKET) {
			fm_interface_add(ifa->ifa_name,
						(const struct sockaddr_ll *) ifa->ifa_addr);
		} else {
			entry = fm_address_prefix_array_append(&fm_local_address_prefixes,
						(fm_address_t *) ifa->ifa_addr, pfxlen);

			entry->ifname = strdup(ifa->ifa_name);
			entry->source_addr = *(fm_address_t *) ifa->ifa_addr;

			fm_prefix_to_mask(ifa->ifa_addr->sa_family, pfxlen, entry->raw_mask, sizeof(entry->raw_mask));
		}
	}

	freeifaddrs(head);

	for (i = 0; i < fm_local_address_prefixes.count; ++i) {
		fm_address_prefix_t *entry = &fm_local_address_prefixes.elements[i];

		if (entry->ifname == NULL)
			continue;

		entry->device = fm_interface_by_name(entry->ifname);
	}
}

const fm_address_prefix_t *
fm_address_find_local_prefix(const fm_address_t *addr)
{
	const unsigned char *raw_addr1;
	const unsigned char *raw_addr2;
	unsigned int i, k, addr_bits, noctets;

	raw_addr1 = fm_address_get_raw_addr(addr, &addr_bits);
	if (raw_addr1 == NULL)
		return NULL;

	noctets = addr_bits / 8;

	for (i = 0; i < fm_local_address_prefixes.count; ++i) {
		fm_address_prefix_t *entry = &fm_local_address_prefixes.elements[i];
		int xor = 0;

		if (entry->address.ss_family != addr->ss_family)
			continue;

		raw_addr2 = fm_address_get_raw_addr(&entry->address, NULL);
		for (k = 0; k < noctets && xor == 0; ++k)
			xor = entry->raw_mask[k] & (raw_addr1[k] ^ raw_addr2[k]);

		if (xor == 0)
			return entry;
	}

	return NULL;
}

const fm_interface_t *
fm_address_find_local_device(const fm_address_t *addr)
{
	const fm_address_prefix_t *local_prefix;

	/* Find the local address prefix and the device it lives on */
	if (!(local_prefix = fm_address_find_local_prefix(addr)))
		return NULL;

	return local_prefix->device;
}
