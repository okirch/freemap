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
#include <linux/if_arp.h>

#include "addresses.h"
#include "network.h"
#include "logging.h"

#if AF_UNSPEC >= 32
# error "AF_UNSPEC is too large, fix this code"
#endif
#if AF_INET >= 32
# error "AF_INET is too large, fix this code"
#endif
#if AF_INET6 >= 32
# error "AF_INET6 is too large, fix this code"
#endif

extern const fm_address_prefix_t *	fm_local_prefix_for_address(const fm_address_t *);

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

bool
fm_address_parse(const char *addr_string, fm_address_t *ss)
{
	return fm_try_parse_ipv4_address(addr_string, (struct sockaddr_in *) ss)
	    || fm_try_parse_ipv6_address(addr_string, (struct sockaddr_in6 *) ss);
}

/*
 * Parse a prefix in add/len notation
 */
bool
fm_address_prefix_parse(const char *addr_string, fm_address_prefix_t *prefix)
{
	char *addr_copy, *slash, *end;
	unsigned int nbits;
	bool ok = false;

	memset(prefix, 0, sizeof(*prefix));

	addr_copy = strdup(addr_string);
	if (addr_copy == NULL)
		return false;

	if ((slash = strchr(addr_copy, '/')) == NULL)
		goto out;

	*slash++ = '\0';
	if (!fm_address_parse(addr_copy, &prefix->address))
		goto out;

	nbits = strtoul(slash, &end, 0);
	if (*end)
		goto out;

	if (nbits > fm_addrfamily_max_addrbits(prefix->address.family))
		goto out;

	prefix->pfxlen = nbits;

	ok = true;
out:
	free(addr_copy);
	return ok;
}

static unsigned char *
fm_get_raw_addr(int af, fm_address_t *ss, unsigned int *nbits)
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
fm_address_get_port(const fm_address_t *ss)
{
	switch (ss->family) {
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
fm_address_set_port(fm_address_t *ss, unsigned short port)
{
	switch (ss->family) {
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
fm_address_get_raw_addr(const fm_address_t *ss, unsigned int *nbits)
{
	return fm_get_raw_addr(ss->family, (fm_address_t *) ss, nbits);
}

bool
fm_address_set_raw_addr(fm_address_t *addr, int family, const unsigned char *src_raw, size_t len)
{
	unsigned char *dst_raw;
	unsigned int nbits;

	memset(addr, 0, sizeof(*addr));
	if ((dst_raw = fm_get_raw_addr(family, addr, &nbits)) == NULL)
		return false;

	if (len < nbits / 8)
		return false;

	addr->family = family;
	memcpy(dst_raw, src_raw, nbits / 8);
	return true;
}

void
fm_address_set_ipv4(fm_address_t *ss, u_int32_t raw_addr)
{
	memset(ss, 0, sizeof(*ss));
	ss->family = AF_INET;
	((struct sockaddr_in *) ss)->sin_addr.s_addr = raw_addr;
}

bool
fm_address_get_ipv4(const fm_address_t *addr, u_int32_t *ip_addr)
{
	if (addr->family != AF_INET)
		return false;

	*ip_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
	return true;
}

void
fm_address_set_ipv6(fm_address_t *ss, const struct in6_addr *raw_addr)
{
	memset(ss, 0, sizeof(*ss));
	ss->family = AF_INET6;
	((struct sockaddr_in6 *) ss)->sin6_addr = *raw_addr;
}

bool
fm_address_get_ipv6(const fm_address_t *addr, struct in6_addr *raw_addr)
{
	if (addr->family != AF_INET6)
		return false;

	*raw_addr = ((struct sockaddr_in6 *) addr)->sin6_addr;
	return true;
}

void
fm_address_set_ipv4_local_broadcast(fm_address_t *ss)
{
	fm_address_set_ipv4(ss, 0xffffffff);
}

void
fm_address_set_ipv6_all_hosts_multicast(fm_address_t *ss)
{
	static struct in6_addr all_hosts = { .s6_addr =  { 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };

	fm_address_set_ipv6(ss, &all_hosts);
}

bool
fm_address_is_ipv6_link_local(const fm_address_t *addr)
{
	struct sockaddr_in6 *six;

	if (addr->family != AF_INET6)
		return false;

	six = (struct sockaddr_in6 *) addr;
	return ntohs(six->sin6_addr.s6_addr16[0]) == 0xFE80;
}

bool
fm_address_ipv6_update_scope_id(fm_address_t *ss, int ifindex)
{
	struct sockaddr_in6 *six;

	if (!fm_address_is_ipv6_link_local(ss))
		return false;

	six = (struct sockaddr_in6 *) ss;
	six->sin6_scope_id = ifindex;
	return true;
}

bool
fm_address_link_update_upper_protocol(fm_address_t *addr, int family)
{
	struct sockaddr_ll *sll;

	if (!(sll = fm_address_to_link(addr)))
		return false;

	if (sll->sll_hatype == ARPHRD_ETHER) {
		if (family == AF_INET) {
			sll->sll_protocol = htons(ETH_P_IP);
			return true;
		}
		if (family == AF_INET6) {
			sll->sll_protocol = htons(ETH_P_IPV6);
			return true;
		}
	}

	return false;
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
		snprintf(abuf[index], sizeof(abuf[index]), "<unsupported address family %d>", ap->family);
		return abuf[index];
	}

	if (ap->family == AF_PACKET) {
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
		return inet_ntop(ap->family, raw_addr, abuf[index], sizeof(abuf[index]));
	} else {
		char tmpbuf[128];

		if (!inet_ntop(ap->family, raw_addr, tmpbuf, sizeof(tmpbuf)))
			return NULL;

		if (ap->family == AF_INET6)
			snprintf(abuf[index], sizeof(abuf[index]), "[%s]:%u", tmpbuf, port);
		else
			snprintf(abuf[index], sizeof(abuf[index]), "%s:%u", tmpbuf, port);
		return abuf[index];
	}
}

bool
fm_address_equal(const fm_address_t *a, const fm_address_t *b, bool with_port)
{
	if (a->family != b->family)
		return false;

	if (a->family == AF_INET) {
		const struct sockaddr_in *sina = (const struct sockaddr_in *) a;
		const struct sockaddr_in *sinb = (const struct sockaddr_in *) b;

		if (with_port && sina->sin_port != sinb->sin_port)
			return false;

		return sina->sin_addr.s_addr == sinb->sin_addr.s_addr;
	} else
	if (a->family == AF_INET6) {
		const struct sockaddr_in6 *sixa = (const struct sockaddr_in6 *) a;
		const struct sockaddr_in6 *sixb = (const struct sockaddr_in6 *) b;

		if (with_port && sixa->sin6_port != sixb->sin6_port)
			return false;

		return !memcmp(&sixa->sin6_addr, &sixb->sin6_addr, 16);
	}

	return false;
}

bool
fm_address_prefix_match_address(const fm_address_prefix_t *prefix, const fm_address_t *addr,
			const unsigned char *raw_mask, unsigned int raw_mask_len)
{
	const unsigned char *raw_addr1, *raw_addr2;
	unsigned char tmp_raw_mask[16];
	unsigned int addr_bits, noctets;
	unsigned int k, xor = 0;

	if (prefix->address.family != addr->family)
		return false;

	/* default route */
	if (prefix->pfxlen == 0)
		return true;

	raw_addr1 = fm_address_get_raw_addr(addr, &addr_bits);
	if (raw_addr1 == NULL)
		return false;

	raw_addr2 = fm_address_get_raw_addr(&prefix->address, NULL);
	if (raw_addr2 == NULL)
		return false;

	if (raw_mask == NULL) {
		if (!fm_address_mask_from_prefixlen(prefix->address.family, prefix->pfxlen, tmp_raw_mask, sizeof(tmp_raw_mask)))
			return false;
		raw_mask = tmp_raw_mask;
	}

	if (prefix->pfxlen > addr_bits)
		return false; /* you're weird */

	noctets = (prefix->pfxlen + 7) / 8;
	for (k = 0; k < noctets && xor == 0; ++k)
		xor = raw_mask[k] & (raw_addr1[k] ^ raw_addr2[k]);

	return (xor == 0);
}

bool
fm_address_array_append_unique(fm_address_array_t *array, const fm_address_t *address)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		if (fm_address_equal(&array->elements[i], address, false))
			return false;
	}

	fm_address_array_append(array, address);
	return true;
}

/*
 * Helper functions for hostname resolution
 */
bool
fm_address_resolve(const char *hostname, fm_address_array_t *array, bool check_eligibility)
{
	struct addrinfo hints, *result = NULL, *pos;
	fm_address_t address;
	uint32_t seen_af_mask = 0;
	int err;

	if (fm_address_parse(hostname, &address)) {
		if (check_eligibility && !fm_address_generator_address_eligible(&address)) {
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

		/* Skip address families we've been asked to ignore */
		if (check_eligibility && !fm_address_generator_address_eligible(&address))
			continue;

		/* If try_all is set, really try all addresses. Otherwise, use at
		 * most one of each address family. */
		if (!fm_global.address_generation.try_all) {
			uint32_t af_mask = (1 << pos->ai_family);

			if (seen_af_mask & af_mask)
				continue;
			seen_af_mask |= af_mask;
		}

		/* Record the hostname we used in the query rather than some
		 * weird canonical name (which could be something in a cloud). */
		fm_host_asset_update_hostname_by_address(&address, hostname);

		fm_address_array_append_unique(array, &address);
	}

	freeaddrinfo(result);
	return true;
}
