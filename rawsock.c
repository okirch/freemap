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
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <string.h>

#include "freemap.h"
#include "addresses.h"
#include "lists.h"

struct fm_interface {
	struct hlist		link;
	char *			name;
	int			ifindex;
	struct sockaddr_ll	lladdr;
};

static struct hlist_head	fm_interface_list = { .first = NULL, };

typedef struct fm_raw_socket_cache {
	struct hlist		link;
	struct sockaddr_ll	lladdr;
	fm_socket_t *		sock;
	fm_protocol_t *		protocol;
} fm_raw_socket_cache_t;

static struct hlist_head	raw_sock_cache = { .first = NULL, };

fm_socket_t *
fm_raw_socket_get(const fm_address_t *addr, fm_protocol_t *driver)
{
	const struct sockaddr_ll *lladdr;
	hlist_iterator_t it;
	fm_raw_socket_cache_t *entry;
	fm_socket_t *sock;

	if (addr->ss_family != AF_PACKET) {
		fm_log_error("Cannot create raw socket for address %s", fm_address_format(addr));
		return NULL;
	}

	lladdr = (const struct sockaddr_ll *) addr;

	hlist_iterator_init(&it, &raw_sock_cache);
	while ((entry = hlist_iterator_next(&it)) != NULL) {
		if (entry->protocol == driver
		 && !memcmp(&entry->lladdr, lladdr, sizeof(*lladdr)))
			return entry->sock;
	}

	sock = fm_socket_create(PF_PACKET, SOCK_DGRAM, lladdr->sll_protocol, driver);

	if (!fm_socket_bind(sock, (const fm_address_t *) lladdr)) {
		fm_log_error("Cannot bind raw socket to address %s: %m",
				fm_address_format((fm_address_t *) &lladdr));
		fm_socket_free(sock);
		return NULL;
	}

	entry = calloc(1, sizeof(*entry));
	entry->lladdr = *lladdr;
	entry->sock = sock;
	entry->protocol = driver;

	hlist_append(&raw_sock_cache, &entry->link);

	return sock;
}

/*
 * Manage list of interfaces
 */
void
fm_interface_add(const char *name, const struct sockaddr_ll *lladdr)
{
	fm_interface_t *nic;

	if (lladdr->sll_family != AF_PACKET) {
		fm_log_error("%s: bad address family %d", __func__, lladdr->sll_family);
		return;
	}

	nic = calloc(1, sizeof(*nic));
	nic->name = strdup(name);
	nic->ifindex = lladdr->sll_ifindex;
	nic->lladdr = *lladdr;

	hlist_append(&fm_interface_list, &nic->link);
}

const fm_interface_t *
fm_interface_by_name(const char *ifname)
{
	hlist_iterator_t it;
	fm_interface_t *nic;

	if (ifname == NULL)
		return NULL;

	hlist_iterator_init(&it, &fm_interface_list);
	while ((nic = hlist_iterator_next(&it)) != NULL) {
		if (!strcmp(nic->name, ifname))
			break;
	}

	return nic;
}

const fm_interface_t *
fm_interface_by_index(unsigned int ifindex)
{
	hlist_iterator_t it;
	fm_interface_t *nic;

	hlist_iterator_init(&it, &fm_interface_list);
	while ((nic = hlist_iterator_next(&it)) != NULL) {
		if (nic->ifindex == ifindex)
			break;
	}

	return nic;
}

bool
fm_interface_get_lladdr(const fm_interface_t *nic, struct sockaddr_ll *lladdr)
{
	if (nic == NULL || lladdr == NULL)
		return false;

	*lladdr = nic->lladdr;
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

	raw_mask = fm_address_get_raw_addr((struct sockaddr_storage *) mask, &addr_bits);
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

bool
fm_address_find_local_address(const fm_interface_t *nic, int af, fm_address_t *ret_addr)
{
	unsigned int i;

	for (i = 0; i < fm_local_address_prefixes.count; ++i) {
		fm_address_prefix_t *entry = &fm_local_address_prefixes.elements[i];

		if (entry->device == nic && entry->address.ss_family == af) {
			*ret_addr = entry->address;
			return true;
		}
	}

	return false;
}
