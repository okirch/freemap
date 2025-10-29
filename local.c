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
#include "neighbor.h"
#include "routing.h"
#include "lists.h"

static struct hlist_head	fm_interface_list = { .first = NULL, };

typedef struct fm_raw_socket_cache {
	struct hlist		link;
	int			sotype;
	struct sockaddr_ll	lladdr;
	fm_socket_t *		sock;
	fm_protocol_t *		protocol;
} fm_raw_socket_cache_t;

static struct hlist_head	raw_sock_cache = { .first = NULL, };
static fm_address_prefix_array_t fm_local_address_prefixes;


fm_socket_t *
fm_raw_socket_get(const fm_address_t *addr, fm_protocol_t *driver, int sotype)
{
	const struct sockaddr_ll *lladdr;
	hlist_iterator_t it;
	fm_raw_socket_cache_t *entry;
	fm_socket_t *sock;

	if (sotype < 0)
		sotype = SOCK_DGRAM;

	if (!(lladdr = fm_address_to_link_const(addr))) {
		fm_log_error("Cannot create raw socket for address %s", fm_address_format(addr));
		return NULL;
	}

	hlist_iterator_init(&it, &raw_sock_cache);
	while ((entry = hlist_iterator_next(&it)) != NULL) {
		if (entry->protocol == driver
		 && entry->sotype == sotype
		 && !memcmp(&entry->lladdr, lladdr, sizeof(*lladdr)))
			return entry->sock;
	}


	sock = fm_socket_create(PF_PACKET, sotype, lladdr->sll_protocol, driver);

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
fm_interface_t *
fm_interface_alloc(int ifindex, int hatype)
{
	fm_interface_t *nic;

	nic = calloc(1, sizeof(*nic));
	nic->ifindex = ifindex;

	nic->lladdr.sll_family = AF_PACKET;
	nic->lladdr.sll_hatype = hatype;
	nic->llbcast.sll_family = AF_PACKET;
	nic->llbcast.sll_hatype = hatype;

	nic->neighbor_cache = fm_neighbor_cache_create(nic->ifindex);

	hlist_append(&fm_interface_list, &nic->link);

	return nic;
}

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

	nic->neighbor_cache = fm_neighbor_cache_create(nic->ifindex);

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

const fm_interface_t *
fm_interface_by_address(const fm_address_t *addr)
{
	const fm_address_prefix_t *local_prefix;

	/* Find the local address prefix and the device it lives on */
	if (!(local_prefix = fm_local_prefix_for_address(addr)))
		return NULL;

	return local_prefix->device;
}

const fm_address_prefix_t *
fm_local_prefix_for_address(const fm_address_t *addr)
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

bool
fm_interface_get_network_address(const fm_interface_t *nic, int af, fm_address_t *ret_addr)
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


bool
fm_interface_get_lladdr(const fm_interface_t *nic, struct sockaddr_ll *lladdr)
{
	if (nic == NULL || lladdr == NULL)
		return false;

	*lladdr = nic->lladdr;
	return true;
}

const char *
fm_interface_get_name(const fm_interface_t *nic)
{
	if (nic == NULL)
		return NULL;

	return nic->name;
}

/*
 * Neighbor cache
 */
extern void
fm_local_cache_arp_entry(int ifindex, u_int32_t ipaddr, const struct sockaddr_ll *lladdr)
{
	fm_address_t network_address;
	const fm_interface_t *nic;

	fm_address_set_ipv4(&network_address, ipaddr);

	if ((nic = fm_interface_by_index(ifindex)) == NULL) {
		fm_log_error("%s: no interface for index %u", __func__, ifindex);
		return;
	}

	if (lladdr->sll_family != AF_PACKET || lladdr->sll_ifindex != ifindex) {
		fm_log_error("%s: link address for %s has wrong ifindex %u", __func__,
				fm_address_format(&network_address),
				lladdr->sll_ifindex);
		return;
	}

	fm_neighbor_cache_update(nic->neighbor_cache, &network_address, lladdr);
}

fm_neighbor_t *
fm_interface_get_neighbor(const fm_interface_t *nic, const fm_address_t *network_address, bool create)
{
	if (nic->neighbor_cache == NULL)
		return NULL;

	return fm_neighbor_cache_find_entry(nic->neighbor_cache, network_address, create);
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
/* should probably go to address.c */
unsigned int
fm_address_mask_to_prefixlen(const struct sockaddr *mask)
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

/* should probably go to address.c */
bool
fm_address_mask_from_prefixlen(int af, unsigned int pfxlen, unsigned char *mask, unsigned int size)
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

fm_address_prefix_t *
fm_local_address_prefix_create(const fm_address_t *local_address, unsigned int pfxlen, int ifindex)
{
	fm_address_prefix_t *entry;

	entry = fm_address_prefix_array_append(&fm_local_address_prefixes, local_address, pfxlen);
	entry->source_addr = *local_address;
	entry->ifindex = ifindex;

	fm_address_mask_from_prefixlen(local_address->ss_family, pfxlen,
			entry->raw_mask, sizeof(entry->raw_mask));

	if (ifindex != 0) {
		entry->device = fm_interface_by_index(ifindex);
		if (entry->device == NULL)
			fm_log_warning("address prefix %s/%u: no device for ifinidex %d",
					fm_address_format(local_address), pfxlen, ifindex);
	}

	return entry;
}

void
fm_local_discover(void)
{
	static bool initialized = false;
	struct ifaddrs *head, *ifa;
	unsigned int i;

	if (initialized)
		return;
	initialized = true;

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
			pfxlen = fm_address_mask_to_prefixlen(ifa->ifa_netmask);

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
			entry = fm_local_address_prefix_create((fm_address_t *) ifa->ifa_addr, pfxlen, 0);
			entry->ifname = strdup(ifa->ifa_name);
		}
	}

	freeifaddrs(head);

	for (i = 0; i < fm_local_address_prefixes.count; ++i) {
		fm_address_prefix_t *entry = &fm_local_address_prefixes.elements[i];

		if (entry->ifname == NULL)
			continue;

		entry->device = fm_interface_by_name(entry->ifname);
		entry->ifindex = entry->device->ifindex;
	}
}
