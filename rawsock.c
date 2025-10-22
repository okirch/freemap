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

	if (!fm_socket_bind(sock, (const fm_address_t *) &lladdr)) {
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
