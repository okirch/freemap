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

#ifndef FREEMAP_ADDRESSES_H
#define FREEMAP_ADDRESSES_H

#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "freemap.h"
#include "lists.h"

typedef struct fm_address_prefix fm_address_prefix_t;

struct fm_address_prefix {
	fm_address_t		address;
	unsigned int		pfxlen;

	fm_address_t		source_addr;

	unsigned char		raw_mask[16];

	/* for local addrs */
	char *			ifname;
	const fm_interface_t *	device;
};

typedef struct fm_address_prefix_array fm_address_prefix_array_t;
struct fm_address_prefix_array {
	unsigned int		count;
	fm_address_prefix_t *	elements;
};

struct fm_address_enumerator {
	struct hlist		link;

	fm_gateway_t *		unknown_gateway;

	/* every enumerator has its unique id */
	unsigned int		id;

	const struct fm_address_enumerator_ops {
		size_t		obj_size;
		const char *	name;
		void		(*destroy)(fm_address_enumerator_t *);
		bool		(*get_one_address)(fm_address_enumerator_t *, fm_address_t *);
	} *ops;
};

struct fm_address_enumerator_list {
	struct hlist_head	head;
};

extern fm_address_enumerator_t *fm_address_enumerator_alloc(const struct fm_address_enumerator_ops *);
extern const unsigned char *	fm_address_get_raw_addr(const fm_address_t *, unsigned int *nbits);
extern void			fm_interface_add(const char *name, const struct sockaddr_ll *);

static inline void
fm_address_enumerator_list_append(struct fm_address_enumerator_list *list, fm_address_enumerator_t *entry)
{
	hlist_append(&list->head, &entry->link);
}

static inline void
fm_address_enumerator_list_remove(fm_address_enumerator_t *entry)
{
	hlist_remove(&entry->link);
}

static inline fm_address_enumerator_t *
fm_address_enumerator_list_head(struct fm_address_enumerator_list *list)
{
	return (fm_address_enumerator_t *) list->head.first;
}

static inline fm_address_enumerator_t *
fm_address_enumerator_list_pop(struct fm_address_enumerator_list *list)
{
	fm_address_enumerator_t *entry = fm_address_enumerator_list_head(list);

	if (entry != NULL)
		hlist_remove(&entry->link);
	return entry;
}


#endif /* FREEMAP_ADDRESSES_H */
