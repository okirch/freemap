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

#ifndef FREEMAP_EXTANT_H
#define FREEMAP_EXTANT_H

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "freemap.h"
#include "lists.h"

/*
 * Hold the state of an extant request
 */
typedef struct fm_extant {
	struct hlist		link;

	int			family;
	int			ipproto;

	fm_socket_timestamp_t	timestamp;
	fm_probe_t *		probe;
} fm_extant_t;

typedef struct fm_extant_list {
	struct hlist_head	hlist;
} fm_extant_list_t;

extern fm_extant_t *	fm_extant_alloc(fm_probe_t *, int af, int ipproto,
				const void *payload, size_t payload_size);
extern fm_extant_t *	fm_extant_alloc_list(fm_probe_t *probe, int af, int ipproto,
				const void *payload, size_t payload_size,
				fm_extant_list_t *exlist);
extern void		fm_extant_free(fm_extant_t *extant);

extern void		fm_extant_received_reply(fm_extant_t *extant, const fm_pkt_t *pkt);
extern void		fm_extant_received_error(fm_extant_t *extant, const fm_pkt_t *pkt);

static inline void
fm_extant_append(struct fm_extant_list *list, fm_extant_t *extant)
{
	hlist_append(&list->hlist, &extant->link);
}

static inline void
fm_extant_unlink(fm_extant_t *extant)
{
	hlist_remove(&extant->link);
}

static inline void
fm_extant_iterator_init(hlist_iterator_t *iter, struct fm_extant_list *list)
{
	hlist_iterator_init(iter, &list->hlist);
}

static inline fm_extant_t *
fm_extant_iterator_first(hlist_iterator_t *iter, struct fm_extant_list *list)
{
	return (fm_extant_t *) hlist_iterator_first(iter, &list->hlist);
}

static inline fm_extant_t *
fm_extant_iterator_next(hlist_iterator_t *iter)
{
	return (fm_extant_t *) hlist_iterator_next(iter);
}

static inline fm_extant_t *
fm_extant_iterator_match(hlist_iterator_t *iter, int af, int ipproto)
{
	fm_extant_t *extant;

	while ((extant = fm_extant_iterator_next(iter)) != NULL
	    && extant->family != af && extant->ipproto != ipproto)
		;
	return extant;
}

#endif /* FREEMAP_EXTANT_H */
