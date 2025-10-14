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

#ifndef FREEMAP_LISTS_H
#define FREEMAP_LISTS_H

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

struct hlist {
	struct hlist **		prevp;
	struct hlist *		next;
};

struct hlist_head {
	struct hlist *		first;
};

static inline void
__hlist_insert(struct hlist **prevp, struct hlist *entry)
{
	struct hlist *next = *prevp;

	assert(entry->prevp == NULL && entry->next == NULL);
	if (next != NULL) {
		assert(next->prevp == prevp);
		next->prevp = &entry->next;
		entry->next = next;
	}

	*prevp = entry;
	entry->prevp = prevp;
}

static inline void
hlist_insert(struct hlist_head *list_head, struct hlist *entry)
{
	__hlist_insert(&list_head->first, entry);
}

static inline void
hlist_append(struct hlist_head *list_head, struct hlist *entry)
{
	struct hlist **tailp;

	for (tailp = &list_head->first; *tailp != NULL; tailp = &(*tailp)->next)
		;

	__hlist_insert(tailp, entry);
}

static inline void
hlist_remove(struct hlist *entry)
{
	struct hlist **prevp = entry->prevp;
	struct hlist *next = entry->next;

	if (prevp == NULL)
		return; /* not on a list */

	*prevp = next;
	if (next != NULL)
		next->prevp = prevp;

	entry->prevp = NULL;
	entry->next = NULL;
}

typedef struct list_iterator {
	struct hlist *next;
} hlist_iterator_t;

static inline void
hlist_iterator_init(hlist_iterator_t *iter, struct hlist_head *list_head)
{
	iter->next = list_head->first;
}

static inline void *
hlist_iterator_first(hlist_iterator_t *iter, struct hlist_head *list_head)
{
	struct hlist *cur;

	iter->next = NULL;
	if ((cur = list_head->first) != NULL)
		iter->next = cur->next;
	return cur;
}

static inline void *
hlist_iterator_next(hlist_iterator_t *iter)
{
	struct hlist *cur = iter->next;

	iter->next = NULL;
	if (cur != NULL)
		iter->next = cur->next;
	return cur;
}

#endif /* FREEMAP_LISTS_H */

