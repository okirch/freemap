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

#define HLIST_HEAD_NIL		{ .first = NULL }

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

static inline void *
hlist_head_get_first(struct hlist_head *head)
{
	return head->first;
}

static inline void
hlist_head_reassign(struct hlist_head *src_head, struct hlist_head *dst_head)
{
	struct hlist *entry;

	assert(dst_head->first == NULL);
	if ((entry = src_head->first) != NULL) {
		dst_head->first = entry;
		entry->prevp = &dst_head->first;
	}
	src_head->first = NULL;
}

static inline bool
hlist_is_empty(const struct hlist_head *head)
{
	return head->first == NULL;
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

/*
 * An insertion iterator walks a list, referencing the prev pointer.
 * When the iterator is at the tail tail of the list, splice another list
 * into it and advance to the new end
 */
typedef struct list_insertion_iterator {
	struct hlist **prevp;
} hlist_insertion_iterator_t;

static inline void
hlist_insertion_iterator_init(hlist_insertion_iterator_t *iter, struct hlist_head *list_head)
{
	iter->prevp = &list_head->first;
}

static inline void *
hlist_insertion_iterator_next(hlist_insertion_iterator_t *iter)
{
	struct hlist *cur;

	if ((cur = *(iter->prevp)) != NULL)
		iter->prevp = &cur->next;
	return cur;
}

static inline void
hlist_insertion_iterator_init_tail(hlist_insertion_iterator_t *iter, struct hlist_head *list_head)
{
	hlist_insertion_iterator_init(iter, list_head);
	while (hlist_insertion_iterator_next(iter) != NULL)
		;
}

/*
 * Insert a new entry at the current position (ie after the entry we saw last, and before the
 * entry we will see next).
 */
static inline void
hlist_insertion_iterator_insert(hlist_insertion_iterator_t *iter, struct hlist *entry)
{
	__hlist_insert(iter->prevp, entry);
}

static inline void
hlist_insertion_iterator_insert_and_advance(hlist_insertion_iterator_t *iter, struct hlist *entry)
{
	__hlist_insert(iter->prevp, entry);
	iter->prevp = &entry->next;
}

/*
 * Insert an entire list at the current position. If move_to_new_end is true, move the iterator
 * to the new tail of the list.
 */
static inline void
hlist_insertion_iterator_splice(hlist_insertion_iterator_t *iter, struct hlist_head *list_head, bool move_to_new_end)
{
	struct hlist *entry, *old_next = *(iter->prevp);
	struct hlist **tail;

	/* The list to be spliced is empty - easy. */
	if (list_head->first == NULL)
		return;

	/* find the end of the list to be inserted */
	for (tail = &list_head->first; (entry = *tail) != NULL; tail = &entry->next)
		;

	/* Establish links between the first entry of the list at the iterator's current position */
	*(iter->prevp) = list_head->first;
	list_head->first->prevp = iter->prevp;

	/* If the iterator wasn't already at the tail of its list, establish links with the
	 * last entry of the new list. */
	if (old_next != NULL) {
		old_next->prevp = tail;
		*tail = old_next;
	}

	if (move_to_new_end)
		iter->prevp = tail;

	/* clear the list we just spliced, it's no longer valid */
	list_head->first = NULL;
}

#endif /* FREEMAP_LISTS_H */
