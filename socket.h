/*
 * Copyright (C) 2023 Olaf Kirch <okir@suse.com>
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

#ifndef FREEMAP_SOCKET_H
#define FREEMAP_SOCKET_H

#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "freemap.h"
#include "lists.h"

struct fm_socket {
	struct hlist		link;

	int			fd;
	int			family;
	int			type;
	socklen_t		addrlen;
	int			rpoll;

	void			(*callback)(fm_socket_t *, int, void *user_data);
	void *			user_data;

};

struct fm_socket_list {
	struct hlist_head	hlist;
};

static inline void
fm_socket_list_insert(struct fm_socket_list *list, fm_socket_t *sock)
{
	hlist_insert(&list->hlist, &sock->link);
}

static inline void
fm_socket_list_remove(fm_socket_t *sock)
{
	hlist_remove(&sock->link);
}

#define fm_socket_foreach(list, iter_var) \
	for (iter_var = (fm_socket_t *) ((list)->hlist.first); iter_var != NULL; iter_var = (fm_socket_t *) (iter_var->link.next))


#endif /* FREEMAP_SOCKET_H */

