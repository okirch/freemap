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

enum {
	FM_ERROR_CLASS_IGNORE = 0,
	FM_ERROR_CLASS_TRANSIENT,
	FM_ERROR_CLASS_TOO_MANY_HOPS,
	FM_ERROR_CLASS_NET_UNREACH,
	FM_ERROR_CLASS_HOST_UNREACH,
	FM_ERROR_CLASS_ADMIN_PROHIBITED,
	FM_ERROR_CLASS_PORT_UNREACH,
	FM_ERROR_CLASS_OTHER,
};

extern int		fm_socket_recv(fm_socket_t *sock, void *buffer, size_t size, fm_pkt_info_t *info);
extern bool		fm_socket_recverr(fm_socket_t *sock, fm_pkt_info_t *info);
extern const char *	fm_socket_render_error(const fm_pkt_info_t *info);
extern int		fm_socket_error_class(const fm_pkt_info_t *info);
extern bool		fm_socket_error_dest_unreachable(const fm_pkt_info_t *);


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

