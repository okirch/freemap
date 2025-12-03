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
#include "packet.h"
#include "lists.h"

struct fm_socket {
	struct hlist		link;

	int			fd;
	int			family;
	int			type;
	bool			trace;

	socklen_t		addrlen;
	int			rpoll;

	fm_address_t		local_address;
	fm_address_t		peer_address;

	/* must be set before we can poll */
	fm_protocol_t *		proto;

	struct {
		void		(*callback)(const fm_pkt_t *pkt, void *user_data);
		void *		user_data;
	} data_tap;

	/* Packet analysis code */
	fm_packet_parser_t *	data_parser;
	fm_packet_parser_t *	error_parser;

	/* For quick extant matching */
	fm_extant_map_t *	extant_map;
};

typedef struct fm_socket_pool	fm_socket_pool_t;
struct fm_socket_pool {
	fm_protocol_t *		driver;
	int			sotype;

	fm_socket_t *		(*new_sock)(fm_socket_pool_t *pool, const fm_address_t *bind_addr);

	struct hlist_head	list;
};

extern bool		fm_socket_recverr(fm_socket_t *sock, fm_pkt_info_t *info);
extern void		fm_socket_attach_protocol(fm_socket_t *, fm_protocol_t *);

extern void		fm_socket_attach_extant_map(fm_socket_t *, fm_extant_map_t *);
extern fm_extant_t *	fm_socket_add_extant(fm_socket_t *, fm_host_asset_t *host, int family, int ipproto, const void *data, size_t len);

extern fm_socket_pool_t *fm_socket_pool_create(fm_protocol_t *, int sotype);
extern fm_socket_t *	fm_socket_pool_get_socket(fm_socket_pool_t *, const fm_address_t *local_addr);

static inline bool
fm_socket_is_connected(const fm_socket_t *sock)
{
	return sock->peer_address.family != AF_UNSPEC;
}

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

