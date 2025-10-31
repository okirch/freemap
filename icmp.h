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
 *
 * Simple ICMP reachability functions
 */

#ifndef FREEMAP_ICMP_H
#define FREEMAP_ICMP_H

#include "freemap.h"

typedef struct fm_icmp_extra_params {
	const char *		type_name;
	struct {
		int		send_type;
		int		response_type;
	} ipv4, ipv6;
} fm_icmp_extra_params_t;

typedef struct fm_icmp_request {
	fm_protocol_t *		proto;
	fm_target_t *		target;

	fm_socket_t *		sock;
	bool			sock_is_shared;

	int			family;
	fm_address_t		host_address;
	fm_probe_params_t	params;
	fm_icmp_extra_params_t	extra_params;

	struct icmp_params {
		int		ipproto;
		uint32_t	ident;
		uint32_t	seq;
	} icmp;
} fm_icmp_request_t;


#endif /* FREEMAP_ICMP_H */
