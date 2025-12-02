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
#include "probe_private.h"

typedef struct fm_icmp_extra_params {
	const char *		type_name;
	struct {
		int		send_type;
		int		response_type;
	} ipv4, ipv6;

	uint16_t		tos;		/* copied from probe_params */
	uint16_t		ttl;		/* copied from probe_params */
	uint16_t		ident;
	uint16_t		sequence;
} fm_icmp_extra_params_t;

typedef struct fm_icmp_control {
	fm_protocol_t *		proto;

	fm_socket_t *		sock;
	bool			sock_is_shared;
	bool			kernel_trashes_id;
	bool			extants_are_multi_shot;

	fm_probe_params_t	params;
	fm_icmp_extra_params_t	extra_params;
} fm_icmp_control_t;

typedef struct fm_icmp_request {
	fm_icmp_control_t *	control;
	fm_target_control_t	target_control;
} fm_icmp_request_t;

typedef struct fm_icmp_extant_info {
	struct fm_icmp_match {
		unsigned char	v4_request_type;
		unsigned char	v4_response_type;

		/* a value of id < 0 means ignore the id.
		 * Needed because the icmp dgram sockets overwrite the
		 * id chosen by user space on transmit. */
		int		seq, id;
	} match;
} fm_icmp_extant_info_t;

#endif /* FREEMAP_ICMP_H */
