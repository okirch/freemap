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
 * Simple UDP scanning functions
 */

#ifndef FREEMAP_TRACEROUTE_H
#define FREEMAP_TRACEROUTE_H

#include "freemap.h"
#include "utils.h"

#define FM_MAX_TOPO_DEPTH	64
#define FM_RTT_SAMPLES_WANTED	3

typedef struct fm_tgateway	fm_tgateway_t;

typedef struct fm_topo_extra_params {
	const char *		packet_proto;
	unsigned int		max_depth;
	unsigned int		max_hole_size;

	void *			packet_proto_params;
} fm_topo_extra_params_t;

typedef struct fm_topo_hop_state {
	unsigned int		distance;
	fm_asset_state_t	state;

	fm_probe_t *		pending;
	fm_completion_t *	completion;

	/* used for rate limiting */
	fm_tgateway_t *		gateway;
} fm_topo_hop_state_t;

typedef struct fm_topo_shared_sockets {
	unsigned int		refcount;
	int			family;
	fm_protocol_t *		packet_proto;

	fm_socket_t *		socks[FM_MAX_TOPO_DEPTH];
} fm_topo_shared_sockets_t;

typedef struct fm_topo_state {
	fm_protocol_t *		proto;
	fm_target_t *		target;
	fm_socket_t *		sock;

	int			family;
	fm_address_t		host_address;
	fm_probe_params_t	params;

	fm_topo_extra_params_t	topo_params;
	fm_protocol_t *		packet_proto;
	fm_probe_class_t *	packet_probe_class;

	unsigned int		next_ttl;
	unsigned int		destination_ttl;

	fm_topo_hop_state_t	hop[FM_MAX_TOPO_DEPTH];

	/* share across probes */
	fm_topo_shared_sockets_t *shared_socks;
} fm_topo_state_t;

struct fm_tgateway {
	unsigned int		nhops;
	fm_address_t		address;

	fm_tgateway_t *		previous_hop;
	fm_tgateway_t *		unknown_next_hop;

	fm_ratelimit_t		ratelimit;
	fm_rtt_stats_t		rtt;
};

typedef struct fm_tgateway_array {
	unsigned int		count;
	fm_tgateway_t **	entries;
} fm_tgateway_array_t;


#endif /* FREEMAP_TRACEROUTE_H */
