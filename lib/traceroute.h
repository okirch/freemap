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
#include "probe_private.h"
#include "routing.h"
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

#define FM_TOPO_HOP_GW_CHANGED	0x0001
#define FM_TOPO_HOP_GW_FLAP	0x0002
typedef struct fm_topo_hop_state {
	unsigned short		distance;
	unsigned short		flags;
	fm_asset_state_t	state;

	unsigned int		probes_sent;

	fm_ratelimit_t *	ratelimit;
	double			next_send_time;

	struct fm_topo_hop_extant {
		double		timeout;
		fm_extant_t *	extant;
	} pending[FM_RTT_SAMPLES_WANTED];

	/* The notifier to be installed on any extant for this ttl */
	fm_extant_notifier_t	notifier;

	/* Set when we learn about a new gateway.
	 */
	fm_tgateway_t *		gateway;
	fm_tgateway_t *		alt_gateway;
} fm_topo_hop_state_t;

typedef struct fm_topo_shared_sockets {
	unsigned int		refcount;
	int			family;
	fm_protocol_t *		packet_proto;
	const fm_interface_t *	interface;
	fm_address_t		local_address;

	fm_socket_t *		socks[FM_MAX_TOPO_DEPTH];
} fm_topo_shared_sockets_t;

typedef struct fm_topo_state {
	fm_protocol_t *		proto;
	fm_target_t *		target;
	fm_host_asset_t *	host_asset;

	int			family;
	fm_address_t		host_address;

	fm_target_control_t	_control;

	fm_probe_params_t	params;

	fm_topo_extra_params_t	topo_params;
	fm_protocol_t *		packet_proto;
	fm_probe_class_t *	packet_probe_class;
	fm_string_array_t	packet_probe_params;
	fm_multiprobe_t *	packet_probe;

	unsigned int		next_ttl;
	unsigned int		destination_ttl;

	fm_tgateway_t *		unknown_gateway;

	fm_topo_hop_state_t	hop[FM_MAX_TOPO_DEPTH];

	/* share across probes */
	fm_topo_shared_sockets_t *shared_socks;
} fm_topo_state_t;

struct fm_tgateway {
	unsigned int		nhops;
	fm_address_t		address;

	fm_ratelimit_t		unknown_next_hop_rate[FM_MAX_TOPO_DEPTH];

	fm_rtt_stats_t		rtt;
};

typedef struct fm_tgateway_array {
	unsigned int		count;
	fm_tgateway_t **	entries;
} fm_tgateway_array_t;

/* These are hard-coded for now, but should eventually have a home in fm_global */
#define FM_TOPO_SEND_RATE		10
#define FM_TOPO_SEND_BURST		3	/* must be <= min(UNKNOWN_RATE, SEND_RATE - UNKNOWN_RATE) */
#define FM_TOPO_UNKNOWN_RATE		5

#endif /* FREEMAP_TRACEROUTE_H */
