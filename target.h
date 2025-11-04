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

#ifndef FREEMAP_TARGET_H
#define FREEMAP_TARGET_H

#include <stdlib.h>
#include <stdbool.h>

#include "freemap.h"
#include "lists.h"
#include "addresses.h"
#include "scheduler.h"
#include "probe.h"

struct fm_target {
	fm_address_t		address;
	char *			id;

	/* Use this address to bind the PF_PACKET socket for ARP et al */
	const fm_interface_t *	local_device;

	/* Use this address when binding to a port */
	fm_address_t		local_bind_address;

	fm_socket_t *		raw_icmp4_sock;
	fm_socket_t *		raw_icmp6_sock;
	fm_socket_t *		udp_sock;

	/* for now, just a boolean state: in progress vs done.
	 * Maybe later we need 3 states or more. */
	bool			scan_done;

	/* Limit the rate at which we send packets to this host */
	fm_ratelimit_t		host_rate_limit;

	/* sequence number for host probes, eg ICMP seq */
	unsigned int		host_probe_seq;

	/* Unique ID identifying a network that we scan */
	fm_network_t *		network;

	struct fm_extant_list	expecting;

	/* This is where we report host/port state to */
	fm_host_asset_t *	host_asset;

	fm_job_group_t		job_group;
};

struct fm_target_pool {
	unsigned int		size;
	unsigned int		count;
	fm_target_t **		slots;

	unsigned int		cursor;
};

struct fm_target_manager {
	fm_address_enumerator_array_t address_generators;

	bool			all_targets_exhausted;
	unsigned int		current_generator;

	/* Initial value for the packet send rate per target host. */
	unsigned int		host_packet_rate;
};

extern void		fm_target_forget_pending(fm_target_t *target, const fm_probe_t *probe);
extern void		fm_target_schedule(fm_target_t *, fm_sched_stats_t *);
extern unsigned int	fm_target_get_send_quota(fm_target_t *, unsigned int quota_limit);

extern void		fm_target_pool_make_active(fm_target_pool_t *);
extern fm_target_t *	fm_target_pool_find(const fm_address_t *);

extern void		fm_scheduler_create_new_probes(fm_scheduler_t *, fm_sched_stats_t *);
extern fm_probe_t *	fm_scheduler_get_next_probe(fm_scheduler_t *, fm_target_t *);
extern bool		fm_scheduler_attach_target(fm_scheduler_t *, fm_target_t *);
extern void		fm_scheduler_detach_target(fm_scheduler_t *, fm_target_t *);
extern fm_scheduler_t *	fm_linear_scheduler_create(fm_scanner_t *);

#endif /* FREEMAP_TARGET_H */
