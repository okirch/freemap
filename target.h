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
	/* For the time being, the scheduler needs a linked list of targets */
	struct hlist		link;

	/* for queue management */
	unsigned int		pool_id;
	unsigned int		refcount;

	fm_address_t		address;
	char *			id;

	/* Use this address to bind the PF_PACKET socket for ARP et al */
	const fm_interface_t *	local_device;

	/* Use this address when binding to a port */
	fm_address_t		local_bind_address;

	fm_socket_t *		raw_icmp4_sock;
	fm_socket_t *		raw_icmp6_sock;
	fm_socket_t *		udp_sock;
	fm_socket_t *		tcp_sock;

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
};

struct fm_target_pool {
	char *			name;

	/* When to attempt the next resize */
	double			next_resize;

	/* The capacity of the pool */
	unsigned int		size;

	/* Number of targets currently in the pool */
	unsigned int		count;

	/* Assign ids to targets */
	unsigned int		next_id;

	/* for the time being, we maintain a list of targets here. */
	struct hlist_head	targets;
};

typedef struct fm_target_queue {
	fm_target_pool_t *	pool;
	hlist_iterator_t	iter;

	/* The pool_id of the last target we returned. */
	unsigned int		most_recent_id;
} fm_target_queue_t;

struct fm_target_manager {
	fm_job_t		job;

	fm_address_enumerator_array_t address_generators;

	fm_scan_stage_t *	scan_stage;

	bool			all_targets_exhausted;

	/* Initial value for the packet send rate per target host. */
	unsigned int		host_packet_rate;

	fm_address_enumerator_array_t active_generators;

	/* Target pool */
	fm_target_pool_t	pool;

	unsigned int		num_queues;
	fm_target_pool_t **	queues;
};

extern void		fm_target_schedule(fm_target_t *, fm_sched_stats_t *);

typedef struct fm_target_pool_iterator {
	fm_target_pool_t *queue;
	unsigned int	index;
	unsigned int	next_pool_id;
} fm_target_pool_iterator_t;

extern void		fm_target_pool_begin(fm_target_pool_t *, fm_target_pool_iterator_t *);
extern fm_target_t *	fm_target_pool_next(fm_target_pool_iterator_t *);

extern void		fm_scheduler_create_new_probes(fm_scheduler_t *, fm_sched_stats_t *);
extern bool		fm_scheduler_attach_target(fm_scheduler_t *, fm_target_t *);
extern void		fm_scheduler_detach_target(fm_scheduler_t *, fm_target_t *);
extern fm_scheduler_t *	fm_linear_scheduler_create(fm_scanner_t *);

extern fm_target_pool_t *fm_target_manager_create_queue(fm_target_manager_t *, const char *name);
extern bool		fm_target_manager_replenish_pools(fm_target_manager_t *mgr);
extern void		fm_target_manager_begin(fm_target_manager_t *, hlist_iterator_t *);
extern fm_target_t *	fm_target_manager_next(fm_target_manager_t *, hlist_iterator_t *);
extern bool		fm_target_manager_is_done_quiet(fm_target_manager_t *target_manager);
extern bool		fm_target_manager_is_done(fm_target_manager_t *target_manager);
extern bool		fm_target_manager_set_stage(fm_target_manager_t *, fm_scan_stage_t *);
extern void		fm_target_manager_feed_probes(fm_target_manager_t *);

#endif /* FREEMAP_TARGET_H */
