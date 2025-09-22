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

#ifndef FREEMAP_TARGET_H
#define FREEMAP_TARGET_H

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "freemap.h"
#include "lists.h"
#include "addresses.h"

extern fm_fact_t *		fm_fact_create_error(fm_fact_type_t type, const char *fmt, ...);
extern fm_fact_t *		fm_fact_create_port_reachable(const char *proto_id, unsigned int port);
extern fm_fact_t *		fm_fact_create_port_unreachable(const char *proto_id, unsigned int port);
extern fm_fact_t *		fm_fact_create_host_reachable(const char *proto_id);
extern fm_fact_t *		fm_fact_create_host_unreachable(const char *proto_id);

struct fm_probe_ops {
	const char *		name;
	size_t			obj_size;

	long			default_timeout;

	void			(*destroy)(fm_probe_t *);
	fm_fact_t *		(*send)(fm_probe_t *);
	bool			(*should_resend)(const fm_probe_t *);
};

struct fm_probe {
	struct hlist		link;

	const struct fm_probe_ops *ops;

	bool			blocking;

	long			timeout;

	struct timeval		sent;
	struct timeval		expires;

	/* for probes that have completed */
	fm_fact_t *		status;

	void			(*result_callback)(fm_target_t *, fm_fact_t *);
};

struct fm_probe_list {
	struct hlist_head	hlist;
};

struct fm_target {
	fm_address_t		address;
	char *			id;

	bool			plugged;

	/* Limit the rate at which we send packets to this host */
	fm_ratelimit_t		host_rate_limit;

	/* sequence number for host probes, eg ICMP seq */
	unsigned int		host_probe_seq;

	/* When doing an initial ICMP probe, this will record the RTT in millisec. */
	unsigned int		rtt_estimate;

	/* The scan action we're processing */
	struct {
		fm_scan_action_t *action;
		unsigned int	action_index;
		unsigned int	port_index;
	} current_scan;

	struct fm_probe_list	pending_probes;

	fm_fact_log_t		log;
};

struct fm_target_pool {
	unsigned int		size;
	unsigned int		count;
	fm_target_t **		slots;

	unsigned int		cursor;
};

struct fm_target_manager {
	struct fm_address_enumerator_list address_generators;

	bool			all_targets_exhausted;

	/* Initial value for the packet send rate per target host. */
	unsigned int		host_packet_rate;
};

extern fm_probe_t *	fm_probe_alloc(const struct fm_probe_ops *ops);


static inline void
fm_probe_insert(struct fm_probe_list *list, fm_probe_t *probe)
{
	hlist_insert(&list->hlist, &probe->link);
}

static inline void
fm_probe_append(struct fm_probe_list *list, fm_probe_t *probe)
{
	hlist_append(&list->hlist, &probe->link);
}

static inline void
fm_probe_unlink(fm_probe_t *probe)
{
	hlist_remove(&probe->link);
}

static inline fm_probe_t *
fm_probe_list_get_first(struct fm_probe_list *list)
{
	fm_probe_t *probe;

	if ((probe = (fm_probe_t *) list->hlist.first) != NULL)
		fm_probe_unlink(probe);
	return probe;
}

static inline bool
fm_probe_list_is_empty(const struct fm_probe_list *list)
{
	return list->hlist.first == NULL;
}

#define fm_probe_foreach(list, iter_var) \
	for (iter_var = (fm_probe_t *) ((list)->hlist.first); iter_var != NULL; iter_var = (fm_probe_t *) (iter_var->next))

#endif /* FREEMAP_TARGET_H */
