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
#include <assert.h>

#include "freemap.h"
#include "lists.h"
#include "addresses.h"

extern fm_fact_t *		fm_fact_create_error(fm_fact_type_t type, const char *fmt, ...);
extern fm_fact_t *		fm_fact_create_port_reachable(const char *proto_id, unsigned int port);
extern fm_fact_t *		fm_fact_create_port_unreachable(const char *proto_id, unsigned int port);
extern fm_fact_t *		fm_fact_create_port_heisenberg(const char *proto_id, unsigned int port);
extern fm_fact_t *		fm_fact_create_host_reachable(const char *proto_id);
extern fm_fact_t *		fm_fact_create_host_unreachable(const char *proto_id);

typedef enum {
	FM_PROBE_VERDICT_NONE = 0,
	FM_PROBE_VERDICT_REACHABLE,
	FM_PROBE_VERDICT_UNREACHABLE,
	FM_PROBE_VERDICT_TIMEOUT,
} fm_probe_verdict_t;

struct fm_probe_ops {
	const char *		name;
	size_t			obj_size;

	long			default_timeout;

	void			(*destroy)(fm_probe_t *);
	fm_fact_t *		(*send)(fm_probe_t *);
	bool			(*should_resend)(fm_probe_t *);
	fm_fact_t *		(*render_verdict)(fm_probe_t *, fm_probe_verdict_t verdict);
};

struct fm_probe {
	struct hlist		link;

	fm_protocol_t *		proto;
	fm_target_t *		target;

	/* name of the probe, like udp/53 or icmp/echo */
	char *			name;
	unsigned int		netid;

	const struct fm_probe_ops *ops;

	bool			blocking;

	fm_rtt_stats_t *	rtt;

	/* When probing eg UDP based services, we need to slap some
	 * constant value on the timeout derived from the RTT estimate,
	 * because the RTT will be largely based on the network timing;
	 * but for us to receive a UDP response, we need to take into
	 * account the time it takes the server to actually cook up a
	 * response.
	 */
	unsigned int		rtt_application_bias;

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

/*
 * Hold the state of an extant request
 */
typedef struct fm_extant {
	struct hlist		link;

	int			family;
	int			ipproto;

	fm_socket_timestamp_t	timestamp;
	fm_probe_t *		probe;
} fm_extant_t;

struct fm_extant_list {
	struct hlist_head	hlist;
};

struct fm_target {
	fm_address_t		address;
	char *			id;

	/* Use this address when binding to a port */
	fm_address_t		local_bind_address;

	fm_socket_t *		raw_icmp4_sock;
	fm_socket_t *		raw_icmp6_sock;
	fm_socket_t *		udp_sock;

	/* for now, just a boolean state: in progress vs done.
	 * Maybe later we need 3 states or more. */
	bool			scan_done;

	bool			plugged;

	/* Limit the rate at which we send packets to this host */
	fm_ratelimit_t		host_rate_limit;

	/* sequence number for host probes, eg ICMP seq */
	unsigned int		host_probe_seq;

	/* Unique ID identifying a network that we scan */
	unsigned int		netid;

	/* When doing an initial ICMP probe, this will record the RTT in millisec. */
	unsigned int		rtt_estimate;

	/* scheduler stores per-target state here: */
	void *			sched_state;

	/* should be renamed to "active_probes" */
	struct fm_probe_list	pending_probes;

	struct fm_extant_list	expecting;

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

extern fm_probe_t *	fm_probe_alloc(const char *id,
				const struct fm_probe_ops *ops,
				fm_protocol_t *proto,
				fm_target_t *target);


extern fm_extant_t *	fm_extant_alloc(fm_probe_t *, int af, int ipproto,
				const void *payload, size_t payload_size);
extern void		fm_extant_free(fm_extant_t *extant);
extern void		fm_target_forget_pending(fm_target_t *target, const fm_probe_t *probe);

extern void		fm_target_pool_make_active(fm_target_pool_t *);
extern fm_target_t *	fm_target_pool_find(const fm_address_t *);

extern void		fm_probe_received_reply(fm_probe_t *, double *rtt);
extern void		fm_probe_received_error(fm_probe_t *, double *rtt);
extern void		fm_probe_timed_out(fm_probe_t *);

extern void		fm_extant_received_reply(fm_extant_t *extant, const fm_pkt_t *pkt);
extern void		fm_extant_received_error(fm_extant_t *extant, const fm_pkt_t *pkt);

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

static inline void
fm_extant_append(struct fm_extant_list *list, fm_extant_t *extant)
{
	hlist_append(&list->hlist, &extant->link);
}

static inline void
fm_extant_unlink(fm_extant_t *extant)
{
	hlist_remove(&extant->link);
}

static inline void
fm_extant_iterator_init(hlist_iterator_t *iter, struct fm_extant_list *list)
{
	hlist_iterator_init(iter, &list->hlist);
}

static inline fm_extant_t *
fm_extant_iterator_first(hlist_iterator_t *iter, struct fm_extant_list *list)
{
	return (fm_extant_t *) hlist_iterator_first(iter, &list->hlist);
}

static inline fm_extant_t *
fm_extant_iterator_next(hlist_iterator_t *iter)
{
	return (fm_extant_t *) hlist_iterator_next(iter);
}

static inline fm_extant_t *
fm_extant_iterator_match(hlist_iterator_t *iter, int af, int ipproto)
{
	fm_extant_t *extant;

	while ((extant = fm_extant_iterator_next(iter)) != NULL
	    && extant->family != af && extant->ipproto != ipproto)
		;
	return extant;
}

#endif /* FREEMAP_TARGET_H */
