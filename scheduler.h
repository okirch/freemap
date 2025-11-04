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

#ifndef FREEMAP_SCHEDULER_H
#define FREEMAP_SCHEDULER_H

#include "freemap.h"
#include "lists.h"

struct fm_sched_stats {
	struct timeval		timeout;

	unsigned int		job_quota;
	unsigned int		num_sent;
	unsigned int		num_processed;;
};

typedef struct fm_job_group {
	char *			name;	/* usually the address of the target this is attached to */

	bool			plugged;

	/* For scan targets, this is target->host_rate_limit.
	 * Can be NULL otherwise.
	 * FIXME: maybe we should just have a rate limit for every job group.
	 */
	fm_ratelimit_t *	rate_limit;

	/* scheduler stores per-target state here: */
	void *			sched_state;

	/* probes that are waiting for some event before they
	 * can continue */
	struct hlist_head 	postponed_probes;

	/* probes that can continue */
	struct hlist_head 	ready_probes;

	/* should be renamed to "active_probes" */
	struct hlist_head 	pending_probes;
} fm_job_group_t;

/*
 * A scheduler determines which target and port are scanned next.
 * The default implementation just does everything in a linear fashion;
 * but of course, it's possible to implement more complex approaches
 * (focusing eg on stealth, minimizing the impact of ICMP rate limiting etc)
 */
struct fm_scheduler {
	fm_scanner_t *		scanner;
	fm_target_pool_t *	target_pool;

	const struct fm_scheduler_ops {
		const char *	name;
		size_t		size;

		bool		(*attach)(fm_scheduler_t *, fm_target_t *);
		void		(*detach)(fm_scheduler_t *, fm_target_t *);
		void		(*create_new_probes)(fm_scheduler_t *, fm_sched_stats_t *);
		fm_probe_t *	(*get_next_probe)(fm_scheduler_t *, fm_target_t *);
		void		(*destroy)(fm_scheduler_t *);
	} *ops;
};

extern void		fm_job_move_to_group(fm_probe_t *job, struct hlist_head *head);
extern void		fm_job_list_destroy(struct hlist_head *head);

extern void		fm_job_group_init(fm_job_group_t *, const char *, fm_ratelimit_t *);
extern fm_error_t	fm_job_group_add_new(fm_job_group_t *, fm_probe_t *probe);
extern void		fm_job_group_process_timeouts(fm_job_group_t *job_group);
extern void		fm_job_group_schedule(fm_job_group_t *job_group, fm_sched_stats_t *stats);
extern bool		fm_job_group_reap_complete(fm_job_group_t *job_group);
extern void		fm_job_group_destroy(fm_job_group_t *);
extern bool		fm_job_group_is_done(const fm_job_group_t *);

static inline bool
fm_job_list_is_empty(const struct hlist_head *head)
{
	return head->first == NULL;
}

struct fm_linear_scheduler {
	fm_scheduler_t		base;
};

struct fm_linear_sched_target_state {
	fm_scan_action_t *	action;
	unsigned int		action_index;
	unsigned int		probe_index;
};

#endif /* FREEMAP_SCHEDULER_H */
