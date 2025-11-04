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

struct fm_sched_stats {
	struct timeval		timeout;

	unsigned int		job_quota;
	unsigned int		num_sent;
	unsigned int		num_processed;;
};

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

struct fm_linear_scheduler {
	fm_scheduler_t		base;
};

struct fm_linear_sched_target_state {
	fm_scan_action_t *	action;
	unsigned int		action_index;
	unsigned int		probe_index;
};

#endif /* FREEMAP_SCHEDULER_H */
