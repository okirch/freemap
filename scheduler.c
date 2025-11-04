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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "freemap.h"
#include "target.h"
#include "scheduler.h"

fm_scheduler_t *
fm_scheduler_alloc(fm_scanner_t *scanner, const struct fm_scheduler_ops *ops)
{
	fm_scheduler_t *ret;

	assert(ops->size >= sizeof(*ret));
	ret = calloc(1, ops->size);
	ret->scanner = scanner;
	ret->target_pool = fm_scanner_get_target_pool(scanner);
	ret->ops = ops;
	return ret;
}

void
fm_scheduler_free(fm_scheduler_t *sched)
{
	if (sched->ops->destroy)
		sched->ops->destroy(sched);
	memset(sched, 0, sizeof(sched->ops->size));
	free(sched);
}

void
fm_scheduler_create_new_probes(fm_scheduler_t *sched, fm_sched_stats_t *stats)
{
	sched->ops->create_new_probes(sched, stats);
}

fm_probe_t *
fm_scheduler_get_next_probe(fm_scheduler_t *sched, fm_target_t *target)
{
	return sched->ops->get_next_probe(sched, target);
}

bool
fm_scheduler_attach_target(fm_scheduler_t *sched, fm_target_t *target)
{
	return sched->ops->attach(sched, target);
}

void
fm_scheduler_detach_target(fm_scheduler_t *sched, fm_target_t *target)
{
	sched->ops->detach(sched, target);
}

/*
 * fm_job_group primitives
 */
void
fm_job_move_to_group(fm_probe_t *job, struct hlist_head *head)
{
	hlist_remove(&job->link);
	hlist_insert(head, &job->link);
}

void
fm_job_list_destroy(struct hlist_head *head)
{
	hlist_iterator_t iter;
	fm_probe_t *job;

	hlist_iterator_init(&iter, head);
	while ((job = hlist_iterator_next(&iter)) != NULL)
		fm_probe_free(job);
}


/*
 * Linear scheduler
 */
static bool
fm_linear_scheduler_attach(fm_scheduler_t *sched, fm_target_t *target)
{
	struct fm_linear_sched_target_state *state;

	assert(target->job_group.sched_state == NULL);

	state = calloc(1, sizeof(*state));
	target->job_group.sched_state = state;
	return true;
}

static void
fm_linear_scheduler_detach(fm_scheduler_t *sched, fm_target_t *target)
{
	assert(target->job_group.sched_state != NULL);
	free(target->job_group.sched_state);
	target->job_group.sched_state = NULL;
}

static fm_probe_t *
fm_linear_scheduler_get_next_probe(fm_scheduler_t *sched, fm_target_t *target)
{
	struct fm_linear_sched_target_state *state = target->job_group.sched_state;
	fm_scan_action_t *action;
	fm_probe_t *probe;

	assert(state != NULL);

	while (!target->scan_done && !target->job_group.plugged) {
		action = state->action;
		if (action == NULL) {
			if (!(action = fm_scanner_get_action(sched->scanner, state->action_index)))
				return NULL;

			state->action = action;
			state->action_index += 1;
			state->probe_index = 0;

			if (!fm_scan_action_validate(action, target))
				goto skip_this_action;
		}

		probe = fm_scan_action_get_next_probe(action, target, state->probe_index);
		if (probe != NULL) {
			state->probe_index += 1;
			break;
		}

		if (state->probe_index == 0)
			fm_log_warning("scan action %s does not generate any probe packets at all!\n", fm_scan_action_id(action));

skip_this_action:
		state->action = NULL;
		state->probe_index = 0;
	}

	return probe;
}

static void
fm_linear_scheduler_create_new_probes(fm_scheduler_t *sched, fm_sched_stats_t *stats)
{
	unsigned int num_visited = 0;
	unsigned int num_created = 0, max_create;

	max_create = stats->job_quota - stats->num_sent;
	while (num_created < max_create) {
		unsigned int target_quota, target_created = 0;
		fm_target_t *target;

		target = fm_target_pool_get_next(sched->target_pool, &num_visited);
		if (target == NULL)
			break;

		target_quota = fm_target_get_send_quota(target, max_create - num_created);
		while (target_created < target_quota) {
			fm_probe_t *probe;

			if (target->scan_done || target->job_group.plugged)
				break;

			/* FIXME: which is the right place and time to detach? */
			if (target->job_group.sched_state == NULL)
				fm_scheduler_attach_target(sched, target);

			probe = fm_scheduler_get_next_probe(sched, target);
			if (probe == NULL) {
				fm_scheduler_detach_target(sched, target);
				target->scan_done = true;
				break;
			}

			fm_target_add_new_probe(target, probe);
			target_created += 1;
		}
	}
}

static struct fm_scheduler_ops		fm_linear_scheduler_ops = {
	.name		= "linear",
	.size		= sizeof(fm_scheduler_t),

	.attach		= fm_linear_scheduler_attach,
	.detach		= fm_linear_scheduler_detach,
	.get_next_probe	= fm_linear_scheduler_get_next_probe,
	.create_new_probes = fm_linear_scheduler_create_new_probes,
};

fm_scheduler_t *
fm_linear_scheduler_create(fm_scanner_t *scanner)
{
	return fm_scheduler_alloc(scanner, &fm_linear_scheduler_ops);
}

/*
 * Helper functions
 */
bool
fm_sched_stats_update_timeout_min(fm_sched_stats_t *stats, const struct timeval *expiry, const char *who)
{
	if (!fm_timestamp_is_set(&stats->timeout)
	 || (fm_timestamp_is_set(expiry) && fm_timestamp_older(expiry, &stats->timeout))) {
		stats->timeout = *expiry;

		if (fm_debug_level && fm_timestamp_is_set(&stats->timeout)) {
			double delay = fm_timestamp_expires_when(&stats->timeout, NULL);
			fm_log_debug("%s: new timeout is %f", who, delay);
			assert(delay >= 0);
		}
		return true;
	}
	return false;
}

bool
fm_sched_stats_update_timeout_max(fm_sched_stats_t *stats, const struct timeval *expiry, const char *who)
{
	if (fm_timestamp_is_set(&stats->timeout)
	 && fm_timestamp_is_set(expiry) && fm_timestamp_older(&stats->timeout, expiry)) {
		stats->timeout = *expiry;

		fm_log_debug("%s: new timeout is %f", who, fm_timestamp_expires_when(&stats->timeout, NULL));
		return true;
	}
	return false;
}

void
fm_sched_stats_update_from_nested(fm_sched_stats_t *stats, const fm_sched_stats_t *nested)
{
	fm_sched_stats_update_timeout_min(stats, &nested->timeout, __func__);
	stats->num_sent += nested->num_sent;
	stats->num_processed += nested->num_processed;
}

