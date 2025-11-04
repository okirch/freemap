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
fm_job_group_init(fm_job_group_t *job_group, const char *name, fm_ratelimit_t *rate_limit)
{
	memset(job_group, 0, sizeof(*job_group));
	job_group->name = strdup(name);
	job_group->rate_limit = rate_limit;
}

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

void
fm_job_group_destroy(fm_job_group_t *job_group)
{
	fm_job_list_destroy(&job_group->postponed_probes);
	fm_job_list_destroy(&job_group->ready_probes);
	fm_job_list_destroy(&job_group->pending_probes);
	drop_string(&job_group->name);
}

bool
fm_job_group_is_done(const fm_job_group_t *job_group)
{
	return fm_job_list_is_empty(&job_group->postponed_probes)
	    && fm_job_list_is_empty(&job_group->ready_probes)
	    && fm_job_list_is_empty(&job_group->pending_probes);
}

/*
 * Add a newly created job to a job group
 */
fm_error_t
fm_job_group_add_new(fm_job_group_t *job_group, fm_probe_t *job)
{
	if (job->event_listener == NULL) {
		fm_job_move_to_group(job, &job_group->ready_probes);
	} else {
		fm_job_move_to_group(job, &job_group->postponed_probes);
		fm_log_debug("%s: postponed", job->name);
	}

	/* If the probe is marked as blocking, do not allow
	 * any further probes to be created until we've
	 * processed everything that is in the queue. */
	if (job->blocking)
		job_group->plugged = true;

	return 0;
}

/*
 * Process all timeouts in a job group
 */
void
fm_job_group_process_timeouts(fm_job_group_t *job_group)
{
	const struct timeval *now = fm_timestamp_now();
	hlist_insertion_iterator_t ready_tail_iter;
	hlist_iterator_t wait_iter;
	fm_probe_t *probe;

	hlist_iterator_init(&wait_iter, &job_group->pending_probes);

	hlist_insertion_iterator_init_tail(&ready_tail_iter, &job_group->ready_probes);

	while ((probe = hlist_iterator_next(&wait_iter)) != NULL) {
		if (fm_timestamp_older(&probe->expires, now)) {
			hlist_remove(&probe->link);
			hlist_insertion_iterator_insert_and_advance(&ready_tail_iter, &probe->link);
		}
	}
}

/*
 * The next couple of functions are the main work-horse for the job scheduler
 */

/*
 * Insert the remaining probes at the head of the runnable list again
 */
static void
fm_job_group_postpone_remaining_runnable(fm_job_group_t *job_group, hlist_iterator_t *iter)
{
	hlist_insertion_iterator_t insert_iter;
	fm_probe_t *probe;

	hlist_insertion_iterator_init(&insert_iter, &job_group->ready_probes);
	while ((probe = hlist_iterator_next(iter)) != NULL) {
		hlist_remove(&probe->link);
		hlist_insertion_iterator_insert_and_advance(&insert_iter, &probe->link);
	}
}

static void
fm_job_group_process_runnable(fm_job_group_t *job_group, fm_sched_stats_t *stats)
{
	struct hlist_head runnable = HLIST_HEAD_NIL;
	hlist_iterator_t runnable_iter;
	fm_probe_t *probe;

	/* reassign runnable probes to a temporary list. This allows any probes to
	 * become runnable without interfering with our processing, such as resulting
	 * in endless loops. */
	hlist_head_reassign(&job_group->ready_probes, &runnable);

	/* Now process the list of probes that are ready to run.
	 * Note that we don't use an iterator, we always refer to the first runnable
	 * job at the head of the ready_list. The reason is that any pending probe
	 * may disappear from that list at any point in time (eg traceroute will
	 * actively cancel pending packet probes after the first reply).
	 *
	 * NB we could implement a "greedy" scheduling mode that does not return
	 * as long as probes on this host are ready to run (and making progress)
	 */
	hlist_iterator_init(&runnable_iter, &runnable);
	while (stats->num_sent < stats->job_quota && (probe = hlist_iterator_next(&runnable_iter)) != NULL) {
		bool first_transmission;
		fm_error_t error;

		first_transmission = !fm_timestamp_is_set(&probe->sent);

		fm_timestamp_clear(&probe->expires);

		error = fm_probe_send(probe);
		if (error == FM_TRY_AGAIN) {
			/* the probe asked to be postponed. */
		} else {
			if (error != FM_SEND_ERROR)
				stats->num_sent += 1;

			if (error != 0) {
				/* complain about probes that are so broken they don't even manage to
				 * send a single package. */
				if (first_transmission)
					fm_log_warning("%s: probe is DOA", probe->fullname);

				fm_probe_set_error(probe, error);
			} else if (first_transmission)
				fm_timestamp_init(&probe->sent);

			stats->num_processed += 1;
		}

		hlist_remove(&probe->link);
		if (probe->done) {
			/* rather than freeing it immediately, should we have a recycler list? */
			fm_probe_free(probe);
			continue;
		}

		if (fm_timestamp_is_set(&probe->expires))
			fm_job_move_to_group(probe, &job_group->pending_probes);
		else
			fm_job_move_to_group(probe, &job_group->ready_probes);
	}

	if (runnable.first != NULL)
		fm_job_group_postpone_remaining_runnable(job_group, &runnable_iter);
}

static void
fm_job_group_check_for_hung_state(fm_job_group_t *job_group, const fm_sched_stats_t *stats)
{
	if (fm_debug_level) {
		const struct timeval *now = fm_timestamp_now();
		static struct timeval next_ps;
		bool update_ts = false;
		fm_probe_t *probe;

		if (stats->num_processed != 0) {
			fm_timestamp_clear(&next_ps);
		} else if (!fm_timestamp_is_set(&next_ps)) {
			update_ts = true;
		} else
		if (fm_timestamp_older(&next_ps, now)) {
			struct list_iterator wait_iter;

			if (job_group->pending_probes.first == NULL) {
				fm_log_debug("%s: no pending probes", job_group->name);
			} else {
				fm_log_debug("%s: *** pending ***", job_group->name);
			}

			hlist_iterator_init(&wait_iter, &job_group->pending_probes);
			while ((probe = hlist_iterator_next(&wait_iter)) != NULL) {
				double probe_wait;

				probe_wait = fm_timestamp_expires_when(&probe->expires, NULL);
				fm_log_debug("   %4u ms %s", (unsigned int) (1000 * probe_wait), probe->name);
			}
			update_ts = true;
		}

		if (update_ts) {
			fm_timestamp_set_timeout(&next_ps, 5000);
		}

	}
}

static void
fm_job_group_get_next_schedule_time(fm_job_group_t *job_group, fm_sched_stats_t *stats)
{
	hlist_iterator_t wait_iter;
	fm_probe_t *probe;

	if (job_group->ready_probes.first != NULL) {
		fm_sched_stats_update_timeout_min(stats, fm_timestamp_now(), "runnable jobs");
		return;
	}

	hlist_iterator_init(&wait_iter, &job_group->pending_probes);
	while ((probe = hlist_iterator_next(&wait_iter)) != NULL) {
		fm_sched_stats_update_timeout_min(stats, &probe->expires, probe->name);
	}

	if (job_group->rate_limit && !fm_ratelimit_available(job_group->rate_limit)) {
		struct timeval target_come_back;
		double delay;

		delay = fm_ratelimit_wait_until(job_group->rate_limit, 1);

		fm_timestamp_set_timeout(&target_come_back, delay);
		fm_sched_stats_update_timeout_max(stats, &target_come_back, job_group->name);
	}
}

void
fm_job_group_schedule(fm_job_group_t *job_group, fm_sched_stats_t *stats)
{
	fm_job_group_process_timeouts(job_group);
	fm_job_group_process_runnable(job_group, stats);
	fm_job_group_get_next_schedule_time(job_group, stats);

	if (fm_debug_level)
		fm_job_group_check_for_hung_state(job_group, stats);
}

/*
 * Reap completed jobs
 */
bool
fm_job_group_reap_complete(fm_job_group_t *job_group)
{
	hlist_iterator_t iter;
	fm_probe_t *job;
	bool rv = false;

	/* FIXME: we should have a list for completed probes */
	hlist_iterator_init(&iter, &job_group->pending_probes);
	while ((job = hlist_iterator_next(&iter)) != NULL) {
		if (job->done) {
			fm_probe_free(job);
			rv = true;
		}
	}

	if (fm_job_list_is_empty(&job_group->pending_probes))
		job_group->plugged = false;

	return rv;
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

