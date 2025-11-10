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
#include "scanner.h"
#include "events.h"


static fm_job_group_t *fm_global_group = NULL;


fm_scheduler_t *
fm_scheduler_alloc(fm_scanner_t *scanner, const struct fm_scheduler_ops *ops)
{
	fm_scheduler_t *ret;

	assert(ops->size >= sizeof(*ret));
	ret = calloc(1, ops->size);
	ret->scanner = scanner;
	ret->target_manager = scanner->target_manager;
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
 * fm_probe primitives
 */
void
fm_job_free(fm_job_t *job)
{
	if (job->completion)
		fm_log_fatal("BUG: %s(%s) with pending completion", __func__, job->fullname);

	if (job->event_listener != NULL)
		fm_event_listener_free(job->event_listener);

	hlist_remove(&job->link);
	job->group = NULL;

	if (job->ops->destroy) {
		job->ops->destroy(job);

		assert(job->link.prevp == NULL);
	}

	fm_log_debug("%s destroyed", job->fullname);
	drop_string(&job->fullname);

	memset(job, 0, sizeof(*job));
	free(job);
}

void
fm_job_run(fm_job_t *job, fm_job_group_t *job_group)
{
	if (job_group == NULL) {
		job_group = fm_scheduler_create_global_queue();
		assert(job_group);
	}

	fm_job_group_add_new(job_group, job);
}

/*
 * Set timeout on a job
 */
void
fm_job_set_expiry(fm_job_t *job, double seconds)
{
	if (seconds < 0)
		fm_log_error("%s: asking to set a negative expiry value %f", job->fullname, seconds);

	if (seconds <= 0) {
		job->expires = 0;
	} else {
		job->expires = fm_time_now() + seconds;
	}
}


void
fm_job_mark_complete(fm_job_t *job)
{
	/* could be set to gather stats on job runtime */
	if (!job->done && job->ops->complete)
		job->ops->complete(job, job->error);
	job->done = true;

	fm_job_invoke_completion(job);
}

void
fm_job_set_error(fm_job_t *job, fm_error_t error)
{
	if (!job->done) {
		if (!job->error)
			job->error = error;
	}
	fm_job_mark_complete(job);
}

void
fm_job_postpone(fm_job_t *job)
{
	fm_job_group_t *job_group = job->group;

	assert(job_group);
	fm_job_move_to_group(job, &job_group->postponed_probes);

	if (job->blocking)
		job_group->plugged = true;

	fm_log_debug("%s: postponed", job->fullname);
}

void
fm_job_continue(fm_job_t *job)
{
	fm_job_group_t *job_group = job->group;

	assert(job_group);
	fm_job_move_to_group(job, &job_group->ready_probes);

	/* stop waiting, re-visit ASAP */
	job->expires = 0;

	if (fm_debug_level >= 2)
		fm_log_debug("%s: moved to ready", job->fullname);
}

/*
 * completions are a way to notify someone when a subordinate job exits
 */
void
fm_job_invoke_completion(fm_job_t *job)
{
	fm_completion_t *completion;

	if ((completion = job->completion) != NULL) {
		job->completion = NULL;
		completion->callback(job, completion->user_data);
	}
}

fm_completion_t *
fm_job_wait_for_completion(fm_job_t *job, void (*func)(const fm_job_t *, void *), void *user_data)
{
	fm_completion_t *completion;

	if (job->completion != NULL) {
		fm_log_error("%s: refusing to install more than one completion", job->fullname);
		return NULL;
	}

	completion = calloc(1, sizeof(*completion));
	completion->callback = func;
	completion->user_data = user_data;

	job->completion = completion;
	return completion;
}

void
fm_job_cancel_completion(fm_job_t *job, const fm_completion_t *completion)
{
	if (job->completion == completion)
		job->completion = NULL;
}

void
fm_completion_free(fm_completion_t *completion)
{
	completion = NULL;
}

/*
 * A job can also wait for an event, such as a neighbor cache update.
 */
bool
fm_job_wait_for_event(fm_job_t *job, fm_event_callback_t *callback, fm_event_t event)
{
        fm_event_listener_t *evl;

        if ((evl = job->event_listener) != NULL) {
                if (evl->callback == callback && evl->event == event)
                        return true;
                fm_log_error("%s: cannot wait for more than one event at a time", job->fullname);
                return false;
        }

        job->event_listener = fm_event_listener_alloc(job, callback, event);
        return true;
}

void
fm_job_finish_waiting(fm_job_t *job)
{
        fm_event_listener_t *evl;

        if ((evl = job->event_listener) != NULL) {
                fm_event_listener_disable(evl);
                job->event_listener = NULL;
        }

	fm_job_continue(job);
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
fm_job_move_to_group(fm_job_t *job, struct hlist_head *head)
{
	hlist_remove(&job->link);
	hlist_insert(head, &job->link);
}

void
fm_job_list_destroy(struct hlist_head *head)
{
	hlist_iterator_t iter;
	fm_job_t *job;

	hlist_iterator_init(&iter, head);
	while ((job = hlist_iterator_next(&iter)) != NULL)
		fm_job_free(job);
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

unsigned int
fm_job_group_get_send_quota(fm_job_group_t *job_group, unsigned int max_quota)
{
	unsigned int quota;

	quota = fm_ratelimit_available(job_group->rate_limit);
	if (quota > max_quota)
		quota = max_quota;
	return quota;
}

/*
 * Initialize an empty job
 */
void
fm_job_init(fm_job_t *job, const fm_job_ops_t *ops, const char *name)
{
	job->_name = name;
	job->ops = ops;

	assert(ops->run && ops->destroy);
}

/*
 * Add a newly created job to a job group
 */
fm_error_t
fm_job_group_add_new(fm_job_group_t *job_group, fm_job_t *job)
{
	assert(job->group == NULL);
	job->group = job_group;

	assert(job->ops != NULL);

	if (job->fullname == NULL)
		asprintf(&job->fullname, "%s/%s", job_group->name, job->_name);

	if (job->event_listener == NULL) {
		fm_job_move_to_group(job, &job_group->ready_probes);
	} else {
		fm_job_move_to_group(job, &job_group->postponed_probes);
		fm_log_debug("%s: postponed", job->fullname);
	}

	/* If the probe is marked as blocking, do not allow
	 * any further probes to be created until we've
	 * processed everything that is in the queue. */
	if (job->blocking)
		job_group->plugged = true;

	fm_log_debug("%s: added", job->fullname);
	return 0;
}

/*
 * Process all timeouts in a job group
 */
void
fm_job_group_process_timeouts(fm_job_group_t *job_group)
{
	fm_time_t now = fm_time_now();
	hlist_insertion_iterator_t ready_tail_iter;
	hlist_iterator_t wait_iter;
	fm_job_t *probe;

	hlist_iterator_init(&wait_iter, &job_group->pending_probes);

	hlist_insertion_iterator_init_tail(&ready_tail_iter, &job_group->ready_probes);

	while ((probe = hlist_iterator_next(&wait_iter)) != NULL) {
		if (probe->expires <= now) {
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
	fm_job_t *probe;

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
	fm_job_t *job;

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
	while (stats->num_sent < stats->job_quota && (job = hlist_iterator_next(&runnable_iter)) != NULL) {
		fm_error_t error;

		job->expires = 0;

		error = job->ops->run(job, stats);
		if (error == FM_TRY_AGAIN) {
			/* the job asked to be postponed. */
			if (job->expires == 0) {
				fm_log_warning("BUG: job %s returned status=%d but did not set expiry", job->fullname, -error);
				job->expires = fm_time_now() + 10;
			}
		} else if (error == 0) {
			if (job->group->rate_limit)
				fm_ratelimit_consume(job->group->rate_limit, 1);
			stats->num_processed += 1;
		} else {
			fm_log_debug("%s: %s", job->fullname, fm_strerror(error));
			fm_job_set_error(job, error);
			stats->num_processed += 1;
		}

		hlist_remove(&job->link);
		if (job->done) {
			/* rather than freeing it immediately, should we have a recycler list? */
			fm_job_free(job);
			continue;
		}

		if (job->expires > 0)
			fm_job_move_to_group(job, &job_group->pending_probes);
		else
			fm_job_move_to_group(job, &job_group->ready_probes);
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
		fm_job_t *probe;

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

				probe_wait = probe->expires - fm_time_now();
				fm_log_debug("   %4u ms %s", (unsigned int) (1000 * probe_wait), probe->fullname);
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
	fm_job_t *probe;

	if (job_group->ready_probes.first != NULL) {
		fm_sched_stats_update_timeout_min(stats, fm_time_now(), "runnable jobs");
		return;
	}

	hlist_iterator_init(&wait_iter, &job_group->pending_probes);
	while ((probe = hlist_iterator_next(&wait_iter)) != NULL) {
		fm_sched_stats_update_timeout_min(stats, probe->expires, probe->fullname);
	}

	if (job_group->rate_limit && !fm_ratelimit_available(job_group->rate_limit)) {
		double delay;

		delay = fm_ratelimit_wait_until(job_group->rate_limit, 1);

		fm_sched_stats_update_timeout_max(stats,
				fm_time_now() + delay,
				job_group->name);
	}
}

void
fm_job_group_schedule(fm_job_group_t *job_group, fm_sched_stats_t *stats)
{
	if (job_group->rate_limit != NULL) {
		fm_ratelimit_update(job_group->rate_limit);

                stats->job_quota = fm_job_group_get_send_quota(job_group, stats->job_quota);
	}

	if (stats->job_quota == 0)
		return;

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
	fm_job_t *job;
	bool rv = false;

	/* FIXME: we should have a list for completed probes */
	hlist_iterator_init(&iter, &job_group->pending_probes);
	while ((job = hlist_iterator_next(&iter)) != NULL) {
		if (job->done) {
			fm_job_free(job);
			rv = true;
		}
	}

	if (fm_job_list_is_empty(&job_group->pending_probes))
		job_group->plugged = false;

	return rv;
}

/*
 * We maintain a single, global queue not associated with a target
 * for things like discovery tasks
 */
fm_job_group_t *
fm_scheduler_create_global_queue(void)
{
	if (fm_global_group == NULL) {
		fm_global_group = calloc(1, sizeof(*fm_global_group));
		fm_job_group_init(fm_global_group, "GLOBAL", NULL);
	}
	return fm_global_group;
}

fm_job_group_t *
fm_scheduler_get_global_queue(void)
{
	return fm_global_group;
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
	hlist_iterator_t iter;
	unsigned int num_created = 0, max_create;

	fm_target_manager_begin(sched->target_manager, &iter);

	max_create = stats->job_quota - stats->num_sent;
	while (num_created < max_create) {
		unsigned int target_quota, target_created = 0;
		fm_target_t *target;

		target = fm_target_manager_next(sched->target_manager, &iter);
		if (target == NULL)
			break;

		target_quota = fm_job_group_get_send_quota(&target->job_group, max_create - num_created);
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
fm_sched_stats_update_timeout_min(fm_sched_stats_t *stats, fm_time_t expiry, const char *who)
{
	if (expiry <= 0)
		return false;

	if (stats->timeout == 0 || expiry < stats->timeout) {
		stats->timeout = expiry;

		if (fm_debug_level > 1) {
			double delay = stats->timeout - fm_time_now();
			fm_log_debug("%s: new timeout is %f", who, delay);
			/* assert(delay >= -1e-6); */
		}
		return true;
	}
	return false;
}

bool
fm_sched_stats_update_timeout_max(fm_sched_stats_t *stats, fm_time_t expiry, const char *who)
{
	if (stats->timeout > 0 && stats->timeout < expiry) {
		stats->timeout = expiry;

		fm_log_debug("%s: new timeout is %f", who, stats->timeout - fm_time_now());
		return true;
	}
	return false;
}

void
fm_sched_stats_update_from_nested(fm_sched_stats_t *stats, const fm_sched_stats_t *nested)
{
	fm_sched_stats_update_timeout_min(stats, nested->timeout, __func__);
	stats->num_sent += nested->num_sent;
	stats->num_processed += nested->num_processed;
}

