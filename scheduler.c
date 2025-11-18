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
#include "logging.h"
#include "target.h"
#include "scheduler.h"
#include "scanner.h"
#include "events.h"


#define debugmsg	fm_debug_scheduler

static fm_job_group_t *fm_global_group = NULL;

/*
 * fm_job primitives
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

	debugmsg("%s destroyed", job->fullname);
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

	debugmsg("%s: postponed", job->fullname);
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
		debugmsg("%s: moved to ready", job->fullname);
}

bool
fm_job_is_active(const fm_job_t *job)
{
	return job->group != NULL;
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
		debugmsg("%s: postponed", job->fullname);
	}

	/* If the probe is marked as blocking, do not allow
	 * any further probes to be created until we've
	 * processed everything that is in the queue. */
	if (job->blocking)
		job_group->plugged = true;

	debugmsg("%s: added", job->fullname);
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

		if (job->cond_await != NULL)
			fm_job_cancel_wait(job);

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
			debugmsg("%s: %s", job->fullname, fm_strerror(error));
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
	if (fm_debug_facilities & FM_DEBUG_FACILITY_SCHEDULER) {
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
 * Condition variables.
 * A job can wait on a condition variable by calling fm_job_wait_condition().
 * It must save the pointer returned by this.
 * When woken up by the scheduler, it can either remove itself from the
 * wait list by calling fm_job_wait_free(), or go back to sleep and wait some
 * more by using fm_job_wait_continue().
 *
 * When waiting with a timeout, this value is applied end-to-end, ie no matter
 * how many times a task may be woken up intermittently, the task will be
 * awoken after the time elapsed since first waiting exceeds the specified timeout.
 *
 * FIXME: right now, the job is supposed to re-check its condition(s) and then
 * decide whether to cancel the awaiter, or to continue. This is a bit error prone.
 * We could either
 *    - add a "check_condition()" callback to the awaiter, and invoke that
 *	before calling job.run(). If the condition isn't met, put the job back
 *	to sleep
 *    - always free the awaiter as soon as the job is woken up. This has the
 *	drawback that we lose the ability to track the timeout end-to-end.
 */
fm_cond_await_t *
fm_job_wait_condition_timed(fm_cond_var_t *cond_var, fm_job_t *job, double timeout)
{
	fm_cond_await_t *await;

	if (job->cond_await != NULL) {
		fm_log_error("%s: cannot wait on two condition variables at the same time", job->fullname);
		return NULL;
	}

	await = calloc(1, sizeof(*await));
	await->job = job;

	if (timeout > 0) {
		await->expires = fm_time_now() + timeout;
		job->expires = await->expires;
	} else {
		await->expires = 0;
		job->expires = fm_time_now() + 30;
	}

	hlist_insert(&cond_var->waiters, &await->link);

	job->cond_await = await;

	return await;
}

fm_cond_await_t *
fm_job_wait_condition(fm_cond_var_t *cond_var, fm_job_t *job)
{
	return fm_job_wait_condition_timed(cond_var, job, 0);
}

bool
fm_job_wait_continue(fm_cond_await_t *await)
{
	if (await->expires && await->expires <= fm_time_now())
		return false;
	assert(await->link.prevp != NULL);
	return true;
}

void
fm_job_wait_free(fm_cond_await_t *await)
{
	hlist_remove(&await->link);
	await->job = NULL;
	free(await);
}

void
fm_job_cancel_wait(fm_job_t *job)
{
	if (job->cond_await != NULL) {
		fm_job_wait_free(job->cond_await);
		job->cond_await = NULL;
	}
}

void
fm_scheduler_notify_condition(fm_cond_var_t *cond_var)
{
	hlist_iterator_t iter;
	fm_cond_await_t *await;

	hlist_iterator_init(&iter, &cond_var->waiters);
	while ((await = hlist_iterator_next(&iter)) != NULL) {
		fm_job_t *job = await->job;

		if (job->ops->check_condition != NULL
		 && !job->ops->check_condition(job, cond_var)) {
			/* keep waiting */
			continue;
		}

		/* hlist_iterator tolerates removal of the current item */
		fm_job_cancel_wait(job);

		fm_job_continue(job);
	}
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
			debugmsg("%s: new timeout is %f", who, delay);
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

		debugmsg("%s: new timeout is %f", who, stats->timeout - fm_time_now());
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

