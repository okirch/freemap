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

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "scanner.h"
#include "target.h"
#include "protocols.h"
#include "program.h"
#include "services.h"
#include "utils.h"


static bool			fm_scanner_start_stage(fm_scanner_t *scanner);
static fm_scan_action_t *	fm_probe_scan_create(const fm_probe_class_t *, int, const fm_probe_params_t *, const fm_uint_array_t *);
static fm_scan_action_t *	fm_scan_action_reachability_check(void);

static inline void
fm_scan_action_array_append(struct fm_scan_action_array *array, fm_scan_action_t *action)
{
	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = action;
}

static inline fm_scan_action_t *
fm_scan_action_array_get(const struct fm_scan_action_array *array, unsigned int index)
{
	if (index >= array->count)
		return NULL;
	return array->entries[index];
}

fm_scan_action_t *
fm_scan_action_create(int mode, const struct fm_scan_action_ops *ops, const char *id, fm_probe_class_t *pclass)
{
	fm_scan_action_t *action;

	action = calloc(1, ops->obj_size);
	action->mode = mode; /* FM_PROBE_MODE_ or 0 */
	action->id = strdup(id);
	action->ops = ops;

	action->probe_class = pclass;
	if (pclass != NULL)
		action->flags = pclass->action_flags;

	return action;
}

const char *
fm_scan_action_id(const fm_scan_action_t *action)
{
	return action->id;
}

bool
fm_scan_action_validate(fm_scan_action_t *action, fm_target_t *target)
{
	if ((action->flags & FM_SCAN_ACTION_FLAG_LOCAL_ONLY) && target->local_device == NULL) {
		if (!(action->flags & FM_SCAN_ACTION_FLAG_OPTIONAL))
			fm_log_error("%s: action %s only supported with local targets",
					fm_address_format(&target->address),
					fm_scan_action_id(action));
		return false;

	}

	if (action->ops->validate == NULL)
		return true;

	return action->ops->validate(action, target);
}

fm_scanner_t *
fm_scanner_create(void)
{
	fm_scanner_t *scanner;

	scanner = calloc(1, sizeof(*scanner));

	scanner->target_manager = fm_target_manager_create();
	scanner->report = fm_report_create();

	/* Set the global packet send rate.
	 * The maximum burst size defaults to 0.1 sec worth of packets. */
	fm_ratelimit_init(&scanner->send_rate_limit,
			FM_DEFAULT_GLOBAL_PACKET_RATE,
			FM_DEFAULT_GLOBAL_PACKET_RATE / 10);

	scanner->proto = fm_protocol_engine_create_default();

	fm_routing_discover();

	return scanner;
}

/*
 * Convenience function for adding scan targets from
 * a string, such as 1.2.3.4/24, or "some.host.com"
 */
bool
fm_scanner_add_target_from_spec(fm_scanner_t *scanner, const char *spec)
{
	fm_target_manager_t *target_manager = scanner->target_manager;
	bool okay;

	if (strchr(spec, '/')) {
		okay = fm_create_cidr_address_enumerator(spec, target_manager);
	} else if (spec[0] == '%') {
		okay = fm_create_local_address_enumerator(spec + 1, target_manager);
	} else {
		okay = fm_create_simple_address_enumerator(spec, target_manager);
	}

	return okay;
}

bool
fm_scanner_ready(fm_scanner_t *scanner)
{
	fm_target_manager_t *target_manager = scanner->target_manager;

	if (target_manager->address_generators.count == 0) {
		fm_log_error("No scan targets configured; nothing to scan");
		return false;
	}

	fm_timestamp_update(&scanner->scan_started);
	fm_timestamp_set_timeout(&scanner->next_pool_resize, FM_TARGET_POOL_RESIZE_TIME * 1000);

	fm_scanner_start_stage(scanner);

	return true;
}

fm_report_t *
fm_scanner_get_report(fm_scanner_t *scanner)
{
	return scanner->report;
}

fm_scan_action_t *
fm_scanner_get_action(fm_scanner_t *scanner, unsigned int index)
{
	const fm_scan_action_array_t *stage = fm_scanner_get_current_stage(scanner);

	return fm_scan_action_array_get(stage, index);
}

static void
fm_scanner_queue_action(fm_scanner_t *scanner, fm_scan_action_t *action)
{
	fm_scan_action_array_t *stage = fm_scanner_get_current_stage(scanner);

	if (action->mode == FM_PROBE_MODE_TOPO)
		stage = fm_scanner_get_stage(scanner, FM_SCAN_STAGE_TOPO);
	else
		stage = fm_scanner_get_stage(scanner, FM_SCAN_STAGE_GENERAL);
	fm_scan_action_array_append(stage, action);

	/* Create a separate target queue through which we'll feed new
	 * scan targets to the probe. */
	action->target_queue = fm_target_manager_create_queue(scanner->target_manager);

#if 0
	/* This is the wrong place; this needs to happen in the multiprobe code when
	 * selecting the next port */
	if (multiprobe && port && action->service_catalog) {
		fm_service_probe_t *service_probe;

		service_probe = fm_service_catalog_get_service_probe(action->service_catalog,
						action->probe_class->proto_id, port);
		if (service_probe != NULL) {
			fm_log_error("%s: implement multiprobe set_service");
		}
	}
#endif
}

double
fm_scanner_elapsed(fm_scanner_t *scanner)
{
	return 1000 * fm_timestamp_since(&scanner->scan_started);
}

void
fm_scanner_abort_target(fm_target_t *target)
{
	/* fm_scheduler_detach_target(scanner->scheduler, target); */
	target->scan_done = true;
}

void
fm_scanner_insert_barrier(fm_scanner_t *scanner, int probe_mode)
{
	fm_scan_action_array_t *stage = fm_scanner_get_current_stage(scanner);

	if (probe_mode == FM_PROBE_MODE_TOPO)
		stage = fm_scanner_get_stage(scanner, FM_SCAN_STAGE_TOPO);
	else
		stage = fm_scanner_get_stage(scanner, FM_SCAN_STAGE_GENERAL);

        if (stage->count) {
                fm_scan_action_t *action = stage->entries[stage->count - 1];
                action->barrier = true;
        }
}

/*
 * Add a job at the global level, for instance a discovery probe.
 */
void
fm_scanner_add_global_job(fm_scanner_t *scanner, fm_job_t *job)
{
	fm_job_group_t *job_group = fm_scheduler_create_global_queue();

	assert(job_group);

	fm_job_group_add_new(job_group, job);
}

/*
 * Schedule everything that needs to be scheduled.
 */
static inline void
fm_scanner_schedule_job_group(fm_scanner_t *scanner, fm_job_group_t *job_group, fm_sched_stats_t *global_stats)
{
	fm_sched_stats_t sched_stats;

	memset(&sched_stats, 0, sizeof(sched_stats));
	sched_stats.job_quota = global_stats->job_quota;

	fm_job_group_schedule(job_group, &sched_stats);

	fm_sched_stats_update_from_nested(global_stats, &sched_stats);
	fm_ratelimit_consume(&scanner->send_rate_limit, sched_stats.num_sent);
}

void
fm_scanner_schedule(fm_scanner_t *scanner, fm_sched_stats_t *global_stats)
{
	fm_job_group_t *global_queue;

	if (global_stats->job_quota != 0
	 && (global_queue = fm_scheduler_get_global_queue()) != NULL)
		fm_scanner_schedule_job_group(scanner, global_queue, global_stats);
}

/*
 * Create new probes
 */
static void
fm_scanner_create_new_probes(fm_scanner_t *scanner, fm_sched_stats_t *sched_stats)
{
	bool have_new_targets = false;
	unsigned int k;

	if (scanner->current_stage.next_pool_id != scanner->target_manager->next_free_pool_id)
		have_new_targets = true;

	for (k = scanner->current_stage.num_done; k < scanner->current_stage.actions->count; ++k) {
		fm_scan_action_t *action = scanner->current_stage.actions->entries[k];
		fm_multiprobe_t *multiprobe;
		fm_target_pool_iterator_t iter;
		fm_target_t *target;

		multiprobe = action->multiprobe;
		if (have_new_targets && multiprobe) {
			if (multiprobe->job.group == NULL)
				fm_scanner_add_global_job(scanner, &multiprobe->job);

			fm_target_pool_begin(action->target_queue, &iter);
			while ((target = fm_target_pool_next(&iter)) != NULL) {
				if (!fm_multiprobe_add_target(multiprobe, target)) {
					fm_target_pool_remove(action->target_queue, target);
					fm_log_debug("%s: could not add %s", action->id, target->id);
				}
			}
			fm_job_continue(&multiprobe->job);
		}

		if (multiprobe == NULL) {
			if (scanner->current_stage.num_done == k) {
				scanner->current_stage.num_done = k +1;
				fm_log_debug("num_done=%u", scanner->current_stage.num_done);
			}
			continue;
		}

		fm_multiprobe_transmit(action->multiprobe, sched_stats);

		if (multiprobe != NULL) {
			/* inform the pool about targets that we're done with */
			while ((target = fm_multiprobe_get_completed(multiprobe)) != NULL) {
				fm_log_debug("target %s done with scan %s", target->id, action->id);
				fm_target_pool_remove(action->target_queue, target);
			}
		}

		if (fm_multiprobe_is_idle(multiprobe) && scanner->target_manager->all_targets_exhausted) {
			fm_log_debug("%s done with scanning all available targets", multiprobe->name);
			fm_job_mark_complete(&multiprobe->job);
			action->multiprobe = NULL;
		}
	}

	scanner->current_stage.next_pool_id = scanner->target_manager->next_free_pool_id;
}

/*
 * Reap all targets that have completed.
 */
void
fm_scanner_process_completed(fm_scanner_t *scanner)
{
	hlist_iterator_t iter;

	/* We just iterate over all targets. This will remove completed ones */
	fm_target_manager_begin(scanner->target_manager, &iter);
	while (fm_target_manager_next(scanner->target_manager, &iter) != NULL)
		;
}

bool
fm_scanner_transmit(fm_scanner_t *scanner, fm_time_t *timeout)
{
	fm_sched_stats_t scan_stats;

	/* This should probably also be a job... */
	if (fm_timestamp_older(&scanner->next_pool_resize, NULL)) {
		fm_log_debug("Trying to resize target pool\n");
		fm_target_manager_resize_pool(scanner->target_manager, FM_TARGET_POOL_MAX_SIZE);
		fm_timestamp_set_timeout(&scanner->next_pool_resize, FM_TARGET_POOL_RESIZE_TIME * 1000);
	}

	if (!fm_target_manager_replenish_pools(scanner->target_manager)) {
		fm_log_debug("Looks like we're done\n");
		fm_report_flush(scanner->report);
		return false;
	}

	fm_ratelimit_update(&scanner->send_rate_limit);

	memset(&scan_stats, 0, sizeof(scan_stats));
	scan_stats.job_quota = fm_ratelimit_available(&scanner->send_rate_limit);

	/* Run all runnable jobs (to the degree rate limits allow) */
	fm_scanner_schedule(scanner, &scan_stats);

	/* Process events */
	fm_event_process_all();

	/* Schedule and transmit a few additional probes */
	fm_scanner_create_new_probes(scanner, &scan_stats);

	/* Reap any targets that we're done with, making room in the pool for
	 * the next batch of targets. */
	fm_scanner_process_completed(scanner);

	if (timeout)
		*timeout = scan_stats.timeout;

	return true;
}

static bool
fm_scanner_start_stage(fm_scanner_t *scanner)
{
	unsigned int index = scanner->current_stage.index;
	fm_scan_action_array_t *array;

	scanner->current_stage.actions = NULL;
	scanner->current_stage.num_done = 0;

	while (index <  __FM_SCAN_STAGE_MAX) {
		array = &scanner->stage_requests[index];
		if (array->count > 0) {
			fm_target_manager_restart(scanner->target_manager, index);
			scanner->current_stage.index = index;
			scanner->current_stage.actions = array;
			return true;
		}
		index++;
	}

	scanner->current_stage.index = index;
	return false;
}

bool
fm_scanner_next_stage(fm_scanner_t *scanner)
{
	scanner->current_stage.index += 1;
	return fm_scanner_start_stage(scanner);
}


fm_protocol_t *
fm_scanner_get_protocol_engine(fm_scanner_t *scanner, const char *protocol_name)
{
	return fm_protocol_engine_get_protocol(scanner->proto, protocol_name);
}

void
fm_scanner_dump_program(fm_scanner_t *scanner)
{
	unsigned int i, j;

	printf("compiled program:\n");
	for (j = 0; j < __FM_SCAN_STAGE_MAX; ++j) {
		fm_scan_action_array_t *array = fm_scanner_get_stage(scanner, j);

		if (array->count == 0)
			continue;

		printf("scan stage %d\n", j);

		for (i = 0; i < array->count; ++i) {
			fm_scan_action_t *action = array->entries[i];

			printf(" %2u: %s", i, action->id);
			if (action->barrier)
				printf("; barrier");
			printf("\n");
		}
	}
}

/*
 * Dummy probe that does nothing
 */
static bool
fm_dummy_probe_validate(fm_scan_action_t *action, fm_target_t *target)
{
	return false;
}

static const struct fm_scan_action_ops	fm_dummy_host_scan_ops = {
	.obj_size	= sizeof(fm_scan_action_t),
	.validate	= fm_dummy_probe_validate,
};

fm_scan_action_t *
fm_scanner_add_dummy_probe(void)
{
	fm_scan_action_t *action;

	action = fm_scan_action_create(0, &fm_dummy_host_scan_ops, "dummy", NULL);
	action->nprobes = 0;
	return action;
}

/*
 * Create a topo, host or port scan action
 */
fm_scan_action_t *
fm_scanner_add_probe(fm_scanner_t *scanner, const fm_config_probe_t *parsed_probe)
{
	const char *probe_name = parsed_probe->name;
	int mode = parsed_probe->mode;
	fm_probe_class_t *pclass;
	fm_scan_action_t *action = NULL;
	fm_uint_array_t ports;
	int flags = 0, param_type;

	memset(&ports, 0, sizeof(ports));

	if (parsed_probe->optional)
		flags = FM_SCAN_ACTION_FLAG_OPTIONAL;

	pclass = fm_probe_class_find(probe_name, mode);
	if (pclass == NULL) {
		if (!(flags & FM_SCAN_ACTION_FLAG_OPTIONAL)) {
			fm_log_error("Unknown host %s class %s\n",
					fm_probe_mode_to_string(mode),
					probe_name);
			goto failed;
		}

		fm_log_debug("Ignoring optional %s %s probe - creating dummy action",
				fm_probe_mode_to_string(mode), probe_name);
		action = fm_scanner_add_dummy_probe();
		return action;
	}

	param_type = fm_config_probe_process_params(parsed_probe, &ports);
	if (param_type < 0)
		goto failed;

	action = fm_probe_scan_create(pclass, mode, &parsed_probe->probe_params, &ports);

	assert(action->nprobes >= 1);
	action->flags |= flags;

	action->multiprobe = fm_multiprobe_from_config(pclass, parsed_probe);

	fm_scanner_queue_action(scanner, action);

	if (pclass->features & FM_FEATURE_SERVICE_PROBES_MASK)
		action->service_catalog = scanner->service_catalog;

	return action;

failed:
	if (action) {
		/* no fm_action_free() yet, leak */
	}

	fm_uint_array_destroy(&ports);
	return NULL;
}

/*
 * The service_catalog tells you whether the scan has been configured to use service
 * probes for certain ports
 */
void
fm_scanner_set_service_catalog(fm_scanner_t *scanner, const fm_service_catalog_t *service_catalog)
{
	scanner->service_catalog = service_catalog;
}

fm_scan_action_t *
fm_scanner_add_reachability_check(fm_scanner_t *scanner)
{
#if 0
	fm_scan_action_t *action;

	if ((action = fm_scan_action_reachability_check()) != NULL) {
		fm_scanner_queue_action(scanner, action);
		action->barrier = true;
	}
	return action;
#else
	return NULL;
#endif
}

/*
 * After executing a number of probes, chech whether at least one has reached the target host
 */
static bool
fm_host_reachability_check_validate(fm_scan_action_t *action, fm_target_t *target)
{
	fm_host_asset_t *host = target->host_asset;

	if (host == NULL || fm_host_asset_get_state(host) != FM_ASSET_STATE_OPEN) {
		fm_log_debug("%s does not respond to any probe, skipping all other scan actions\n", fm_address_format(&target->address));
		fm_scanner_abort_target(target);
	}

	return false;
}

static const struct fm_scan_action_ops	fm_host_reachability_check_ops = {
	.obj_size	= sizeof(fm_scan_action_t),
	.validate	= fm_host_reachability_check_validate,
};


fm_scan_action_t *
fm_scan_action_reachability_check(void)
{
	return fm_scan_action_create(0, &fm_host_reachability_check_ops, "reachability-check", NULL);
}

/*
 * Generic scan action representing a probe.
 */
static bool
fm_probe_scan_action_validate(fm_scan_action_t *action, fm_target_t *target)
{
	if (action->probe_class->family != AF_UNSPEC
	 && action->probe_class->family != target->address.ss_family) {
		fm_log_debug("%s: skipping incompatible probe %s",
				fm_address_format(&target->address),
				action->probe_class->name);
		return false;
	}

	return true;
}

static const struct fm_scan_action_ops	fm_probe_scan_action_ops = {
	.obj_size	= sizeof(fm_scan_action_t),
	.validate	= fm_probe_scan_action_validate,
};

fm_scan_action_t *
fm_probe_scan_create(const fm_probe_class_t *pclass, int mode, const fm_probe_params_t *params, const fm_uint_array_t *ports)
{
	const char *mode_string = fm_probe_mode_to_string(mode);
	fm_scan_action_t *action;
	char idbuf[128];

	if (mode == FM_PROBE_MODE_PORT) {
		if (ports == NULL || ports->count == 0) {
			fm_log_error("%s: %s scan requires ports", pclass->name, mode_string);
			return NULL;
		}
	} else {
		if (ports != NULL && ports->count != 0) {
			fm_log_error("%s: %s scan cannot handle port range", pclass->name, mode_string);
			return NULL;
		}
	}


	snprintf(idbuf, sizeof(idbuf), "%sscan/%s", mode_string, pclass->name);

	action = fm_scan_action_create(mode, &fm_probe_scan_action_ops, idbuf, pclass);
	action->probe_params = *params;

	if (mode == FM_PROBE_MODE_PORT) {
		/* simply assign the port array. The caller better not free their copy */
		action->numeric_params = *ports;
		action->nprobes = action->numeric_params.count;
	} else {
		action->nprobes = 1;
	}


	return action;
}
