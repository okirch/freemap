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

fm_probe_t *
fm_scan_action_get_next_probe(fm_scan_action_t *action, fm_target_t *target, unsigned int index)
{
	fm_probe_t *probe;

	probe = action->ops->get_next_probe(action, target, index);
	if (probe != NULL) {
		if (action->barrier && index + 1 >= action->nprobes)
			probe->blocking = true;

		fm_log_debug("   %s created next probe for %s index=%d%s\n",
				fm_target_get_id(target), action->id, index,
				probe->blocking? " (blocking)": "");
	}
	return probe;
}

fm_scanner_t *
fm_scanner_create(void)
{
	fm_scanner_t *scanner;

	scanner = calloc(1, sizeof(*scanner));

	scanner->target_manager = fm_target_manager_create();
	scanner->target_pool = fm_target_pool_create(FM_INITIAL_TARGET_POOL_SIZE);
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
	fm_address_enumerator_t *agen;

	if (strchr(spec, '/')) {
		agen = fm_create_cidr_address_enumerator(spec);
	} else if (spec[0] == '%') {
		agen = fm_create_local_address_enumerator(spec + 1);
	} else {
		agen = fm_create_simple_address_enumerator(spec);
	}

	if (agen == NULL)
		return false;

	fm_target_manager_add_address_generator(scanner->target_manager, agen);
	return true;
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

	if (scanner->scheduler == NULL)
		scanner->scheduler = fm_linear_scheduler_create(scanner);

	fm_target_pool_make_active(scanner->target_pool);
	fm_target_manager_restart(scanner->target_manager, scanner->current_stage);

	return true;
}

fm_report_t *
fm_scanner_get_report(fm_scanner_t *scanner)
{
	return scanner->report;
}

fm_target_pool_t *
fm_scanner_get_target_pool(fm_scanner_t *scanner)
{
	return scanner->target_pool;
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
 * Process the timeouts for all probes. This does not actually invoke any
 * of the probes, it just moves them to the list of runnable probes.
 */
void
fm_scanner_schedule(fm_scanner_t *scanner, fm_sched_stats_t *global_stats)
{
	unsigned int num_visited = 0;

	while (true) {
		fm_target_t *target;
		fm_sched_stats_t sched_stats;

		if (global_stats->job_quota == 0)
			break; /* we exhausted our global send quota */

		target = fm_target_pool_get_next(scanner->target_pool, &num_visited);
		if (target == NULL)
			break;

		fm_ratelimit_update(&target->host_rate_limit);

		memset(&sched_stats, 0, sizeof(sched_stats));
		sched_stats.job_quota = fm_target_get_send_quota(target, global_stats->job_quota);
		if (sched_stats.job_quota != 0) {
			fm_target_schedule(target, &sched_stats);

			fm_sched_stats_update_from_nested(global_stats, &sched_stats);
			fm_ratelimit_consume(&scanner->send_rate_limit, sched_stats.num_sent);
		}
	}
}

void
fm_scanner_process_completed(fm_scanner_t *scanner)
{
	unsigned int num_visited = 0;

	while (true) {
		fm_target_t *target;

		target = fm_target_pool_get_next(scanner->target_pool, &num_visited);
		if (target == NULL)
			break;

		if (fm_target_is_done(target)) {
			fm_log_debug("%s is done - reaping what we have sown\n", fm_address_format(&target->address));

			fm_target_pool_remove(scanner->target_pool, target);

			/* wrap up reporting for this target */
			fm_report_write(scanner->report, target);

			if (target->job_group.sched_state != NULL)
				fm_scheduler_detach_target(scanner->scheduler, target);

			fm_target_free(target);
		}
	}
}

bool
fm_scanner_transmit(fm_scanner_t *scanner, struct timeval *timeout)
{
	fm_sched_stats_t scan_stats;

	/* This should probably also be a job... */
	if (fm_timestamp_older(&scanner->next_pool_resize, NULL)) {
		fm_log_debug("Trying to resize target pool\n");
		fm_target_pool_auto_resize(scanner->target_pool, FM_TARGET_POOL_MAX_SIZE);
		fm_timestamp_set_timeout(&scanner->next_pool_resize, FM_TARGET_POOL_RESIZE_TIME * 1000);
	}

	if (!fm_target_manager_replenish_pool(scanner->target_manager, scanner->target_pool)) {
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
	fm_scheduler_create_new_probes(scanner->scheduler, &scan_stats);

	/* Reap any targets that we're done with, making room in the pool for
	 * the next batch of targets. */
	fm_scanner_process_completed(scanner);

	/* This loops over the entire pool and reaps the status of completed probes */
	fm_target_pool_reap_completed(scanner->target_pool);

	if (timeout)
		*timeout = scan_stats.timeout;

	return true;
}

bool
fm_scanner_next_stage(fm_scanner_t *scanner)
{
	while (++(scanner->current_stage) < __FM_SCAN_STAGE_MAX) {
		fm_scan_action_array_t *stage;

		stage = fm_scanner_get_current_stage(scanner);
		if (stage->count > 0) {
			fm_target_manager_restart(scanner->target_manager, scanner->current_stage);
			return true;
		}
	}
	scanner->current_stage = __FM_SCAN_STAGE_MAX;
	return false;
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
 * Process a port or port range
 */
static bool
fm_scanner_process_port(fm_probe_class_t *pclass, const char *arg, fm_uint_array_t *array)
{
	fm_port_range_t range;
	unsigned int low_port, high_port;

	if (!fm_parse_port_range(arg, &range)) {
		fm_log_error("%s: unable to parse port range \"%s\"", pclass->name, arg);
		return false;
	}

	low_port = range.first;
	high_port = range.last;

	if (low_port == 0 || low_port > high_port || high_port > 65535) {
		fm_log_error("%s: invalid port range %u-%u", pclass->name, low_port, high_port);
		return false;
	}

	while (low_port <= high_port)
		fm_uint_array_append(array, low_port++);

	return true;
}

static bool
fm_scanner_process_port_array(fm_probe_class_t *pclass, const fm_string_array_t *strings,  fm_uint_array_t *port_array)
{
	unsigned int i;

	for (i = 0; i < strings->count; ++i) {
		const char *arg = strings->entries[i];

		if (!fm_scanner_process_port(pclass, arg, port_array))
			return false;
	}

	if (port_array->count == 0) {
		fm_log_error("%s: requires one or more ports, but none were specified", pclass->name);
		return false;
	}

	return true;
}

static bool
fm_scanner_process_proto_args(fm_probe_class_t *pclass, fm_scan_action_t *action, int mode, const fm_string_array_t *extra_args)
{
	if (extra_args->count == 0)
		return true;

	if (pclass->process_extra_parameters != NULL) {
		void *extra_params;

		extra_params = pclass->process_extra_parameters(pclass, extra_args);
		if (extra_params == NULL)
			return false;

		action->extra_params = extra_params;
	} else
	if (extra_args->count != 0) {
		fm_log_error("found %u unrecognized parameters in %s probe for %s", extra_args->count,
				fm_probe_mode_to_string(mode), pclass->name);
		return false;
	}

	return true;
}

/*
 * Process probe arguments
 */
static bool
fm_scanner_process_arguments(fm_probe_class_t *pclass, int mode, const fm_string_array_t *args,
			fm_probe_params_t *params, fm_string_array_t *proto_args, fm_uint_array_t *ports)
{
	bool randomize = false;
	unsigned int i;

	if (mode == FM_PROBE_MODE_PORT && !ports) {
		fm_log_error("%s: trying to parse port scan arguments, but ports argument is NULL", __func__);
		return false;
	}

	for (i = 0; i < args->count; ++i) {
		const char *arg = args->entries[i];
		fm_param_type_t param_type = FM_PARAM_TYPE_NONE;

		if (isdigit(*arg) && mode == FM_PROBE_MODE_PORT) {
			if (!fm_scanner_process_port(pclass, arg, ports))
				return false;
		} else
		if (fm_parse_numeric_argument(arg, "retries", &params->retries)) {
			param_type = FM_PARAM_TYPE_RETRIES;
		} else if (fm_parse_numeric_argument(arg, "ttl", &params->ttl)) {
			param_type = FM_PARAM_TYPE_TTL;
		} else if (fm_parse_numeric_argument(arg, "tos", &params->tos)) {
			param_type = FM_PARAM_TYPE_TOS;
		} else if (!strcmp(arg, "random")) {
			randomize = true;
		} else {
			fm_string_array_append(proto_args, arg);
		}

		if (param_type != FM_PARAM_TYPE_NONE
		 && !fm_probe_class_supports(pclass, param_type)) {
			fm_log_error("probe %s does not support parameter %s", pclass->name, arg);
			return false;
		}
	}

	if (mode == FM_PROBE_MODE_PORT) {
		if (ports->count == 0) {
			fm_log_error("%s: port scan request does not specify any ports to scan", pclass->name);
			return false;
		}

		if (randomize)
			fm_uint_array_randomize(ports);
	}

	return true;
}

/*
 * Create a topo, host or port scan action
 */
static fm_scan_action_t *
fm_scanner_create_probe_action(const char *probe_name, int mode, int flags, const fm_string_array_t *args)
{
	fm_probe_class_t *pclass;
	fm_scan_action_t *action;
	fm_probe_params_t params;
	fm_string_array_t proto_args;
	fm_uint_array_t ports;

	memset(&proto_args, 0, sizeof(proto_args));
	memset(&params, 0, sizeof(params));
	memset(&ports, 0, sizeof(ports));

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

	if (!fm_scanner_process_arguments(pclass, mode, args, &params, &proto_args, &ports))
		return NULL;

	action = fm_probe_scan_create(pclass, mode, &params, &ports);

	if (!fm_scanner_process_proto_args(pclass, action, mode, &proto_args))
		goto failed;

	assert(action->nprobes >= 1);
	action->flags |= flags;

	return action;

failed:
	if (action) {
		/* no fm_action_free() yet, leak */
	}

	fm_uint_array_destroy(&ports);
	return NULL;
}

fm_scan_action_t *
fm_scanner_add_probe(fm_scanner_t *scanner, const fm_config_probe_t *parsed_probe)
{
	const char *probe_name = parsed_probe->name;
	int mode = parsed_probe->mode;
	fm_probe_class_t *pclass;
	fm_scan_action_t *action = NULL;
	fm_uint_array_t ports;
	int flags = 0;

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

	if (mode == FM_PROBE_MODE_PORT
	 && !fm_scanner_process_port_array(pclass, &parsed_probe->string_ports, &ports))
		goto failed;

	action = fm_probe_scan_create(pclass, mode, &parsed_probe->probe_params, &ports);

	if (!fm_scanner_process_proto_args(pclass, action, mode, &parsed_probe->extra_args))
		goto failed;

	assert(action->nprobes >= 1);
	action->flags |= flags;

	if (action != NULL)
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

fm_scan_action_t *
fm_scanner_add_topo_probe(fm_scanner_t *scanner, const char *probe_name, int flags, const fm_string_array_t *args)
{
	fm_scan_action_t *action;

	action = fm_scanner_create_probe_action(probe_name, FM_PROBE_MODE_TOPO, flags, args);
	if (action != NULL)
		fm_scanner_queue_action(scanner, action);

	/* FIXME: for a topo probe, we do not want to scan each and every address in the scan range,
	 * but usually just 1-2 per assumed target network size */

	return action;
}

fm_scan_action_t *
fm_scanner_add_host_probe(fm_scanner_t *scanner, const char *probe_name, int flags, const fm_string_array_t *args)
{
	fm_scan_action_t *action;

	action = fm_scanner_create_probe_action(probe_name, FM_PROBE_MODE_HOST, flags, args);
	if (action != NULL)
		fm_scanner_queue_action(scanner, action);

	return action;
}

fm_scan_action_t *
fm_scanner_add_port_probe(fm_scanner_t *scanner, const char *probe_name, int flags, const fm_string_array_t *args)
{
	fm_scan_action_t *action;

	action = fm_scanner_create_probe_action(probe_name, FM_PROBE_MODE_PORT, flags, args);
	if (action != NULL)
		fm_scanner_queue_action(scanner, action);

	return action;
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
	fm_scan_action_t *action;

	if ((action = fm_scan_action_reachability_check()) != NULL) {
		fm_scanner_queue_action(scanner, action);
		action->barrier = true;
	}
	return action;
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
static fm_probe_t *
fm_probe_scan_action_get_next_probe(const fm_scan_action_t *action, fm_target_t *target, unsigned int index)
{
	fm_probe_t *probe;
	int port = 0;

	if (action->mode == FM_PROBE_MODE_PORT) {
		if ((port = fm_uint_array_get(&action->numeric_params, index)) < 0)
			return NULL;

		probe = fm_create_port_probe(action->probe_class, target, port, &action->probe_params);
	} else {
		if (index != 0)
			return NULL;

		probe = fm_create_host_probe(action->probe_class, target, &action->probe_params, action->extra_params);
	}

	if (probe && port && action->service_catalog) {
		fm_service_probe_t *service_probe;

		service_probe = fm_service_catalog_get_service_probe(action->service_catalog,
						action->probe_class->proto_id, port);
		if (service_probe != NULL)
			fm_probe_set_service(probe, service_probe);
	}

	return probe;
}

static const struct fm_scan_action_ops	fm_probe_scan_action_ops = {
	.obj_size	= sizeof(fm_scan_action_t),
	.get_next_probe	= fm_probe_scan_action_get_next_probe,
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
