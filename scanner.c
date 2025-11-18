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
#include "logging.h"
#include "utils.h"

static bool			fm_scanner_start_stage(fm_scanner_t *scanner, unsigned int stage_id);

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
fm_scan_action_create(fm_multiprobe_t *multiprobe)
{
	fm_scan_action_t *action;

	action = calloc(1, sizeof(*action));
	action->multiprobe = multiprobe;
	return action;
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
fm_scanner_ready(fm_scanner_t *scanner, unsigned int first_stage_id)
{
	fm_timestamp_update(&scanner->scan_started);
	fm_timestamp_set_timeout(&scanner->next_pool_resize, FM_TARGET_POOL_RESIZE_TIME * 1000);

	if (!fm_scanner_start_stage(scanner, first_stage_id))
		return false;

	return true;
}

fm_report_t *
fm_scanner_get_report(fm_scanner_t *scanner)
{
	return scanner->report;
}

static fm_scan_stage_t *
fm_scanner_create_stage(fm_scanner_t *scanner, unsigned int stage_id)
{
	fm_scan_stage_t *stage;

	assert(stage_id < __FM_SCAN_STAGE_MAX);
	if ((stage = scanner->stages[stage_id]) == NULL) {
		stage = calloc(1, sizeof(*stage));
		stage->stage_id = stage_id;
		scanner->stages[stage_id] = stage;
	}

	return stage;
}

static void
fm_scanner_queue_probe(fm_scanner_t *scanner, int stage_id, fm_multiprobe_t *multiprobe)
{
	fm_scan_stage_t *stage;
	fm_scan_action_t *action;
	fm_target_pool_t *target_queue;

	stage = fm_scanner_create_stage(scanner, stage_id);

	action = fm_scan_action_create(multiprobe);
	fm_scan_action_array_append(&stage->actions, action);

	if (stage_id != FM_SCAN_STAGE_DISCOVERY) {
		/* Create a separate target queue through which we'll feed new
		 * scan targets to the probe. */
		target_queue = fm_target_manager_create_queue(scanner->target_manager, multiprobe->name);

		/* Install it */
		action->target_queue = target_queue;
		multiprobe->target_queue = target_queue;
	}

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
 * Feed new targets to all probes in the current stage
 */
static void
fm_scanner_create_new_probes(fm_scanner_t *scanner)
{
	fm_target_manager_feed_probes(scanner->target_manager, scanner->current_stage);
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

	if (scanner->current_stage->stage_id != FM_SCAN_STAGE_DISCOVERY) {
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
	}

	fm_ratelimit_update(&scanner->send_rate_limit);

	memset(&scan_stats, 0, sizeof(scan_stats));
	scan_stats.job_quota = fm_ratelimit_available(&scanner->send_rate_limit);

	/* Run all runnable jobs (to the degree rate limits allow) */
	fm_scanner_schedule(scanner, &scan_stats);

	/* Process events */
	fm_event_process_all();

	/* Schedule and transmit a few additional probes */
	fm_scanner_create_new_probes(scanner);

	/* Reap any targets that we're done with, making room in the pool for
	 * the next batch of targets. */
	fm_scanner_process_completed(scanner);

	if (timeout)
		*timeout = scan_stats.timeout;

	return true;
}

static bool
fm_scanner_start_stage(fm_scanner_t *scanner, unsigned int index)
{
	scanner->current_stage = NULL;

	while (index <  __FM_SCAN_STAGE_MAX) {
		fm_scan_stage_t *stage = scanner->stages[index];

		if (stage && stage->actions.count > 0) {
			fm_target_manager_restart(scanner->target_manager, index);
			assert(stage->num_done == 0);
			stage->stage_id = index;
			scanner->current_stage = stage;
			break;
		}
		index++;
	}

	if (scanner->current_stage == NULL)
		return false;

	if (index != FM_SCAN_STAGE_DISCOVERY) {
		fm_target_manager_t *target_manager = scanner->target_manager;

		if (target_manager->address_generators.count == 0) {
			fm_log_error("No scan targets configured; nothing to scan");
			return false;
		}
	}

	scanner->next_stage_id = index + 1;
	return true;
}

bool
fm_scanner_next_stage(fm_scanner_t *scanner)
{
	return fm_scanner_start_stage(scanner, scanner->next_stage_id);
}


fm_protocol_t *
fm_scanner_get_protocol_engine(fm_scanner_t *scanner, const char *protocol_name)
{
	return fm_protocol_engine_get_protocol(scanner->proto, protocol_name);
}

void
fm_scanner_dump_program(fm_scanner_t *scanner)
{
	fm_log_notice("%s: does nothing right now");
}

/*
 * Create a topo, host or port scan action
 */
bool
fm_scanner_add_probe(fm_scanner_t *scanner, int stage, const fm_config_probe_t *parsed_probe)
{
	const char *probe_name = parsed_probe->name;
	int mode = parsed_probe->mode;
	fm_probe_class_t *pclass;
	fm_multiprobe_t *multiprobe;

	pclass = fm_probe_class_find(probe_name, mode);
	if (pclass == NULL) {
		if (!parsed_probe->optional) {
			fm_log_error("Unknown host %s class %s\n",
					fm_probe_mode_to_string(mode),
					probe_name);
			return false;
		}

		fm_log_debug("Ignoring optional %s %s probe", fm_probe_mode_to_string(mode));
		return true;
	}

	multiprobe = fm_multiprobe_from_config(pclass, parsed_probe);
	if (pclass->features & FM_FEATURE_SERVICE_PROBES_MASK)
		fm_multiprobe_set_service_catalog(multiprobe, scanner->service_catalog);

	fm_scanner_queue_probe(scanner, stage, multiprobe);

	return true;
}

/*
 * Discovery scans
 */
static void
fm_scanner_discovery_callback(const fm_pkt_t *pkt, void *user_data)
{
	fm_address_enumerator_t *agen = user_data;

	/* extract the sender address and feed it to the addrgen */
	fm_address_enumerator_add(agen, &pkt->peer_addr);
}

static void
fm_scanner_discovery_complete(void *user_data)
{
	fm_address_enumerator_t *agen = user_data;
	fm_address_t null = { 0 };

	/* send a NULL address down the pipe to indicate EOF */
	fm_address_enumerator_add(agen, &null);
}

/* Maybe this wants to live in addrgen.c */
static bool
fm_scanner_discovery_select_prefixes(const fm_interface_t *nic, fm_address_prefix_array_t *selected)
{
	fm_address_prefix_array_t prefix_array = { 0 };
	const fm_address_prefix_t *ipv6_prefix = NULL;
	const fm_address_prefix_t *ipv4_prefix = NULL;
	unsigned int i;

	fm_interface_get_local_prefixes(nic, &prefix_array);
	for (i = 0; i < prefix_array.count; ++i) {
                const fm_address_prefix_t *prefix = &prefix_array.elements[i];
		int family;

                if (!fm_address_generator_address_eligible_any_state(&prefix->address))
                        continue;

		family = prefix->address.ss_family;
		if (fm_global.address_generation.try_all
		 && (family == AF_INET || family == AF_INET6)) {
			fm_address_prefix_array_append(selected, prefix);
			continue;
		}

		if (family == AF_INET) {
			if (ipv4_prefix)
				continue;
			ipv4_prefix = prefix;
		} else
		if (family == AF_INET6) {
			if (!fm_global.address_generation.try_all && ipv6_prefix
			 && !fm_address_is_ipv6_link_local(&ipv6_prefix->address))
				continue;
			ipv6_prefix = prefix;
		} else {
			continue;
		}
	}

	if (ipv4_prefix)
		fm_address_prefix_array_append(selected, ipv4_prefix);
	if (ipv6_prefix)
		fm_address_prefix_array_append(selected, ipv6_prefix);

	fm_address_prefix_array_destroy(&prefix_array);
	return selected->count != 0;
}

bool
fm_scanner_initiate_discovery(fm_scanner_t *scanner, const char *addrspec)
{
	fm_scan_stage_t *stage;
	const fm_interface_t *nic;
	fm_address_prefix_array_t selected_prefixes = { 0 };
	unsigned int i;

	/* For now, we support %ifname discovery only */
	if (addrspec[0] == '%') {
		const char *ifname = addrspec + 1;

		nic = fm_interface_by_name(ifname);
		if (nic == NULL) {
			fm_log_error("Cannot initiate discovery scan: unknown interface %s", ifname);
			return false;
		}

		if (!fm_scanner_discovery_select_prefixes(nic, &selected_prefixes)) {
			fm_log_error("No discovery for interface %s: no suitable prefixes", ifname);
			return false;
		}
	} else {
		fm_log_error("Cannot perform discovery for argument %s", addrspec);
		return false;
	}

	stage = fm_scanner_get_stage(scanner, FM_SCAN_STAGE_DISCOVERY);
	if (stage == NULL) {
		fm_log_error("%s: you need to attach a discovery probe first", __func__);
		return false;
	}

	if (scanner->addr_discovery == NULL)
		scanner->addr_discovery = fm_address_enumerator_new_discovery();

	for (i = 0; i < stage->actions.count; ++i) {
		fm_scan_action_t *action = stage->actions.entries[i];
		fm_multiprobe_t *multiprobe = action->multiprobe;

		/* First time around, install the data tap. This needs to happen before we
		 * add the first broadcast target. */
		if (!fm_job_is_active(&multiprobe->job))
			fm_multiprobe_install_data_tap(multiprobe, fm_scanner_discovery_callback, scanner->addr_discovery);

		for (i = 0; i < selected_prefixes.count; ++i) {
			const fm_address_prefix_t *prefix = &selected_prefixes.elements[i];
			const fm_address_t *src_addr = &prefix->source_addr;
			int family = src_addr->ss_family;

			if (!fm_multiprobe_add_link_level_broadcast(multiprobe, family, nic, src_addr)) {
				fm_log_error("%s: cannot broadcast to %s on device %s",
						multiprobe->name,
						fm_address_format(src_addr),
						fm_interface_get_name(nic));
				continue;
			}
		}

		/* Activate the job if it's not running yet */
		if (!fm_job_is_active(&multiprobe->job))
			fm_job_run(&multiprobe->job, NULL);
	}

	return true;
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
