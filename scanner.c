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
#include <netdb.h>
#include "scanner.h"
#include "target.h"
#include "protocols.h"


static void			fm_scanner_map_heisenberg(fm_target_t *);
static fm_scan_action_t *	fm_scan_action_simple_port_scan(fm_protocol_engine_t *proto, unsigned short port);
static fm_scan_action_t *	fm_scan_action_host_reachability_scan(fm_protocol_engine_t *proto, unsigned int retries);

fm_protocol_engine_t *
fm_protocol_engine_create(const struct fm_protocol_ops *ops)
{
	fm_protocol_engine_t *prot;

	prot = calloc(1, ops->obj_size);
	prot->ops = ops;
	return prot;
}

static fm_rtt_stats_t *
fm_protocol_engine_get_rtt(const fm_protocol_engine_t *proto, int ipproto, unsigned int netid)
{
	fm_rtt_stats_t *rtt;

	if (proto->ops->create_rtt_estimator == NULL)
		return NULL;

	if ((rtt = fm_rtt_stats_get(ipproto, netid)) == NULL)
		rtt = proto->ops->create_rtt_estimator(proto, ipproto, netid);
	return rtt;
}

static inline void
fm_protocol_engine_attach_rtt_estimator(fm_protocol_engine_t *proto, fm_probe_t *probe)
{
	probe->rtt = fm_protocol_engine_get_rtt(proto, probe->ipproto, probe->netid);
}

/*
 * Create host/port probes
 */
fm_probe_t *
fm_protocol_engine_create_port_probe(fm_protocol_engine_t *proto, fm_target_t *target, uint16_t port)
{
	fm_probe_t *probe;

	if (proto->ops->create_port_probe == NULL) {
		fprintf(stderr, "Error: protocol %s cannot create a port probe\n", proto->ops->name);
		return NULL;
	}

	if ((probe = proto->ops->create_port_probe(proto, target, port)) != NULL)
		fm_protocol_engine_attach_rtt_estimator(proto, probe);
	return probe;
}

fm_probe_t *
fm_protocol_engine_create_host_probe(fm_protocol_engine_t *proto, fm_target_t *target, unsigned int retries)
{
	fm_probe_t *probe;

	if (proto->ops->create_host_probe == NULL) {
		fprintf(stderr, "Error: protocol %s cannot create a host probe\n", proto->ops->name);
		return NULL;
	}

	if ((probe = proto->ops->create_host_probe(proto, target, retries)) != NULL)
		fm_protocol_engine_attach_rtt_estimator(proto, probe);
	return probe;
}

static inline void
fm_scan_action_array_append(struct fm_scan_action_array *array, fm_scan_action_t *action)
{
	array->entries = realloc(array->entries, (array->count + 1) * sizeof(array->entries[0]));
	array->entries[array->count++] = action;
}

static inline fm_scan_action_t *
fm_scan_action_array_get(struct fm_scan_action_array *array, unsigned int index)
{
	if (index >= array->count)
		return NULL;
	return array->entries[index];
}

fm_scan_action_t *
fm_scan_action_create(const struct fm_scan_action_ops *ops, const char *id)
{
	fm_scan_action_t *action;

	action = calloc(1, ops->obj_size);
	action->id = strdup(id);
	action->ops = ops;
	return action;
}

fm_probe_t *
fm_scan_action_get_next_probe(fm_scan_action_t *action, fm_target_t *target, unsigned int index)
{
	fm_probe_t *probe;

	probe = action->ops->get_next_probe(action, target, index);
	if (probe != NULL) {
		fm_log_debug("   %s created next probe for %s index=%d\n", fm_target_get_id(target), action->id, index);
		probe->result_callback = action->result_callback;
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

	scanner->tcp_engine = fm_tcp_engine_create();
	scanner->udp_engine = fm_udp_engine_create();
	scanner->icmp_engine = fm_icmp_engine_create();

	return scanner;
}

bool
fm_scanner_ready(fm_scanner_t *scanner)
{
	if (scanner->tcp_engine == NULL)
		scanner->tcp_engine = fm_tcp_engine_create();
	fm_timestamp_update(&scanner->scan_started);
	fm_timestamp_set_timeout(&scanner->next_pool_resize, FM_TARGET_POOL_RESIZE_TIME * 1000);

	return true;
}

fm_report_t *
fm_scanner_get_report(fm_scanner_t *scanner)
{
	return scanner->report;
}

double
fm_scanner_elapsed(fm_scanner_t *scanner)
{
	return 1000 * fm_timestamp_since(&scanner->scan_started);
}

static inline fm_probe_t *
fm_scanner_get_next_probe_for_target(fm_scanner_t *scanner, fm_target_t *target)
{
	fm_scan_action_t *action;
	fm_probe_t *probe;

	while (true) {
		action = target->current_scan.action;
		if (action == NULL) {
			if (!(action = fm_scan_action_array_get(&scanner->requests, target->current_scan.action_index)))
				return NULL;

			target->current_scan.action = action;
			target->current_scan.action_index += 1;
			target->current_scan.port_index = 0;
		}

		probe = fm_scan_action_get_next_probe(action, target, target->current_scan.port_index);
		if (probe != NULL) {
			target->current_scan.port_index += 1;
			break;
		}

		if (target->current_scan.port_index == 0)
			fm_log_warning("scan action %s does not generate any probe packets at all!\n", action->id);

		target->current_scan.action = NULL;
		target->current_scan.port_index = 0;
	}

	return probe;
}

void
fm_scanner_abort_target(fm_target_t *target)
{
	target->current_scan.action = NULL;
	target->current_scan.action_index = (unsigned int) -1;
}

bool
fm_scanner_transmit(fm_scanner_t *scanner)
{
	unsigned int quota, target_quota;
	unsigned int num_visited = 0;

	fm_ratelimit_update(&scanner->send_rate_limit);
	quota = fm_ratelimit_available(&scanner->send_rate_limit);
	if (!quota)
		return true;

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

	while (quota) {
		unsigned int num_sent = 0;
		fm_target_t *target;

		target = fm_target_pool_get_next(scanner->target_pool, &num_visited);
		if (target == NULL)
			break;

		target_quota = fm_target_get_send_quota(target);
		if (target_quota > quota)
			target_quota = quota;

#if 0
		fm_log_debug("Try to send probes to %s (quota=%u)\n", 
				fm_target_get_id(target), target_quota);
#endif

		num_sent += fm_target_process_timeouts(target, target_quota - num_sent);

		while (num_sent < target_quota && !target->plugged) {
			fm_probe_t *probe;

			probe = fm_scanner_get_next_probe_for_target(scanner, target);
			if (probe == NULL)
				break;

			fm_target_send_probe(target, probe);
			num_sent += 1;
		}

		quota -= num_sent;

		if (fm_target_is_done(target)) {
			fm_log_debug("%s is done - reaping what we have sown\n", fm_address_format(&target->address));

			fm_target_pool_remove(scanner->target_pool, target);

			fm_scanner_map_heisenberg(target);

			/* wrap up reporting for this target */
			fm_report_write(scanner->report, target);

			fm_target_free(target);
		}
	}

	/* This loops over the entire pool and reaps the status of completed probes */
	fm_target_pool_reap_completed(scanner->target_pool);

	return true;
}

fm_protocol_engine_t *
fm_scanner_get_protocol_engine(fm_scanner_t *scanner, const char *protocol_name)
{
	struct protoent *pe;

	pe = getprotobyname(protocol_name);
	if (pe == NULL)
		return NULL;

	switch (pe->p_proto) {
	case IPPROTO_TCP:
		return scanner->tcp_engine;

	case IPPROTO_UDP:
		return scanner->udp_engine;

	case IPPROTO_ICMP:
		return scanner->icmp_engine;
	}

	return NULL;
}

/*
 * Deal with UDP ports that had a timeout
 */
void
fm_scanner_map_heisenberg(fm_target_t *target)
{
	int map_heisenberg = FM_FACT_NONE;
	unsigned int i, j;

	for (i = 0; i < target->log.count; ++i) {
		fm_fact_t *fact = target->log.entries[i];

		if (fact->type == FM_FACT_PORT_HEISENBERG) {
			fm_log_debug("*** %s %s ***\n",
					fm_address_format(&target->address),
					fm_fact_render(fact));
			if (map_heisenberg == FM_FACT_NONE) {
				unsigned int num_reachable = 0, num_unreachable = 0;

				for (j = 0; j < target->log.count; ++j) {
					fm_fact_t *other = target->log.entries[i];

					if (other->type == FM_FACT_PORT_REACHABLE && fm_fact_check_protocol(other, "udp"))
						num_reachable += 1;
					else
					if (other->type == FM_FACT_PORT_UNREACHABLE && fm_fact_check_protocol(other, "udp"))
						num_unreachable += 1;
				}

				if (num_reachable || num_unreachable)
					map_heisenberg = FM_FACT_PORT_MAYBE_REACHABLE;
				else
					map_heisenberg = FM_FACT_PORT_UNREACHABLE;
			}

			fact->type = map_heisenberg;
			fm_log_debug("STATUS ADJUSTED %s %s\n", fm_address_format(&target->address), fm_fact_render(fact));
		}
	}
}

/*
 * Reachability probe
 */
static void
fm_scanner_host_reachability_callback(fm_target_t *target, fm_fact_t *status)
{
	if (status->type != FM_FACT_HOST_REACHABLE) {
		fm_log_debug("%s does not respond to ICMP echo ping, skipping all other scan actions\n", fm_address_format(&target->address));
		fm_scanner_abort_target(target);
	} else if (status->elapsed != 0) {
		target->rtt_estimate = 1000 * status->elapsed;
	}
}

bool
fm_scanner_add_host_reachability_check(fm_scanner_t *scanner, const char *protocol_name, bool abort_on_fail)
{
	fm_protocol_engine_t *proto;
	fm_scan_action_t *action;

	if (!(proto = fm_scanner_get_protocol_engine(scanner, protocol_name))) {
		fprintf(stderr, "No protocol engine for protocol id %s\n", protocol_name);
		return false;
	}

	if (!(action = fm_scan_action_host_reachability_scan(proto, 0)))
		return false;

	if (abort_on_fail)
		action->result_callback = fm_scanner_host_reachability_callback;

	fm_scan_action_array_append(&scanner->requests, action);
	return true;
}

bool
fm_scanner_add_single_port_scan(fm_scanner_t *scanner, const char *protocol_name, unsigned int port)
{
	fm_protocol_engine_t *proto;
	fm_scan_action_t *action;

	if (!(proto = fm_scanner_get_protocol_engine(scanner, protocol_name))) {
		fprintf(stderr, "No protocol engine for protocol id %s/%u\n", protocol_name, port);
		return false;
	}

	if (!(action = fm_scan_action_simple_port_scan(proto, port)))
		return false;

	fm_scan_action_array_append(&scanner->requests, action);
	return true;
}

/*
 * Check host reachability
 */
struct fm_host_reachability_scan {
	fm_scan_action_t	base;

	fm_protocol_engine_t *	proto;
	unsigned int		retries;
};

static fm_probe_t *
fm_host_reachability_scan_get_next_probe(const fm_scan_action_t *action, fm_target_t *target, unsigned int index)
{
	struct fm_host_reachability_scan *hostscan = (struct fm_host_reachability_scan *) action;

	if (index != 0)
		return NULL;

	return fm_protocol_engine_create_host_probe(hostscan->proto, target, hostscan->retries);
}

static const struct fm_scan_action_ops	fm_host_reachability_scan_ops = {
	.obj_size	= sizeof(struct fm_host_reachability_scan),
	.get_next_probe	= fm_host_reachability_scan_get_next_probe,
};


fm_scan_action_t *
fm_scan_action_host_reachability_scan(fm_protocol_engine_t *proto, unsigned int retries)
{
	struct fm_host_reachability_scan *hostscan;

	hostscan = (struct fm_host_reachability_scan *) fm_scan_action_create(&fm_host_reachability_scan_ops, proto->ops->name);
	hostscan->proto = proto;
	hostscan->retries = retries;

	return &hostscan->base;
}

/*
 * Probe for a tcp or udp port
 */
struct fm_simple_port_scan {
	fm_scan_action_t	base;

	fm_protocol_engine_t *	proto;
	uint16_t		port;
};

static fm_probe_t *
fm_simple_port_scan_get_next_probe(const fm_scan_action_t *action, fm_target_t *target, unsigned int index)
{
	struct fm_simple_port_scan *portscan = (struct fm_simple_port_scan *) action;

	if (index != 0)
		return NULL;

	return fm_protocol_engine_create_port_probe(portscan->proto, target, portscan->port);
}

static const struct fm_scan_action_ops	fm_simple_port_scan_ops = {
	.obj_size	= sizeof(struct fm_simple_port_scan),
	.get_next_probe	= fm_simple_port_scan_get_next_probe,
};


fm_scan_action_t *
fm_scan_action_simple_port_scan(fm_protocol_engine_t *proto, unsigned short port)
{
	struct fm_simple_port_scan *portscan;
	char idbuf[128];

	snprintf(idbuf, sizeof(idbuf), "%s/%u", proto->ops->name, port);

	portscan = (struct fm_simple_port_scan *) fm_scan_action_create(&fm_simple_port_scan_ops, idbuf);
	portscan->proto = proto;
	portscan->port = port;

	return &portscan->base;
}
