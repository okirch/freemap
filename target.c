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
#include "target.h"
#include "scanner.h"
#include "network.h"
#include "logging.h"
#include "utils.h"

static fm_target_t *	fm_target_manager_get_next_target(fm_target_manager_t *);
static void		fm_target_release(fm_target_t *target);

static fm_job_ops_t     fm_target_manager_job_ops;
static fm_cond_var_t	fm_task_manager_cond_var = FM_COND_VAR_INIT;


#define debugmsg	fm_debug_addrpool

/*
 * abstract target manager
 */
fm_target_manager_t *
fm_target_manager_create(void)
{
	fm_target_manager_t *mgr;

	mgr = calloc(1, sizeof(*mgr));

	mgr->host_packet_rate = FM_DEFAULT_HOST_PACKET_RATE;

	mgr->pool.size = FM_INITIAL_TARGET_POOL_SIZE;
	mgr->pool.next_resize = fm_time_now() + FM_TARGET_POOL_RESIZE_TIME;
	mgr->pool.next_id = 1;

	fm_job_init(&mgr->job, &fm_target_manager_job_ops, "target-manager");

	return mgr;
}

/*
 * For now, we will just walk linearly through all address pools.
 * We exhaust one pool, then move to the next.
 */
void
fm_target_manager_add_address_generator(fm_target_manager_t *mgr, fm_address_enumerator_t *agen)
{
	fm_address_enumerator_array_append(&mgr->address_generators, agen);
}

unsigned int
fm_target_manager_get_generator_count(const fm_target_manager_t *mgr)
{
	return mgr->address_generators.count;
}

/*
 * Resize the pool at regular interval, up to the configured upper limit
 */
static void
fm_target_manager_maybe_resize_pool(fm_target_manager_t *mgr)
{
	unsigned int max_size = FM_TARGET_POOL_MAX_SIZE;
	unsigned int current_size, new_size;

	if (mgr->pool.size >= max_size || mgr->pool.next_resize > fm_time_now())
		return;

	current_size = mgr->pool.size;
	if (current_size < max_size / 2)
		new_size = current_size * 2;
	else
		new_size = max_size;

	debugmsg("Resizing target pool; new capacity %u", new_size);
	mgr->pool.size = new_size;

	mgr->pool.next_resize = fm_time_now() + FM_TARGET_POOL_RESIZE_TIME;
}

/*
 * Connect the target manager to the next scan stage
 */
bool
fm_target_manager_set_stage(fm_target_manager_t *target_manager, fm_scan_stage_t *stage)
{
	target_manager->scan_stage = stage;

	if (stage != NULL) {
		unsigned int k;

		if (target_manager->address_generators.count == 0) {
			fm_log_error("No scan targets configured; nothing to scan");
			return false;
                }

		fm_target_manager_restart(target_manager, stage->stage_id);

		assert(stage->stage_id != FM_SCAN_STAGE_DISCOVERY);

		/* For each probe, create a separate target queue through which we'll feed new
                 * scan targets to the probe. */
		for (k = 0; k < stage->probes.count; ++k) {
			fm_multiprobe_t *multiprobe = stage->probes.entries[k];

			/* Tell the multiprobe it's being fed by us.
			 * Right now, this pointer does little useful; we could also
			 * just use a bool has_target_queue instead. */
			multiprobe->target_queue = &target_manager->pool;
		}

		if (!fm_job_is_active(&target_manager->job))
			fm_job_run(&target_manager->job, NULL);
		fm_job_continue(&target_manager->job);
	}
	return true;
}

/*
 * Feed new targets to all probes in the current stage
 */
void
fm_target_manager_feed_probes(fm_target_manager_t *target_manager)
{
	fm_scan_stage_t *stage = target_manager->scan_stage;
	unsigned int k;

	if (stage == NULL)
		return;

	/* Retire all targets that the probes are done with */
	for (k = stage->num_done; k < stage->probes.count; ++k) {
		fm_multiprobe_t *multiprobe = stage->probes.entries[k];
		fm_target_t *target;

		assert(multiprobe);

		/* inform the pool about targets that we're done with */
		while ((target = fm_multiprobe_get_completed(multiprobe)) != NULL) {
			debugmsg("%s: done with target %s (refcount %u)", multiprobe->name, target->id, target->refcount);

			fm_target_release(target);

			if (target->refcount == 1) {
				assert(target_manager->pool.count != 0);
				target_manager->pool.count -= 1;
				fm_target_release(target);
			}
		}
	}

	if (target_manager->all_targets_exhausted) {
		/* Detach the target queue from all multiprobes, telling them that they
		 * can exit as soon as they're done. */
		while (stage->num_done < stage->probes.count) {
			fm_multiprobe_t *multiprobe = stage->probes.entries[stage->num_done];

			if (!fm_multiprobe_is_idle(multiprobe))
				break;

			debugmsg("%s done with scanning all available targets", multiprobe->name);
			fm_job_mark_complete(&multiprobe->job);

			stage->num_done += 1;
		}

		if (stage->num_done >= stage->probes.count
		 && !fm_target_manager_is_done(target_manager)) {
			abort();
		}

		return;
	}

	while (target_manager->pool.count < target_manager->pool.size) {
		fm_target_t *target;

		if ((target = fm_target_manager_get_next_target(target_manager)) == NULL)
			break;

		assert(target->refcount == 1);

		if (stage->stage_id == FM_SCAN_STAGE_HOST)
			fm_target_reset_host_state(target, FM_PROTO_NONE);

		for (k = stage->num_done; k < stage->probes.count; ++k) {
			fm_multiprobe_t *multiprobe = stage->probes.entries[k];

			assert(multiprobe);
			assert(multiprobe->target_queue);

			if (fm_multiprobe_add_target(multiprobe, target)) {
				target->refcount += 1;

				assert(fm_job_is_active(&multiprobe->job));
				fm_job_continue(&multiprobe->job);
			} else {
				debugmsg("%s: could not add %s", multiprobe->name, target->id);
			}
		}

		if (target->refcount > 1) {
			target_manager->pool.count += 1;
		} else {
			fm_target_release(target);
		}
	}

	stage->next_pool_id = target_manager->pool.next_id;
}

/*
 * We have room in the target pool. Try to get a new address from one of the
 * address generators.
 */
fm_target_t *
fm_target_manager_get_next_target(fm_target_manager_t *mgr)
{
	fm_target_t *target = NULL;
	unsigned int index = 0;

	while (target == NULL && index < mgr->active_generators.count) {
		fm_address_enumerator_t *agen;
		fm_network_t *target_net;
		fm_address_t target_addr;
		fm_error_t error;

		agen = mgr->active_generators.entries[index];
		if (agen == NULL)
			break;

		error = fm_address_enumerator_get_one(agen, &target_addr);
		if (error == FM_TRY_AGAIN) {
			index++;
			continue;
		} else
		if (error < 0) {
			/* This address generator is spent. Remove it from the active list */
			fm_address_enumerator_array_remove_shallow(&mgr->active_generators, index);
			fm_log_notice("agen %s retired", agen->ops->name);
			continue;
		}

		target_net = fm_network_for_host(&target_addr);
		if (target_net->last_hop == NULL)
			target_net->last_hop = agen->unknown_gateway;

		target = fm_target_create(&target_addr, target_net);

		/* Set the packet send rate per host.
		 * The maximum burst size defaults to 0.1 sec worth of packets. */
		fm_ratelimit_init(&target->host_rate_limit,
				mgr->host_packet_rate,
				mgr->host_packet_rate / 10);

		hlist_insert(&mgr->pool.targets, &target->link);
		target->refcount += 1;

		debugmsg("%s added to address pool\n", target->id);
	}

	/* When all generators have completed, call it a day */
	if (target == NULL && mgr->active_generators.count == 0) {
		debugmsg("Exhausted all address generators");
		mgr->all_targets_exhausted = true;
	}

	return target;
}

/*
 * Returns true if the target manager has exhausted all enumerators,
 * and probes are done processing their targets.
 */
static bool
_fm_target_manager_is_done(fm_target_manager_t *target_manager, bool quiet)
{
	if (!target_manager->all_targets_exhausted)
		return false;

	return hlist_is_empty(&target_manager->pool.targets);
}

bool
fm_target_manager_is_done(fm_target_manager_t *target_manager)
{
	return _fm_target_manager_is_done(target_manager, false);
}

bool
fm_target_manager_is_done_quiet(fm_target_manager_t *target_manager)
{
	return _fm_target_manager_is_done(target_manager, true);
}

/*
 * Restart all address generators for a new scanning stage.
 */
void
fm_target_manager_restart(fm_target_manager_t *mgr, unsigned int stage)
{
	fm_address_enumerator_array_t *array = &mgr->address_generators;
	unsigned int i;

	fm_address_enumerator_array_destroy_shallow(&mgr->active_generators);
	for (i = 0; i < array->count; ++i) {
		fm_address_enumerator_t *gen = array->entries[i];

		fm_address_enumerator_restart(gen, stage);
		fm_address_enumerator_array_append(&mgr->active_generators, gen);
	}
	mgr->all_targets_exhausted = false;
}

/*
 * The target_manager<->job glue
 */
static fm_error_t
fm_target_manager_job_run(fm_job_t *job, fm_sched_stats_t *stats)
{
        fm_target_manager_t *target_manager = (fm_target_manager_t *) job;

	if (fm_target_manager_is_done(target_manager))
		return FM_TASK_COMPLETE;

	if (target_manager->scan_stage != NULL) {
		fm_target_manager_maybe_resize_pool(target_manager);

		fm_target_manager_feed_probes(target_manager);
		/* we still miss some wake-up call from somewhere (probably around retiring
		 * targets); so we have to do a bit of busy-waiting */
		job->expires = fm_time_now() + .5;
		return FM_TRY_AGAIN;
		return 0;
	}

	fm_job_wait_condition(&fm_task_manager_cond_var, job);
	return FM_TRY_AGAIN;
}

static void
fm_target_manager_job_destroy(fm_job_t *job)
{
        fm_target_manager_t *target_manager = (fm_target_manager_t *) job;

	(void) target_manager;
	fm_log_notice("Target manager job complete");
}

static fm_job_ops_t     fm_target_manager_job_ops = {
        .run            = fm_target_manager_job_run,
        .destroy        = fm_target_manager_job_destroy,
};

/*
 * Target objects
 */
fm_target_t *
fm_target_create(const fm_address_t *address, fm_network_t *network)
{
	fm_target_t *tgt;

	tgt = calloc(1, sizeof(*tgt));
	tgt->address = *address;
	tgt->id = strdup(fm_address_format(address));
	tgt->network = network;

	/* Initial sequence number for ICMP probes */
	tgt->host_probe_seq = 1;

	/* The initial packet rate is very restricted */
	fm_ratelimit_init(&tgt->host_rate_limit, 1, 1);

	/* FIXME: this is worse than useless: */
	tgt->local_device = fm_interface_by_address(address);
	if (tgt->local_device != NULL)
		fm_interface_get_network_address(tgt->local_device, address->family, &tgt->local_bind_address);

	tgt->host_asset = fm_host_asset_get(address, true);
	fm_host_asset_attach(tgt->host_asset);

	return tgt;
}

void
fm_target_free(fm_target_t *target)
{
	drop_string(&target->id);

	if (target->tcp_sock) {
		fm_log_debug("%s closing shared TCP socket", fm_address_format(&target->address));
		fm_socket_free(target->tcp_sock);
		target->tcp_sock = NULL;
	}

	if (target->udp_sock) {
		fm_log_debug("%s closing shared UDP socket", fm_address_format(&target->address));
		fm_socket_free(target->udp_sock);
		target->udp_sock = NULL;
	}

	if (target->raw_icmp4_sock) {
		fm_log_debug("%s closing shared ICMP socket", fm_address_format(&target->address));
		fm_socket_free(target->raw_icmp4_sock);
		target->raw_icmp4_sock = NULL;
	}

	if (target->raw_icmp6_sock) {
		fm_log_debug("%s closing shared ICMPv6 socket", fm_address_format(&target->address));
		fm_socket_free(target->raw_icmp6_sock);
		target->raw_icmp6_sock = NULL;
	}

	/* destroy extant requests */

	/* Release the host asset (meaning it can be unmapped) */
	if (target->host_asset != NULL)
		fm_host_asset_detach(target->host_asset);

	free(target);
}

void
fm_target_release(fm_target_t *target)
{
	assert(target->refcount);

	target->refcount -= 1;
	if (target->refcount != 0)
		return;

	debugmsg("%s is done - reaping what we have sown\n", target->id);

	hlist_remove(&target->link);
	fm_target_free(target);
}

const char *
fm_target_get_id(const fm_target_t *target)
{
	return target->id;
}

/*
 * In order to determine the local ifaddr to bind to, create a connected UDP socket
 * and query its sockname.
 * We could do something way more complex by using netlink to discover the routing
 * table, and then do the routing ourselves. We would same a few syscalls per target
 * but that's not really that much of a saving.
 */
bool
fm_target_get_local_bind_address(fm_target_t *target, fm_address_t *bind_address)
{
	if (target->local_bind_address.family == AF_UNSPEC) {
		const fm_address_t *daddr = &target->address;
		fm_socket_t *sock;

		sock = fm_socket_create(daddr->family, SOCK_DGRAM, 0, NULL);
		if (sock == NULL)
			return false;

		if (fm_socket_connect(sock, daddr)
		 && fm_socket_get_local_address(sock, &target->local_bind_address))
			fm_address_set_port(&target->local_bind_address, 0);

		fm_socket_free(sock);
	}

	if (target->local_bind_address.family == AF_UNSPEC)
		return false;

	*bind_address = target->local_bind_address;
	return true;
}

/*
 * Update the host asset information
 */
void
fm_target_reset_host_state(fm_target_t *target, unsigned int proto_id)
{
	/* ignore the proto id for now */
	if (target->host_asset)
		fm_host_asset_reset_state(target->host_asset);
}

void
fm_target_update_host_state(fm_target_t *target, unsigned int proto_id, fm_asset_state_t state)
{
	if (target->host_asset) {
		/* ignore the proto id for now */
		if (fm_host_asset_update_state(target->host_asset, state))
			fm_event_post(FM_EVENT_ID_ASSET_CHANGED);
	}
}

void
fm_target_update_port_state(fm_target_t *target, unsigned int proto_id, unsigned int port, fm_asset_state_t state)
{
	if (target->host_asset) {
		if (fm_host_asset_update_port_state(target->host_asset, proto_id, port, state))
			fm_event_post(FM_EVENT_ID_ASSET_CHANGED);
	}
}

bool
fm_target_is_done(const fm_target_t *target)
{
	/* FIXME: do we need to check for pending probes? */
	return target->scan_done;
}

/*
 * Deal with network stats
 * Maybe this code should live in scanner.c
 */
void
fm_rtt_stats_init(fm_rtt_stats_t *stats, unsigned long initial_rtt, unsigned int multiple)
{
	memset(stats, 0, sizeof(*stats));
	stats->multiple = multiple;

	fm_rtt_stats_update(stats, 1e-3 * initial_rtt);
}

void
fm_rtt_stats_update(fm_rtt_stats_t *stats, double rtt)
{
	stats->rtt_sum += rtt;
	stats->nsamples += 1;

	stats->rtt = (unsigned int) (stats->rtt_sum * (1000.0 / stats->nsamples));

	/* Do not allow the rtt estimate to become 0 */
	if (stats->rtt == 0)
		stats->rtt = 1;

	stats->timeout = stats->rtt * stats->multiple;
}
