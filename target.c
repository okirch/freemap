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
#include "network.h"
#include "logging.h"
#include "utils.h"

static void		fm_target_pool_check(fm_target_pool_t *pool);
static void		fm_target_release(fm_target_t *target);

static fm_target_pool_t *fm_active_target_pool = NULL;

/*
 * The target pool
 */
fm_target_pool_t *
fm_target_pool_create(unsigned int size)
{
	fm_target_pool_t *pool;

	pool = calloc(1, sizeof(*pool));
	pool->size = size;
	pool->slots = calloc(size, sizeof(pool->slots[0]));
	pool->first_pool_id = 0;
	pool->next_pool_id = 1;

	return pool;
}

void
fm_target_pool_resize(fm_target_pool_t *pool, unsigned int new_size)
{
	unsigned int i;

	if (pool->size < new_size) {
		pool->slots = realloc(pool->slots, new_size * sizeof(pool->slots[0]));
		for (i = pool->size; i < new_size; ++i)
			pool->slots[i] = NULL;
		pool->size = new_size;
	}
}

static inline unsigned int
fm_target_pool_get_free_slots(const fm_target_pool_t *pool)
{
	assert(pool->count < pool->size);
	return pool->size - pool->count - 1;
}

static inline bool
fm_target_pool_has_free_slots(const fm_target_pool_t *pool)
{
	return pool->count < pool->size;
}

static void
fm_target_pool_add(fm_target_pool_t *pool, fm_target_t *target)
{
	assert(target != NULL);
	assert(target->pool_id != 0);
	assert(pool->count + 1 < pool->size);

	if (pool->count == 0)
		pool->first_pool_id = target->pool_id;

	pool->slots[pool->count++] = target;
	target->refcount++;
}

static int
fm_target_pool_bsearch(fm_target_pool_t *pool, unsigned int target_id)
{
	unsigned int i0, i1, mid;
	unsigned int mid_id;

	i0 = 0;
	i1 = pool->count;

	while (i1 - i0 >= 2) {
		mid = (i0 + i1) / 2;
		mid_id = pool->slots[mid]->pool_id;

		if (mid_id == target_id)
			return mid;

		if (target_id < mid_id)
			i1 = mid;
		else
			i0 = mid;
	}

	if (pool->slots[i0]->pool_id == target_id)
		return i0;
	if (pool->slots[i1]->pool_id == target_id)
		return i1;
	return -1;
}

bool
fm_target_pool_remove(fm_target_pool_t *pool, fm_target_t *target)
{
	unsigned int i;
	int index;

	index = fm_target_pool_bsearch(pool, target->pool_id);
	assert(index >= 0);

	assert(pool->slots[index] == target);

	pool->count -= 1;
	for (i = index; i < pool->count; ++i)
		pool->slots[i] = pool->slots[i + 1];

	fm_target_release(target);
	return true;
}

static inline void
fm_target_pool_check(fm_target_pool_t *pool)
{
	/* NOP for now */
}

bool
fm_target_pool_reap_completed(fm_target_pool_t *pool)
{
#if 1
	return false;
#else
	fm_target_t *target;
	unsigned int i;
	bool completed_some = false;

	for (i = 0; i < pool->size; ++i) {
		if ((target = pool->slots[i]) != NULL) {
			if (fm_job_group_reap_complete(&target->job_group))
				completed_some = true;

			if (fm_target_is_done(target))
				fm_log_debug("%s all outstanding probes collected\n", target->job_group.name);
		}
	}

	fm_target_pool_check(pool);

	return completed_some;
#endif
}

void
fm_target_pool_make_active(fm_target_pool_t *pool)
{
	fm_active_target_pool = pool;
}

fm_target_t *
fm_target_pool_find(const fm_address_t *addr)
{
	return NULL;
}

/*
 * Iterate through a target pool
 */
fm_target_t *
fm_target_pool_get_next(fm_target_pool_t *queue)
{
	int index;

	index = fm_target_pool_bsearch(queue, queue->next_pool_id);
	if (index < 0)
		return NULL;

	queue->next_pool_id += 1;
	return queue->slots[index];
}

void
fm_target_pool_begin(fm_target_pool_t *queue, fm_target_pool_iterator_t *iter)
{
	iter->queue = queue;
	iter->index = fm_target_pool_bsearch(queue, queue->next_pool_id);
}

fm_target_t *
fm_target_pool_next(fm_target_pool_iterator_t *iter)
{
	fm_target_pool_t *queue = iter->queue;
	fm_target_t *target;
	int index;

	if (iter->index < 0)
		return NULL;

	/* Things are a bit complicated because someone may drop
	 * a target while we're iterating over the pool (for instance,
	 * if a probe rejects an incompatible target - think ARP vs IPv6).
	 *
	 * Maybe this should become a list instead of an array?
	 */
	if ((index = iter->index) >= queue->count)
		index = queue->count - 1;

	while (index >= 0) {
		target = queue->slots[index];
		if (target->pool_id == queue->next_pool_id)
			break;

		if (target->pool_id < queue->next_pool_id) {
			fm_log_warning("fm_target_pool_next: bad index/id - should never happen");
			return NULL;
		}

		index -= 1;
	}

	if (index < 0)
		return NULL;

	if (iter->index >= queue->count)
		return NULL;

	iter->index = index + 1;

	assert(target->pool_id == queue->next_pool_id);
	queue->next_pool_id += 1;
	return target;
}

/*
 * abstract target manager
 */
fm_target_manager_t *
fm_target_manager_create(void)
{
	fm_target_manager_t *mgr;

	mgr = calloc(1, sizeof(*mgr));

	mgr->next_free_pool_id = 1;
	mgr->pool_size = FM_INITIAL_TARGET_POOL_SIZE;
	mgr->host_packet_rate = FM_DEFAULT_HOST_PACKET_RATE;

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

fm_target_pool_t *
fm_target_manager_create_queue(fm_target_manager_t *mgr)
{
	fm_target_pool_t *queue;

	maybe_realloc_array(mgr->queues, mgr->num_queues, 4);

	queue = fm_target_pool_create(mgr->pool_size);
	mgr->queues[mgr->num_queues++] = queue;
	return queue;
}

void
fm_target_manager_resize_pool(fm_target_manager_t *mgr, unsigned int max_size)
{
	unsigned int current_size, new_size;
	unsigned int i;

	current_size = mgr->pool_size;
	if (current_size < max_size / 2)
		new_size = current_size * 2;
	else
		new_size = max_size;

	if (new_size > current_size) {
		for (i = 0; i < mgr->num_queues; ++i)
			fm_target_pool_resize(mgr->queues[i], new_size);
	}
}

static unsigned int
fm_target_manager_get_free_slots(const fm_target_manager_t *mgr)
{
	unsigned int k, min_free;

	if (mgr->num_queues == 0)
		return 0;

	min_free = mgr->pool_size;
	for (k = 0; k < mgr->num_queues; ++k) {
		unsigned int count = fm_target_pool_get_free_slots(mgr->queues[k]);

		if (count < min_free)
			min_free = count;
	}

	return min_free;
}

/*
 * Iterate over all active targets
 */
void
fm_target_manager_begin(fm_target_manager_t *mgr, hlist_iterator_t *iter)
{
	hlist_iterator_init(iter, &mgr->targets);
}

fm_target_t *
fm_target_manager_next(fm_target_manager_t *mgr, hlist_iterator_t *iter)
{
	fm_target_t *target;

	while ((target = hlist_iterator_next(iter)) != NULL) {
		if (target->refcount > 1)
			return target;

		/* This target is done. */
		fm_target_release(target);
	}

	return NULL;
}

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
	}

	/* When all generators have completed, call it a day */
	if (target == NULL && mgr->active_generators.count == 0) {
		fm_log_debug("Exhausted all address generators");
		mgr->all_targets_exhausted = true;
	}

	return target;
}

/*
 * Returns true if there are active targets in at least one of the queues.
 */
bool
fm_target_manager_replenish_pools(fm_target_manager_t *mgr)
{
	unsigned int k, budget;

	if (mgr->all_targets_exhausted) {
		for (k = 0; k < mgr->num_queues; ++k) {
			if (mgr->queues[k]->count)
				return true;
		}
		return false;
	}

	budget = fm_target_manager_get_free_slots(mgr);
	while (budget--) {
		fm_target_t *target;

		if ((target = fm_target_manager_get_next_target(mgr)) == NULL)
			break;

		/* Give this target a pool id */
		target->pool_id = mgr->next_free_pool_id++;

		for (k = 0; k < mgr->num_queues; ++k)
			fm_target_pool_add(mgr->queues[k], target);

		hlist_insert(&mgr->targets, &target->link);
		target->refcount += 1;

		fm_log_debug("%s added to address pool\n", fm_target_get_id(target));
	}

	return true;
}

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
		fm_interface_get_network_address(tgt->local_device, address->ss_family, &tgt->local_bind_address);

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

	fm_log_debug("%s is done - reaping what we have sown\n", target->id);

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
	if (target->local_bind_address.ss_family == AF_UNSPEC) {
		const fm_address_t *daddr = &target->address;
		fm_socket_t *sock;

		sock = fm_socket_create(daddr->ss_family, SOCK_DGRAM, 0, NULL);
		if (sock == NULL)
			return false;

		if (fm_socket_connect(sock, daddr)
		 && fm_socket_get_local_address(sock, &target->local_bind_address))
			fm_address_set_port(&target->local_bind_address, 0);

		fm_socket_free(sock);
	}

	if (target->local_bind_address.ss_family == AF_UNSPEC)
		return false;

	*bind_address = target->local_bind_address;
	return true;
}

/*
 * Update the host asset information
 */
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
