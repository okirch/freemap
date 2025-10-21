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
#include "utils.h"

static bool		fm_target_inspect_pending(fm_target_t *target);
static void		fm_target_pool_check(fm_target_pool_t *pool);

static fm_target_pool_t *fm_active_target_pool = NULL;

fm_probe_t *
fm_probe_alloc(const char *id, const struct fm_probe_ops *ops, fm_protocol_t *proto, fm_target_t *target)
{
	fm_probe_t *probe;

	assert(ops->obj_size >= sizeof(*probe));
	probe = calloc(1, ops->obj_size);
	probe->target = target;
	probe->name = strdup(id);
	probe->ops = ops;
	probe->proto = proto;

	return probe;
}

void
fm_probe_free(fm_probe_t *probe)
{
	if (probe->ops->destroy)
		probe->ops->destroy(probe);

	if (probe->status != NULL)
		fm_fact_free(probe->status);

	if (probe->target != NULL)
		fm_target_forget_pending(probe->target, probe);

	fm_probe_unlink(probe);

	memset(probe, 0, sizeof(*probe));
	free(probe);
}

fm_fact_t *
fm_probe_send(fm_probe_t *probe)
{
	fm_fact_t *error;

	probe->timeout = 0;

	error = probe->ops->send(probe);
	if (error == NULL) {
		/* Record when we sent the first packet */
		fm_timestamp_init(&probe->sent);

		/* If we have an RTT estimator, use the timeout it suggests */
		if (probe->timeout == 0 && probe->rtt != NULL)
			probe->timeout = probe->rtt->timeout + probe->rtt_application_bias;

		if (probe->timeout == 0)
			probe->timeout = probe->ops->default_timeout;

		if (probe->timeout > 0)
			fm_timestamp_set_timeout(&probe->expires, probe->timeout);
		else
			fm_log_warning("%s: timeout=0\n", probe->name);
	}
	return error;
}

void
fm_probe_set_status(fm_probe_t *probe, fm_fact_t *fact)
{
	if (probe->status) {
		fm_fact_free(fact);
	} else {
		fact->elapsed = fm_timestamp_since(&probe->sent);
		probe->status = fact;
	}
}

static void
fm_probe_render_verdict(fm_probe_t *probe, fm_probe_verdict_t verdict)
{
	fm_fact_t *fact;

	if (probe->status != NULL) {
		fm_log_error("%s: ignoring redundant verdict", probe->name);
		return;
	}

	fact = probe->ops->render_verdict(probe, verdict);
	if (fact == NULL) {
		fm_log_error("%s: cannot render verdict %d", probe->name, verdict);
		return;
	}

	fact->elapsed = fm_timestamp_since(&probe->sent);
	probe->status = fact;
}

void
fm_probe_set_rtt_estimator(fm_probe_t *probe, fm_rtt_stats_t *rtt)
{
	probe->rtt = rtt;
}

static inline void
fm_probe_update_rtt_estimate(fm_probe_t *probe, double *rtt)
{
	if (probe->rtt) {
		if (rtt == NULL || *rtt < 0) {
			/* This fallback should probably go away soon */
			fm_rtt_stats_update(probe->rtt, fm_timestamp_since(&probe->sent));
		} else {
			fm_rtt_stats_update(probe->rtt, *rtt);
		}

	}
}

void
fm_probe_received_reply(fm_probe_t *probe, double *rtt)
{
	fm_probe_render_verdict(probe, FM_PROBE_VERDICT_REACHABLE);
	fm_probe_update_rtt_estimate(probe, rtt);
}

void
fm_probe_received_error(fm_probe_t *probe, double *rtt)
{
	fm_probe_render_verdict(probe, FM_PROBE_VERDICT_UNREACHABLE);
	fm_probe_update_rtt_estimate(probe, rtt);
}

void
fm_probe_timed_out(fm_probe_t *probe)
{
	fm_probe_render_verdict(probe, FM_PROBE_VERDICT_TIMEOUT);
}

/*
 * Tracking of extant requests
 */
fm_extant_t *
fm_extant_alloc(fm_probe_t *probe, int af, int ipproto, const void *payload, size_t payload_size)
{
	fm_target_t *target = probe->target;
	fm_extant_t *extant;

	extant = calloc(1, sizeof(*extant) + payload_size);

	extant->family = af;
	extant->ipproto = ipproto;
	extant->probe = probe;

	fm_socket_timestamp_update(&extant->timestamp);

	if (payload != NULL)
		memcpy(extant + 1, payload, payload_size);

	fm_extant_append(&target->expecting, extant);

	return extant;
}

void
fm_extant_free(fm_extant_t *extant)
{
	fm_extant_unlink(extant);
	free(extant);
}

/*
 * Process the verdict on an extant packet.
 * If the kernel did not give us a timestamp via SO_TIMESTAMP, recv_time will be
 * unset. In this case, fm_timestamp_delta() will just use the current wall time
 * instead.
 */
void
fm_extant_received_reply(fm_extant_t *extant, const fm_pkt_t *pkt)
{
	double rtt = fm_pkt_rtt(pkt, &extant->timestamp);

	fm_probe_received_reply(extant->probe, &rtt);
}

void
fm_extant_received_error(fm_extant_t *extant, const fm_pkt_t *pkt)
{
	double rtt = fm_pkt_rtt(pkt, &extant->timestamp);

	fm_probe_received_error(extant->probe, &rtt);
}

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
	return pool;
}

void
fm_target_pool_auto_resize(fm_target_pool_t *pool, unsigned int max_size)
{
	unsigned int i, new_size;

	if (pool->size < max_size / 2)
		new_size = pool->size * 2;
	else
		new_size = max_size;

	if (pool->size < new_size) {
		pool->slots = realloc(pool->slots, new_size * sizeof(pool->slots[0]));
		for (i = pool->size; i < new_size; ++i)
			pool->slots[i] = NULL;
		pool->size = new_size;
	}
}

static inline bool
fm_target_pool_has_free_slots(const fm_target_pool_t *pool)
{
	return pool->count < pool->size;
}

static void
fm_target_pool_add(fm_target_pool_t *pool, fm_target_t *target)
{
	unsigned int pos;

	assert(target != NULL);
	for (pos = 0; pos < pool->size; ++pos) {
		if (pool->slots[pos] == NULL) {
			pool->slots[pos] = target;
			pool->count += 1;
			return;
		}
	}

	fprintf(stderr, "fatal: counters of target pool out of whack\n");
	abort();
}

fm_target_t *
fm_target_pool_get_next(fm_target_pool_t *pool, unsigned int *num_visited)
{
	fm_target_t *target = NULL;
	unsigned int i;

	if (pool->count == 0)
		return NULL;

	for (i = 0; i < pool->size && target == NULL && *num_visited < pool->size; ++i) {
		target = pool->slots[pool->cursor];

		pool->cursor = (pool->cursor + 1) % pool->size;
		*num_visited += 1;
	}

	return target;
}

bool
fm_target_pool_remove(fm_target_pool_t *pool, fm_target_t *target)
{
	unsigned int i;

	for (i = 0; i < pool->size; ++i) {
		if (pool->slots[i] == target) {
			pool->slots[i] = NULL;
			pool->count -= 1;
			return true;
		}
	}

	return false;
}

static void
fm_target_pool_check(fm_target_pool_t *pool)
{
	unsigned int i, true_count = 0;

	for (i = 0; i < pool->size; ++i) {
		if (pool->slots[i] != NULL)
			true_count += 1;
	}

	assert(pool->count == true_count);
}

bool
fm_target_pool_reap_completed(fm_target_pool_t *pool)
{
	fm_target_t *target;
	unsigned int i;
	bool completed_some = false;

	for (i = 0; i < pool->size; ++i) {
		if ((target = pool->slots[i]) != NULL) {
			if (fm_target_inspect_pending(target))
				completed_some = true;
		}
	}

	fm_target_pool_check(pool);

	return completed_some;
}

void
fm_target_pool_make_active(fm_target_pool_t *pool)
{
	fm_active_target_pool = pool;
}

fm_target_t *
fm_target_pool_find(const fm_address_t *addr)
{
	fm_target_pool_t *pool;
	unsigned int i;

	assert(fm_active_target_pool);
	pool = fm_active_target_pool;

	for (i = 0; i < pool->size; ++i) {
		fm_target_t *target = pool->slots[pool->cursor];

		if (fm_address_equal(&target->address, addr, false))
			return target;
	}

	return NULL;
}

/*
 * abstract target manager
 */
fm_target_manager_t *
fm_target_manager_create(void)
{
	fm_target_manager_t *mgr;

	mgr = calloc(1, sizeof(*mgr));

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
	fm_address_enumerator_list_append(&mgr->address_generators, agen);
}

fm_target_t *
fm_target_manager_get_next_target(fm_target_manager_t *mgr)
{
	fm_address_enumerator_t *agen;
	fm_target_t *target = NULL;

	while (target == NULL) {
		fm_network_t *target_net;
		fm_address_t target_addr;

		if (!(agen = fm_address_enumerator_list_head(&mgr->address_generators)))
			break;

		if (!fm_address_enumerator_get_one(agen, &target_addr)) {
			/* This address generator is spent; move to the next */
			fm_address_enumerator_destroy(agen);
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

	return target;
}

bool
fm_target_manager_replenish_pool(fm_target_manager_t *mgr, fm_target_pool_t *pool)
{
	if (!mgr->all_targets_exhausted) {
		while (fm_target_pool_has_free_slots(pool)) {
			fm_target_t *target;

			if ((target = fm_target_manager_get_next_target(mgr)) == NULL) {
				mgr->all_targets_exhausted = true;
				break;
			}

			fm_log_debug("%s added to address pool\n", fm_target_get_id(target));
			fm_target_pool_add(pool, target);
		}

		fm_target_pool_check(pool);
	}

	return pool->count > 0;
}

fm_target_t *
fm_target_create(const fm_address_t *address, fm_network_t *network)
{
	fm_target_t *tgt;
	const fm_address_t *lladdr;

	tgt = calloc(1, sizeof(*tgt));
	tgt->address = *address;
	tgt->id = strdup(fm_address_format(address));
	tgt->network = network;

	/* Initial sequence number for ICMP probes */
	tgt->host_probe_seq = 1;

	/* The initial packet rate is very restricted */
	fm_ratelimit_init(&tgt->host_rate_limit, 1, 1);

	if ((lladdr = fm_address_find_lladdr(address)) != NULL)
		tgt->local_interface_address = *lladdr;

	return tgt;
}

void
fm_target_free(fm_target_t *target)
{
	fm_probe_t *probe;

	while ((probe = fm_probe_list_get_first(&target->pending_probes)) != NULL)
		fm_probe_free(probe);

	drop_string(&target->id);

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

	/* destroy the log, too */

	free(target);
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


/* FIXME: split update and query into separate functions
 */
unsigned int
fm_target_get_send_quota(fm_target_t *target)
{
	fm_ratelimit_update(&target->host_rate_limit);
	return fm_ratelimit_available(&target->host_rate_limit);
}

bool
fm_target_is_done(const fm_target_t *target)
{
	if (!target->scan_done)
		return false;

	return fm_probe_list_is_empty(&target->pending_probes);
}

void
fm_target_send_probe(fm_target_t *tgt, fm_probe_t *probe)
{
	fm_fact_t *error;

	error = fm_probe_send(probe);
	if (error != NULL) {
		fm_probe_free(probe);
		fm_fact_log_append(&tgt->log, error);
	} else {
		fm_probe_insert(&tgt->pending_probes, probe);

		/* If the probe is marked as blocking, do not allow
		 * any further probes to be transmitted until we've
		 * processed everything that is in the queue. */
		if (probe->blocking)
			tgt->plugged = true;

		fm_ratelimit_consume(&tgt->host_rate_limit, 1);
	}
}

unsigned int
fm_target_process_timeouts(fm_target_t *target, unsigned int quota)
{
	const struct timeval *now = fm_timestamp_now();
	unsigned int num_sent = 0;
	fm_probe_t *probe, *next;

        for (probe = (fm_probe_t *) (target->pending_probes.hlist.first); probe != NULL; probe = next) {
                next = (fm_probe_t *) probe->link.next;

		if (fm_timestamp_older(&probe->expires, now)) {
			if (probe->ops->should_resend != NULL
			 && probe->ops->should_resend(probe)) {
				if (num_sent < quota) {
					fm_fact_t *error;

					fm_log_debug("%s: resending %s probe\n", fm_address_format(&target->address), probe->name);
					error = fm_probe_send(probe);
					if (error != NULL)
						fm_probe_set_status(probe, error);
					num_sent += 1;
				}
				continue;
			}

			fm_probe_set_status(probe, fm_fact_create_error(FM_FACT_PROBE_TIMED_OUT,
						"%s no response received",
						probe->name));
		}
	}

	fm_ratelimit_consume(&target->host_rate_limit, num_sent);

	return num_sent;
}

bool
fm_target_inspect_pending(fm_target_t *target)
{
	fm_probe_t *probe, *next;
	bool rv = false;

        for (probe = (fm_probe_t *) (target->pending_probes.hlist.first); probe != NULL; probe = next) {
                next = (fm_probe_t *) probe->link.next;

		if (probe->status != NULL) {
			fm_log_debug("STATUS %s %s\n", fm_address_format(&target->address), fm_fact_render(probe->status));
			if (probe->result_callback)
				probe->result_callback(target, probe->status);

			fm_fact_log_append(&target->log, probe->status);
			probe->status = NULL;

			fm_probe_free(probe);
			rv = true;
		}
	}

	if (fm_probe_list_is_empty(&target->pending_probes))
		target->plugged = false;

	if (fm_target_is_done(target)) {
		fm_log_debug("%s all outstanding probes collected\n", fm_address_format(&target->address));
	}

	return rv;
}

/*
 * Management of extant packets awaiting a reply
 */
void
fm_target_forget_pending(fm_target_t *target, const fm_probe_t *probe)
{
	hlist_iterator_t iter;
	fm_extant_t *extant;

	for (extant = fm_extant_iterator_first(&iter, &target->expecting);
	     extant != NULL;
	     extant = fm_extant_iterator_next(&iter)) {
		if (extant->probe == probe)
			fm_extant_free(extant);
	}
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
