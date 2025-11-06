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
 *
 * Simple UDP scanning functions
 */

#include <sys/socket.h>
#include <linux/errqueue.h>
#include <linux/icmp.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "traceroute.h"
#include "scanner.h"
#include "protocols.h"
#include "target.h" /* for fm_probe_t */
#include "socket.h"
#include "utils.h"


static fm_topo_state_t *	fm_topo_probe_get_request(const fm_probe_t *probe);
static void			fm_topo_probe_set_request(fm_probe_t *probe, fm_topo_state_t *topo);
static void			fm_topo_state_free(fm_topo_state_t *topo);
static fm_probe_class_t *	fm_topo_get_packet_probe_class(const char *proto_name);

static fm_tgateway_t *		fm_tgateway_default(void);
static fm_tgateway_t *		fm_tgateway_for_address(unsigned int, const fm_address_t *);

static fm_topo_shared_sockets_t *fm_topo_shared_sockets_get(fm_protocol_t *packet_proto, int af);
static fm_socket_t *		fm_topo_shared_socket_open(fm_topo_shared_sockets_t *shared, unsigned ttl);
static void			fm_topo_shared_sockets_release(fm_topo_shared_sockets_t *shared);

/*
 * topology scan state
 */
static fm_topo_state_t *
fm_topo_state_alloc(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const fm_topo_extra_params_t *extra_params)
{
	fm_topo_state_t *topo;
	const char *packet_proto_name = NULL;
	unsigned int ttl;

	topo = calloc(1, sizeof(*topo));
	topo->proto = proto;
	topo->target = target;
	topo->params = *params;

	topo->family = target->address.ss_family;
	topo->host_address = target->address;
	topo->host_asset = target->host_asset;
	if (topo->host_asset != NULL) {
		fm_host_asset_clear_routing(topo->host_asset, topo->family);
		fm_host_asset_update_state(topo->host_asset, FM_ASSET_STATE_PROBE_SENT);
	}

	if (topo->params.port == 0)
		topo->params.port = 44444; /* make this configurable */
	if (topo->params.retries <= FM_RTT_SAMPLES_WANTED)
		topo->params.retries = FM_RTT_SAMPLES_WANTED;

	if (extra_params != NULL)
		topo->topo_params = *extra_params;
	if (topo->topo_params.max_depth == 0)
		topo->topo_params.max_depth = 16;
	if (topo->topo_params.max_hole_size == 0)
		topo->topo_params.max_hole_size = 5;

	topo->packet_probe_class = fm_topo_get_packet_probe_class(topo->topo_params.packet_proto);
	if (topo->packet_probe_class == NULL)
		goto failed;

	topo->packet_proto = topo->packet_probe_class->proto;

	/* Set the globally unknown gateway and its rate limiters. */
	topo->unknown_gateway = fm_tgateway_default();

	for (ttl = 0; ttl < FM_MAX_TOPO_DEPTH; ++ttl) {
		fm_topo_hop_state_t *hop = &topo->hop[ttl];

		hop->distance = ttl;
		hop->ratelimit = &topo->unknown_gateway->unknown_next_hop_rate[ttl];
	}

	if (topo->packet_proto->supported_parameters & FM_FEATURE_SOCKET_SHARING_MASK) {
		topo->shared_socks = fm_topo_shared_sockets_get(topo->packet_proto, topo->family);

		if (extra_params->packet_proto_params) {
			fm_log_warning("traceroute: ignoring %s options", packet_proto_name);
			/* If we want to honor these, we would need to share fm_topo_shared_sockets_t
			 * per traceroute probe rather than locally.
			 * FIXME: maybe stick fm_topo_shared_sockets_t into the tracerout extra_params?
			 * Would be icky, because it's not really a parameter... :-( */
		}
	}

	/* start with ttl 1 */
	topo->next_ttl = 1;

	return topo;

failed:
	fm_topo_state_free(topo);
	return NULL;

	return topo;
}

/*
 * traceroute can be used with different packet protos (udp, tcp, icmp, ...)
 * We need the proto handle as well as a suitable probe class that goes with it.
 */
static fm_probe_class_t *
fm_topo_get_packet_probe_class(const char *proto_name)
{
	fm_probe_class_t *probe_class;
	fm_protocol_t *proto;
	unsigned int required_mask;

	if (proto_name == NULL)
		proto_name = "udp";

	proto = fm_protocol_by_name(proto_name);
	if (proto == NULL) {
		fm_log_error("traceroute: unknown packet protocol %s", proto_name);
		return NULL;
	}
	if (proto->id == FM_PROTO_NONE) {
		fm_log_error("traceroute: not packet protocol: %s", proto_name);
		return NULL;
	}

	/* Now get a corresponding probe for this protocol */
	probe_class = fm_probe_class_by_proto_id(proto->id, FM_PROBE_MODE_TOPO);
	if (probe_class == NULL) {
		fm_log_error("traceroute: no (host) probe for packet protocol %s", proto_name);
		return NULL;
	}

	required_mask = FM_PARAM_TYPE_PORT_MASK | FM_PARAM_TYPE_TTL_MASK | FM_PARAM_TYPE_RETRIES_MASK | FM_FEATURE_STATUS_CALLBACK_MASK;
	if (~(probe_class->features) & required_mask) {
		fm_log_error("traceroute: packet protocol %s does not support all required features", proto_name);
		return NULL;
	}

	return probe_class;
}

static void
fm_topo_state_free(fm_topo_state_t *topo)
{
	unsigned int i;

	if (topo->shared_socks != NULL) {
		fm_topo_shared_sockets_release(topo->shared_socks);
		topo->shared_socks = NULL;
	}

	for (i = 0; i < FM_MAX_TOPO_DEPTH; ++i) {
		fm_topo_hop_state_t *hop = &topo->hop[i];

		if (hop->pending) {
			fm_job_cancel_completion(hop->pending, hop->completion);
			hop->pending = NULL;

			fm_completion_free(hop->completion);
			hop->completion = NULL;
		}
	}

	free(topo);
}

/*
 * Assign a gateway to a hop
 */
static void
fm_topo_hop_set_gateway(fm_topo_hop_state_t *hop, const fm_address_t *gw_addr)
{
	fm_tgateway_t *gw;

	gw = fm_tgateway_for_address(hop->distance, gw_addr);
	if (hop->gateway == gw)
		return;
	if (hop->gateway != NULL) {
		if (hop->alt_gateway != NULL)
			hop->alt_gateway = gw;
		return;
	}

	hop->flags |= FM_TOPO_HOP_GW_CHANGED;
	hop->gateway = gw;
}

static void
fm_topo_state_report_flapping_gateways(fm_topo_state_t *topo)
{
	unsigned int ttl;

	for (ttl = 0; ttl < FM_MAX_TOPO_DEPTH; ++ttl) {
		fm_topo_hop_state_t *hop = &topo->hop[ttl];

		if (hop->alt_gateway && !(hop->flags & FM_TOPO_HOP_GW_FLAP)) {
			fm_log_notice("%s: gateway at ttl=%u is not stable (%s vs %s)",
					fm_address_format(&topo->host_address),
					hop->distance,
					fm_address_format(&hop->gateway->address),
					fm_address_format(&hop->alt_gateway->address));

			if (topo->host_asset != NULL)
				fm_host_asset_update_routing_hop(topo->host_asset, ttl,
						&hop->alt_gateway->address, NULL,
						true);

			/* report just once */
			hop->flags |= FM_TOPO_HOP_GW_FLAP;
		}

		/* FIXME: we could also report routers sending responses from
		 * a private IP address, like 10.* */
	}
}

/*
 * Callback from the packet protocol when it received a response, or an error
 * Returning true means: please keep going.
 */
static bool
fm_topo_hop_probe_pkt_callback(const fm_probe_t *probe, const fm_pkt_t *pkt, double rtt, void *user_data)
{
	fm_topo_hop_state_t *hop = user_data;
	const struct sock_extended_err *ee;

	if ((ee = pkt->info.ee) == NULL) {
		/* For UDP, we never receive a response packet - but for ICMP echo probes,
		 * we actually do. */
		fm_log_debug("%s responded to %s",
				fm_address_format(&pkt->peer_addr),
				probe->name);

		fm_topo_hop_set_gateway(hop, &pkt->peer_addr);
	} else {
		if (ee->ee_origin != SO_EE_ORIGIN_ICMP && ee->ee_origin != SO_EE_ORIGIN_LOCAL)
			return true;

		if (pkt->info.offender == NULL) {
			fm_log_error("received ICMP packet but no offender?");
			return true;
		}

		if (ee->ee_type == ICMP_TIME_EXCEEDED) {
			fm_log_debug("time exceeded ttl=%u, gw=%s, rtt=%f", hop->distance,
					fm_address_format(pkt->info.offender),
					rtt);
		} else
		if (ee->ee_type == ICMP_DEST_UNREACH) {
			fm_log_debug("destination unreachable ttl=%u, gw=%s, rtt=%f", hop->distance,
					fm_address_format(pkt->info.offender),
					rtt);
		} else {
			fm_log_debug("ICMP message type %d code %d ttl=%u, gw=%s, rtt=%f",
					ee->ee_type, ee->ee_code,
					hop->distance,
					fm_address_format(pkt->info.offender),
					rtt);
			return true;
		}

		fm_topo_hop_set_gateway(hop, pkt->info.offender);
	}

	hop->state = FM_ASSET_STATE_OPEN;

	{
		fm_rtt_stats_t *rtt_stats = &hop->gateway->rtt;

		fm_rtt_stats_update(rtt_stats, rtt);
		if (rtt_stats->nsamples < FM_RTT_SAMPLES_WANTED) {
			/* keep going, we want more rtt samples */
			return true;
		}
	}

	/* FIXME: when sending the probe, we consumed one token from the
	 * target's host rate. However, we now know the packet never
	 * reached the target host (viz the ICMP error); so we should be
	 * able to give that token back to the rate limiter.
	 * Alas, we do not have a back pointer to the target here. */

	return false;
}

/*
 * Callback from the scheduler when one of our hop probes completes
 */
static void
fm_topo_hop_probe_complete(const fm_job_t *job, void *user_data)
{
	fm_topo_hop_state_t *hop = user_data;

	if (hop->pending != job)
		return;

	fm_log_debug("%s completed", job->fullname);
	hop->pending = NULL;

	if (hop->completion) {
		fm_completion_free(hop->completion);
		hop->completion = NULL;
	}
}

/*
 * Get the current probing horizon
 */
static inline unsigned int
fm_topo_state_max_ttl(fm_topo_state_t *topo)
{
	unsigned int max_ttl;

	max_ttl = topo->next_ttl + topo->topo_params.max_hole_size;
	if (max_ttl > topo->topo_params.max_depth)
		max_ttl = topo->topo_params.max_depth;
	if (topo->destination_ttl != 0 && max_ttl > topo->destination_ttl)
		max_ttl = topo->destination_ttl;
	return max_ttl;
}

/*
 * Check whether we have pending probes
 */
static bool
fm_topo_state_check_pending(fm_topo_state_t *topo, double *delay_ret)
{
	const struct timeval *now = fm_timestamp_now();
	unsigned int ttl, max_ttl;
	bool have_pending = false;

	max_ttl = fm_topo_state_max_ttl(topo);
	for (ttl = 1; ttl < max_ttl; ++ttl) {
		fm_topo_hop_state_t *hop = &topo->hop[ttl];
		fm_job_t *pending;
		double delay;

		if ((pending = hop->pending) == NULL)
			continue;

		delay = fm_timestamp_expires_when(&pending->expires, now);
		if (delay < 0) {
			fm_log_warning("traceroute: hop %u has a pending probe w/o expiry", ttl);
		} else if (delay < *delay_ret) {
			*delay_ret = delay;
		}
		fm_log_debug("  %2u pending probe %s delay=%f sec", ttl, pending->fullname, delay);
		have_pending = true;
	}

	return have_pending;
}

/*
 * Check for gateway changes
 * The point of this exercise is that we need to be mindful of stuff like
 * ICMP send rate limits in gateways.
 * Assume that gateway, *if* they do send any ICMP packets at all, they
 * are willing and able of sending at least RATE (which is N packet per
 * second).
 *
 * Initially, we treat all gateways at distance TTL the same way; ie we
 * do not send more than N pkt/s. This is limited by global rate limiters,
 * one for each TTL value. Call them the "global unknown router limits",
 * or GlobalLimit(TTL).
 *
 * However, we learn. So assume we are tracing hosts A and B, and their
 * paths are different - let's say we learned that at TTL=4, the path
 * to A goes through Router RouterA, and the one to B goes through RouterB.
 * Then it's fair to assume that packets with TTL=5 will not be handled
 * by the same router; IOW we can use distinct rate limit objects for
 * limiting our probe packets: RouterALimit(+1) and RouterBLimit(+1).
 *
 * Things become a bit complicated by the fact that we do not proceed
 * one TTL at a time, but that we have a probing window where we transmit
 * several probes simultaneously. So what happens if we start probing
 * host C, and transmit probes for TTL=1,2,3,4,5?
 *
 * The probe with TTL=5 could hit a gateway one hop behind RouterA (call it RouterA'),
 * but it could also hit RouterB' or some as yet unknown RC'. As we do not
 * know, we use the global unknown limit for TTL=5 when sending the
 * probe. But that means, to begin with, that sending actually needs to
 * be controlled by the combination of GobalLimit(5) and RouterALimit(+1),
 * as well as GlobalLimit(5) and RouterBLimit(+1), respectively.
 * We achieve this by granting a fraction of RATE to global limits,
 * and a fraction to each router limit, so that
 * GlobalLimit(x) + Router*Limit(y) == RATE.
 *
 * The other part of the problem is what happens after we receive a
 * response from RouterB in response to our probe packet to C with TTL=5?
 * In order to improve throughput, we can now transfer 1 token from
 * RouterBLimit(+1) to GlobalLimit(5), because we know that the
 * response really came back from the next hop behind RouterB
 * rather than some unknown RouterC'.
 *
 * This is what this algorithm tries to do.
 */
static void
fm_topo_state_check_gateways(fm_topo_state_t *topo)
{
	unsigned int ttl, max_ttl;
	fm_tgateway_t *gw;
	unsigned gw_ttl = 0;
	bool changed = false;

	gw = topo->unknown_gateway;

	fm_topo_state_report_flapping_gateways(topo);

	max_ttl = fm_topo_state_max_ttl(topo);
	for (ttl = 1; ttl < max_ttl; ++ttl) {
		fm_topo_hop_state_t *hop = &topo->hop[ttl];

		if (changed) {
			fm_ratelimit_t *old_ratelimit = hop->ratelimit;

			/* Set the new rate limit to RouterLimit(+X) */
			hop->ratelimit = &gw->unknown_next_hop_rate[ttl - gw_ttl];

			/* transfer one token from our new rate limiter to
			 * the one we used to send the probe. */
			fm_ratelimit_transfer(hop->ratelimit, old_ratelimit, hop->probes_sent);
			hop->probes_sent = 0;
		}

		if (hop->gateway != NULL) {
			gw = hop->gateway;
			gw_ttl = ttl;
			if (hop->flags & FM_TOPO_HOP_GW_CHANGED) {
				/* Update the route asset */
				if (topo->host_asset != NULL) {
					double rtt = 0;

					/* When we get here, by definition we should have a sample... but you never know */
					if (gw->rtt.nsamples != 0)
						rtt = gw->rtt.rtt_sum / gw->rtt.nsamples;

					fm_host_asset_update_routing_hop(topo->host_asset, ttl,
							&gw->address, &rtt,
							false);
				}

				hop->flags &= ~FM_TOPO_HOP_GW_CHANGED;
				changed = true;
			}
		}
	}
}

/*
 * Select the next distance to probe
 */
static fm_error_t
fm_topo_state_select_ttl(fm_topo_state_t *topo, double *delay_ret, fm_topo_hop_state_t **next_hop_ret)
{
	unsigned int ttl, max_ttl;
	bool have_pending = false;
	bool done = false;

	*next_hop_ret = NULL;

	/* Check for any changed gateway, and adjust ratelimits etc */
	fm_topo_state_check_gateways(topo);

	/* First, check whether we can advance next_ttl */
	while ((ttl = topo->next_ttl) < FM_MAX_TOPO_DEPTH) {
		fm_topo_hop_state_t *hop = &topo->hop[ttl];
		fm_tgateway_t *gw;

		if ((gw = hop->gateway) == NULL)
			break;

		if (fm_address_equal(&topo->host_address, &hop->gateway->address, false)) {
			fm_log_debug("  %2u reached destination", ttl);
			topo->destination_ttl = ttl;
			break;
		}

		fm_log_debug("  %2u addr=%s; we can progress", ttl, fm_address_format(&hop->gateway->address));
		topo->next_ttl += 1;
	}

	max_ttl = fm_topo_state_max_ttl(topo);
	for (ttl = topo->next_ttl; ttl < max_ttl; ++ttl) {
		fm_topo_hop_state_t *hop = &topo->hop[ttl];

		if (hop->pending != NULL)
			continue; /* we've dealt with you already */

		if (hop->state != FM_ASSET_STATE_UNDEF) {
			fm_log_debug("  %2u state=%d", ttl, hop->state);
			continue;
		}

		/* Consult the rate limit
		 * Can we consume 1 token, or would we have to wait?
		 */
		fm_ratelimit_update(hop->ratelimit);
		if (fm_ratelimit_available(hop->ratelimit) >= 1) {
			fm_log_debug("  %2u ready to create new probe", ttl);

			if (*next_hop_ret == NULL)
				*next_hop_ret = hop;
		} else {
			double delay = fm_ratelimit_wait_until(hop->ratelimit, 1);

			fm_log_debug("  %2u delay=%f sec", ttl, delay);
			if (delay < *delay_ret)
				*delay_ret = delay;
		}
	}

	have_pending = fm_topo_state_check_pending(topo, delay_ret);

	if (topo->destination_ttl != 0) {
		/* We have reached the destination.
		 * If we have outstanding probes that reach further, cancel them right away.
		 */
		for (ttl = topo->destination_ttl + 1; ttl < max_ttl; ++ttl) {
			fm_topo_hop_state_t *hop = &topo->hop[ttl];

			if (hop->pending == NULL)
				continue;

			fm_log_debug("  %2u cancel pending probe %s", ttl, hop->pending->fullname);
			fm_job_cancel_completion(hop->pending, hop->completion);
			fm_job_mark_complete(hop->pending);
			hop->pending = NULL;
		}

		done = true;
	}

	if (*next_hop_ret == NULL) {
		if (have_pending)
			return FM_TRY_AGAIN;
		if (done)
			return 0;
		return FM_TIMED_OUT;
	}

	return 0;
}

static fm_error_t
fm_topo_state_send_probe(fm_topo_state_t *topo, fm_topo_hop_state_t *hop, double *delay_ret)
{
	fm_protocol_t *packet_proto = topo->packet_proto;
	unsigned int ttl = hop->distance;
	fm_probe_params_t params;
	fm_probe_t *probe;
	fm_error_t error;

	assert(hop->pending == NULL);

	memset(&params, 0, sizeof(params));
	/* copy retries, port, tos and override ttl */
	params = topo->params;
	params.ttl = ttl;

	probe = fm_create_host_probe(topo->packet_probe_class, topo->target, &params, NULL);
	if (probe == NULL) {
		fm_log_error("%s: unable to create %s probe", fm_address_format(&topo->target->address), packet_proto->name);
		return FM_SEND_ERROR;
	}

	/* sock sharing is very sustainable. not very hygienic, but sustainable */
	if (topo->shared_socks != NULL) {
		fm_socket_t *sock;

		sock = fm_topo_shared_socket_open(topo->shared_socks, ttl);
		assert(sock->family == topo->host_address.ss_family);

		error = fm_probe_set_socket(probe, sock);
		if (error != 0) {
			fm_log_error("%s: unable to set shared socket: %s", probe->name, fm_strerror(error));
			fm_probe_free(probe);
			return error;
		}
	}

	hop->completion = fm_probe_wait_for_completion(probe, fm_topo_hop_probe_complete, hop);

	fm_probe_install_status_callback(probe, fm_topo_hop_probe_pkt_callback, hop);

	error = fm_target_add_new_probe(topo->target, probe);

	if (error == 0) {
		fm_ratelimit_consume(hop->ratelimit, 1);
		hop->state = FM_ASSET_STATE_PROBE_SENT;
		hop->pending = &probe->job;
	} else {
		hop->state = FM_ASSET_STATE_CLOSED;
	}

	return error;
}

static void
fm_topo_state_display(fm_topo_state_t *topo)
{
	unsigned int ttl, max_ttl;

	fm_log_debug("traceroute results for %s", fm_address_format(&topo->host_address));
	fm_log_debug(" %4s %5s %8s %s", "ttl", "nresp", "rtt/ms", "address");

	if (topo->destination_ttl != 0)
		max_ttl = topo->destination_ttl + 1;

	max_ttl = fm_topo_state_max_ttl(topo);
	for (ttl = 1; ttl < max_ttl; ++ttl) {
		fm_topo_hop_state_t *hop = &topo->hop[ttl];
		fm_tgateway_t *gw;

		gw = hop->gateway;
		if (gw == NULL) {
			fm_log_debug(" %3u: %5u        * ?", hop->distance, 0);
		} else {
			fm_log_debug(" %3u: %5u %8.5f %s%s", hop->distance,
							gw->rtt.nsamples,
							gw->rtt.rtt_sum / gw->rtt.nsamples,
							fm_address_format(&gw->address),
							(hop->flags & FM_TOPO_HOP_GW_FLAP)? ", flapping": "");
		}
	}
}

static fm_tgateway_t *
fm_tgateway_alloc(unsigned int distance, const fm_address_t *addr)
{
	fm_tgateway_t *gw;
	unsigned int i, rate;

	gw = calloc(1, sizeof(*gw));
	gw->nhops = distance;

	if (addr == NULL) {
		rate = FM_TOPO_UNKNOWN_RATE;
	} else {
		rate = FM_TOPO_SEND_RATE - FM_TOPO_UNKNOWN_RATE;
		gw->address = *addr;

		/* FIXME: we should look up the host_asset here, so that
		 * we can prime its rtt estimates etc. */
	}

	for (i = 0; i < FM_MAX_TOPO_DEPTH; ++i)
		fm_ratelimit_init(&gw->unknown_next_hop_rate[i], rate, FM_TOPO_UNKNOWN_RATE);
	return gw;
}

/*
 * The "dummy" gateways
 */
static fm_tgateway_t *
fm_tgateway_default(void)
{
	static fm_tgateway_t *first;

	if (first == NULL)
		first = fm_tgateway_alloc(1, NULL);
	return first;
}

static void
fm_tgateway_array_append(fm_tgateway_array_t *array, fm_tgateway_t *gw)
{
	maybe_realloc_array(array->entries, array->count, 16);
	array->entries[array->count++] = gw;
}

static fm_tgateway_t *
fm_tgateway_for_address(unsigned int distance, const fm_address_t *addr)
{
	static fm_tgateway_array_t known;
	unsigned int i;
	fm_tgateway_t *gw;

	for (i = 0; i < known.count; ++i) {
		gw = known.entries[i];

		if (fm_address_equal(&gw->address, addr, false)) {
			/* Note; this can happen. For instance, when routers with a private IP like 10.x send ICMP errors... */
			if (gw->nhops != distance)
				fm_log_warning("I'm seeing the double: %s is at distance %u and %u simultaneously",
						fm_address_format(addr), gw->nhops, distance);
			return gw;
		}
	}

	gw = fm_tgateway_alloc(distance, addr);
	fm_tgateway_array_append(&known, gw);

	return gw;
}

/*
 * Shared sockets
 */
static fm_topo_shared_sockets_t *
fm_topo_shared_sockets_get(fm_protocol_t *packet_proto, int af)
{
	static fm_topo_shared_sockets_t *shared_socks[64];
	static unsigned int nshared = 0;
	fm_topo_shared_sockets_t *s;
	unsigned int i;

	for (i = 0; i < nshared; ++i) {
		s = shared_socks[i];

		if (s->packet_proto == packet_proto && s->family == af) {
			s->refcount++;
			return s;
		}
	}

	assert(nshared < 64);

	s = calloc(1, sizeof(*s));
	s->refcount = 1;
	s->packet_proto = packet_proto;
	s->family = af;

	shared_socks[nshared++] = s;
	return s;
}

static fm_socket_t *
fm_topo_shared_socket_open(fm_topo_shared_sockets_t *shared, unsigned ttl)
{
	fm_address_t local_addr;
	fm_socket_t *sock;

	if ((sock = shared->socks[ttl]) == NULL) {
		sock = fm_protocol_create_socket(shared->packet_proto, shared->family);

		memset(&local_addr, 0, sizeof(local_addr));
		local_addr.ss_family = shared->family;
		if (!fm_socket_bind(sock, &local_addr))
			fm_log_fatal("%s: cannot bind socket", __func__);

		fm_log_debug("Created shared %s socket", shared->packet_proto->name);
		shared->socks[ttl] = sock;
	}

	return sock;
}

static void
fm_topo_shared_sockets_release(fm_topo_shared_sockets_t *shared)
{
	unsigned int i;

	assert(shared->refcount > 0);

	if (--(shared->refcount) != 0)
		return;

	for (i = 0; i < FM_MAX_TOPO_DEPTH; ++i) {
		fm_socket_t *sock = shared->socks[i];

		if (sock != NULL) {
			fm_socket_free(sock);
			shared->socks[i] = NULL;
		}
	}
}

/*
 * Probe destructor
 */
static void
fm_topo_probe_destroy(fm_probe_t *probe)
{
	fm_topo_probe_set_request(probe, NULL);
}

/*
 * Schedule the probe.
 * This is a no-op, we will do the decision inside fm_topo_probe_send()
 */
static fm_error_t
fm_topo_probe_schedule(fm_probe_t *probe)
{
	return 0;
}

/*
 * Send the probe.
 */
static fm_error_t
fm_topo_probe_send(fm_probe_t *probe)
{
	fm_topo_state_t *topo;
	fm_topo_hop_state_t *hop;
	double delay = 1;
	fm_error_t error;

	fm_log_debug("%s: traceroute ready to run", fm_probe_name(probe));

	topo = fm_topo_probe_get_request(probe);
	error = fm_topo_state_select_ttl(topo, &delay, &hop);
	if (hop == NULL) {
		if (error == 0 || error == FM_TIMED_OUT) {
			if (fm_debug_level >= 1)
				fm_topo_state_display(topo);
		}

		if (error == 0) {
			fm_probe_mark_complete(probe);
		} else
		if (error == FM_TIMED_OUT) {
			fm_log_debug("%s: no more hops, timed out", fm_address_format(&topo->host_address));
		} else
		if (error == FM_TRY_AGAIN) {
			fm_log_debug("%s: come back in %f seconds", fm_address_format(&topo->host_address), delay);
			fm_probe_set_expiry(probe, delay);
		}

		return error;
	}

	fm_log_debug("%s: %s: sending probe with ttl=%u", fm_address_format(&topo->host_address), probe->name, hop->distance);

	error = fm_topo_state_send_probe(topo, hop, &delay);
	if (error == 0 || error == FM_TRY_AGAIN) {
		fm_log_debug("%s: hop %u probe sent, come back in %f seconds", fm_address_format(&topo->host_address), hop->distance, delay);
		fm_probe_set_expiry(probe, delay);
	}

	return error;
}

struct fm_topo_probe {
	fm_probe_t		base;
	fm_topo_state_t *	topo;
};

static struct fm_probe_ops fm_topo_probe_ops = {
	.obj_size	= sizeof(struct fm_topo_probe),
	.name 		= "topo",

	.destroy	= fm_topo_probe_destroy,
	.send		= fm_topo_probe_send,
	.schedule	= fm_topo_probe_schedule,
};

static fm_topo_state_t *
fm_topo_probe_get_request(const fm_probe_t *probe)
{
	if (probe->ops != &fm_topo_probe_ops)
		return NULL;

	return ((struct fm_topo_probe *) probe)->topo;
}

static void
fm_topo_probe_set_request(fm_probe_t *probe, fm_topo_state_t *topo)
{
	if (probe->ops == &fm_topo_probe_ops) {
		struct fm_topo_probe *priv = (struct fm_topo_probe *) probe;

		if (priv->topo != NULL)
			fm_topo_state_free(priv->topo);
		priv->topo = topo;
	}
}

static void *
fm_topo_process_extra_parameters(fm_probe_class_t *pclass, const fm_string_array_t *extra_args)
{
	fm_topo_extra_params_t *extra_params;
	fm_string_array_t proto_args;
	unsigned int i;

	extra_params = calloc(1, sizeof(*extra_params));
	extra_params->packet_proto = "udp"; /* default */

	memset(&proto_args, 0, sizeof(proto_args));
	for (i = 0; i < extra_args->count; ++i) {
		const char *arg = extra_args->entries[i];
		const char *proto_name;
		unsigned int proto_id;

		if (fm_parse_string_argument(arg, "packet-proto", &proto_name)) {
			proto_id = fm_protocol_string_to_id(proto_name);
			if (proto_id == FM_PROTO_NONE) {
				fm_log_error("%s: Unknown protocol in %s", pclass->name,  arg);
				goto failed;
			}
			extra_params->packet_proto = fm_protocol_id_to_string(proto_id);
		} else
		if (fm_parse_numeric_argument(arg, "max-depth", &extra_params->max_depth)
		 || fm_parse_numeric_argument(arg, "max-hole-size", &extra_params->max_hole_size)) {
			/* good to go */
		} else {
			fm_string_array_append(&proto_args, arg);
		}
	}

	if (proto_args.count != 0) {
		fm_probe_class_t *packet_probe_class = fm_topo_get_packet_probe_class(extra_params->packet_proto);

		if (packet_probe_class == NULL)
			goto failed;

		if (packet_probe_class->process_extra_parameters != NULL)
			extra_params->packet_proto_params = packet_probe_class->process_extra_parameters(packet_probe_class, &proto_args);

		if (extra_params->packet_proto_params == NULL) {
			fm_log_error("traceroute/%s: cannot process extra parameters", extra_params->packet_proto);
			for (i = 0; i < proto_args.count; ++i)
				fm_log_error("  unknown option %s", proto_args.entries[i]);

			goto failed;
		}

	}

	fm_string_array_destroy(&proto_args);
	return extra_params;

failed:
	free(extra_params);
	return NULL;
}

static fm_probe_t *
fm_topo_create_probe(fm_probe_class_t *pclass, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_topo_state_t *topo;
	fm_probe_t *probe;
	char name[32];

	topo = fm_topo_state_alloc(NULL, target, params, (fm_topo_extra_params_t *) extra_params);
	if (topo == NULL)
		return NULL;

	snprintf(name, sizeof(name), "topo/%s", topo->packet_proto->name);
	probe = fm_probe_alloc(name, &fm_topo_probe_ops, target);

	fm_topo_probe_set_request(probe, topo);

	return probe;
}

/*
 * The probe class that does traceroute like protocol probes.
 * It feels wrong to call this a protocol
 */
static struct fm_probe_class fm_traceroute_host_probe_class = {
	.name		= "traceroute",
	.proto_id	= FM_PROTO_NONE,
	.modes		= FM_PROBE_MODE_TOPO|FM_PROBE_MODE_HOST,
	.features	= FM_PARAM_TYPE_PORT_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK,

	.process_extra_parameters = fm_topo_process_extra_parameters,
	.create_probe	= fm_topo_create_probe,
};

FM_PROBE_CLASS_REGISTER(fm_traceroute_host_probe_class)
