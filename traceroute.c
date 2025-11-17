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
#include "target.h"
#include "socket.h"
#include "utils.h"
#include "logging.h"


static void			fm_topo_state_free(fm_topo_state_t *topo);
static fm_probe_class_t *	fm_topo_get_packet_probe_class(const char *proto_name);
static bool			fm_topo_create_packet_probe(fm_topo_state_t *topo);
static void			fm_topo_hop_remove_extant(fm_topo_hop_state_t *hop, const fm_extant_t *extant);
static void			fm_topo_hop_pkt_notifier(const fm_extant_t *extant, const fm_pkt_t *pkt, const double *rtt, void *user_data);

static fm_tgateway_t *		fm_tgateway_default(void);
static fm_tgateway_t *		fm_tgateway_for_address(unsigned int, const fm_address_t *);

static fm_topo_shared_sockets_t *fm_topo_shared_sockets_get(fm_protocol_t *packet_proto, const fm_address_t *dst_addr);
static fm_socket_t *		fm_topo_shared_socket_open(fm_topo_shared_sockets_t *shared, unsigned ttl);
static void			fm_topo_shared_sockets_release(fm_topo_shared_sockets_t *shared);

/*
 * topology scan state
 */
static fm_topo_state_t *
fm_topo_state_alloc(fm_protocol_t *proto, const fm_probe_params_t *params, const fm_topo_extra_params_t *extra_params)
{
	fm_topo_state_t *topo;
	unsigned int ttl;

	topo = calloc(1, sizeof(*topo));
	topo->proto = proto;
	topo->params = *params;

	if (topo->params.port == 0)
		topo->params.port = 65534; /* make this configurable */
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

	if (!fm_topo_create_packet_probe(topo))
		goto failed;

	/* Set the globally unknown gateway and its rate limiters. */
	topo->unknown_gateway = fm_tgateway_default();

	for (ttl = 0; ttl < FM_MAX_TOPO_DEPTH; ++ttl) {
		fm_topo_hop_state_t *hop = &topo->hop[ttl];

		hop->distance = ttl;
		hop->ratelimit = &topo->unknown_gateway->unknown_next_hop_rate[ttl];

		hop->notifier.callback = fm_topo_hop_pkt_notifier;
		hop->notifier.user_data = hop;
	}

	/* start with ttl 1 */
	topo->next_ttl = 1;

	return topo;

failed:
	fm_topo_state_free(topo);
	return NULL;

	return topo;
}

static bool
fm_topo_state_init_target(fm_topo_state_t *topo, fm_target_control_t *target_control, fm_target_t *target)
{
	const fm_address_t *addr = &target->address;

	target_control->family = addr->ss_family;
	target_control->target = target;
	target_control->address = *addr;
	return true;
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

static bool
fm_topo_create_packet_probe(fm_topo_state_t *topo)
{
	fm_multiprobe_t *packet_probe;
	fm_probe_params_t params = { .port = 65534, };

	packet_probe = fm_multiprobe_alloc(FM_PROBE_MODE_TOPO, topo->packet_probe_class->name);

	if (!fm_multiprobe_configure(packet_probe, topo->packet_probe_class, &params, NULL)) {
		fm_multiprobe_free(packet_probe);
		return false;
	}

	topo->packet_probe = packet_probe;
	return true;
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
		unsigned int k;

		for (k = 0; k < FM_RTT_SAMPLES_WANTED; ++k) {
			fm_extant_t *extant = hop->pending[k].extant;

			if (extant != NULL) {
				hop->pending[k].extant = NULL;
				fm_extant_free(extant);
			}
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
 */
static void
fm_topo_hop_pkt_notifier(const fm_extant_t *extant, const fm_pkt_t *pkt, const double *rtt, void *user_data)
{
	fm_topo_hop_state_t *hop = user_data;
	const struct sock_extended_err *ee;

	/* First things first - forget about this extant; it will be freed by the caller */
	fm_topo_hop_remove_extant(hop, extant);

	if ((ee = pkt->info.ee) == NULL) {
		/* For UDP, we never receive a response packet - but for ICMP echo probes,
		 * we actually do. */
		fm_log_debug("%s responded to traceroute probe",
				fm_address_format(&pkt->peer_addr));

		fm_topo_hop_set_gateway(hop, &pkt->peer_addr);
	} else {
		if (ee->ee_origin != SO_EE_ORIGIN_ICMP && ee->ee_origin != SO_EE_ORIGIN_LOCAL)
			return;

		if (pkt->info.offender == NULL) {
			fm_log_error("received ICMP packet but no offender?");
			return;
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
			return;
		}

		fm_topo_hop_set_gateway(hop, pkt->info.offender);
	}

	hop->state = FM_ASSET_STATE_OPEN;

	if (rtt != NULL) {
		fm_rtt_stats_t *rtt_stats = &hop->gateway->rtt;

		fm_rtt_stats_update(rtt_stats, *rtt);
		if (rtt_stats->nsamples >= FM_RTT_SAMPLES_WANTED) {
			/* FIXME: we're done with this hop */
		}
	}

	/* FIXME: when sending the probe, we consumed one token from the
	 * target's host rate. However, we now know the packet never
	 * reached the target host (viz the ICMP error); so we should be
	 * able to give that token back to the rate limiter.
	 * Alas, we do not have a back pointer to the target here. */

	return;
}

/*
 * After sending the probe packet for given ttl, record the extant here.
 */
static void
fm_topo_hop_add_extant(fm_topo_hop_state_t *hop, fm_extant_t *extant, double relative_timeout)
{
	unsigned int index;

	assert(hop->probes_sent < FM_RTT_SAMPLES_WANTED);

	index = hop->probes_sent++;
	hop->pending[index].extant = extant;
	hop->pending[index].timeout = fm_time_now() + relative_timeout;

	fm_extant_set_notifier(extant, &hop->notifier);
}

/*
 * We received a response. The extant will no longer be valid.
 */
static void
fm_topo_hop_remove_extant(fm_topo_hop_state_t *hop, const fm_extant_t *extant)
{
	unsigned int k;

	for (k = 0; k < hop->probes_sent; ++k) {
		struct fm_topo_hop_extant *hop_pending = &hop->pending[k];

		if (hop_pending->extant == extant)
			hop_pending->extant = NULL;
	}
}

/*
 * Check all extant probe packets; expire those that are over time.
 */
static bool
fm_topo_hop_check_pending(fm_topo_hop_state_t *hop, double *timeout_ret)
{
	fm_time_t now = fm_time_now();
	bool have_pending = false;
	unsigned int k;

	fm_timeout_update(timeout_ret, hop->next_send_time);

	for (k = 0; k < hop->probes_sent; ++k) {
		struct fm_topo_hop_extant *hop_pending = &hop->pending[k];

		if (hop_pending->extant != NULL) {
			if (hop_pending->timeout <= now) {
				fm_log_debug("  hop %2u probe %u expired", hop->distance, k);
				fm_extant_free(hop_pending->extant);
				hop_pending->extant = NULL;
			} else {
				fm_timeout_update(timeout_ret, hop_pending->timeout);
				have_pending = true;
			}
		}
	}

	return have_pending;
}

/*
 * Get the packet timeout for a given hop
 */
static bool
fm_topo_hop_get_timeout(fm_topo_hop_state_t *hop, double *timeout_ret)
{
	unsigned int k;

	/* The pending extant are in order of packet transmission, and their
	 * respective timeout will be send_time + packet_timeout.
	 * If we can still send packets, return the next_send_time (Assuming
	 * that packet_spacing <= packet_timeout).
	 */
	if (hop->next_send_time != 0) {
		fm_timeout_update(timeout_ret, hop->next_send_time);
		return true;
	}

	for (k = 0; k < hop->probes_sent; ++k) {
		if (hop->pending[k].extant != NULL) {
			fm_timeout_update(timeout_ret, hop->pending[k].timeout);
			return true;
		}
	}

	return false;
}

/*
 * Cancel any pending extants.
 */
static bool
fm_topo_hop_cancel_pending(fm_topo_hop_state_t *hop)
{
	unsigned int k, num_dropped = 0;

	/* The pending extant are in order of packet transmission, and their
	 * respective timeout will be send_time + packet_spacing */
	for (k = 0; k < hop->probes_sent; ++k) {
		if (hop->pending[k].extant != NULL) {
			fm_extant_free(hop->pending[k].extant);
			hop->pending[k].extant = NULL;
			num_dropped += 1;
		}
	}

	return !!num_dropped;
}

/*
 * Callback from the scheduler when one of our hop probes completes
 */
#if 0
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
#endif

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
fm_topo_state_check_pending(fm_topo_state_t *topo, double *timeout_ret)
{
	const fm_time_t now = fm_time_now();
	unsigned int ttl, max_ttl;
	bool have_pending = false;

	max_ttl = fm_topo_state_max_ttl(topo);
	for (ttl = 1; ttl < max_ttl; ++ttl) {
		fm_topo_hop_state_t *hop = &topo->hop[ttl];
		double hop_timeout = 0;

		if (fm_topo_hop_check_pending(hop, &hop_timeout)) {
			assert(hop_timeout);

			fm_log_debug("  %2u pending probe delay=%f sec", ttl, hop_timeout - now);
			fm_timeout_update(timeout_ret, hop_timeout);
			have_pending = true;
		} else {
			fm_log_debug("  %2u nothing is pending", ttl);
		}
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
fm_topo_state_select_ttl(fm_topo_state_t *topo, double *timeout_ret, fm_topo_hop_state_t **next_hop_ret)
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

		if (hop->probes_sent >= FM_RTT_SAMPLES_WANTED)
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
			double timeout, delay = fm_ratelimit_wait_until(hop->ratelimit, 1);

			fm_log_debug("  %2u delay=%f sec", ttl, delay);

			timeout = fm_time_now() + delay;
			if (*timeout_ret == 0 || timeout < *timeout_ret)
				*timeout_ret = timeout;
		}
	}

	have_pending = fm_topo_state_check_pending(topo, timeout_ret);

	if (topo->destination_ttl != 0) {
		/* We have reached the destination.
		 * If we have outstanding probes that reach further, cancel them right away.
		 */
		for (ttl = topo->destination_ttl + 1; ttl < max_ttl; ++ttl) {
			fm_topo_hop_state_t *hop = &topo->hop[ttl];

			if (fm_topo_hop_cancel_pending(hop))
				fm_log_debug("  %2u cancelled pending probe(s)", ttl);
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
fm_topo_state_send_probe(fm_topo_state_t *topo, fm_topo_hop_state_t *hop, double *timeout_ret)
{
	unsigned int ttl = hop->distance;
	fm_target_control_t fake_control = topo->_control;
	fm_extant_t *extant;
	fm_socket_t *sock;
	double timeout;
	fm_error_t error;

	assert(hop->probes_sent < FM_RTT_SAMPLES_WANTED);

	/* sock sharing is very sustainable. not very hygienic, but sustainable */
	if (topo->shared_socks == NULL) {
		abort();
	} else {
		sock = fm_topo_shared_socket_open(topo->shared_socks, ttl);
	}

	assert(sock->family == topo->host_address.ss_family);

	/* Overwrite the target control information with the socket for this TTL value, and
	 * the source address of this socket */
	fake_control.local_address = sock->local_address;
	fake_control.sock = sock;

	error = fm_multiprobe_transmit_ttl_probe(topo->packet_probe, &fake_control, ttl, &extant, &timeout);
	if (error != 0) {
		fm_log_error("fm_multiprobe_transmit_ttl_probe: %s", fm_strerror(error));
		hop->state = FM_ASSET_STATE_CLOSED;
		return error;
	}

	fm_topo_hop_add_extant(hop, extant, topo->packet_probe->timings.timeout);

	hop->next_send_time = 0;
	if (hop->probes_sent < FM_RTT_SAMPLES_WANTED)
		hop->next_send_time = fm_time_now() + topo->packet_probe->timings.packet_spacing;

	// hop->completion = fm_probe_wait_for_completion(probe, fm_topo_hop_probe_complete, hop);

	// fm_multiprobe_install_status_callback(topo->packet_probe, fm_topo_hop_probe_pkt_callback, hop);

	// error = fm_target_add_new_probe(topo->target, probe);

	/* Consume 1 token from the gateway rate limit */
	fm_ratelimit_consume(hop->ratelimit, 1);

	if (hop->probes_sent >= FM_RTT_SAMPLES_WANTED)
		hop->state = FM_ASSET_STATE_PROBE_SENT;

	/* The timeout values of this hop have changed; update the global timeout */
	fm_topo_hop_get_timeout(hop, timeout_ret);

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
fm_topo_shared_sockets_get(fm_protocol_t *packet_proto, const fm_address_t *dst_addr)
{
	static fm_topo_shared_sockets_t *shared_socks[64];
	static unsigned int nshared = 0;
	fm_routing_info_t rtinfo;
	fm_topo_shared_sockets_t *s;
	unsigned int i;
	int af;

	memset(&rtinfo, 0, sizeof(rtinfo));
	rtinfo.dst.network_address = *dst_addr;

	if (!fm_routing_lookup(&rtinfo)) {
		fm_log_error("traceroute: no route to %s", fm_address_format(dst_addr));
		return NULL;
	}

	af = dst_addr->ss_family;
	for (i = 0; i < nshared; ++i) {
		s = shared_socks[i];

		if (s->packet_proto == packet_proto && s->family == af && s->interface == rtinfo.nic) {
			s->refcount++;
			return s;
		}
	}

	assert(nshared < 64);

	s = calloc(1, sizeof(*s));
	s->refcount = 1;
	s->packet_proto = packet_proto;
	s->local_address = rtinfo.src.network_address;
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
		sock->trace = true;

		memset(&local_addr, 0, sizeof(local_addr));
		local_addr.ss_family = shared->family;
		if (!fm_socket_bind(sock, &shared->local_address))
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

static bool
fm_topo_process_extra_parameters(const fm_string_array_t *extra_args, fm_topo_extra_params_t *extra_params)
{
	unsigned int i;

	extra_params = calloc(1, sizeof(*extra_params));
	extra_params->packet_proto = "udp"; /* default */

	for (i = 0; i < extra_args->count; ++i) {
		const char *arg = extra_args->entries[i];
		const char *proto_name;
		unsigned int proto_id;

		if (fm_parse_string_argument(arg, "packet-proto", &proto_name)) {
			proto_id = fm_protocol_string_to_id(proto_name);
			if (proto_id == FM_PROTO_NONE) {
				fm_log_error("traceroute: Unknown protocol in %s", arg);
				return false;
			}
			extra_params->packet_proto = fm_protocol_id_to_string(proto_id);
		} else
		if (fm_parse_numeric_argument(arg, "max-depth", &extra_params->max_depth)
		 || fm_parse_numeric_argument(arg, "max-hole-size", &extra_params->max_hole_size)) {
			/* good to go */
		} else {
			fm_log_error("traceroute: unknown option %s", arg);
			return false;
		}
	}

	return true;
}

/*
 * New multiprobe implementation
 */
static bool
fm_topo_multiprobe_add_target(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_target_t *target)
{
	fm_target_control_t *target_control = &host_task->control;
	fm_topo_state_t *topo = multiprobe->control;
	fm_host_asset_t *host_asset;

	if (topo->target != NULL) {
		fm_log_error("%s: traceroute probe currently supports only one target at a time", multiprobe->name);
		return false;
	}

	if (!fm_topo_state_init_target(topo, target_control, target))
		return false;

	/* At the moment, traceroute is not multiprobe compliant */
	topo->_control = host_task->control;

	topo->host_address = target->address;

	host_asset = target->host_asset;
	if (host_asset != NULL) {
		fm_host_asset_clear_routing(host_asset, topo->family);
		fm_host_asset_update_state(host_asset, FM_ASSET_STATE_PROBE_SENT);
	}

	// if (topo->packet_proto->supported_parameters & FM_FEATURE_SOCKET_SHARING_MASK) {
	if (true) {
		topo->shared_socks = fm_topo_shared_sockets_get(topo->packet_proto, &target_control->address);

		/* Apply extra params if any */
	}

	return true;
}

static fm_error_t
fm_topo_multiprobe_transmit(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
		int param_type, int param_value,
		fm_extant_t **extant_ret, double *timeout_ret)
{
	fm_topo_state_t *topo = multiprobe->control;
	fm_topo_hop_state_t *hop;
	double timeout = 0;
	fm_error_t error;

	fm_log_debug("%s: traceroute ready to run", multiprobe->name);

	error = fm_topo_state_select_ttl(topo, &timeout, &hop);
	if (hop == NULL) {
		if (error == 0) {
			// fm_job_mark_complete(&multiprobe->job);
			/* Signal to the caller that this host is complete */
			error = FM_TASK_COMPLETE;
		} else
		if (error == FM_TIMED_OUT) {
			fm_log_debug("%s: no more hops, timed out", host_task->name);
		} else
		if (error == FM_TRY_AGAIN) {
			fm_log_debug("%s: come back in %f seconds", host_task->name, timeout - fm_time_now());
			*timeout_ret = timeout;
			assert(*timeout_ret);
		}

		if (error == FM_TASK_COMPLETE || error == FM_TIMED_OUT) {
			if (fm_debug_level >= 1)
				fm_topo_state_display(topo);
		}

		return error;
	}

	fm_log_debug("%s/ttl=%u: sending probe packet %u", multiprobe->name, hop->distance, hop->probes_sent);

	error = fm_topo_state_send_probe(topo, hop, &timeout);
	if (error == 0) {
		fm_topo_hop_state_t *next_hop;

		*timeout_ret = timeout;

		fm_ratelimit_consume(&host_task->target->host_rate_limit, 1);

		/* The traceroute multiprobe uses just one tasklet for the entire activity, rather than one
		 * for each probe packet (or one for each hop distance).
		 * So, we just return TRY_AGAIN and ask to be called back soon.
		 *
		 * However, when we do that, the caller will *not* consume any tokens from the
		 * rate limit of the target host - which is why we have to do it here. */
		error = fm_topo_state_select_ttl(topo, timeout_ret, &next_hop);
		if (error == 0) {
			fm_log_debug("%s: hop %u probe sent; hop %u ready to send", multiprobe->name, hop->distance, next_hop->distance);
			*timeout_ret = fm_time_now();
			error = FM_TRY_AGAIN;
		} else {
			assert(error == FM_TRY_AGAIN);
			fm_log_debug("%s: hop %u probe sent; come back in %f sec", multiprobe->name, hop->distance, timeout - fm_time_now());
		}
	}

	if (error == FM_TRY_AGAIN)
		assert(*timeout_ret);

	return error;
}

static void
fm_topo_multiprobe_destroy(fm_multiprobe_t *multiprobe)
{
	fm_topo_state_t *icmp = multiprobe->control;

	multiprobe->control = NULL;
	fm_topo_state_free(icmp);
}

static fm_multiprobe_ops_t	fm_topo_multiprobe_ops = {
	.add_target		= fm_topo_multiprobe_add_target,
	.transmit		= fm_topo_multiprobe_transmit,
	.destroy		= fm_topo_multiprobe_destroy,
};

static bool
fm_topo_configure_probe(const fm_probe_class_t *pclass, fm_multiprobe_t *multiprobe, const fm_string_array_t *extra_string_args)
{
	fm_topo_extra_params_t parsed_extra_params, *extra_params = NULL;
	fm_topo_state_t *topo;

	if (multiprobe->control != NULL) {
		fm_log_error("cannot reconfigure probe %s", multiprobe->name);
		return false;
	}

#ifdef notyet
	/* Set the default timings and retries */
	multiprobe->timings.packet_spacing = fm_global.traceroute.packet_spacing;
	multiprobe->timings.timeout = fm_global.traceroute.timeout;
	if (multiprobe->params.retries == 0)
		multiprobe->params.retries = fm_global.traceroute.retries;
#endif

	if (extra_string_args && extra_string_args->count) {
		memset(&parsed_extra_params, 0, sizeof(parsed_extra_params));
		if (!fm_topo_process_extra_parameters(extra_string_args, &parsed_extra_params))
			return false;

		extra_params = &parsed_extra_params;
	}

	topo = fm_topo_state_alloc(pclass->proto, &multiprobe->params, extra_params);
	if (topo == NULL)
		return false;

	multiprobe->ops = &fm_topo_multiprobe_ops;
	multiprobe->control = topo;

	return true;
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

	.configure	= fm_topo_configure_probe,
};

FM_PROBE_CLASS_REGISTER(fm_traceroute_host_probe_class)
