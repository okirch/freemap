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

#include <netinet/ip_icmp.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "fakenet.h"
#include "rawpacket.h"
#include "packet.h"
#include "buffer.h"
#include "logging.h"


static double		fm_fake_host_delay(const fm_fake_host_t *host);
static double		fm_fake_router_delay(const fm_fake_router_t *router);

void
fm_fake_response_free(fm_fake_response_t *resp)
{
	hlist_remove(&resp->link);
	fm_buffer_free(resp->packet);
	free(resp);
}

static fm_fake_response_t *
fm_fake_host_prepare_response(fm_fake_host_t *host, const fm_ip_header_info_t *ip, unsigned int transport_len, fm_ip_header_info_t *reply_info)
{
	fm_fake_response_t *resp;
	fm_buffer_t *reply;

	memset(reply_info, 0, sizeof(*reply_info));
	reply_info->src_addr = ip->dst_addr;
	reply_info->dst_addr = ip->src_addr;
	reply_info->ipproto = ip->ipproto;
	reply_info->ttl = 64;
	reply_info->tos = 0;

	reply = fm_buffer_alloc(128);
	reply->rpos = reply->wpos = 4;

	if (!fm_raw_packet_add_ip_header(reply, reply_info, transport_len)) {
		fm_buffer_free(reply);
		return NULL;
	}

	resp = calloc(1, sizeof(*resp));
	resp->when = fm_time_now() + fm_fake_host_delay(host);
	resp->packet = reply;

	return resp;
}

static fm_fake_response_t *
fm_fake_router_prepare_response(fm_fake_router_t *router, const fm_ip_header_info_t *ip, unsigned int transport_len, fm_ip_header_info_t *reply_info)
{
	fm_fake_response_t *resp;
	fm_buffer_t *reply;

	memset(reply_info, 0, sizeof(*reply_info));

	if (ip->src_addr.family == AF_INET) {
		reply_info->src_addr = router->ipv4_address;
		reply_info->ipproto = IPPROTO_ICMP;
	} else if (ip->src_addr.family == AF_INET6) {
		reply_info->src_addr = router->ipv6_address;
		reply_info->ipproto = IPPROTO_ICMPV6;
	}

	if (reply_info->src_addr.family == AF_UNSPEC)
		return NULL;

	reply_info->dst_addr = ip->src_addr;
	reply_info->ttl = 64;
	reply_info->tos = 0;

	reply = fm_buffer_alloc(128);
	reply->rpos = reply->wpos = 4;

	if (!fm_raw_packet_add_ip_header(reply, reply_info, transport_len)) {
		fm_buffer_free(reply);
		return NULL;
	}

	resp = calloc(1, sizeof(*resp));
	resp->when = fm_time_now() + fm_fake_router_delay(router);
	resp->packet = reply;

	return resp;
}

static fm_fake_response_t *
fm_fake_host_receive_icmp(fm_fake_host_t *host, fm_parsed_pkt_t *cooked, const fm_ip_header_info_t *ip, const fm_icmp_header_info_t *icmp, fm_buffer_t *payload)
{
	fm_fake_response_t *resp;
	fm_ip_header_info_t ip_reply_info;
	fm_icmp_header_info_t icmp_reply_info;
	fm_icmp_msg_type_t *reply_type;
	unsigned int transport_len = 0;

	if (icmp->msg_type == NULL) {
		fm_log_debug("   unidentified ICMP packet");
		return NULL;
	}

	fm_log_debug("   ICMP %s packet", icmp->msg_type->desc);

	reply_type = fm_icmp_msg_type_get_reply(icmp->msg_type);
	if (reply_type == NULL)
		return NULL;

	/* For now, all I can do is ping */
	if (reply_type->v4_type != ICMP_ECHOREPLY)
		return NULL;

	/* We know we could send a response now. But should we? */
	fm_ratelimit_update(&host->icmp_rate);
	if (!fm_ratelimit_okay(&host->icmp_rate)) {
		fm_log_debug("   dropped due to rate limit.");
		return NULL;
	}

	transport_len = 8 + fm_buffer_available(payload);

	resp = fm_fake_host_prepare_response(host, ip, transport_len, &ip_reply_info);
	if (resp == NULL)
		return NULL;

	icmp_reply_info = *icmp;
	icmp_reply_info.msg_type = reply_type;

	if (!fm_raw_packet_add_icmp_header(resp->packet, &icmp_reply_info, &ip_reply_info, payload)) {
		fm_fake_response_free(resp);
		return NULL;
	}

	return resp;
}

static fm_fake_response_t *
fm_fake_host_receive(fm_fake_host_t *host, fm_parsed_pkt_t *cooked, const fm_ip_header_info_t *ip, fm_buffer_t *payload)
{
	fm_parsed_hdr_t *hdr;

	if (!(hdr = fm_parsed_packet_next_header(cooked)))
		return NULL; /* no next protocol that we'd understand; or just an IPv6 packet with extension headers */

	switch (hdr->proto_id) {
	case FM_PROTO_ICMP:
		return fm_fake_host_receive_icmp(host, cooked, ip, &hdr->icmp, payload);
	}

	return NULL;
}

/*
 * Router sends an ICMP error
 */
static fm_fake_response_t *
fm_fake_router_send_error(fm_fake_router_t *router, fm_icmp_msg_type_t *error_type, const fm_parsed_hdr_t *hdr)
{
	unsigned int snap_len;
	fm_buffer_t *snap_buf;
	fm_fake_response_t *resp;
	fm_ip_header_info_t ip_reply_info;
	fm_icmp_header_info_t icmp_reply_info = { 0 };

	if (error_type == NULL) {
		fm_log_error("%s: icmp message type is NULL", __func__);
		return NULL;
	}

	fm_log_debug("  %s to send %s error", router->config.name, error_type->desc);

	/* According to RFC, the original IP header + 64 bits of transport stuff */
	snap_len = hdr->raw.hdr_len + 8;
	if (snap_len > hdr->raw.tot_len)
		snap_len = hdr->raw.tot_len;

	resp = fm_fake_router_prepare_response(router, &hdr->ip, 8 + snap_len, &ip_reply_info);
	if (resp == NULL)
		return NULL;

	snap_buf = fm_buffer_alloc(snap_len);
	fm_buffer_append(snap_buf, hdr->raw.data, snap_len);

	icmp_reply_info.msg_type = error_type;
	if (!fm_raw_packet_add_icmp_header(resp->packet, &icmp_reply_info, &ip_reply_info, snap_buf)) {
		fm_fake_response_free(resp);
		fm_buffer_free(snap_buf);
		return NULL;
	}

	fm_buffer_free(snap_buf);

	return resp;
}

/*
 * We received a traceroute packet, and the TTL was not large enough to reach the destination
 * host.
 * The router argument passed to us is the ingress router of the destination network.
 */
static fm_fake_response_t *
fm_fake_router_ttl_exceeded(fm_fake_router_t *router, fm_parsed_pkt_t *cooked, const fm_parsed_hdr_t *hdr, fm_buffer_t *payload)
{
	const fm_ip_header_info_t *ip = &hdr->ip;
	unsigned int ttl = ip->ttl;
	fm_icmp_msg_type_t *error_type;

	while (ttl < router->ttl && router)
		router = router->prev;

	if (router == NULL) {
		fm_log_warning("Weird, we do not seem to have a router for ttl %u", ttl);
		return NULL;
	}

	/* In theory, we should modify the incoming IP header and set its TTL to 1,
	 * plus update the checksum, yadda yadda yadda. Does anyone care? */
	error_type = fm_icmp_msg_type_by_name("ttl-exceeded");
	return fm_fake_router_send_error(router, error_type, hdr);
}

/*
 * Compute a delay that emulates the rtt along the path
 */
static double
fm_fake_router_delay(const fm_fake_router_t *router)
{
	unsigned int nstd = 0;

	for (; router; router = router->prev) {
		if (router->link_delay) {
			abort();
		} else {
			nstd += 2;
		}
	}

	/* Standard link delay is 1ms, sigma = .1ms */
	return fm_n_gaussians(nstd, 1e-3, 5e-4);
}

static double
fm_fake_host_delay(const fm_fake_host_t *host)
{
	double delay = 0;

	/* Delay on the target network: mu = 0.1ms, sigma = 0.05ms */
	delay = fm_n_gaussians(2, 1e-4, 5e-5);

	delay += fm_fake_router_delay(host->network->router);

	return delay;
}

fm_fake_response_t *
fm_fakenet_process_packet(fm_parsed_pkt_t *cooked, const fm_fake_config_t *config, fm_buffer_t *payload)
{
	fm_parsed_hdr_t *hdr;
	fm_fake_network_t *net;
	fm_fake_host_t *host;

	if (!(hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_IP)))
		return NULL;

	net = fm_fake_config_get_network_by_addr(config, &hdr->ip.dst_addr);
	if (net == NULL)
		return NULL; /* We don't know you. FIXME: we should provide more realistic routing. */

	/* TBD: perform filtering along the way */

	if (hdr->ip.ttl <= net->router->ttl) {
		/* find the proper router, send time exceeded */
		return fm_fake_router_ttl_exceeded(net->router, cooked, hdr, payload);
	}

	host = fm_fake_network_get_host_by_addr(net, &hdr->ip.dst_addr);
	if (host == NULL)
		return NULL;

	fm_log_debug("packet to %s (net %s)", host->name, host->network->name);

	/* TBD: perform filtering at the host */

	return fm_fake_host_receive(host, cooked, &hdr->ip, payload);
}

