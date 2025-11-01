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
 * Scanning IP protocols
 */

#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "scanner.h"
#include "protocols.h"
#include "wellknown.h"
#include "target.h" /* for fm_probe_t */
#include "socket.h"
#include "rawpacket.h"
#include "buffer.h"
#include "utils.h"

typedef struct fm_ipproto_request {
	fm_protocol_t *		proto;
	fm_target_t *		target;

	fm_socket_t *		sock;
	bool			sock_is_shared;

	int			family;
	fm_address_t		host_address;
	fm_probe_params_t	params;

	fm_ip_info_t		ip;
	fm_routing_info_t	rtinfo;

	bool			wait_for_ndisc;
} fm_ipproto_request_t;

typedef struct fm_ipproto_extant_info {
	unsigned int		proto;
} fm_ipproto_extant_info_t;

static fm_socket_t *	fm_ipproto_create_socket(fm_protocol_t *proto, int ipproto);
static bool		fm_ipproto_process_error(fm_protocol_t *proto, fm_pkt_t *pkt);

static fm_ipproto_request_t *fm_ipproto_probe_get_request(const fm_probe_t *probe);
static void		fm_ipproto_probe_set_request(fm_probe_t *probe, fm_ipproto_request_t *req);

static struct fm_protocol	fm_ipproto_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "ipproto",
	.require_raw	= true,
	.id		= FM_PROTO_IP,

	.create_socket	= fm_ipproto_create_socket,
	/* We do not expect to receive a response, so no response handler for now */
	.process_error	= fm_ipproto_process_error,
};

FM_PROTOCOL_REGISTER(fm_ipproto_ops);

static fm_socket_t *
fm_ipproto_create_socket(fm_protocol_t *proto, int ipproto)
{
	return NULL;
}

static fm_socket_t *
fm_rawip_create_socket(fm_protocol_t *proto, const fm_address_t *addr)
{
	fm_address_t lladdr = *addr;
	fm_socket_t *sock;

	if (lladdr.ss_family != AF_PACKET)
		return NULL;

	((struct sockaddr_ll *) &lladdr)->sll_protocol = htons(ETH_P_IP);

	sock = fm_raw_socket_get(&lladdr, proto, SOCK_RAW);
	if (sock == NULL)
		return NULL;

	fm_socket_enable_recverr(sock);

	return sock;
}

/*
 * IPPROTO action
 */
static void
fm_ipproto_request_free(fm_ipproto_request_t *req)
{
	/* beware, do not free the socket; it's shared globally */
	free(req);
}

static fm_ipproto_request_t *
fm_ipproto_request_alloc(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_ipproto_request_t *req;

	if (target->address.ss_family != AF_INET) {
		fm_log_error("Cannot implement ipproto probe for %s: not supported",
				fm_address_format(&target->address));
		return NULL;
	}

	if (params->port == 0) {
		fm_log_error("%s: trying to create a req request without destination port");
		return NULL;
	}

	req = calloc(1, sizeof(*req));
	req->proto = proto;
	req->target = target;
	req->params = *params;

	if (req->params.retries == 0)
		req->params.retries = 3; /* fm_global.ipproto.retries; */

	req->family = target->address.ss_family;
	req->host_address = target->address;

	req->ip.src_addr = target->local_bind_address;
	req->ip.dst_addr = target->address;

	/* it's not a port, it's a proto */
	req->ip.ipproto = params->port;

	memset(&req->rtinfo, 0, sizeof(req->rtinfo));

	req->rtinfo.dst.network_address = req->host_address;
	if (!fm_routing_lookup(&req->rtinfo)) {
		fm_ipproto_request_free(req);
		return NULL;
	}

	if (req->rtinfo.incomplete_neighbor_entry) {
		if (!fm_neighbor_initiate_discovery(req->rtinfo.incomplete_neighbor_entry)) {
			fm_log_error("%s: neighbor discovery failed", fm_address_format(&target->address));
			fm_ipproto_request_free(req);
			return NULL;
		}
		req->wait_for_ndisc = true;
	}

	return req;
}

static void
fm_ipproto_request_set_socket(fm_ipproto_request_t *req, fm_socket_t *sock)
{
	req->sock = sock;
	req->sock_is_shared = true;
}

/*
 * Do the scheduling
 */
static fm_error_t
fm_ipproto_request_schedule(fm_ipproto_request_t *req, struct timeval *expires)
{
	if (req->params.retries == 0)
		return FM_TIMED_OUT;

	/* After sending the last probe, we wait until the full timeout has expired.
	 * For any earlier probe, we wait for the specified packet spacing */
	if (req->params.retries == 1)
		fm_timestamp_set_timeout(expires, 1000);
	else
		fm_timestamp_set_timeout(expires, 250);
	return 0;
}


static fm_pkt_t *
fm_ipproto_build_proto_probe(fm_ipproto_request_t *req)
{
	fm_routing_info_t *rtinfo = &req->rtinfo;
	fm_pkt_t *pkt;
	fm_buffer_t *bp;

	if (rtinfo->dst.network_address.ss_family != AF_INET)
		return NULL;

	/* should be plenty */
	bp = fm_buffer_alloc(1500);

	if (!fm_raw_packet_add_link_header(bp, &rtinfo->src.link_address, &rtinfo->nh.link_address)
	 || !fm_raw_packet_add_network_header(bp, &rtinfo->src.network_address, &rtinfo->nh.network_address,
		 	req->ip.ipproto, 64, 0,
			44)) {
		fm_buffer_free(bp);
		return NULL;
	}

	/* put random trash into payload, we don't care */
	memset(fm_buffer_push(bp, 44), 0, 44);

	pkt = fm_pkt_alloc(req->family, 0);
	pkt->peer_addr = rtinfo->nh.link_address;
	pkt->payload = bp;

	return pkt;
}

static bool
fm_ipproto_request_event_handler(fm_ipproto_request_t *req, fm_event_t event)
{
	if (event != FM_EVENT_ID_NEIGHBOR_CACHE)
		return false;

	/* This does not do another full routing lookup, it just checks
	 * whether the neighbor discovery completed.
	 * NB, discovery may have failed, and we need to check for that in
	 * the send() function.
	 */
	return fm_routing_lookup_complete(&req->rtinfo);
}

static fm_error_t
fm_ipproto_request_send(fm_ipproto_request_t *req, fm_ipproto_extant_info_t *extant_info)
{
	fm_routing_info_t *rtinfo = &req->rtinfo;
	fm_ip_info_t *ip = &req->ip;
	fm_pkt_t *pkt;

	if (rtinfo->nh.link_address.ss_family == AF_UNSPEC) {
		fm_log_error("%s: neighbor discovery failed",
				fm_address_format(&ip->dst_addr));
		return FM_SEND_ERROR;
	}

	/* This creates a globally shared socket. */
	if (req->sock == NULL) {
		req->sock = fm_rawip_create_socket(req->proto, &rtinfo->nh.link_address);
		if (req->sock == NULL) {
			fm_log_error("Unable to create packet socket for %s: %m",
					fm_address_format(&ip->dst_addr));
			return FM_SEND_ERROR;
		}
	}

	if (!(pkt = fm_ipproto_build_proto_probe(req))) {
		fm_log_error("Unable to build IP proto probe");
		return FM_SEND_ERROR;
	}

	if (fm_debug_level) {
		struct sockaddr_ll *lladdr = fm_address_to_link(&rtinfo->nh.link_address);
		const fm_interface_t *nic;
		fm_buffer_t *bp = pkt->payload;

		assert(lladdr != NULL);
		nic = fm_interface_by_index(lladdr->sll_ifindex);
		fm_log_debug("About to send raw packet via %s", fm_interface_get_name(nic));
		fm_print_hexdump(bp->data, bp->wpos);
	}

	if (!fm_socket_send_pkt_and_burn(req->sock, pkt)) {
		fm_log_error("Unable to send IP proto probe: %m");
		return FM_SEND_ERROR;
	}

	/* update the asset state */
	fm_target_update_host_state(req->target, FM_PROTO_IP, FM_ASSET_STATE_PROBE_SENT);

	req->params.retries -= 1;
	return 0;
}


/*
 * Track extant IP proto requests.
 * We currently do not track individual packets and their response(s), we just
 * record the fact that we *did* send a specific protocol probe to a target.
 * We do not even distinguish by the source port used on our end.
 */
static fm_extant_t *
fm_ipproto_locate_probe(fm_protocol_t *proto, fm_pkt_t *pkt, fm_asset_state_t state)
{
	fm_target_t *target;
	hlist_iterator_t iter;
	int ipproto;

	ipproto = 5;

	target = fm_target_pool_find(&pkt->peer_addr);
	if (target == NULL)
		return NULL;

	fm_target_update_host_state(target, FM_PROTO_IP, state);

	fm_extant_iterator_init(&iter, &target->expecting);
	return fm_extant_iterator_match(&iter, pkt->family, ipproto);
}

static bool
fm_ipproto_process_error(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant;

	extant = fm_ipproto_locate_probe(proto, pkt, FM_ASSET_STATE_CLOSED);
	if (extant != NULL) {
		fm_extant_received_error(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

/*
 * ipproto probes
 */
struct fm_ipproto_host_probe {
	fm_probe_t		base;
	fm_ipproto_request_t *	request;
};

static fm_error_t
fm_ipproto_host_probe_schedule(fm_probe_t *probe)
{
	fm_ipproto_request_t *req;

	req = fm_ipproto_probe_get_request(probe);
	if (req == NULL)
		return FM_NOT_SUPPORTED;

	return fm_ipproto_request_schedule(req, &probe->expires);
}


static fm_error_t
fm_ipproto_host_probe_send(fm_probe_t *probe)
{
	fm_ipproto_request_t *req;
	fm_ipproto_extant_info_t extant_info;
	fm_error_t error;

	if (!(req = fm_ipproto_probe_get_request(probe)))
		return FM_NOT_SUPPORTED;

	error = fm_ipproto_request_send(req, &extant_info);
	if (error == 0)
		fm_extant_alloc(probe, req->family, req->ip.ipproto, NULL, 0);

	return error;
}

#if 0
static fm_error_t
fm_ipproto_host_probe_send(fm_probe_t *probe)
{
	struct fm_ipproto_host_probe *ipprobe = (struct fm_ipproto_host_probe *) probe;
	fm_routing_info_t *rtinfo = &ipprobe->rtinfo;
	fm_ip_info_t *ip = &ipprobe->ip;
	fm_socket_t *sock;
	fm_buffer_t *bp;

	if (rtinfo->nh.link_address.ss_family == AF_UNSPEC) {
		fm_log_error("%s: neighbor discovery failed",
				fm_address_format(&ip->dst_addr));
		return FM_SEND_ERROR;
	}

	sock = fm_rawip_create_socket(probe->proto, &rtinfo->nh.link_address);
	if (sock == NULL) {
		fm_log_error("Unable to create packet socket for %s: %m",
				fm_address_format(&ip->dst_addr));
		return FM_SEND_ERROR;
	}

	if (!(bp = fm_ipproto_build_proto_probe(rtinfo, ip->ipproto))) {
		fm_log_error("Unable to build IP proto probe");
		return FM_SEND_ERROR;
	}

	if (fm_debug_level) {
		struct sockaddr_ll *lladdr = fm_address_to_link(&rtinfo->nh.link_address);
		const fm_interface_t *nic;

		assert(lladdr != NULL);
		nic = fm_interface_by_index(lladdr->sll_ifindex);
		fm_log_debug("About to send raw packet via %s", fm_interface_get_name(nic));
		fm_print_hexdump(bp->data, bp->wpos);
	}

	if (!fm_socket_send(sock, &rtinfo->nh.link_address, bp->data, bp->wpos)) {
		fm_log_error("Unable to send IP proto probe: %m");
		return FM_SEND_ERROR;
	}

	fm_ipproto_expect_response(probe, rtinfo->dst.network_address.ss_family, ip->ipproto);

	/* update the asset state */
	fm_target_update_host_state(probe->target, FM_PROTO_IP, FM_ASSET_STATE_PROBE_SENT);

	ipprobe->send_retries -= 1;

	return 0;
}
#endif

/*
 * Event handling callback
 */
static bool
fm_ipproto_event_handler(fm_probe_t *probe, fm_event_t event)
{
	fm_ipproto_request_t *req;

	req = fm_ipproto_probe_get_request(probe);
	if (req == NULL)
		return false;

	return fm_ipproto_request_event_handler(req, event);
}

static fm_error_t
fm_ipproto_host_probe_set_socket(fm_probe_t *probe, fm_socket_t *sock)
{
	fm_ipproto_request_t *req = fm_ipproto_probe_get_request(probe);

	if (req == NULL)
		return FM_NOT_SUPPORTED;

	fm_ipproto_request_set_socket(req, sock);
	return 0;
}

static void
fm_ipproto_host_probe_destroy(fm_probe_t *probe)
{
	fm_ipproto_probe_set_request(probe, NULL);
}

static struct fm_probe_ops fm_ipproto_host_probe_ops = {
	.obj_size	= sizeof(struct fm_ipproto_host_probe),
	.name 		= "ipproto",

	.destroy	= fm_ipproto_host_probe_destroy,
	.send		= fm_ipproto_host_probe_send,
	.schedule	= fm_ipproto_host_probe_schedule,
	.set_socket	= fm_ipproto_host_probe_set_socket,
};

static fm_ipproto_request_t *
fm_ipproto_probe_get_request(const fm_probe_t *probe)
{
	if (probe->ops != &fm_ipproto_host_probe_ops)
		return NULL;

	return ((struct fm_ipproto_host_probe *) probe)->request;
}

static void
fm_ipproto_probe_set_request(fm_probe_t *probe, fm_ipproto_request_t *req)
{
	struct fm_ipproto_host_probe *ipproto_probe;

	if (probe->ops != &fm_ipproto_host_probe_ops)
		return;

	ipproto_probe = (struct fm_ipproto_host_probe *) probe;
	if (ipproto_probe->request != NULL)
		fm_ipproto_request_free(ipproto_probe->request);
	ipproto_probe->request = req;
}


static fm_probe_t *
fm_ipproto_create_host_probe(fm_probe_class_t *pclass, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_protocol_t *proto = pclass->proto; /* this is just a dummy for now until we have a real rawip protocol */
	fm_ipproto_request_t *req;
	fm_probe_t *probe;
	char name[32];

	req = fm_ipproto_request_alloc(proto, target, params, extra_params);
	if (req == NULL)
		return NULL;

	snprintf(name, sizeof(name), "req/port=%u,ttl=%u", params->port, params->ttl);
	probe = fm_probe_alloc(name, &fm_ipproto_host_probe_ops, target);
	fm_ipproto_probe_set_request(probe, req);

	if (req->wait_for_ndisc)
		fm_probe_wait_for_event(probe, fm_ipproto_event_handler, FM_EVENT_ID_NEIGHBOR_CACHE);

	fm_log_debug("Created IP protocol socket probe for %s\n", fm_address_format(&req->host_address));
	return probe;
}

static struct fm_probe_class fm_ipproto_host_probe_class = {
	.name		= "ipproto",
	.proto_id	= FM_PROTO_IP,
	.modes		= FM_PROBE_MODE_HOST,
	.create_probe	= fm_ipproto_create_host_probe,
};

FM_PROBE_CLASS_REGISTER(fm_ipproto_host_probe_class)
