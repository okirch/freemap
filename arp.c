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

#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "freemap.h"
#include "protocols.h"
#include "target.h"
#include "scanner.h"
#include "rawpacket.h"
#include "socket.h"
#include "logging.h"
#include "utils.h"

typedef struct fm_arp_control {
	fm_protocol_t *		proto;
	fm_socket_t *		sock;

	fm_probe_params_t	params;
} fm_arp_control_t;

typedef struct fm_arp_extant_info {
	struct in_addr		dst_addr;
} fm_arp_extant_info_t;

static void		get_eth_address(const struct sockaddr_ll *, unsigned char *, unsigned int);

static fm_socket_t *	fm_arp_create_socket(fm_protocol_t *proto, int ipproto);
static fm_extant_t *	fm_arp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_arp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);

static void		fm_arp_update_cache(const fm_arp_header_info_t *arp_info, fm_extant_t *extant, int ifindex);

/* Global extant map for all ARP related stuff */
static fm_extant_map_t fm_arp_extant_map = FM_EXTANT_MAP_INIT;

static struct fm_protocol	fm_arp_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "arp",
	.id		= FM_PROTO_ARP,

	.supported_parameters = FM_PARAM_TYPE_RETRIES_MASK,

	.create_socket	= fm_arp_create_socket,

	.locate_error	= fm_arp_locate_error,
	.locate_response= fm_arp_locate_response,
};

FM_PROTOCOL_REGISTER(fm_arp_ops);

static fm_socket_t *
fm_arp_create_socket(fm_protocol_t *proto, int dummy)
{
	/* We probably never get here */
	return fm_socket_create(PF_PACKET, SOCK_DGRAM, ntohs(ETH_P_ARP), proto);
}

/*
 * ARP request object
 */
static void
fm_arp_control_free(fm_arp_control_t *arp)
{
	free(arp);
}

static fm_arp_control_t *
fm_arp_control_alloc(fm_protocol_t *proto, const fm_probe_params_t *params, const void *extra_params)
{
	fm_arp_control_t *arp;

	arp = calloc(1, sizeof(*arp));
	arp->proto = proto;
	arp->params = *params;

	if (arp->params.retries == 0)
		arp->params.retries = FM_ARP_PROBE_RETRIES;

	return arp;
}

static bool
fm_arp_control_init_target(const fm_arp_control_t *arp, fm_target_control_t *target_control, fm_target_t *target)
{
	uint32_t src_ipaddr, dst_ipaddr;
	struct sockaddr_ll src_lladdr;

	if (!fm_address_get_ipv4(&target_control->local_address, &src_ipaddr)
	 || !fm_address_get_ipv4(&target_control->address, &dst_ipaddr)
	 || !fm_interface_get_lladdr(target->local_device, &src_lladdr)) {
		fm_log_error("%s: cannot create ARP probe: incompatible address family",
				fm_address_format(&target->address));
		return false;
	}

	if (src_lladdr.sll_ifindex == 0) {
		fm_log_error("Cannot create ARP probe on %s: NIC address lacks ifindex: %s",
				fm_interface_get_name(target->local_device),
				fm_address_format((fm_address_t *) &src_lladdr));
		return false;
	}

	target_control->target = target;
	target_control->family = AF_PACKET;

	target_control->arp.dst_ipaddr = dst_ipaddr;
	target_control->arp.src_ipaddr = src_ipaddr;
	target_control->arp.src_lladdr = src_lladdr;
	return true;
}

/*
 * Helper functions.
 * We may want to promote them to fm_address_*() one day
 */
void
get_eth_address(const struct sockaddr_ll *lladdr, unsigned char *eth_addr, unsigned int size)
{
	if (lladdr->sll_family != AF_PACKET
	 || lladdr->sll_hatype != ARPHRD_ETHER
	 || lladdr->sll_halen != size) {
		memset(eth_addr, 0, size);
	} else {
		memcpy(eth_addr, lladdr->sll_addr, size);
	}
}

/*
 * For now, we only do ethernet
 */
static unsigned int
fm_arp_build_request(const fm_target_control_t *target_control, unsigned char *buf, size_t bufsz)
{
	struct arphdr *arp;
	unsigned char *ap;

	memset(buf, 0, bufsz);
	if (bufsz < sizeof(*arp) + 8 + 2 * ETH_ALEN)
		return 0;

	arp = (struct arphdr *) buf;
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op  = htons(ARPOP_REQUEST);

	ap = (unsigned char *) (arp + 1);

	get_eth_address(&target_control->arp.src_lladdr, ap, ETH_ALEN);
	ap += ETH_ALEN;

	memcpy(ap, &target_control->arp.src_ipaddr, 4);
	ap += 4;

	get_eth_address(&target_control->arp.dst_lladdr, ap, ETH_ALEN);
	ap += ETH_ALEN;

	memcpy(ap, &target_control->arp.dst_ipaddr, 4);
	ap += 4;

	return ap - buf;
}

/*
 * ARP request/reply matching
 */
static void
fm_arp_extant_info_build(fm_target_control_t *target_control, fm_arp_extant_info_t *extant_info)
{
	extant_info->dst_addr.s_addr = target_control->arp.dst_ipaddr;
}

static fm_extant_t *
fm_arp_locate_common(fm_pkt_t *pkt, const struct in_addr *dst_ipaddr, hlist_iterator_t *iter)
{
	fm_extant_t *extant;
	fm_address_t peer_addr;
	fm_host_asset_t *host;

	/* Look up the host asset.
	 * It's possible that we do not have this host assset mapped.
	 * This happens with discovery probes, for instance, or ARP lookups initiated
	 * by the neighbor cache.
	 */
	fm_address_set_raw_addr(&peer_addr, AF_INET, (const unsigned char *) dst_ipaddr, sizeof(*dst_ipaddr));
	host = fm_host_asset_get_active(&peer_addr);
	if (host != NULL)
		fm_host_asset_update_state(host, FM_ASSET_STATE_OPEN);

	while ((extant = fm_extant_iterator_match(iter, pkt->family, IPPROTO_UDP)) != NULL) {
		const fm_arp_extant_info_t *info = (fm_arp_extant_info_t *) (extant + 1);

		if (info->dst_addr.s_addr == dst_ipaddr->s_addr)
			return extant;
	}

	return NULL;
}

static fm_extant_t *
fm_arp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	return NULL;
}

static fm_extant_t *
fm_arp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	fm_parsed_pkt_t *cooked;
	fm_parsed_hdr_t *hdr;
	fm_extant_t *extant;

	if ((cooked = pkt->parsed) == NULL)
		return NULL;

	/* Then, look at the enclosed ARP header */
	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_ARP)) == NULL)
		return NULL;

	fm_log_debug("ARP packet op=%d from %s", hdr->arp.op, inet_ntoa(hdr->arp.src_ipaddr));
	if (hdr->arp.op != ARPOP_REPLY)
		return NULL;

	extant = fm_arp_locate_common(pkt, &hdr->arp.src_ipaddr, iter);

	/* See if we can update our local neighbor cache */
	if (extant != NULL) {
		const struct sockaddr_ll *sll = fm_address_to_link(&pkt->peer_addr);

		fm_arp_update_cache(&hdr->arp, extant, sll->sll_ifindex);
	}

	return extant;
}

static void
fm_arp_update_cache(const fm_arp_header_info_t *arp_info, fm_extant_t *extant, int ifindex)
{
	struct sockaddr_ll lladdr;

	if (ifindex <= 0) {
		fm_log_warning("Can't update ARP cache; no idea what the ifindex is");
		return;
	}

	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_hatype = ARPHRD_ETHER;
	lladdr.sll_halen = ETH_ALEN;
	lladdr.sll_protocol = htons(ETH_P_IP);
	lladdr.sll_ifindex = ifindex;
	memcpy(lladdr.sll_addr, arp_info->src_hwaddr, ETH_ALEN);

	fm_local_cache_arp_entry(arp_info->src_ipaddr.s_addr, (fm_address_t *) &lladdr);
}

static fm_error_t
fm_arp_control_send(const fm_arp_control_t *arp, fm_target_control_t *target_control, fm_extant_t **extant_ret)
{
	fm_arp_extant_info_t extant_info;
	fm_target_t *target = target_control->target;
	struct sockaddr_ll src_lladdr, eth_bcast;
	fm_socket_t *sock;
	unsigned char pktbuf[128];
	size_t pktlen;

	/* The src_lladdr is used to locate the appropriate PF_PACKET socket;
	 * so we need to tell it what protocol we want. */
	src_lladdr = target_control->arp.src_lladdr;
	((struct sockaddr_ll *) &src_lladdr)->sll_protocol = htons(ETH_P_ARP);

	sock = fm_raw_socket_get((fm_address_t *) &src_lladdr, arp->proto, SOCK_DGRAM);
	if (sock == NULL) {
		fm_log_error("Unable to create ARP socket for %s",
				fm_address_format(&target->address));
		return FM_SEND_ERROR;
	}

	if (sock->extant_map == NULL)
		fm_socket_attach_extant_map(sock, &fm_arp_extant_map);

	pktlen = fm_arp_build_request(target_control, pktbuf, sizeof(pktbuf));
	if (pktlen == 0) {
		fm_log_error("Don't know how to build ARP packet");
		return FM_SEND_ERROR;
	}

	fm_arp_extant_info_build(target_control, &extant_info);

	eth_bcast = target_control->arp.src_lladdr;
	eth_bcast.sll_pkttype = PACKET_BROADCAST;
	eth_bcast.sll_protocol = htons(ETH_P_ARP);
	memset(eth_bcast.sll_addr, 0xFF, ETH_ALEN);

	if (!fm_socket_send(sock, (fm_address_t *) &eth_bcast, pktbuf, pktlen)) {
		fm_log_error("Unable to send ARP packet: %m");
		return FM_SEND_ERROR;
	}

	*extant_ret = fm_socket_add_extant(sock, NULL, AF_PACKET, ETH_P_IP,
			&extant_info, sizeof(extant_info));

	/* Update the asset state */
	fm_target_update_host_state(target, FM_PROTO_ARP, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

/*
 * New multiprobe implementation
 */
static bool
fm_arp_multiprobe_add_target(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_target_t *target)
{
	const fm_arp_control_t *arp = multiprobe->control;

	return fm_arp_control_init_target(arp, &host_task->control, target);
}

static fm_error_t
fm_arp_multiprobe_transmit(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
			int param_type, int param_value,
			fm_extant_t **extant_ret, double *timeout_ret)
{
	const fm_arp_control_t *arp = multiprobe->control;
	fm_target_control_t *target_control = &host_task->control;

	return fm_arp_control_send(arp, target_control, extant_ret);
}

static void
fm_arp_multiprobe_destroy(fm_multiprobe_t *multiprobe)
{
	fm_arp_control_t *arp = multiprobe->control;

	multiprobe->control = NULL;
	fm_arp_control_free(arp);
}

static fm_multiprobe_ops_t	fm_arp_multiprobe_ops = {
	.add_target		= fm_arp_multiprobe_add_target,
	.transmit		= fm_arp_multiprobe_transmit,
	.destroy		= fm_arp_multiprobe_destroy,
};

static bool
fm_arp_configure_probe(const fm_probe_class_t *pclass, fm_multiprobe_t *multiprobe, const fm_string_array_t *extra_string_args)
{
	fm_arp_control_t *arp;

	if (multiprobe->control != NULL) {
		fm_log_error("cannot reconfigure probe %s", multiprobe->name);
		return false;
	}

	/* Set the default timings and retries */
	multiprobe->timings.packet_spacing = fm_global.arp.packet_spacing * 1e-3;
	multiprobe->timings.timeout = fm_global.arp.timeout * 1e-3;
	if (multiprobe->params.retries == 0)
		multiprobe->params.retries = fm_global.arp.retries;

	if (extra_string_args && extra_string_args->count != 0) {
		fm_log_error("%s: found unsupported extra parameters", multiprobe->name);
		return false;
	}

	arp = fm_arp_control_alloc(pclass->proto, &multiprobe->params, NULL);
	if (arp == NULL)
		return false;

	multiprobe->ops = &fm_arp_multiprobe_ops;
	multiprobe->control = arp;
	return true;
}

static struct fm_probe_class fm_arp_host_probe_class = {
	.name		= "arp",
	.family		= AF_INET,
	.proto_id	= FM_PROTO_ARP,
	.action_flags	= FM_SCAN_ACTION_FLAG_LOCAL_ONLY,
	.modes		= FM_PROBE_MODE_HOST,

	.configure	= fm_arp_configure_probe,
};

FM_PROBE_CLASS_REGISTER(fm_arp_host_probe_class)

/*
 * ARP discovery, eg to be used by raw IP queries that need to find the link-level
 * address of the gateway.
 * Note, the use of a target is totally misplaced here; this needs to be rewritten
 * so it can work exclusively with an fm_address.
 */
bool
fm_arp_discover(fm_protocol_t *proto, fm_target_t *target, int retries)
{
	fm_probe_params_t params;
	fm_multiprobe_t *multiprobe;

	memset(&params, 0, sizeof(params));
	params.retries = retries? : FM_ARP_PROBE_RETRIES;

	multiprobe = fm_multiprobe_alloc(FM_PROBE_MODE_HOST, "arp-query");
	if (!fm_multiprobe_configure(multiprobe, &fm_arp_host_probe_class, &params, NULL)
	 || !fm_multiprobe_add_target(multiprobe, target)) {
		fm_multiprobe_free(multiprobe);
		return false;
	}

	fm_job_run(&multiprobe->job, NULL);
	return true;
}

/*
 * ARP related utility functions
 */
const char *
fm_arp_type_to_string(int hatype)
{
	static char buf[16];

	switch (hatype) {
	case ARPHRD_ETHER:
		return "ether";
	case ARPHRD_LOOPBACK:
		return "loopback";
	case ARPHRD_TUNNEL:
		return "tunnel";
	}

	snprintf(buf, sizeof(buf), "arp%04x", hatype);
	return buf;
}

