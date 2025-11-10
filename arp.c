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
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "freemap.h"
#include "protocols.h"
#include "target.h" /* for fm_probe_t */
#include "scanner.h"
#include "rawpacket.h"
#include "socket.h"
#include "utils.h"

typedef struct fm_arp_params {
	uint32_t		src_ipaddr;
	uint32_t		dst_ipaddr;
	struct sockaddr_ll	src_lladdr;
	struct sockaddr_ll	dst_lladdr;
} fm_arp_params_t;

typedef struct fm_arp_request {
	fm_protocol_t *		proto;
	fm_target_t *		target;
	fm_socket_t *		sock;

	int			family;
	fm_address_t		host_address;
	fm_probe_params_t	params;

	fm_arp_params_t		arp_params;
} fm_arp_request_t;

typedef struct fm_arp_extant_info {
	struct in_addr		dst_addr;
} fm_arp_extant_info_t;

static bool		get_eth_address(const struct sockaddr_ll *, unsigned char *, unsigned int);

static fm_socket_t *	fm_arp_create_socket(fm_protocol_t *proto, int ipproto);
static fm_extant_t *	fm_arp_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);
static fm_extant_t *	fm_arp_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *);

static int		fm_arp_probe_original_ifindex(const fm_probe_t *);
static void		fm_arp_update_cache(const fm_arp_header_info_t *arp_info, fm_extant_t *extant);

static fm_arp_request_t *fm_arp_probe_get_request(const fm_probe_t *probe);
static void		fm_arp_probe_set_request(fm_probe_t *probe, fm_arp_request_t *arp);

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
fm_arp_request_free(fm_arp_request_t *arp)
{
	free(arp);
}

static fm_arp_request_t *
fm_arp_request_alloc(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_arp_request_t *arp;
	uint32_t src_ipaddr, dst_ipaddr;
	struct sockaddr_ll src_lladdr;

	if (!fm_address_get_ipv4(&target->local_bind_address, &src_ipaddr)
	 || !fm_address_get_ipv4(&target->address, &dst_ipaddr)
	 || !fm_interface_get_lladdr(target->local_device, &src_lladdr)) {
		fm_log_error("%s: cannot create ARP probe: incompatible address family",
				fm_address_format(&target->address));
		return NULL;
	}

	if (src_lladdr.sll_ifindex == 0) {
		fm_log_error("Cannot create ARP probe on %s: NIC address lacks ifindex: %s",
				fm_interface_get_name(target->local_device),
				fm_address_format((fm_address_t *) &src_lladdr));
		return NULL;
	}

	arp = calloc(1, sizeof(*arp));
	arp->proto = proto;
	arp->target = target;
	arp->params = *params;
	arp->family = AF_PACKET;

	if (arp->params.retries == 0)
		arp->params.retries = FM_ARP_PROBE_RETRIES;

	arp->arp_params.dst_ipaddr = dst_ipaddr;
	arp->arp_params.src_ipaddr = src_ipaddr;
	arp->arp_params.src_lladdr = src_lladdr;

	fm_log_debug("Created ARP socket probe for %s\n", fm_address_format(&target->address));
	return arp;
}

/*
 * Helper functions.
 * We may want to promote them to fm_address_*() one day
 */
bool
get_eth_address(const struct sockaddr_ll *lladdr, unsigned char *eth_addr, unsigned int size)
{
	if (lladdr->sll_family != AF_PACKET
	 || lladdr->sll_hatype != ARPHRD_ETHER
	 || lladdr->sll_halen != size)
		return false;

	memcpy(eth_addr, lladdr->sll_addr, size);
	return true;
}

/*
 * For now, we only do ethernet
 */
static unsigned int
fm_arp_build_request(const fm_arp_params_t *params, unsigned char *buf, size_t bufsz)
{
	struct arphdr *arp;
	unsigned char *ap;

	if (bufsz < sizeof(*arp) + 8 + 2 * ETH_ALEN)
		return 0;

	arp = (struct arphdr *) buf;
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op  = htons(ARPOP_REQUEST);

	ap = (unsigned char *) (arp + 1);

	get_eth_address(&params->src_lladdr, ap, ETH_ALEN);
	ap += ETH_ALEN;

	memcpy(ap, &params->src_ipaddr, 4);
	ap += 4;

	get_eth_address(&params->dst_lladdr, ap, ETH_ALEN);
	ap += ETH_ALEN;

	memcpy(ap, &params->dst_ipaddr, 4);
	ap += 4;

	return ap - buf;
}

/*
 * ARP request/reply matching
 */
static void
fm_arp_extant_info_build(fm_arp_request_t *arp, fm_arp_extant_info_t *extant_info)
{
	extant_info->dst_addr.s_addr = arp->arp_params.dst_ipaddr;
}

static fm_extant_t *
fm_arp_locate_common(fm_pkt_t *pkt, const struct in_addr *dst_ipaddr, hlist_iterator_t *iter)
{
	fm_extant_t *extant;

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

	if (hdr->arp.op != ARPOP_REPLY)
		return NULL;

	extant = fm_arp_locate_common(pkt, &hdr->arp.src_ipaddr, iter);

	/* See if we can update our local neighbor cache */
	if (extant != NULL) {
		fm_arp_update_cache(&hdr->arp, extant);
	}

	return extant;
}

static void
fm_arp_update_cache(const fm_arp_header_info_t *arp_info, fm_extant_t *extant)
{
	int ifindex;
	struct sockaddr_ll lladdr;

	if (extant->probe == NULL)
		return;

	ifindex = fm_arp_probe_original_ifindex(extant->probe);
	if (ifindex <= 0)
		return;

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
fm_arp_request_send(fm_arp_request_t *arp, fm_extant_t **extant_ret)
{
	fm_arp_extant_info_t extant_info;
	fm_target_t *target = arp->target;
	struct sockaddr_ll eth_bcast;
	fm_socket_t *sock;
	unsigned char pktbuf[128];
	size_t pktlen;

	/* The src_lladdr is used to locate the appropriate PF_PACKET socket;
	 * so we need to tell it what protocol we want. */
	arp->arp_params.src_lladdr.sll_protocol = htons(ETH_P_ARP);

	sock = fm_raw_socket_get((fm_address_t *) &arp->arp_params.src_lladdr, arp->proto, SOCK_DGRAM);
	if (sock == NULL) {
		fm_log_error("Unable to create ARP socket for %s",
				fm_address_format(&target->address));
		return FM_SEND_ERROR;
	}

	if (sock->extant_map == NULL)
		fm_socket_attach_extant_map(sock, &fm_arp_extant_map);

	pktlen = fm_arp_build_request(&arp->arp_params, pktbuf, sizeof(pktbuf));
	if (pktlen == 0) {
		fm_log_error("Don't know how to build ARP packet");
		return FM_SEND_ERROR;
	}

	fm_arp_extant_info_build(arp, &extant_info);

	eth_bcast = arp->arp_params.src_lladdr;
	eth_bcast.sll_pkttype = PACKET_BROADCAST;
	memset(eth_bcast.sll_addr, 0xFF, ETH_ALEN);

	if (!fm_socket_send(sock, (fm_address_t *) &eth_bcast, pktbuf, pktlen)) {
		fm_log_error("Unable to send ARP packet: %m");
		return FM_SEND_ERROR;
	}

	*extant_ret = fm_socket_add_extant(sock, NULL, AF_PACKET, ETH_P_IP,
			&extant_info, sizeof(extant_info));

	/* Update the asset state */
	fm_target_update_host_state(target, FM_PROTO_ARP, FM_ASSET_STATE_PROBE_SENT);

	if (arp->params.retries > 0)
		arp->params.retries -= 1;

	return 0;
}


/*
 * ARP probes using standard BSD sockets
 */
struct fm_arp_host_probe {
	fm_probe_t		base;
	fm_arp_request_t *	arp;
};

/*
 * Probe destructor
 */
static void
fm_arp_host_probe_destroy(fm_probe_t *probe)
{
	fm_arp_request_t *arp = fm_arp_probe_get_request(probe);

	if (arp != NULL) {
		fm_arp_request_free(arp);
		fm_arp_probe_set_request(probe, NULL);
	}

	fm_extant_map_forget_probe(&fm_arp_extant_map, probe);
}

static fm_error_t
fm_arp_host_probe_send(fm_probe_t *probe)
{
	fm_arp_request_t *arp = fm_arp_probe_get_request(probe);
	fm_extant_t *extant;
	fm_error_t error;

	error = fm_arp_request_send(arp, &extant);
	if (extant != NULL)
		extant->probe = probe;

	return error;
}

static fm_error_t
fm_arp_host_probe_schedule(fm_probe_t *probe)
{
	fm_arp_request_t *arp = fm_arp_probe_get_request(probe);

	if (arp->params.retries == 0)
		return FM_TIMED_OUT;

	/* After sending the last probe, we wait until the full timeout has expired.
	 * For any earlier probe, we wait for the specified packet spacing */
	if (arp->params.retries == 1)
		probe->job.expires = fm_time_now() + 1e-3 * fm_global.arp.timeout;
	else
		probe->job.expires = fm_time_now() + 1e-3 * fm_global.arp.packet_spacing;
	return 0;
}

static struct fm_probe_ops fm_arp_host_probe_ops = {
	.obj_size	= sizeof(struct fm_arp_host_probe),
	.name 		= "arp",

	.default_timeout= 1000,	/* FM_ARP_RESPONSE_TIMEOUT */

	.destroy	= fm_arp_host_probe_destroy,
	.send		= fm_arp_host_probe_send,
	.schedule	= fm_arp_host_probe_schedule,
};

static fm_arp_request_t *
fm_arp_probe_get_request(const fm_probe_t *probe)
{
	if (probe->ops != &fm_arp_host_probe_ops)
		return NULL;

	return ((struct fm_arp_host_probe *) probe)->arp;
}

static void
fm_arp_probe_set_request(fm_probe_t *probe, fm_arp_request_t *arp)
{
	((struct fm_arp_host_probe *) probe)->arp = arp;
}

static fm_probe_t *
fm_arp_create_host_probe(fm_probe_class_t *pclass, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_protocol_t *proto = pclass->proto;
	fm_arp_request_t *arp;
	fm_probe_t *probe;

	assert(proto && proto->id == FM_PROTO_ARP);

	arp = fm_arp_request_alloc(proto, target, params, extra_params);
	if (arp == NULL)
		return NULL;

	probe = fm_probe_alloc("arp", &fm_arp_host_probe_ops, target);
	fm_arp_probe_set_request(probe, arp);

	fm_log_debug("Created ARP socket probe for %s\n", fm_address_format(&target->address));
	return probe;
}

static struct fm_probe_class fm_arp_host_probe_class = {
	.name		= "arp",
	.family		= AF_INET,
	.proto_id	= FM_PROTO_ARP,
	.action_flags	= FM_SCAN_ACTION_FLAG_LOCAL_ONLY,
	.modes		= FM_PROBE_MODE_HOST,

	.create_probe	= fm_arp_create_host_probe,
};

FM_PROBE_CLASS_REGISTER(fm_arp_host_probe_class)

bool
fm_arp_discover(fm_protocol_t *proto, fm_target_t *target, int retries)
{
	fm_probe_params_t params;
	fm_probe_t *probe;

	memset(&params, 0, sizeof(params));
	params.retries = retries? : FM_ARP_PROBE_RETRIES;

	probe = fm_arp_create_host_probe(&fm_arp_host_probe_class, target, &params, NULL);
	if (probe == NULL)
		return false;

	fm_target_add_new_probe(target, probe);
	return true;
}

int
fm_arp_probe_original_ifindex(const fm_probe_t *probe)
{
	fm_arp_request_t *arp = fm_arp_probe_get_request(probe);

	if (arp == NULL)
		return -1;

	return arp->arp_params.src_lladdr.sll_ifindex;
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

