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
#include "utils.h"

struct arp_host_probe_params {
	uint32_t	src_ipaddr;
	uint32_t	dst_ipaddr;
	struct sockaddr_ll src_lladdr;
	struct sockaddr_ll dst_lladdr;
	unsigned int	retries;
};

static bool		get_eth_address(const struct sockaddr_ll *, unsigned char *, unsigned int);
static fm_extant_t *	fm_arp_locate_probe(uint32_t ipaddr, const unsigned char *eth_addr, struct sockaddr_ll *);

static fm_socket_t *	fm_arp_create_socket(fm_protocol_t *proto, int ipproto);
static bool		fm_arp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt);

static int		fm_arp_probe_original_ifindex(const fm_probe_t *);
static fm_scan_action_t *fm_arp_create_host_probe_action(fm_protocol_t *proto, const fm_string_array_t *args);

static struct fm_protocol_ops	fm_arp_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "arp",
	.id		= FM_PROTO_ARP,
	.require_raw	= true,

	.create_socket	= fm_arp_create_socket,
	.create_host_probe_action = fm_arp_create_host_probe_action,
	.process_packet	= fm_arp_process_packet,
};

FM_PROTOCOL_REGISTER(fm_arp_ops);

static fm_socket_t *
fm_arp_create_socket(fm_protocol_t *proto, int dummy)
{
	return fm_socket_create(PF_PACKET, SOCK_DGRAM, ntohs(ETH_P_ARP), proto);
}

static bool
fm_arp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant = NULL;
	const struct arphdr *arp;
	unsigned char src_hwaddr[ETH_ALEN];
	uint32_t src_ipaddr;
	struct sockaddr_ll src_lladdr = { 0 };

	/* fm_print_hexdump(pkt->data, pkt->len); */

	if (pkt->family != AF_PACKET)
		return false;

	if (!(arp = fm_pkt_pull(pkt, sizeof(*arp) + 2 * ETH_ALEN + 2 * 4))) {
		fm_log_debug("%s: bad ARP header", proto->ops->name);
		return false;
	}

	if (arp->ar_op != htons(ARPOP_REPLY)
	 || arp->ar_hln != ETH_ALEN
	 || arp->ar_pln != 4)
		return false;

	memcpy(src_hwaddr, (unsigned char *) (arp + 1), ETH_ALEN);
	memcpy(&src_ipaddr, ((unsigned char *) (arp + 1) + ETH_ALEN), 4);

	extant = fm_arp_locate_probe(src_ipaddr, src_hwaddr, &src_lladdr);
	if (extant != NULL) {
		/* Mark the probe as successful, and update the RTT estimate */
		fm_extant_received_reply(extant, pkt);

		if (src_lladdr.sll_family != AF_UNSPEC) {
			int ifindex = fm_arp_probe_original_ifindex(extant->probe);

			if (ifindex > 0) {
				src_lladdr.sll_ifindex = ifindex;
				fm_local_cache_arp_entry(ifindex, src_ipaddr, &src_lladdr);
			}
		}

		fm_extant_free(extant);
	}

	return true;
}

/*
 * ARP param block.
 */
static inline bool
fm_arp_build_params(struct arp_host_probe_params *params, const fm_string_array_t *args)
{
	unsigned int i;

	memset(params, 0, sizeof(*params));

	for (i = 0; i < args->count; ++i) {
		const char *arg = args->entries[i];
		unsigned int value;

		if (fm_parse_numeric_argument(arg, "retries", &value)) {
			params->retries = value;
		} else {
			fm_log_error("Cannot create ARP host probe: invalid argument \"%s\"", arg);
			return false;
		}
	}

	if (params->retries == 0)
		params->retries = FM_ARP_PROBE_RETRIES;

	return true;
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
fm_arp_build_request(const struct arp_host_probe_params *params, unsigned char *buf, size_t bufsz)
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
static bool
fm_arp_expect_response(uint32_t dst_ipaddr, fm_probe_t *probe)
{
	fm_extant_alloc(probe, AF_PACKET, ETH_P_IP, NULL, 0);
	return true;
}

static fm_extant_t *
fm_arp_locate_probe(uint32_t ipaddr, const unsigned char *eth_addr, struct sockaddr_ll *found_addr)
{
	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { ipaddr }};
	fm_target_t *target;
	hlist_iterator_t iter;

	target = fm_target_pool_find((struct sockaddr_storage *) &sin);
	if (target == NULL) {
		fm_log_debug("ignoring arp response from %s", fm_address_format((struct sockaddr_storage *) &sin));
		return NULL;
	}

	/* Update the asset state */
	fm_target_update_host_state(target, FM_PROTO_ARP, FM_ASSET_STATE_OPEN);

	{
		struct sockaddr_ll lladdr;

		memset(&lladdr, 0, sizeof(lladdr));
		lladdr.sll_family = AF_PACKET;
		lladdr.sll_hatype = ARPHRD_ETHER;
		lladdr.sll_halen = ETH_ALEN;
		lladdr.sll_protocol = htons(ETH_P_IP);
		memcpy(lladdr.sll_addr, eth_addr, ETH_ALEN);

		fm_log_debug("%s is at ethernet address %s",
				fm_address_format(&target->address),
				fm_address_format((fm_address_t *) &lladdr));

		if (found_addr != NULL)
			*found_addr = lladdr;
	}

        fm_extant_iterator_init(&iter, &target->expecting);

	/* No need to loop over several extant probes; one is just enough as we only ever send
	 * ARP requests */
        return fm_extant_iterator_match(&iter, AF_PACKET, ETH_P_IP);
}

/*
 * ARP probes using standard BSD sockets
 */
struct fm_arp_host_probe {
	fm_probe_t	base;

	struct arp_host_probe_params params;
};

static fm_error_t
fm_arp_host_probe_send(fm_probe_t *probe)
{
	fm_target_t *target = probe->target;
	struct fm_arp_host_probe *arp = (struct fm_arp_host_probe *) probe;
	struct sockaddr_ll eth_bcast;
	fm_socket_t *sock;
	unsigned char pktbuf[128];
	size_t pktlen;

	/* The src_lladdr is used to locate the appropriate PF_PACKET socket;
	 * so we need to tell it what protocol we want. */
	arp->params.src_lladdr.sll_protocol = htons(ETH_P_ARP);

	sock = fm_raw_socket_get((fm_address_t *) &arp->params.src_lladdr, probe->proto, SOCK_DGRAM);
	if (sock == NULL) {
		fm_log_error("Unable to create ARP socket for %s",
				fm_address_format(&target->address));
		return FM_SEND_ERROR;
	}

	pktlen = fm_arp_build_request(&arp->params, pktbuf, sizeof(pktbuf));
	if (pktlen == 0) {
		fm_log_error("Don't know how to build ARP packet");
		return FM_SEND_ERROR;
	}

	/* inform the ARP response matching code that we're waiting for a response to this packet */
	fm_arp_expect_response(arp->params.dst_ipaddr, probe);

	eth_bcast = arp->params.src_lladdr;
	eth_bcast.sll_pkttype = PACKET_BROADCAST;
	memset(eth_bcast.sll_addr, 0xFF, ETH_ALEN);

	if (!fm_socket_send(sock, (fm_address_t *) &eth_bcast, pktbuf, pktlen)) {
		fm_log_error("Unable to send ARP packet: %m");
		return FM_SEND_ERROR;
	}

	/* Update the asset state */
	fm_target_update_host_state(target, FM_PROTO_ARP, FM_ASSET_STATE_PROBE_SENT);

	if (arp->params.retries > 0)
		arp->params.retries -= 1;

	probe->timeout = FM_ARP_RESPONSE_TIMEOUT;
	return 0;
}

static bool
fm_arp_host_probe_should_resend(fm_probe_t *probe)
{
	const struct fm_arp_host_probe *arp = (struct fm_arp_host_probe *) probe;

	if (arp->params.retries == 0) {
		fm_probe_timed_out(probe);
		return false;
	}

	return true;
}

static struct fm_probe_ops fm_arp_host_probe_ops = {
	.obj_size	= sizeof(struct fm_arp_host_probe),
	.name 		= "arp",

	.default_timeout= 1000,	/* FM_ARP_RESPONSE_TIMEOUT */

	.send		= fm_arp_host_probe_send,
	.should_resend	= fm_arp_host_probe_should_resend,
};

static fm_probe_t *
fm_arp_create_host_probe(fm_protocol_t *proto, fm_target_t *target, const struct arp_host_probe_params *arp_args)
{
	struct fm_arp_host_probe *probe;
	uint32_t src_ipaddr, dst_ipaddr;
	struct sockaddr_ll src_lladdr;

	if (!fm_address_get_ipv4(&target->local_bind_address, &src_ipaddr)
	 || !fm_address_get_ipv4(&target->address, &dst_ipaddr)
	 || !fm_interface_get_lladdr(target->local_device, &src_lladdr)) {
		fm_log_error("%s: cannot create ARP probe: incompatible address family",
				fm_address_format(&target->address));
		return NULL;
	}

	probe = (struct fm_arp_host_probe *) fm_probe_alloc("arp", &fm_arp_host_probe_ops, proto, target);

	probe->params = *arp_args;

	probe->params.dst_ipaddr = dst_ipaddr;
	probe->params.src_ipaddr = src_ipaddr;
	probe->params.src_lladdr = src_lladdr;

	fm_log_debug("Created ARP socket probe for %s\n", fm_address_format(&target->address));
	return &probe->base;
}

bool
fm_arp_discover(fm_protocol_t *proto, fm_target_t *target, int retries)
{
	struct arp_host_probe_params params;
	fm_probe_t *probe;

	memset(&params, 0, sizeof(params));
	params.retries = retries? : FM_ARP_PROBE_RETRIES;

	probe = fm_arp_create_host_probe(proto, target, &params);
	if (probe == NULL)
		return false;

	fm_target_send_probe(target, probe);
	return true;
}

int
fm_arp_probe_original_ifindex(const fm_probe_t *probe)
{
	const struct fm_arp_host_probe *arp;

	if (probe->ops != &fm_arp_host_probe_ops)
		return -1;

	arp = (struct fm_arp_host_probe *) probe;
	return arp->params.src_lladdr.sll_ifindex;
}

/*
 * ARP host probe
 */
struct fm_arp_host_scan {
	fm_scan_action_t	base;

	fm_protocol_t *		proto;
	struct arp_host_probe_params params;
};

static fm_probe_t *
fm_arp_host_scan_get_next_probe(const fm_scan_action_t *action, fm_target_t *target, unsigned int index)
{
	struct fm_arp_host_scan *hostscan = (struct fm_arp_host_scan *) action;

	if (index != 0)
		return NULL;

	return fm_arp_create_host_probe(hostscan->proto, target, &hostscan->params);
}

static const struct fm_scan_action_ops	fm_arp_host_scan_ops = {
	.obj_size	= sizeof(struct fm_arp_host_scan),
	.get_next_probe	= fm_arp_host_scan_get_next_probe,
};


fm_scan_action_t *
fm_arp_create_host_probe_action(fm_protocol_t *proto, const fm_string_array_t *args)
{
	struct fm_arp_host_scan *hostscan;
	struct arp_host_probe_params arp_args;

	if (!fm_arp_build_params(&arp_args, args))
		return false;

	hostscan = (struct fm_arp_host_scan *) fm_scan_action_create(&fm_arp_host_scan_ops, "arp");
	hostscan->proto = proto;
	hostscan->params = arp_args;

	hostscan->base.flags = FM_SCAN_ACTION_FLAG_LOCAL_ONLY;
	hostscan->base.nprobes = 1;

	return &hostscan->base;
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

	snprintf(buf, sizeof(buf), "arp%u", hatype);
	return buf;
}

