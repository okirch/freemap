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

#include <linux/if_ether.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "scanner.h"
#include "protocols.h"
#include "target.h"
#include "socket.h"
#include "packet.h"
#include "rawpacket.h"
#include "rawip.h"
#include "logging.h"
#include "buffer.h"


/* Global pool for rawip sockets */
static fm_socket_pool_t	*fm_raw_ipv4_socket_pool = NULL;
static fm_socket_pool_t	*fm_raw_ipv6_socket_pool = NULL;

/* Global extant map for all rawip related stuff */
static fm_extant_map_t fm_raw_ipv4_extant_map = FM_EXTANT_MAP_INIT;
static fm_extant_map_t fm_raw_ipv6_extant_map = FM_EXTANT_MAP_INIT;

/*
 * Track extant rawip requests.
 */
void
fm_rawip_extant_info_build(int ipproto, fm_rawip_extant_info_t *extant_info)
{
	extant_info->ipproto = ipproto;
}

static fm_extant_t *
fm_rawip_locate_common(fm_pkt_t *pkt, const fm_ip_header_info_t *ip_info, hlist_iterator_t *iter)
{
	fm_host_asset_t *host;
	fm_extant_t *extant;

	host = fm_host_asset_get_active(&pkt->peer_addr);
	if (host == NULL)
		return NULL;

	while ((extant = fm_extant_iterator_match(iter, pkt->family, 0)) != NULL) {
		const fm_rawip_extant_info_t *info = (fm_rawip_extant_info_t *) (extant + 1);

		if (extant->host == host && info->ipproto == ip_info->ipproto)
			return extant;
	}

	return NULL;
}

static fm_extant_t *
fm_rawip_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	fm_parsed_pkt_t *cooked;
	fm_parsed_hdr_t *hdr;
	bool unreachable;

	if ((cooked = pkt->parsed) == NULL)
		return NULL;

	if (pkt->info.ee != NULL) {
		/* raw socket, received error packet from errqueue.
		 * The ICMP info we're looking for is in the extended error: */
		unreachable = fm_pkt_is_dest_unreachable(pkt);
	} else {
		/* First, check the ICMP error header - does it tell us the port is unreachable? */
		if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_ICMP)) == NULL)
			return NULL;
		unreachable = fm_icmp_header_is_host_unreachable(&hdr->icmp);
	}

	/* Then, look at the enclosed IP header */
	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_IP)) == NULL)
		return NULL;

	/* Do something with what we just learned */
	(void) unreachable;
	fm_log_debug("fm_rawip_locate_error()");

	return fm_rawip_locate_common(pkt, &hdr->ip, iter);
}

static fm_extant_t *
fm_rawip_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	fm_parsed_pkt_t *cooked;
	fm_parsed_hdr_t *hdr;
	fm_extant_t *extant;

	if ((cooked = pkt->parsed) == NULL)
		return NULL;

	if ((hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_IP)) == NULL)
		return NULL;

	extant = fm_rawip_locate_common(pkt, &hdr->ip, iter);

	if (extant != NULL && extant->host)
		fm_host_asset_update_state(extant->host, FM_ASSET_STATE_OPEN);

	return extant;
}

/*
 * RAW IPv4
 */
static fm_socket_t *
fm_raw_ipv4_create_socket(fm_protocol_t *proto, int af, const fm_address_t *bind_addr)
{
	fm_socket_t *sock;
	int ipproto;

	ipproto = fm_address_get_port(bind_addr);
	if (ipproto <= 0 || ipproto > 255)
		return NULL;

	sock = fm_socket_create(af, SOCK_RAW, ipproto, proto);
	if (sock) {
		fm_socket_enable_recverr(sock);
		fm_socket_enable_hdrincl(sock);

		fm_socket_install_data_parser(sock, FM_PROTO_IP);
		fm_socket_install_error_parser(sock, FM_PROTO_IP);

		fm_socket_attach_extant_map(sock, &fm_raw_ipv4_extant_map);
	}
	return sock;
}

static struct fm_protocol	fm_raw_ipv4_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "raw-ipv4",

	.supported_parameters =
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_FEATURE_SOCKET_SHARING_MASK,

	.create_socket	= fm_raw_ipv4_create_socket,
	.locate_error	= fm_rawip_locate_error,
	.locate_response= fm_rawip_locate_response,
};

FM_PROTOCOL_REGISTER(fm_raw_ipv4_ops);

/*
 * RAW IPv6
 */
static fm_socket_t *
fm_raw_ipv6_create_socket(fm_protocol_t *proto, int af, const fm_address_t *bind_addr)
{
	fm_socket_t *sock;
	int ipproto;

	ipproto = fm_address_get_port(bind_addr);
	if (ipproto <= 0 || ipproto > 255)
		return NULL;

	sock = fm_socket_create(af, SOCK_RAW, ipproto, proto);
	if (sock) {
		fm_socket_enable_recverr(sock);
		fm_socket_enable_hdrincl(sock);

		fm_socket_install_data_parser(sock, FM_PROTO_IP);
		fm_socket_install_error_parser(sock, FM_PROTO_IP);

		fm_socket_attach_extant_map(sock, &fm_raw_ipv6_extant_map);
	}
	return sock;
}

static struct fm_protocol	fm_raw_ipv6_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "raw-ipv6",

	.supported_parameters =
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_FEATURE_SOCKET_SHARING_MASK,

	.create_socket	= fm_raw_ipv6_create_socket,
	.locate_error	= fm_rawip_locate_error,
	.locate_response= fm_rawip_locate_response,
};

FM_PROTOCOL_REGISTER(fm_raw_ipv6_ops);

/*
 * Get rawip socket pool
 */
static fm_socket_pool_t *
fm_rawip_get_socket_pool(int af)
{
	if (af == AF_INET) {
		if (fm_raw_ipv4_socket_pool == NULL)
			fm_raw_ipv4_socket_pool = fm_socket_pool_create(&fm_raw_ipv6_ops, SOCK_DGRAM);
		return fm_raw_ipv4_socket_pool;
	}
	if (af == AF_INET6) {
		if (fm_raw_ipv6_socket_pool == NULL)
			fm_raw_ipv6_socket_pool = fm_socket_pool_create(&fm_raw_ipv6_ops, SOCK_DGRAM);
		return fm_raw_ipv6_socket_pool;
	}
	return NULL;
}

/*
 * Create a rawip socket for a given target.
 */
fm_socket_t *
fm_rawip_create_shared_socket(fm_target_t *target, int ipproto)
{
	fm_address_t bind_addr;
	fm_socket_pool_t *pool;

	/* Pick adequate source address to use when talking to this target. */
	if (!fm_target_get_local_bind_address(target, &bind_addr)) {
		fm_log_error("%s: cannot determine source address", target->id);
		return NULL;
	}

	/* raw sockets identify their ipproto using the port field */
	fm_address_set_port(&bind_addr, ipproto);

	if (!(pool = fm_rawip_get_socket_pool(target->address.family)))
		return NULL;

	return fm_socket_pool_get_socket(pool, &bind_addr);
}
