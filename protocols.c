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

#include <assert.h>
#include <netinet/ip.h>
#include "protocols.h"
#include "socket.h"

static fm_protocol_engine_t *
fm_protocol_engine_create_socket(void)
{
	static struct fm_protocol_engine *engine = NULL;

	if (engine == NULL) {
		engine = calloc(1, sizeof(*engine));

		engine->icmp = fm_icmp_bsdsock_create();
		engine->tcp = fm_tcp_bsdsock_create();
		engine->udp = fm_udp_bsdsock_create();
	}

	return engine;
}

fm_protocol_engine_t *
fm_protocol_engine_create_default(void)
{
	fm_protocol_engine_t *proto;

	proto = fm_protocol_engine_create_socket();

	assert(proto->icmp == NULL || proto->icmp->ops->id == FM_PROTO_ICMP);
	assert(proto->udp == NULL || proto->udp->ops->id == FM_PROTO_UDP);
	assert(proto->tcp == NULL || proto->tcp->ops->id == FM_PROTO_TCP);

	return proto;
}

/*
 * indirection code for handling response packets
 */
static bool
fm_protocol_packet_redirect(fm_socket_t *sock, fm_pkt_t *pkt)
{
	fm_protocol_t *proto = sock->response_handle;

	return proto->ops->process_packet(proto, pkt);
}

fm_socket_t *
fm_protocol_create_socket(fm_protocol_t *proto, int ipproto)
{
	fm_socket_t *sock;

	if (proto->ops->create_socket == NULL)
		return NULL;
	sock = proto->ops->create_socket(proto, ipproto);
	if (sock != NULL && proto->ops->process_packet != NULL) {
		sock->process_packet = fm_protocol_packet_redirect;
		sock->response_handle = proto;
	}

	return sock;
}

/*
 * IPv4 header analysis
 */
static bool
fm_pkt_pull_ipv4_hdr(fm_pkt_t *pkt, fm_ip_info_t *info)
{
	const struct iphdr *ip = (const struct iphdr *) fm_pkt_peek(pkt, sizeof(struct iphdr));
	unsigned int hlen;

	hlen = ip->ihl << 2;
	if (hlen < 20 || !fm_pkt_pull(pkt, hlen))
		return false;

	if (ip->version != 4)
		return false;

	fm_address_set_ipv4(&info->src_addr, ip->saddr);
	fm_address_set_ipv4(&info->dst_addr, ip->daddr);
	info->ipproto = ip->protocol;

	return true;
}

bool
fm_pkt_pull_ip_hdr(fm_pkt_t *pkt, fm_ip_info_t *info)
{
	if (pkt->family == AF_INET)
		return fm_pkt_pull_ipv4_hdr(pkt, info);
	if (pkt->family == AF_INET6)
		abort();

	return false;
}
