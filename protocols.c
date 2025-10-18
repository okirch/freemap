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
#include "target.h"
#include "socket.h"
#include "network.h"

static fm_protocol_engine_t *
fm_protocol_engine_create_bsd_socket(void)
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

static fm_protocol_engine_t *
fm_protocol_engine_create_raw_socket(void)
{
	static struct fm_protocol_engine *engine = NULL;
	static bool initialized = false;

	if (!initialized) {
		fm_socket_t *sock;

		initialized = true;

		sock = fm_socket_create(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (sock == NULL)
			return NULL;
		fm_socket_free(sock);

		engine = calloc(1, sizeof(*engine));

		engine->icmp = fm_icmp_rawsock_create();
		engine->tcp = fm_tcp_bsdsock_create();
		engine->udp = fm_udp_bsdsock_create();
	}

	return engine;
}

fm_protocol_engine_t *
fm_protocol_engine_create_default(void)
{
	fm_protocol_engine_t *proto;

	proto = fm_protocol_engine_create_raw_socket();
	if (proto == NULL)
		proto = fm_protocol_engine_create_bsd_socket();

	assert(proto->icmp == NULL || proto->icmp->ops->id == FM_PROTO_ICMP);
	assert(proto->udp == NULL || proto->udp->ops->id == FM_PROTO_UDP);
	assert(proto->tcp == NULL || proto->tcp->ops->id == FM_PROTO_TCP);

	return proto;
}

/*
 * fm_protocol API
 */
fm_protocol_t *
fm_protocol_create(const struct fm_protocol_ops *ops)
{
	fm_protocol_t *prot;

	prot = calloc(1, ops->obj_size);
	prot->ops = ops;
	return prot;
}

static inline void
fm_protocol_attach_rtt_estimator(fm_protocol_t *proto, fm_target_t *target, fm_probe_t *probe)
{
	fm_network_t *net = target->network;
	unsigned int proto_id = proto->ops->id;
	fm_rtt_stats_t *rtt;

	assert(proto_id <= __FM_PROTO_MAX);

	rtt = net->rtt_stats[proto_id];
	if (rtt == NULL) {
		rtt = proto->ops->create_rtt_estimator(proto, net->netid);
		net->rtt_stats[proto_id] = rtt;
	}

	fm_probe_set_rtt_estimator(probe, rtt);
}

/*
 * Create host/port probes
 */
fm_probe_t *
fm_protocol_create_port_probe(fm_protocol_t *proto, fm_target_t *target, uint16_t port)
{
	fm_probe_t *probe;

	if (proto->ops->create_port_probe == NULL) {
		fprintf(stderr, "Error: protocol %s cannot create a port probe\n", proto->ops->name);
		return NULL;
	}

	if ((probe = proto->ops->create_port_probe(proto, target, port)) != NULL)
		fm_protocol_attach_rtt_estimator(proto, target, probe);
	return probe;
}

fm_probe_t *
fm_protocol_create_host_probe(fm_protocol_t *proto, fm_target_t *target, unsigned int retries)
{
	fm_probe_t *probe;

	if (proto->ops->create_host_probe == NULL) {
		fprintf(stderr, "Error: protocol %s cannot create a host probe\n", proto->ops->name);
		return NULL;
	}

	if ((probe = proto->ops->create_host_probe(proto, target, retries)) != NULL)
		fm_protocol_attach_rtt_estimator(proto, target, probe);
	return probe;
}

fm_socket_t *
fm_protocol_create_socket(fm_protocol_t *proto, int ipproto)
{
	fm_socket_t *sock;

	if (proto->ops->create_socket == NULL)
		return NULL;
	sock = proto->ops->create_socket(proto, ipproto);

	if (sock->proto == NULL) {
		fm_log_warning("protocol driver %s forgot to attach itself to new socket", proto->ops->name);
		fm_socket_attach_protocol(sock, proto);
	}

	return sock;
}

fm_socket_t *
fm_protocol_create_host_shared_socket(fm_protocol_t *proto, fm_target_t *target)
{
	if (target == NULL || proto->ops->create_host_shared_socket == NULL)
		return NULL;

	return proto->ops->create_host_shared_socket(proto, target);
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
