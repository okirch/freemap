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
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include "protocols.h"
#include "target.h"
#include "socket.h"
#include "network.h"

static unsigned int	fm_protocol_directory_count;
static struct fm_protocol_ops *fm_protocol_directory[256];

/*
 * Using gcc constructors, all our protocol drivers come here when the
 * application starts.
 * We inspect and vet them later.
 */
void
fm_protocol_directory_add(struct fm_protocol_ops *ops)
{
	if (fm_protocol_directory_count < 256)
		fm_protocol_directory[fm_protocol_directory_count++] = ops;
}

void
fm_protocol_directory_display(void)
{
	unsigned int i;

	printf("Found %d protocol drivers:\n", fm_protocol_directory_count);
	for (i = 0; i < fm_protocol_directory_count; ++i) {
		struct fm_protocol_ops *ops = fm_protocol_directory[i];

		printf("%-12s", ops->name);

		if (ops->id != FM_PROTO_NONE)
			printf("; implements %s", fm_protocol_id_to_string(ops->id));

		printf("\n");
	}
}

static const struct fm_protocol_ops *
fm_protocol_directory_select(unsigned int proto_id, bool have_raw)
{
	unsigned int i, best_rating = 0;
	const struct fm_protocol_ops *best = NULL;

	for (i = 0; i < fm_protocol_directory_count; ++i) {
		struct fm_protocol_ops *ops = fm_protocol_directory[i];
		unsigned int rating;

		if (ops->id != proto_id)
			continue;
		if (ops->require_raw && !have_raw)
			continue;

		rating = 1;
		if (ops->require_raw)
			rating |= 2;

		if (rating > best_rating)
			best = ops;
	}

	return best;
}

/* This should probably go to socket.c */
static bool
fm_socket_have_raw(void)
{
	static int have_raw = -1;

	if (have_raw < 0) {
		fm_socket_t *sock;

		sock = fm_socket_create(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL);

		if (sock == NULL) {
			have_raw = 0;
		} else {
			fm_socket_free(sock);
			have_raw = 1;
		}
	}

	return (bool) have_raw;
}

/*
 * Engine setup
 */
static void
fm_protocol_engine_create_standard(struct fm_protocol_engine *engine)
{
	unsigned int id;
	bool have_raw;

	have_raw = fm_socket_have_raw();

	for (id = 0; id < __FM_PROTO_MAX; ++id) {
		const struct fm_protocol_ops *ops;
		const char *proto_name;

		proto_name = fm_protocol_id_to_string(id);

		ops = fm_protocol_directory_select(id, have_raw);
		if (ops == NULL) {
			fm_log_debug("%02u %-10s no driver", id, proto_name);
			continue;
		}

		fm_log_debug("%02u %-10s use driver %s", id, proto_name, ops->name);
		engine->driver[id] = fm_protocol_create(ops);
		assert(engine->driver[id]);
	}
}

static void
fm_protocol_engine_create_other(struct fm_protocol_engine *engine)
{
	unsigned int i;
	bool have_raw;

	have_raw = fm_socket_have_raw();

	for (i = 0; i < fm_protocol_directory_count; ++i) {
		struct fm_protocol_ops *ops = fm_protocol_directory[i];

		if (ops->id != FM_PROTO_NONE)
			continue;
		if (ops->require_raw && !have_raw)
			continue;

		if (engine->num_other >= FM_PROTOCOL_ENGINE_MAX)
			fm_log_fatal("%s: too many protocol drivers", __func__);

		engine->other[engine->num_other++] = fm_protocol_create(ops);
	}
}

fm_protocol_engine_t *
fm_protocol_engine_create_default(void)
{
	static struct fm_protocol_engine *engine = NULL;;

	if (engine == NULL) {
		unsigned int id;

		engine = calloc(1, sizeof(*engine));
		fm_protocol_engine_create_standard(engine);
		fm_protocol_engine_create_other(engine);

		for (id = 0; id < __FM_PROTO_MAX; ++id) {
			fm_protocol_t *driver = engine->driver[id];

			if (driver != NULL && driver->ops->id != id) {
				fm_log_error("created %s protocol driver \"%s\", but it provides protocol id %u",
						fm_protocol_id_to_string(id),
						driver->ops->name,
						driver->ops->id);
				abort();
			}
		}
	}

	return engine;
}

fm_protocol_t *
fm_protocol_engine_get_protocol(fm_protocol_engine_t *engine, const char *name)
{
	unsigned int id, k;

	id = fm_protocol_string_to_id(name);
	if (id != FM_PROTO_NONE)
		return engine->driver[id];

	for (k = 0; k < engine->num_other; ++k) {
		fm_protocol_t *proto = engine->other[k];

		if (!strcmp(proto->ops->name, name))
			return proto;
	}

	return NULL;
}

/*
 * mapping between FM_PROTO_* constants and protocol names
 */
static const char *	fm_protocol_names[__FM_PROTO_MAX] = {
	[FM_PROTO_IP]	= "ip",
	[FM_PROTO_IPV6]	= "ipv6",
	[FM_PROTO_ARP]	= "arp",
	[FM_PROTO_ICMP]	= "icmp",
	[FM_PROTO_TCP]	= "tcp",
	[FM_PROTO_UDP]	= "udp",
};

const char *
fm_protocol_id_to_string(unsigned int id)
{
	if (id < __FM_PROTO_MAX)
		return fm_protocol_names[id];
	return NULL;
}

unsigned int
fm_protocol_string_to_id(const char *name)
{
	unsigned int id;

	for (id = 0; id < __FM_PROTO_MAX; ++id) {
		if (fm_protocol_names[id] && !strcmp(fm_protocol_names[id], name))
			return id;
	}
	return FM_PROTO_NONE;
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

static void
fm_protocol_init_rtt_estimator(fm_protocol_t *proto, fm_rtt_stats_t *rtt)
{
	switch (proto->ops->id) {
	case FM_PROTO_ICMP:
		fm_rtt_stats_init(rtt, FM_ICMP_PACKET_SPACING / 5, 5);
		break;

	case FM_PROTO_UDP:
	case FM_PROTO_TCP:
		fm_rtt_stats_init(rtt, 250 / 2, 2);
		break;
	}
}


static inline void
fm_protocol_attach_rtt_estimator(fm_protocol_t *proto, fm_target_t *target, fm_probe_t *probe)
{
	fm_network_t *net = target->network;
	unsigned int proto_id = proto->ops->id;
	fm_rtt_stats_t *rtt;

	assert(proto_id <= __FM_PROTO_MAX);

	rtt = &net->rtt_stats[proto_id];
	if (rtt->nsamples == 0)
		fm_protocol_init_rtt_estimator(proto, rtt);

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

	if (sock && sock->proto == NULL) {
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

/*
 * IPv6 header analysis
 */
static bool
fm_pkt_pull_ipv6_hdr(fm_pkt_t *pkt, fm_ip_info_t *info)
{
	fm_log_error("%s: not yet implemented", __func__);
	return false;
}

bool
fm_pkt_pull_ip_hdr(fm_pkt_t *pkt, fm_ip_info_t *info)
{
	if (pkt->family == AF_INET)
		return fm_pkt_pull_ipv4_hdr(pkt, info);
	if (pkt->family == AF_INET6)
		return fm_pkt_pull_ipv6_hdr(pkt, info);

	return false;
}
