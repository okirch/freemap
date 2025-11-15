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
#include "buffer.h"

static unsigned int	fm_protocol_directory_count;
static struct fm_protocol *fm_protocol_directory[256];

/*
 * Using gcc constructors, all our protocol drivers come here when the
 * application starts.
 * We inspect and vet them later.
 */
void
fm_protocol_directory_add(struct fm_protocol *proto)
{
	if (proto->id == FM_PROTO_NONE)
		fm_log_fatal("Attempt to add protocol %s without protocol id", proto->name);
	if (fm_protocol_directory_count < 256)
		fm_protocol_directory[fm_protocol_directory_count++] = proto;
}

void
fm_protocol_directory_display(void)
{
	unsigned int i;

	printf("Found %d protocol drivers:\n", fm_protocol_directory_count);
	for (i = 0; i < fm_protocol_directory_count; ++i) {
		struct fm_protocol *ops = fm_protocol_directory[i];

		printf("%-12s; implements %s\n", ops->name, fm_protocol_id_to_string(ops->id));
	}
}

static const struct fm_protocol *
fm_protocol_directory_select(unsigned int proto_id)
{
	unsigned int i;

	for (i = 0; i < fm_protocol_directory_count; ++i) {
		struct fm_protocol *ops = fm_protocol_directory[i];

		if (ops->id == proto_id)
			return ops;
	}

	return NULL;
}

/*
 * Engine setup
 */
static void
fm_protocol_engine_create_standard(struct fm_protocol_engine *engine)
{
	unsigned int id;

	for (id = 0; id < __FM_PROTO_MAX; ++id) {
		fm_protocol_t *proto;
		const char *proto_name;

		proto_name = fm_protocol_id_to_string(id);

		proto = fm_protocol_directory_select(id);
		if (proto == NULL) {
			fm_log_debug("%02u %-10s no driver", id, proto_name);
			continue;
		}

		fm_log_debug("%02u %-10s use driver %s", id, proto_name, proto->name);
		engine->driver[id] = proto;
		assert(engine->driver[id]);
	}
}

static void
fm_protocol_engine_create_other(struct fm_protocol_engine *engine)
{
	unsigned int i;

	for (i = 0; i < fm_protocol_directory_count; ++i) {
		fm_protocol_t *proto = fm_protocol_directory[i];

		if (proto->id == FM_PROTO_NONE)
			continue;

		if (engine->num_alt >= FM_PROTOCOL_ENGINE_MAX)
			fm_log_fatal("%s: too many protocol drivers", __func__);

		engine->alt_driver[engine->num_alt++] = proto;
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

			if (driver != NULL && driver->id != id) {
				fm_log_error("created %s protocol driver \"%s\", but it provides protocol id %u",
						fm_protocol_id_to_string(id),
						driver->name,
						driver->id);
				abort();
			}
		}
	}

	return engine;
}

/*
 * Get the best protocol driver that implements protocol arp, icmp, udp, tcp, ...
 */
fm_protocol_t *
fm_protocol_engine_get_protocol(fm_protocol_engine_t *engine, const char *name)
{
	unsigned int id;

	id = fm_protocol_string_to_id(name);
	if (id != FM_PROTO_NONE)
		return engine->driver[id];
	return NULL;
}

/*
 * Get the protocol driver with the given name.
 * For instance, "icmp" will give you the icmp implementation using the standard
 * BSD socket interface, whereas "icmp-raw" may give you the one based on SOCK_RAW sockets.
 */
fm_protocol_t *
fm_protocol_engine_get_protocol_alt(fm_protocol_engine_t *engine, const char *name)
{
	unsigned int k;

	for (k = 0; k < engine->num_alt; ++k) {
		fm_protocol_t *proto = engine->alt_driver[k];

		if (!strcmp(proto->name, name))
			return proto;
	}

	return NULL;
}

fm_protocol_t *
fm_protocol_by_name(const char *name)
{
	fm_protocol_engine_t *engine = fm_protocol_engine_create_default();

	assert(engine != NULL);
	return fm_protocol_engine_get_protocol(engine, name);
}

fm_protocol_t *
fm_protocol_by_id(unsigned int proto_id)
{
	fm_protocol_engine_t *engine = fm_protocol_engine_create_default();

	assert(engine != NULL);
	if (proto_id >= __FM_PROTO_MAX)
		return NULL;
	return engine->driver[proto_id];
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
fm_protocol_create(const struct fm_protocol *proto)
{
	return proto;
}

static void
fm_protocol_init_rtt_estimator(unsigned int proto_id, fm_rtt_stats_t *rtt)
{
	switch (proto_id) {
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
fm_protocol_attach_rtt_estimator(fm_probe_class_t *pclass, fm_target_t *target, void *probe)
{
	fm_network_t *net = target->network;
	unsigned int proto_id = pclass->proto_id;
	fm_rtt_stats_t *rtt;

	/* no packet protocol, or some generic mechanism like with traceroute. handle yourselves. */
	if (proto_id == FM_PROTO_NONE)
		return;

	assert(proto_id <= __FM_PROTO_MAX);

	rtt = &net->rtt_stats[proto_id];
	if (rtt->nsamples == 0)
		fm_protocol_init_rtt_estimator(proto_id, rtt);

	// fm_probe_set_rtt_estimator(probe, rtt);
}

fm_socket_t *
fm_protocol_create_socket(fm_protocol_t *proto, int ipproto)
{
	fm_socket_t *sock;

	if (proto->create_socket == NULL)
		return NULL;
	sock = proto->create_socket(proto, ipproto);

	if (sock && sock->proto == NULL) {
		fm_log_warning("protocol driver %s forgot to attach itself to new socket", proto->name);
		fm_socket_attach_protocol(sock, proto);
	}

	return sock;
}

fm_socket_t *
fm_protocol_create_host_shared_socket(fm_protocol_t *proto, fm_target_t *target)
{
	if (target == NULL || proto->create_host_shared_socket == NULL)
		return NULL;

	return proto->create_host_shared_socket(proto, target);
}

/*
 * locate extants
 */
fm_extant_t *
fm_protocol_locate_error(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	if (proto->locate_error == NULL)
		return NULL;
	return proto->locate_error(proto, pkt, iter);
}

fm_extant_t *
fm_protocol_locate_response(fm_protocol_t *proto, fm_pkt_t *pkt, hlist_iterator_t *iter)
{
	if (proto->locate_response == NULL)
		return NULL;
	return proto->locate_response(proto, pkt, iter);
}
