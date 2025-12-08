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
#include "logging.h"
#include "buffer.h"

static unsigned int	fm_protocol_directory_count;
static fm_protocol_t *	fm_protocol_directory[256];

static fm_protocol_t *	fm_standard_protocol[__FM_PROTO_MAX];

/*
 * Using gcc constructors, all our protocol drivers come here when the
 * application starts.
 * We inspect and vet them later.
 */
void
fm_protocol_directory_add(struct fm_protocol *proto)
{
	assert(proto->name != NULL);
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
		const fm_protocol_t *ops = fm_protocol_directory[i];

		printf("%-12s; implements %s\n", ops->name, fm_protocol_id_to_string(ops->id));
	}
}

/*
 * Set up the table of standard protocols
 */
static inline void
fm_protocol_setup(void)
{
	static bool initialized = false;
	unsigned int i;

	if (initialized)
		return;
	initialized = true;

	for (i = 0; i < fm_protocol_directory_count; ++i) {
		fm_protocol_t *proto = fm_protocol_directory[i];
		unsigned int id;

		id = proto->id;
		if (id != FM_PROTO_NONE && fm_standard_protocol[id] == NULL)
			fm_standard_protocol[id] = proto;
	}
}

/*
 * Look for protocol by name
 */
fm_protocol_t *
fm_protocol_by_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < fm_protocol_directory_count; ++i) {
		fm_protocol_t *proto = fm_protocol_directory[i];

		if (!strcmp(proto->name, name))
			return proto;
	}
	return NULL;
}

fm_protocol_t *
fm_protocol_by_id(unsigned int proto_id)
{
	fm_protocol_setup();
	return fm_standard_protocol[proto_id];
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
fm_protocol_create_socket(fm_protocol_t *proto, int family, const fm_address_t *bind_addr)
{
	fm_socket_t *sock;

	if (proto->create_socket == NULL)
		return NULL;

	if (bind_addr && bind_addr->family != family)
		return NULL;

	sock = proto->create_socket(proto, family, bind_addr);
	if (sock != NULL) {
		assert(sock->proto != NULL);

		/* The protocol driver may have bound the socket already; if not, we'll do that now */
		if (sock->local_address.family == AF_UNSPEC && bind_addr != NULL
		 && !fm_socket_bind(sock, bind_addr)) {
			fm_log_error("Cannot bind %s socket to address %s: %m",
					proto->name,
					fm_address_format(bind_addr));
			fm_socket_free(sock);
			return NULL;
		}
	}

	return sock;
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
