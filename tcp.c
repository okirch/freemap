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
 * Simple TCP scanning functions
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <linux/errqueue.h>

#include "scanner.h"
#include "protocols.h"
#include "target.h" /* for fm_probe_t */
#include "socket.h" /* for fm_probe_t */

static fm_socket_t *	fm_tcp_create_bsd_socket(fm_protocol_t *proto, int af);
static bool		fm_tcp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt);
static bool		fm_tcp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt);
static bool		fm_tcp_connecton_established(fm_protocol_t *proto, const fm_address_t *);
static fm_rtt_stats_t *	fm_tcp_create_rtt_estimator(const fm_protocol_t *proto, unsigned int netid);
static fm_probe_t *	fm_tcp_create_port_probe(fm_protocol_t *proto, fm_target_t *target, uint16_t port);

static struct fm_protocol_ops	fm_tcp_bsdsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "tcp",
	.id		= FM_PROTO_TCP,

	.create_socket	= fm_tcp_create_bsd_socket,
	.process_packet = fm_tcp_process_packet,
	.process_error	= fm_tcp_process_error,
	.connection_established = fm_tcp_connecton_established,

	.create_rtt_estimator = fm_tcp_create_rtt_estimator,
	.create_port_probe = fm_tcp_create_port_probe,
};

fm_protocol_t *
fm_tcp_bsdsock_create(void)
{
	return fm_protocol_create(&fm_tcp_bsdsock_ops);
}

static fm_rtt_stats_t *
fm_tcp_create_rtt_estimator(const fm_protocol_t *proto, unsigned int netid)
{
	return fm_rtt_stats_create(proto->ops->id, netid, 250 / 2, 2);
}

static fm_socket_t *
fm_tcp_create_bsd_socket(fm_protocol_t *proto, int af)
{
	return fm_socket_create(af, SOCK_STREAM, 0);
}

/*
 * Track extant TCP requests.
 * We currently do not track individual packets and their response(s), we just
 * record the fact that we *did* send to a specific port.
 * We do not even distinguish by the source port used on our end.
 */
struct tcp_extant_info {
	unsigned int		port;
};

static bool
fm_tcp_expect_response(fm_probe_t *probe, int af, unsigned int port)
{
	struct tcp_extant_info info = { .port = port };

	fm_extant_alloc(probe, af, IPPROTO_TCP, &info, sizeof(info));
	return true;
}

static fm_extant_t *
fm_tcp_locate_probe(int af, const fm_address_t *target_addr)
{
	fm_target_t *target;
	unsigned short port;
	hlist_iterator_t iter;
	fm_extant_t *extant;

	target = fm_target_pool_find(target_addr);
	if (target == NULL)
		return NULL;

	port = fm_address_get_port(target_addr);

	fm_extant_iterator_init(&iter, &target->expecting);
	while ((extant = fm_extant_iterator_match(&iter, af, IPPROTO_TCP)) != NULL) {
		const struct tcp_extant_info *info = (struct tcp_extant_info *) (extant + 1);

		if (info->port == port)
			return extant;
	}

	return extant;
}

/*
 * Handle TCP reply packet
 */
static bool
fm_tcp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant;

	extant = fm_tcp_locate_probe(pkt->family, &pkt->recv_addr);
	if (extant != NULL) {
		fm_extant_received_reply(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

static bool
fm_tcp_connecton_established(fm_protocol_t *proto, const fm_address_t *target_addr)
{
	fm_extant_t *extant;

	extant = fm_tcp_locate_probe(target_addr->ss_family, target_addr);
	if (extant != NULL) {
		fm_extant_received_reply(extant, NULL);
		fm_extant_free(extant);
	}

	return true;
}

static bool
fm_tcp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant;

	if (pkt->info.ee && pkt->info.ee->ee_origin == SO_EE_ORIGIN_LOCAL) {
		fm_log_debug("%s: local error %u", fm_address_format(&pkt->recv_addr), pkt->info.ee->ee_errno);
	}

	extant = fm_tcp_locate_probe(pkt->family, &pkt->recv_addr);
	if (extant != NULL) {
		fm_extant_received_error(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

/*
 * TCP port probes using standard BSD sockets
 */
struct fm_tcp_port_probe {
	fm_probe_t	base;

	unsigned int	port;
	fm_address_t	host_address;
	fm_socket_t *	sock;
};

static void
fm_tcp_port_probe_destroy(fm_probe_t *probe)
{
	struct fm_tcp_port_probe *tcp = (struct fm_tcp_port_probe *) probe;

	if (tcp->sock != NULL) {
		fm_socket_set_callback(tcp->sock, NULL, NULL);
		fm_socket_free(tcp->sock);
		tcp->sock = NULL;
	}
}

static fm_fact_t *
fm_tcp_port_probe_send(fm_probe_t *probe)
{
	struct fm_tcp_port_probe *tcp = (struct fm_tcp_port_probe *) probe;

	if (tcp->sock == NULL) {
		tcp->sock = fm_protocol_create_socket(probe->proto, tcp->host_address.ss_family);
		if (tcp->sock == NULL) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to create TCP socket for %s: %m",
					fm_address_format(&tcp->host_address));
		}

		/* fm_socket_enable_recverr(tcp->sock); */

		if (!fm_socket_connect(tcp->sock, &tcp->host_address)) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to connect TCP socket for %s: %m",
					fm_address_format(&tcp->host_address));
		}
	}

	fm_tcp_expect_response(probe, tcp->host_address.ss_family, tcp->port);

	return NULL;
}

static fm_fact_t *
fm_tcp_port_probe_render_verdict(fm_probe_t *probe, fm_probe_verdict_t verdict)
{
	struct fm_tcp_port_probe *tcp = (struct fm_tcp_port_probe *) probe;

	switch (verdict) {
	case FM_PROBE_VERDICT_REACHABLE:
		return fm_fact_create_port_reachable("tcp", tcp->port);

	case FM_PROBE_VERDICT_UNREACHABLE:
		return fm_fact_create_port_unreachable("tcp", tcp->port);

	case FM_PROBE_VERDICT_TIMEOUT:
		return fm_fact_create_port_heisenberg("tcp", tcp->port);

	default:
		break;
	}

	return NULL;
}

static struct fm_probe_ops fm_tcp_port_probe_ops = {
	.obj_size	= sizeof(struct fm_tcp_port_probe),
	.name 		= "tcp",

	.destroy	= fm_tcp_port_probe_destroy,
	.send		= fm_tcp_port_probe_send,
	.render_verdict	= fm_tcp_port_probe_render_verdict,
};

static fm_probe_t *
fm_tcp_create_port_probe(fm_protocol_t *proto, fm_target_t *target, uint16_t port)
{
	struct sockaddr_storage tmp_address = target->address;
	struct fm_tcp_port_probe *probe;
	char name[32];

	if (!fm_address_set_port(&tmp_address, port))
		return NULL;

	snprintf(name, sizeof(name), "tcp/%u", port);

	probe = (struct fm_tcp_port_probe *) fm_probe_alloc(name, &fm_tcp_port_probe_ops, proto, target);

	probe->port = port;
	probe->host_address = tmp_address;
	probe->sock = NULL;

	/* For the time being, assume that any TCP service may take up to .5 sec for the
	 * queued TCP connection to be accepted. */
	probe->base.rtt_application_bias = 500;

	fm_log_debug("Created TCP socket probe for %s\n", fm_address_format(&probe->host_address));
	return &probe->base;
}
