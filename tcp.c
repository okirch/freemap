/*
 * Copyright (C) 2023 Olaf Kirch <okir@suse.com>
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

#include "scanner.h"
#include "protocols.h"
#include "target.h" /* for fm_probe_t */

static fm_probe_t *	fm_tcp_create_port_probe(fm_protocol_engine_t *proto, fm_target_t *target, uint16_t port);

struct fm_tcp_engine_default {
	fm_protocol_engine_t	base;
};

static struct fm_protocol_ops	fm_tcp_engine_default_ops = {
	.obj_size	= sizeof(struct fm_tcp_engine_default),
	.name		= "tcp",

	.create_port_probe = fm_tcp_create_port_probe,
};

fm_protocol_engine_t *
fm_tcp_engine_create(void)
{
	struct fm_tcp_engine_default *tcp;

	tcp = (struct fm_tcp_engine_default *) fm_protocol_engine_create(&fm_tcp_engine_default_ops);

	return &tcp->base;
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

static void
fm_tcp_port_probe_callback(fm_socket_t *sock, int bits, void *user_data)
{
	struct fm_tcp_port_probe *tcp = user_data;

	assert(tcp->sock == sock);

	if (bits & POLLERR) {
		printf("TCP probe %s: error\n", fm_address_format(&tcp->host_address));
		fm_probe_mark_port_unreachable(&tcp->base, "tcp", tcp->port);
	} else if (bits & POLLOUT) {
		printf("TCP probe %s: reachable\n", fm_address_format(&tcp->host_address));
		fm_probe_mark_port_reachable(&tcp->base, "tcp", tcp->port);
	}

	fm_socket_close(sock);
}

static fm_fact_t *
fm_tcp_port_probe_send(fm_probe_t *probe)
{
	struct fm_tcp_port_probe *tcp = (struct fm_tcp_port_probe *) probe;

	if (tcp->sock == NULL) {
		tcp->sock = fm_socket_create(tcp->host_address.ss_family, SOCK_STREAM, 0);
		if (tcp->sock == NULL) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to create TCP socket for %s: %m",
					fm_address_format(&tcp->host_address));
		}

		fm_socket_set_callback(tcp->sock, fm_tcp_port_probe_callback, probe);

		if (!fm_socket_connect(tcp->sock, &tcp->host_address)) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to connect TCP socket for %s: %m",
					fm_address_format(&tcp->host_address));
		}
	}

	return NULL;
}

static struct fm_probe_ops fm_tcp_port_probe_ops = {
	.obj_size	= sizeof(struct fm_tcp_port_probe),
	.name 		= "tcp",

	.destroy	= fm_tcp_port_probe_destroy,
	.send		= fm_tcp_port_probe_send,
};

static fm_probe_t *
fm_tcp_create_port_probe(fm_protocol_engine_t *proto, fm_target_t *target, uint16_t port)
{
	struct sockaddr_storage tmp_address = target->address;
	struct fm_tcp_port_probe *probe;

	if (!fm_address_set_port(&tmp_address, port))
		return NULL;

	probe = (struct fm_tcp_port_probe *) fm_probe_alloc(&fm_tcp_port_probe_ops);

	probe->port = port;
	probe->host_address = tmp_address;
	probe->sock = NULL;

	printf("Created TCP socket probe for %s\n", fm_address_format(&probe->host_address));
	return &probe->base;
}
