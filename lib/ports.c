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

#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#include "freemap.h"
#include "logging.h"

/* FIXME: make these configurable */
#define FM_EPHEM_BASE_PORT	10000
#define FM_EPHEM_LAST_PORT	(FM_EPHEM_BASE_PORT + 1000)

typedef struct fm_port_reservation {
	int		fd;
	uint16_t	port;
} fm_port_reservation_t;

static fm_port_reservation_t	fm_port_reservations[__FM_PROTO_MAX];

/*
 * For probes like TCP or UDP, we do want to reserve a local port
 * so that we don't end up confusing some existing service.
 * This function reserves one port for each supported protocol.
 */
int
fm_port_reserve(unsigned int proto_id)
{
	fm_port_reservation_t *resv;

	if (proto_id >= __FM_PROTO_MAX)
		return -1;

	resv = &fm_port_reservations[proto_id];
	if (resv->port == 0) {
		fm_address_t local_addr;
		int sotype, value = 0;
		socklen_t alen;
		uint16_t port;

		if (proto_id == FM_PROTO_UDP)
			sotype = SOCK_DGRAM;
		else if (proto_id == FM_PROTO_TCP)
			sotype = SOCK_STREAM;
		else {
			fm_log_error("Port reservations for protocol %s not yet implemented", fm_protocol_id_to_string(proto_id));
			return -1;
		}

		resv->fd = socket(AF_INET6, sotype, 0);
		if (resv->fd < 0) {
			fm_log_error("failed to create %s socket: %m", fm_protocol_id_to_string(proto_id));
			return -1;
		}

		/* Make sure this port is valid for v4 and v6 */
		setsockopt(resv->fd, SOL_IPV6, IPV6_V6ONLY, &value, sizeof(value));

		memset(&local_addr, 0, sizeof(local_addr));
		local_addr.family = AF_INET6;

		port = FM_EPHEM_BASE_PORT;
		while (port < FM_EPHEM_LAST_PORT) {
			fm_address_set_port(&local_addr, port++);

			if (bind(resv->fd, (struct sockaddr *) &local_addr, sizeof(local_addr)) >= 0)
				break;

			if (errno == EADDRINUSE)
				continue;

			fm_log_error("failed to bind %s socket for port reservation: %m", fm_protocol_id_to_string(proto_id));
			return -1;
		}

		alen = sizeof(local_addr);
		getsockname(resv->fd, (struct sockaddr *) &local_addr, &alen);
		resv->port = fm_address_get_port(&local_addr);

		fm_log_debug("Reserved local %s port %u", fm_protocol_id_to_string(proto_id), resv->port);
	}

	return resv->port;
}
