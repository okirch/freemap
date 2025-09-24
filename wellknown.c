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
 * Simple UDP scanning functions
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>

#include "freemap.h"
#include "wellknown.h"

fm_wellknown_service_t *
fm_wellknown_service_for_port(const char *protocol_id, unsigned int port)
{
	if (!strcmp(protocol_id, "udp")) {
		if (port == 53)
			return &dns_service;

		if (port == 5353)
			return &mdns_service;

		if (port == 111)
			return &portmap_rpc_service;

		if (port == 2049
		 || (512 < port && port < 1024))
			return &unknown_rpc_service;
	}

	return NULL;
}
