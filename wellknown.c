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

#include "freemap.h"
#include "wellknown.h"
#include "buffer.h"

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

fm_buffer_t *
fm_wellknown_service_build_packet(fm_wellknown_service_t *wks)
{
	fm_probe_packet_t *wpkt = wks->probe_packet;
	fm_buffer_t *bp;

	bp = fm_buffer_alloc(wpkt->len);
	if (!fm_buffer_append(bp, wpkt->data, wpkt->len))
		fm_log_fatal("%s: something spooky is happening", __func__);

	return bp;
}
