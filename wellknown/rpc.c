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

/*
 * Try to elicit a response from an unknown RPC service
 */
static uint8_t		rpc_invalid_null_data[] = {
	1, 2, 3, 4,	/* XID */
	0, 0, 0, 0,	/* CALL */
	0, 0, 0, 1,	/* bad RPC version (1) */

	0, 0, 0, 1,	/* random RPC program (1) */
	0, 0, 0, 1,	/* random RPC program version (1) */
	0, 0, 0, 0,	/* RPC NULL call */

	0, 0, 0, 0,	/* RPC NULL auth and verf */
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
};

static fm_probe_packet_t	rpc_invalid_null_probe = {
	.data =		rpc_invalid_null_data,
	.len =		sizeof(rpc_invalid_null_data),
};

fm_wellknown_service_t	unknown_rpc_service = {
	.id		= "unknown sunrpc",
	.probe_packet	= &rpc_invalid_null_probe,
};

static uint8_t		rpc_pmap_null_data[] = {
	1, 2, 3, 5,	/* XID */
	0, 0, 0, 0,	/* CALL */
	0, 0, 0, 2,	/* RPC version (2) */

	0, 0, 0, 111,	/* random RPC program (1) */
	0, 0, 0, 1,	/* RPC program version (1) */
	0, 0, 0, 0,	/* RPC NULL call */

	0, 0, 0, 0,	/* RPC NULL auth and verf */
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
};

static fm_probe_packet_t	rpc_pmap_null_probe = {
	.data =		rpc_pmap_null_data,
	.len =		sizeof(rpc_pmap_null_data),
};

fm_wellknown_service_t	portmap_rpc_service = {
	.id		= "sunrpc portmap",
	.probe_packet	= &rpc_pmap_null_probe,
};
