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
#include "protocols.h"

static fm_protocol_engine_t *
fm_protocol_engine_create_socket(void)
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

fm_protocol_engine_t *
fm_protocol_engine_create_default(void)
{
	fm_protocol_engine_t *proto;

	proto = fm_protocol_engine_create_socket();

	assert(proto->icmp == NULL || proto->icmp->ops->id == FM_PROTO_ICMP);
	assert(proto->udp == NULL || proto->udp->ops->id == FM_PROTO_UDP);
	assert(proto->tcp == NULL || proto->tcp->ops->id == FM_PROTO_TCP);

	return proto;
}

