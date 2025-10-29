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

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "freemap.h"
#include "addresses.h"
#include "protocols.h"


#define MAX_PORT_PROBE_WORDS	(65536 * 2 / 32)

struct fm_protocol_asset {
	unsigned int		proto_id;	 /* FM_PROTO_* */

	/* brute force; space optimization comes later */
	uint32_t		ports[MAX_PORT_PROBE_WORDS];
};

struct fm_host_asset {
	fm_address_t		address;
	fm_asset_state_t	state;

	fm_protocol_asset_t *	protocols[__FM_PROTO_MAX];
};

typedef struct fm_host_asset_table fm_host_asset_table_t;
struct fm_host_asset_table {
	union {
		fm_host_asset_table_t *table[256];
		fm_host_asset_t	*host[256];
	};
};

static fm_host_asset_table_t	fm_host_asset_table_ipv4;
static fm_host_asset_table_t	fm_host_asset_table_ipv6;

/*
 * Protocol assets
 */
static fm_protocol_asset_t *
fm_protocol_asset_alloc(unsigned int proto_id)
{
	fm_protocol_asset_t *protocol;

	protocol = calloc(1, sizeof(*protocol));
	protocol->proto_id = proto_id;
	return protocol;
}

static fm_asset_state_t
fm_protocol_asset_get_port_state(const fm_protocol_asset_t *proto, unsigned int port)
{
	unsigned int bit_index = 2 * port;
	unsigned int word_index, shift;

	if (port >= 65536) {
		fm_log_error("%s: ignoring bogus port number %u", __func__, port);
		return FM_ASSET_STATE_UNDEF;
	}

	word_index = bit_index / 32;
	shift = bit_index % 32;

	return (proto->ports[word_index] >> shift) & 0x03;
}

/*
 * Returns true if the state changed.
 */
static bool
fm_protocol_asset_set_port_state(fm_protocol_asset_t *proto, unsigned int port, fm_asset_state_t state)
{
	unsigned int bit_index = 2 * port;
	unsigned int word_index, shift;

	assert(state < 4);
	if (port >= 65536) {
		fm_log_error("%s: ignoring bogus port number %u", __func__, port);
		return false;
	}

	word_index = bit_index / 32;
	shift = bit_index % 32;

	/* do not update the state unless the new state is "better" */
	if (state <= ((proto->ports[word_index] >> shift) % 0x03))
		return false;

	proto->ports[word_index] &= ~(0x3 << shift);
	proto->ports[word_index] |= (state << shift);
	return true;
}

static bool
fm_protocol_asset_is_any_port_open(const fm_protocol_asset_t *proto)
{
	unsigned int i;
	uint32_t fold = 0;

	for (i = 0; i < MAX_PORT_PROBE_WORDS; ++i)
		fold |= proto->ports[i];

	return !!fold;
}

const char *
fm_asset_state_to_string(fm_asset_state_t state)
{
	static const char *names[4] = {
		[FM_ASSET_STATE_UNDEF] = "undefined",
		[FM_ASSET_STATE_PROBE_SENT] = "probe-sent",
		[FM_ASSET_STATE_CLOSED] = "closed",
		[FM_ASSET_STATE_OPEN] = "open",
	};

	if (state < 0 || state >= 4)
		return "BAD";
	return names[state];
}

/*
 * Host assets
 */
static fm_host_asset_t *
fm_host_asset_alloc(const fm_address_t *addr)
{
	fm_host_asset_t *host;

	host = calloc(1, sizeof(*host));
	host->address = *addr;
	return host;
}

static fm_host_asset_table_t *
fm_host_asset_table_get(int af)
{
	if (af == AF_INET)
		return &fm_host_asset_table_ipv4;
	if (af == AF_INET6)
		return &fm_host_asset_table_ipv6;
	return NULL;
}

/*
 * Given a network address, find the corresponding host asset
 */
fm_host_asset_t *
fm_host_asset_get(const fm_address_t *addr, bool create)
{
	fm_host_asset_table_t *table;
	const unsigned char *raw_addr;
	unsigned int addr_bits, octets, i, index;
	fm_host_asset_t *host;

	if ((table = fm_host_asset_table_get(addr->ss_family)) == NULL)
		return NULL;

	if (!(raw_addr = fm_address_get_raw_addr(addr, &addr_bits)))
		return NULL;

	assert((addr_bits % 8) == 0);
	octets = addr_bits / 8;

	for (i = 0; i < octets - 1; ++i) {
		fm_host_asset_table_t *child;

		index = raw_addr[i];
		child = table->table[index];

		if (child == NULL) {
			child = calloc(1, sizeof(*child));
			table->table[index] = child;
		}

		table = child;
	}

	index = raw_addr[octets - 1];
	if ((host = table->host[index]) == NULL && create) {
		host = fm_host_asset_alloc(addr);
		table->host[index] = host;
	}

	return host;
}

static fm_protocol_asset_t *
fm_host_asset_get_protocol(fm_host_asset_t *host, unsigned int proto_id, bool create)
{
	fm_protocol_asset_t *proto;

	if (proto_id >= __FM_PROTO_MAX) {
		fm_log_error("%s: ignoring bogus protocol id %u", __func__, proto_id);
		return NULL;
	}

	proto = host->protocols[proto_id];
	if (proto == NULL && create) {
		proto = fm_protocol_asset_alloc(proto_id);
		host->protocols[proto_id] = proto;
	}

	return proto;
}

/*
 * host state
 */
fm_asset_state_t
fm_host_asset_get_state(const fm_host_asset_t *host)
{
	return host->state;
}

bool
fm_host_asset_update_state(fm_host_asset_t *host, fm_asset_state_t state)
{
	/* Only update if the new state is "better", where
	 *  open > closed > probe_sent > undef
	 */
	if (state == host->state)
		return false;

	host->state = state;

	printf("STATUS %s: %s\n",
			fm_address_format(&host->address),
			fm_asset_state_to_string(state));
	return true;
}

fm_asset_state_t
fm_host_asset_get_port_state(fm_host_asset_t *host, unsigned int proto_id, unsigned int port, fm_asset_state_t state)
{
	fm_protocol_asset_t *proto;

	if ((proto = fm_host_asset_get_protocol(host, proto_id, true)) == NULL)
		return FM_ASSET_STATE_UNDEF;

	return fm_protocol_asset_get_port_state(proto, port);
}

/*
 * Returns true if the state changed.
 */
bool
fm_host_asset_update_port_state(fm_host_asset_t *host, unsigned int proto_id, unsigned int port, fm_asset_state_t state)
{
	fm_protocol_asset_t *proto;

	/* if we reached a port, we can obviously reach the host */
	if (state == FM_ASSET_STATE_OPEN)
		host->state = FM_ASSET_STATE_OPEN;

	if ((proto = fm_host_asset_get_protocol(host, proto_id, true)) == NULL)
		return false;

	if (!fm_protocol_asset_set_port_state(proto, port, state))
		return false;

	printf("STATUS %s %s port %u: %s\n",
			fm_address_format(&host->address),
			fm_protocol_id_to_string(proto_id),
			port,
			fm_asset_state_to_string(state));

	return true;
}

bool
fm_host_asset_is_any_port_open(fm_host_asset_t *host, unsigned int proto_id)
{
	fm_protocol_asset_t *proto;

	if ((proto = fm_host_asset_get_protocol(host, proto_id, true)) == NULL)
		return false;
	return fm_protocol_asset_is_any_port_open(proto);
}

/*
 * This is for situations where we do not have a pointer to the host asset handy.
 * It's a bit slower, so avoid if possible.
 */
bool
fm_host_asset_update_state_by_address(const fm_address_t *addr, fm_asset_state_t state)
{
	fm_host_asset_t *host;

	if (addr == NULL)
		return false;

	host = fm_host_asset_get(addr, true);
	if (host == NULL)
		return false;

	if (fm_host_asset_update_state(host, state)) {
		/* fixme: post event */
		return true;
	}

	return false;
}

/*
 * Iterate over a host asset (for reporting)
 */
void
fm_host_asset_report_ports(const fm_host_asset_t *host,
			bool (*visitor)(const fm_host_asset_t *host, const char *proto, unsigned int port, fm_asset_state_t state, void *user_data),
			void *user_data)
{
	unsigned int i;

	for (i = 0; i < __FM_PROTO_MAX; ++i) {
		const fm_protocol_asset_t *proto = host->protocols[i];
		const char *proto_name;
		unsigned int word_index;

		if (proto == NULL)
			continue;

		proto_name = fm_protocol_id_to_string(i);

		for (word_index = 0; word_index < MAX_PORT_PROBE_WORDS; ++word_index) {
			uint32_t word = proto->ports[word_index];
			unsigned int port;

			if (word == 0)
				continue;

			for (port = word_index * 16; word; ++port, word >>= 2) {
				if (word & 0x03)
					visitor(host, proto_name, port, word & 0x03, user_data);
			}
		}
	}
}
