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

#include "assets.h"
#include "freemap.h"
#include "addresses.h"
#include "protocols.h"

#define FM_HOST_ASSET_ATTACHED	0x0001
#define FM_HOST_ASSET_MAPPED	0x0002


static bool			fm_host_asset_map(fm_host_asset_t *host);

static fm_host_asset_table_t	fm_host_asset_table_ipv4;
static fm_host_asset_table_t	fm_host_asset_table_ipv6;

/*
 * Protocol assets
 */
static fm_asset_state_t
fm_protocol_asset_get_port_state(const fm_protocol_asset_t *proto, unsigned int port)
{
	unsigned int bit_index = 2 * port;
	unsigned int word_index, shift;

	if (port >= 65536) {
		fm_log_error("%s: ignoring bogus port number %u", __func__, port);
		return FM_ASSET_STATE_UNDEF;
	}

	if (port >= proto->ondisk->max_port)
		return FM_ASSET_STATE_UNDEF;

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

	if (port >= proto->ondisk->max_port)
		proto->ondisk->max_port = port + 1;

	word_index = bit_index / 32;
	shift = bit_index % 32;

	/* do not update the state unless the new state is "better" */
	if (state <= ((proto->ports[word_index] >> shift) % 0x03))
		return false;

	proto->ports[word_index] &= ~(0x3 << shift);
	proto->ports[word_index] |= (state << shift);
	return true;
}

/*
 * This is a hack, and it's not working as designed.
 */
fm_asset_state_t
fm_protocol_asset_get_state(const fm_protocol_asset_t *proto)
{
	unsigned int i;
	uint32_t fold = 0;

	for (i = 0; i < MAX_PORT_PROBE_WORDS; ++i)
		fold |= proto->ports[i];

	fold |= (fold >> 16);
	fold |= (fold >>  8);
	fold |= (fold >>  4);
	fold |= (fold >>  2);
	return fold & 0x03;
}

bool
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

static inline int
fm_host_asset_iterator_update(fm_host_asset_iterator_t *iter, int depth, unsigned int value)
{
	assert(depth < 16);

	if (value >= 256 && depth >= 0) {
		iter->raw[depth] = 0;
		/* This will actually read raw[-1] at some point, but we don't mind */
		value = iter->raw[--depth] + 1;
	}

	if (depth < 0) {
		iter->done = true;
	} else {
		iter->raw[depth] = value;
	}
	return depth;
}

static fm_host_asset_t *
fm_host_asset_find_next(fm_host_asset_table_t *root, fm_host_asset_iterator_t *iter)
{
	fm_host_asset_table_t *tables[16];
	int depth, max_depth;

	tables[0] = root;
	max_depth = iter->addr_len;
	depth = 0;

	while (depth >= 0) {
		fm_host_asset_table_t *table;
		fm_host_asset_table_t *child;
		unsigned int index;

		table = tables[depth];

		index = iter->raw[depth];
		do {
			child = table->table[index++];
		} while (!child && index < 256);

		if (child != NULL) {
			fm_host_asset_iterator_update(iter, depth, index);

			if (fm_debug_level > 4) {
				int k;

				printf("%*.*s %u %p; raw=", depth, depth, "", index, child);
				for (k = 0; k <= depth; ++k)
					printf(" %d", iter->raw[k]);
				printf("\n");
			}

			if (++depth >= max_depth)
				return (fm_host_asset_t *) child;

			tables[depth] = child;
			iter->raw[depth] = 0; /* start scanning next level at index 0 */
			continue;
		}

		depth = fm_host_asset_iterator_update(iter, depth, index);
		if (depth < 0)
			return NULL;
	}

	return NULL;
}


/*
 * Attach or detach a host asset
 */
void
fm_host_asset_attach(fm_host_asset_t *host)
{
	host->map_flags |= FM_HOST_ASSET_ATTACHED;
	if (!fm_host_asset_map(host)) {
		fm_log_error("Cannot attach backing data for %s", fm_address_format(&host->address));
		/* What can we do? We can abort, we can refuse to update, or we can write
		 * results to some sort of emergency file which than can be merged later, somehow */
	}
}

void
fm_host_asset_detach(fm_host_asset_t *host)
{
	host->map_flags &= ~FM_HOST_ASSET_ATTACHED;

	if (host->mapping != NULL) {
		/* unmap on-disk data */
		fm_assetio_unmap_host(host);
	}
}

static bool
fm_host_asset_map(fm_host_asset_t *host)
{
	if (host->mapping != NULL)
		return true;

	if (!fm_assetio_map_host(host))
		return false;

	assert(host->mapping != NULL);
	return true;
}


static fm_protocol_asset_t *
fm_host_asset_get_protocol(fm_host_asset_t *host, unsigned int proto_id, bool create)
{
	if (proto_id >= __FM_PROTO_MAX) {
		fm_log_error("%s: ignoring bogus protocol id %u", __func__, proto_id);
		return NULL;
	}

	if (!fm_host_asset_is_mapped(host))
		return NULL;

	return &host->protocols[proto_id];
}

/*
 * host state
 */
fm_asset_state_t
fm_host_asset_get_state(fm_host_asset_t *host)
{
	if (!fm_host_asset_is_mapped(host))
		return 0;

	return host->main->host_state;
}

bool
fm_host_asset_update_state(fm_host_asset_t *host, fm_asset_state_t state)
{
	if (!fm_host_asset_is_mapped(host))
		return false;

	/* Only update if the new state is "better", where
	 *  open > closed > probe_sent > undef
	 */
	if (state <= host->main->host_state)
		return false;

	host->main->host_state = state;

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

	if (!fm_host_asset_is_mapped(host))
		return false;

	/* if we reached a port, we can obviously reach the host */
	if (state == FM_ASSET_STATE_OPEN)
		host->main->host_state = FM_ASSET_STATE_OPEN;

	if ((proto = fm_host_asset_get_protocol(host, proto_id, true)) == NULL)
		return false;

	if (!fm_protocol_asset_set_port_state(proto, port, state))
		return false;

	if (state > proto->ondisk->state)
		proto->ondisk->state = state;

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
	bool ok;

	if (addr == NULL)
		return false;

	host = fm_host_asset_get(addr, true);
	if (host == NULL)
		return false;

	if (fm_host_asset_is_mapped(host)) {
		/* easy case - already mapped */
		ok = fm_host_asset_update_state(host, state);
	} else {
		/* map temporarily */
		if (!fm_host_asset_map(host))
			return false;

		ok = fm_host_asset_update_state(host, state);
		fm_assetio_unmap_host(host);
	}

	if (ok) {
		/* fixme: post event */
		return true;
	}

	return false;
}

/*
 * Iterate over host assets
 */
void
fm_host_asset_iterator_init(fm_host_asset_iterator_t *iter)
{
	memset(iter, 0, sizeof(*iter));
	iter->family = AF_INET;
	iter->addr_len = 4;
}

fm_host_asset_t *
fm_host_asset_iterator_next(fm_host_asset_iterator_t *iter)
{
	fm_host_asset_table_t *table;

	if (iter->family == AF_UNSPEC || iter->done)
		return NULL;

	table = fm_host_asset_table_get(iter->family);
	return fm_host_asset_find_next(table, iter);
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
		const fm_protocol_asset_t *proto = &host->protocols[i];
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

void
fm_assets_attach(const char *asset_dir)
{
	fm_assetio_set_mapping(asset_dir, true);
}

void
fm_assets_attach_readonly(const char *asset_dir)
{
	fm_assetio_set_mapping(asset_dir, false);
}

void
fm_host_asset_cache_prime(void)
{
	fm_assets_read_table(AF_INET, &fm_host_asset_table_ipv4);
	fm_assets_read_table(AF_INET6, &fm_host_asset_table_ipv6);
}
