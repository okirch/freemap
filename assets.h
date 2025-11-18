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

#ifndef FREEMAP_ASSETS_H
#define FREEMAP_ASSETS_H

#include "freemap.h"

#define MAX_PORT_PROBE_WORDS	(65536 * 2 / 32)
#define MAX_TOPO_PROBE_ADDRS	64


/*
 * on-disk asset data.
 * For a "live" asset, these regions are mapped into the address
 * space and the in-memory host_asset object has pointers to it
 *
 * Note that the bitmap fields describing the port state should be
 * aligned to 4k page boundaries.
 */
typedef uint32_t		fm_asset_port_bitmap_t[MAX_PORT_PROBE_WORDS];
typedef unsigned char		fm_address_asset_t[16];

typedef struct fm_protocol_asset_ondisk {
	unsigned int		state;
	unsigned int		max_port;
} fm_protocol_asset_ondisk_t;

typedef struct fm_route_asset_ondisk {
	unsigned int		last_ttl;

	uint32_t		present[(MAX_TOPO_PROBE_ADDRS + 31)/32];
	uint32_t		flapping[(MAX_TOPO_PROBE_ADDRS + 31)/32];
	unsigned int		rtt[MAX_TOPO_PROBE_ADDRS];
	fm_address_asset_t	address[MAX_TOPO_PROBE_ADDRS];
} fm_route_asset_ondisk_t;

typedef struct fm_name_asset_ondisk {
	char			hostname[256];

	uint16_t		arp_type;
	unsigned char		link_addr_len;
	unsigned char		link_addr[13];
} fm_name_asset_ondisk_t;

typedef struct fm_host_asset_ondisk {
	unsigned int		host_state;

	fm_protocol_asset_ondisk_t protocols[__FM_PROTO_MAX];
	fm_name_asset_ondisk_t	names;
} fm_host_asset_ondisk_t;

typedef struct fm_assetio_mapped {
	void *			addr;
	size_t			size;
} fm_assetio_mapped_t;

/*
 * In-memory data structurs
 */
struct fm_protocol_asset {
	unsigned int		proto_id;	 /* FM_PROTO_* */

	fm_protocol_asset_ondisk_t *ondisk;
	uint32_t *		ports;
};

struct fm_host_asset {
	fm_address_t		address;

	int			map_flags;

	fm_assetio_mapped_t *	mapping;

	fm_host_asset_ondisk_t *main;
	fm_protocol_asset_t	protocols[__FM_PROTO_MAX];

	/* FIXME: We don't need two different routes; the asset is either v4 or v6 */
	fm_route_asset_ondisk_t	*ipv4_route;
	fm_route_asset_ondisk_t	*ipv6_route;
};


/*
 * Actually, the host asset table implementation is total crap for IPv6
 * because it wastes 8 levels of table on randomized addresses.
 */
typedef struct fm_host_asset_table fm_host_asset_table_t;
struct fm_host_asset_table {
	union {
		fm_host_asset_table_t *table[256];
		fm_host_asset_t	*host[256];
	};
};

typedef struct fm_host_asset_iterator {
	unsigned int		family;
	unsigned int		addr_len;
	unsigned int		next_family;
	unsigned char		raw[16];
	bool			done;
} fm_host_asset_iterator_t;

extern fm_asset_state_t	fm_protocol_asset_get_state(const fm_protocol_asset_t *proto);
extern bool		fm_protocol_asset_is_any_port_open(const fm_protocol_asset_t *proto);

extern void		fm_host_asset_cache_prime(void);
extern void		fm_assets_read_table(int family, fm_host_asset_table_t *table);

extern bool		fm_assetio_map_host(fm_host_asset_t *host);
extern void		fm_assetio_unmap_host(fm_host_asset_t *host);

extern void		fm_assetio_set_mapping(const char *project_dir, bool rw);

extern void		fm_host_asset_iterator_init(fm_host_asset_iterator_t *);
extern void		fm_host_asset_iterator_init_family(fm_host_asset_iterator_t *iter, int family);
extern fm_host_asset_t *fm_host_asset_iterator_next(fm_host_asset_iterator_t *);

extern bool		fm_host_asset_hot_map(fm_host_asset_t *);

static inline bool
fm_host_asset_is_mapped(const fm_host_asset_t *host)
{
	return host->mapping != NULL;
}

#endif /* FREEMAP_ASSETS_H */
