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


/*
 * on-disk asset data.
 * For a "live" asset, these regions are mapped into the address
 * space and the in-memory host_asset object has pointers to it
 *
 * Note that the bitmap fields describing the port state should be
 * aligned to 4k page boundaries.
 */
typedef uint32_t		fm_asset_port_bitmap_t[MAX_PORT_PROBE_WORDS];

typedef struct fm_protocol_asset_ondisk {
	unsigned int		state;
	unsigned int		max_port;
} fm_protocol_asset_ondisk_t;

typedef struct fm_host_asset_ondisk {
	unsigned int		host_state;

	fm_protocol_asset_ondisk_t protocols[__FM_PROTO_MAX];
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
};


typedef struct fm_host_asset_table fm_host_asset_table_t;
struct fm_host_asset_table {
	union {
		fm_host_asset_table_t *table[256];
		fm_host_asset_t	*host[256];
	};
};

extern fm_asset_state_t	fm_protocol_asset_get_state(const fm_protocol_asset_t *proto);
extern bool		fm_protocol_asset_is_any_port_open(const fm_protocol_asset_t *proto);

extern void		fm_assets_write_table(const char *project_dir, int family, const fm_host_asset_table_t *table);
extern void		fm_assets_read_table(const char *project_dir, int family, fm_host_asset_table_t *table);

extern bool		fm_assetio_map_host(fm_host_asset_t *host);
extern void		fm_assetio_unmap_host(fm_host_asset_t *host);

void			fm_assetio_set_mapping(const char *project_dir, bool rw);

#endif /* FREEMAP_ASSETS_H */
