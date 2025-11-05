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

typedef uint32_t		fm_asset_port_bitmap_t[MAX_PORT_PROBE_WORDS];

struct fm_protocol_asset {
	unsigned int		proto_id;	 /* FM_PROTO_* */

	/* brute force; space optimization comes later */
	uint32_t		ports[MAX_PORT_PROBE_WORDS];
};

typedef struct fm_protocol_asset_ondisk {
	unsigned int	state;
	unsigned int	max_port;
	void *		bitmap;
} fm_protocol_asset_ondisk_t;

typedef struct fm_host_asset_ondisk {
	unsigned int	state;

	fm_protocol_asset_ondisk_t protocols[__FM_PROTO_MAX];
} fm_host_asset_ondisk_t;


struct fm_host_asset {
	fm_address_t		address;

	int			map_flags;

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

extern fm_asset_state_t	fm_protocol_asset_get_state(const fm_protocol_asset_t *proto);
extern bool		fm_protocol_asset_is_any_port_open(const fm_protocol_asset_t *proto);

extern void		fm_assets_write_table(const char *project_dir, int family, const fm_host_asset_table_t *table);
extern void		fm_assets_read_table(const char *project_dir, int family, fm_host_asset_table_t *table);

#endif /* FREEMAP_ASSETS_H */
