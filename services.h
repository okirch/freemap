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

#ifndef FREEMAP_SERVICES_H
#define FREEMAP_SERVICES_H

#include "freemap.h"
#include "utils.h"
#include "lists.h"


struct fm_config_packet_array;
struct fm_config_service;

struct fm_service_catalog {
	struct fm_config_service_array *services;
};

/*
 * Array of available port->service mappings.
 * This is not fast, but good enough for now.
 */
struct fm_service_probe {
	unsigned int		proto_id;
	unsigned int		port;

	unsigned int		npackets;
	const fm_buffer_t **	packets;
};

extern fm_service_catalog_t *	fm_service_catalog_alloc(void);
extern bool			fm_service_catalog_add_service(fm_service_catalog_t *, struct fm_config_service *);
extern fm_service_probe_t *	fm_service_catalog_get_service_probe(const fm_service_catalog_t *, unsigned int proto_id, unsigned int port);

#endif /* FREEMAP_SERVICES_H */

