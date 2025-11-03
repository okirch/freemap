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

/*
 * This represents a rather simple way of defining a scan via a
 * file format.
 * This will have to become richer.
 */

#ifndef FREEMAP_PROGRAM_H
#define FREEMAP_PROGRAM_H

#include "utils.h"


typedef struct fm_config_probe fm_config_probe_t;
typedef struct fm_config_packet fm_config_packet_t;

struct fm_config_probe {
	const char *		name;
	int			mode;

	bool			optional;
	bool			random;
	fm_probe_params_t	probe_params;
	fm_string_array_t	string_ports;
	fm_string_array_t	extra_args;
};

typedef struct fm_config_module fm_config_module_t;
typedef struct fm_config_routine fm_config_routine_t;
typedef struct fm_config_service fm_config_service_t;
typedef struct fm_config_catalog fm_config_catalog_t;

typedef struct fm_config_module_array {
	unsigned int		count;
	fm_config_module_t **	entries;
} fm_config_module_array_t;

typedef struct fm_config_routine_array {
	unsigned int		count;
	fm_config_routine_t **	entries;
} fm_config_routine_array_t;

typedef struct fm_config_packet_array {
	unsigned int		count;
	fm_config_packet_t **	entries;
} fm_config_packet_array_t;

typedef struct fm_config_service_array {
	unsigned int		count;
	fm_config_service_t **	entries;
} fm_config_service_array_t;

struct fm_config_packet {
	const char *		module;
	const char *		name;
	fm_buffer_t *		payload;
};

struct fm_config_service {
	const fm_config_module_t *containing_module;

	const char *		name;
	const char *		fullname;

	fm_uint_array_t		tcp_ports;
	fm_uint_array_t		udp_ports;

	fm_config_packet_array_t packets;
};


struct fm_scan_program {
	fm_config_routine_t *	topo_scan;
	fm_config_routine_t *	host_scan;
	fm_config_routine_t *	port_scan;
	fm_service_catalog_t *	service_catalog;
};


extern fm_scan_program_t *	fm_scan_program_alloc(const char *name);
extern fm_scan_program_t *	fm_scan_program_build(const char *name,
					const char *topology_scan,
					const char *reachability_scan,
					const char *service_scan);
extern bool			fm_scan_program_set_service_catalog(fm_scan_program_t *, const char *);
extern void			fm_scan_program_free(fm_scan_program_t *);

extern fm_config_library_t *	fm_config_library_alloc(const char * const *search_paths);
extern fm_config_module_t *	fm_config_library_load_module(fm_config_library_t *, const char *name);
extern fm_config_routine_t *	fm_config_library_resolve_routine(fm_config_library_t *, int, const char *name);
extern fm_config_catalog_t *	fm_config_library_resolve_service_catalog(fm_config_library_t *, const char *name, fm_config_module_t *);

extern void			fm_config_service_array_append(fm_config_service_array_t *array, fm_config_service_t *service);

#endif /* FREEMAP_PROGRAM_H */
