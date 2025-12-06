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
typedef struct fm_config_preset fm_config_preset_t;

struct fm_config_probe {
	const char *		name;
	int			mode;		/* FM_PROBE_MODE_xxx */

	bool			optional;
	bool			random;
	char *			proto_name;
	char *			info;
	fm_probe_params_t	probe_params;
	fm_string_array_t	string_ports;
	fm_string_array_t	extra_args;
};

typedef struct fm_config_module fm_config_module_t;
typedef struct fm_config_routine fm_config_routine_t;
typedef struct fm_config_routine_definition fm_config_routine_definition_t;
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

typedef struct fm_config_routine_definition_array {
	unsigned int		count;
	fm_config_routine_definition_t **entries;
} fm_config_routine_definition_array_t;

typedef struct fm_config_packet_array {
	unsigned int		count;
	fm_config_packet_t **	entries;
} fm_config_packet_array_t;

typedef struct fm_config_service_array {
	unsigned int		count;
	fm_config_service_t **	entries;
} fm_config_service_array_t;

typedef struct fm_config_preset_array {
	unsigned int		count;
	fm_config_preset_t **	entries;
} fm_config_preset_array_t;

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

struct fm_config_preset {
	const fm_config_module_t *containing_module;

	const char *		name;
	fm_string_array_t	udp_ports;
	fm_string_array_t	tcp_ports;

	char *			discovery_scan;
	char *			topology_scan;
	char *			host_scan;
	char *			port_scan;
};

struct fm_config_program {
	const fm_config_routine_t *stage[__FM_SCAN_STAGE_MAX];
	fm_service_catalog_t *	service_catalog;
};


extern fm_config_program_t *	fm_config_program_alloc(void);
extern bool			fm_config_program_set_stage(fm_config_program_t *, unsigned int, const fm_config_routine_t *);
extern bool			fm_config_program_set_service_catalog(fm_config_program_t *, const char *);
extern void			fm_config_program_free(fm_config_program_t *);
extern fm_config_preset_t *	fm_config_load_preset(const char *name);

extern int			fm_config_probe_process_params(const fm_config_probe_t *, fm_uint_array_t *values);

extern fm_config_library_t *	fm_config_library_alloc(const char * const *search_paths);
extern fm_config_module_t *	fm_config_library_load_module(fm_config_library_t *, const char *name);
extern fm_config_preset_t *	fm_config_library_resolve_preset(fm_config_library_t *, const char *name);
extern fm_config_routine_t *	fm_config_library_resolve_routine(fm_config_library_t *, int, const char *name, const fm_config_module_t *);
extern fm_config_catalog_t *	fm_config_library_resolve_service_catalog(fm_config_library_t *, const char *name, const fm_config_module_t *);

extern bool			fm_config_preset_resolve_stage(const fm_config_preset_t *, int stage, fm_config_routine_t **ret);

extern void			fm_config_service_array_append(fm_config_service_array_t *array, fm_config_service_t *service);

/* routine marshaling */
#ifdef FREEMAP_FILEFMT_H
extern void *			fm_project_routine_ptr_alloc(curly_node_t *node, void *data);
extern void *			fm_project_routine_ptr_iterate(const fm_config_child_t *, void *data, unsigned int index);
extern struct fm_config_proc	fm_config_routine_root;
#endif


#endif /* FREEMAP_PROGRAM_H */
