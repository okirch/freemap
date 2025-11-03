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
struct fm_config_probe {
	const char *		name;
	int			mode;

	bool			optional;
	bool			random;
	fm_probe_params_t	probe_params;
	fm_string_array_t	string_ports;
	fm_string_array_t	extra_args;
};

typedef struct fm_new_routine	fm_new_routine_t;

typedef struct fm_new_routine_array {
	unsigned int		count;
	fm_new_routine_t **	entries;
} fm_new_routine_array_t;

struct fm_scan_program {
	fm_new_routine_t *	topo_scan;
	fm_new_routine_t *	host_scan;
	fm_new_routine_t *	port_scan;
};


extern fm_scan_program_t *	fm_scan_program_alloc(const char *name);
extern fm_scan_program_t *	fm_scan_program_build(const char *name,
					const char *topology_scan,
					const char *reachability_scan,
					const char *service_scan);
extern void			fm_scan_program_free(fm_scan_program_t *);

#endif /* FREEMAP_PROGRAM_H */
