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

#ifndef FREEMAP_PROJECTS_H
#define FREEMAP_PROJECTS_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "freemap.h"
#include "utils.h"

struct fm_project {
	char *			name;
	fm_string_array_t	targets;

	char *			preset;
	fm_string_array_t	tcp_ports;
	fm_string_array_t	udp_ports;
	fm_config_routine_t *	discovery_scan;
	fm_config_routine_t *	topology_scan;
	fm_config_routine_t *	host_scan;
	fm_config_routine_t *	port_scan;
};

extern fm_project_t *		fm_project_create(const char *name);
extern bool			fm_project_exists(void);
extern fm_project_t *		fm_project_load(void);
extern bool			fm_project_save(fm_project_t *);
extern void			fm_project_free(fm_project_t *);
extern const char *		fm_project_get_asset_path(fm_project_t *);
extern bool			fm_project_apply_preset(fm_project_t *project, const char *name);

extern bool			fm_config_load_project(fm_project_t *project, const char *path);
extern bool			fm_config_save_project(fm_project_t *project, const char *path);

#endif /* FREEMAP_PROJECTS_H */
