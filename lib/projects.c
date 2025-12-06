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

#include <unistd.h>
#include "projects.h"
#include "program.h"
#include "logging.h"

#define DEFAULT_PROJECT_CONF	"project.conf"

fm_project_t *
fm_project_create(const char *name)
{
	fm_project_t *proj;

	proj = calloc(1, sizeof(*proj));
	if (name != NULL)
		proj->name = strdup(name);
	return proj;
}

void
fm_project_free(fm_project_t *proj)
{
	drop_string(&proj->name);
	drop_string(&proj->preset);
	fm_string_array_destroy(&proj->udp_ports);
	fm_string_array_destroy(&proj->tcp_ports);
	fm_string_array_destroy(&proj->targets);
	free(proj);
}

bool
fm_project_exists(void)
{
	return access(DEFAULT_PROJECT_CONF, F_OK) >= 0;
}

fm_project_t *
fm_project_load(void)
{
	fm_project_t *project;

	project = fm_project_create(NULL);
	if (!fm_config_load_project(project, DEFAULT_PROJECT_CONF)) {
		fm_log_error("Failed to load from %s", DEFAULT_PROJECT_CONF);
		fm_project_free(project);
		return NULL;
	}

	return project;
}

bool
fm_project_save(fm_project_t *project)
{
	if (!fm_config_save_project(project, DEFAULT_PROJECT_CONF)) {
		fm_log_error("Failed to write %s", DEFAULT_PROJECT_CONF);
		return false;
	}
	return true;
}

/*
 * Get the path in the project directory where to store assets
 */
const char *
fm_project_get_asset_path(fm_project_t *project)
{
	return ".";
}

static bool
fm_project_resolve_preset_work(fm_project_t *project, const fm_config_preset_t *preset)
{
	fm_string_array_copy(&project->udp_ports, &preset->udp_ports);
	fm_string_array_copy(&project->tcp_ports, &preset->tcp_ports);

	/* clear the scan pointers. yes, we do leak memory */
	project->discovery_scan = NULL;
	project->topology_scan = NULL;
	project->host_scan = NULL;
	project->port_scan = NULL;

	if (!fm_config_preset_resolve_stage(preset, FM_SCAN_STAGE_DISCOVERY, &project->discovery_scan)
	 || !fm_config_preset_resolve_stage(preset, FM_SCAN_STAGE_TOPO, &project->topology_scan)
	 || !fm_config_preset_resolve_stage(preset, FM_SCAN_STAGE_HOST, &project->host_scan)
	 || !fm_config_preset_resolve_stage(preset, FM_SCAN_STAGE_PORT, &project->port_scan))
		return false;

	return true;
}

bool
fm_project_resolve_preset(fm_project_t *project)
{
	const fm_config_preset_t *preset;

	preset = fm_config_load_preset(project->preset);
	if (preset == NULL) {
		fm_log_error("Unknown preset %s", project->preset);
		return false;
	}

	return fm_project_resolve_preset_work(project, preset);
}

bool
fm_project_apply_preset(fm_project_t *project, const char *name)
{
	const fm_config_preset_t *preset;

	preset = fm_config_load_preset(name);
	if (preset == NULL) {
		fm_log_error("Unknown preset %s", name);
		return false;
	}

	if (!fm_project_resolve_preset_work(project, preset)) {
		fm_log_error("Invalid/incomplete preset %s", name);
		return false;
	}

	assign_string(&project->preset, name);
	return true;
}

