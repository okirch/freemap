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
#include <stdio.h>
#include <stdarg.h>
#include <mcheck.h>

#include "freemap.h"
#include "commands.h"
#include "projects.h"
#include "program.h"

static fm_long_option_t project_long_options[] = {
	{ "force",	FM_ARG_NONE,		OPT_FORCE },
	{ NULL },
};

struct project_options {
	bool		force;
};

static struct project_options	project_options;

static bool
handle_project_options(int c, const char *arg_value)
{
	switch (c) {
	case OPT_FORCE:
		project_options.force = true;
		break;

	default:
		return false;
	}

	return true;
}

void
fm_command_register_project(fm_cmdparser_t *parser)
{
	fm_cmdparser_add_subcommand(parser, "init", FM_CMDID_INIT, NULL, project_long_options, handle_project_options);
	fm_cmdparser_add_subcommand(parser, "add-targets", FM_CMDID_ADD_TARGETS, NULL, project_long_options, handle_project_options);
	fm_cmdparser_add_subcommand(parser, "configure", FM_CMDID_CONFIGURE, NULL, project_long_options, handle_project_options);
}

int
fm_command_perform_init(fm_command_t *cmd)
{
	fm_project_t *project;

	if (cmd->nvalues != 1)
		fm_cmdparser_fatal("Expected exactly one argument, the project name\n");

	if (project_options.force) {
		if (fm_project_exists()) {
			/* fm_project_cleanup(); */
		}
	} else
	if (fm_project_exists()) {
		fm_project_t *project = fm_project_load();

		if (project == NULL) {
			fm_log_error("refusing to initialize project; found corrupted project setup\n");
		} else {
			fm_log_error("refusing to initialize project; found existing project %s\n", project->name);
			fm_project_free(project);
		}
		return 1;
	}

	project = fm_project_create(cmd->values[0]);
	fm_project_save(project);

	printf("Successfully initialized project %s current directory\n", project->name);
	fm_project_free(project);

	return 0;
}

int
fm_command_perform_add_targets(fm_command_t *cmd)
{
	fm_project_t *project;
	unsigned int i;

	if (cmd->nvalues == 0)
		fm_cmdparser_fatal("Expected one or more target identifiers\n");

	project = fm_project_load();
	if (project == NULL) {
		fm_log_error("could not detect scan project, please initialize first\n");
		return 1;
	}

	for (i = 0; i < cmd->nvalues; ++i) {
		const char *name = cmd->values[i];

		if (fm_string_array_contains(&project->targets, name)) {
			fm_log_warning("scan already targets %s; ignoring duplicate", name);
			continue;
		}

		if (!project_options.force) {
			/* TBD: validate the input to make sure we can parse it */
		}

		fm_string_array_append(&project->targets, name);
	}

	fm_project_save(project);
	fm_project_free(project);
	return 0;
}

static bool
sanity_check_probe_name(const char *key, int type, const char *name)
{
	fm_scan_program_t *program;
	bool okay = true;

	program = fm_scan_program_alloc(key);
	if (fm_scan_program_call_routine(program, type, name) == NULL) {
		okay = false;
	}

	fm_scan_program_free(program);
	return okay;
}

int
fm_command_perform_configure(fm_command_t *cmd)
{
	const char *key, *value;
	fm_project_t *project;

	if (cmd->nvalues != 2)
		fm_cmdparser_fatal("Expected arguments: key value\n");

	project = fm_project_load();
	if (project == NULL) {
		fm_log_error("could not detect scan project, please initialize first\n");
		return 1;
	}

	key = cmd->values[0];
	value = cmd->values[1];
	if (!strcmp(key, "topology-probe")) {
		if (!sanity_check_probe_name(key, FM_SCAN_ROUTINE_TOPOLOGY, value))
			return 1;
		assign_string(&project->topology_probe, value);
	} else
	if (!strcmp(key, "reachability-probe")) {
		if (!sanity_check_probe_name(key, FM_SCAN_ROUTINE_HOSTS, value))
			return 1;
		assign_string(&project->reachability_probe, value);
	} else
	if (!strcmp(key, "service-probe")) {
		if (!sanity_check_probe_name(key, FM_SCAN_ROUTINE_SERVICES, value))
			return 1;
		assign_string(&project->service_probe, value);
	} else {
		fm_log_error("Unknown project setting %s=\"%s\"", key, value);
		return 1;
	}

	fm_project_save(project);
	fm_project_free(project);
	return 0;
}
