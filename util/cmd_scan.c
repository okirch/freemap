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
#include "scanner.h"
#include "subcommand.h"
#include "commands.h"
#include "projects.h"
#include "program.h"
#include "logging.h"

static fm_long_option_t scan_long_options[] = {
	{ "logfile",		FM_ARG_REQUIRED,	'L',	},
	{ "program",		FM_ARG_REQUIRED,	OPT_PROGRAM,	},
	{ "dump",		FM_ARG_NONE,		OPT_DUMP },
	{ NULL },
};

struct fm_cmd_scan_options {
	const char *	logfile;
	const char *	program;
	bool		dump;
	int		first_stage;
};

static struct fm_cmd_scan_options scan_options = {
	.first_stage = __FM_SCAN_STAGE_MAX,
};

static bool
handle_scan_options(int c, const char *arg_value)
{
	switch (c) {
	case 'L':
		scan_options.logfile = arg_value;
		break;

	case OPT_DUMP:
		scan_options.dump = true;
		break;

	case OPT_PROGRAM:
		if (scan_options.program)
			fm_log_fatal("duplicate program option given");
		scan_options.program = arg_value;
		break;

	default:
		return false;
	}

	return true;
}

void
fm_command_register_scan(fm_cmdparser_t *parser)
{
	fm_cmdparser_add_subcommand(parser, "scan", FM_CMDID_SCAN, NULL, scan_long_options, handle_scan_options);
	fm_cmdparser_add_subcommand(parser, "discovery-scan", FM_CMDID_DISCOVERY_SCAN, NULL, scan_long_options, handle_scan_options);
	fm_cmdparser_add_subcommand(parser, "topology-scan", FM_CMDID_TOPO_SCAN, NULL, scan_long_options, handle_scan_options);
	fm_cmdparser_add_subcommand(parser, "host-scan", FM_CMDID_HOST_SCAN, NULL, scan_long_options, handle_scan_options);
	fm_cmdparser_add_subcommand(parser, "port-scan", FM_CMDID_PORT_SCAN, NULL, scan_long_options, handle_scan_options);
}

/*
 * Helper function for setting scan routines.
 */
static void
set_stage(fm_config_program_t *program, int stage, const fm_config_routine_t *routine)
{
	if (routine == NULL)
		fm_log_fatal("No %s scan configured for this project.", fm_scan_stage_to_string(stage));

	if (!fm_config_program_set_stage(program, stage, routine))
		fm_log_fatal("cannot set requested %s scan stage", fm_scan_stage_to_string(stage));

	if (stage < scan_options.first_stage)
		scan_options.first_stage = stage;
}

int
fm_command_perform_discovery(fm_command_t *cmd)
{
	fm_project_t *project;
	fm_config_program_t *program = NULL;
	fm_scanner_t *scanner;
	unsigned int k;

	project = fm_project_load();
	if (project == NULL) {
		fm_log_error("could not detect scan project, please initialize first\n");
		return 1;
	}

	fm_assets_attach(fm_project_get_asset_path(project));

	scanner = fm_scanner_create();
	program = fm_config_program_alloc();

	/* Set a discovery routine and compile it right away */
	set_stage(program, FM_SCAN_STAGE_DISCOVERY, project->discovery_scan);
	if (!fm_config_program_compile(program, scanner))
		fm_log_fatal("cannot set requested discovery scan stage");

	if (cmd->nvalues != 0) {
		if (project->targets.count > 0)
			printf("Command line overrides scan targets from the project config\n");
		for (k = 0; k < cmd->nvalues; ++k) {
			const char *spec = cmd->values[k];

			if (!fm_scanner_initiate_discovery(scanner, spec))
				fm_log_fatal("Cannot parse address or network \"%s\"\n", spec);
		}
	} else
	if (project->targets.count > 0) {
		for (k = 0; k < project->targets.count; ++k) {
			const char *spec = project->targets.entries[k];

			if (!fm_scanner_initiate_discovery(scanner, spec))
				fm_log_fatal("Cannot parse address or network \"%s\"\n", spec);
		}
	}

	if (scan_options.logfile != NULL) {
		fm_report_t *report;

		report = fm_scanner_get_report(scanner);
		fm_report_add_logfile(report, scan_options.logfile);
	}

	if (scan_options.dump)
		fm_scanner_dump_program(scanner);

	if (!fm_scanner_ready(scanner, FM_SCAN_STAGE_DISCOVERY)) {
		fprintf(stderr, "scanner is not fully configured\n");
		return 1;
	}

	while (true) {
		fm_time_t timeout;

		if (fm_scanner_transmit(scanner, &timeout)) {
			fm_socket_poll_all(timeout);
		} else
		if (fm_scanner_next_stage(scanner)) {
			fm_log_notice("Proceeding to stage %d\n", scanner->current_stage->stage_id);
		} else {
			fm_log_notice("All probes completed (%.2f msec)\n",
					fm_scanner_elapsed(scanner));
			break;
		}

	}

	return 0;
}

int
fm_command_perform_scan(fm_command_t *cmd)
{
	fm_project_t *project;
	fm_config_program_t *program = NULL;
	fm_scanner_t *scanner;
	unsigned int k;

	project = fm_project_load();
	if (project == NULL) {
		fm_log_error("could not detect scan project, please initialize first\n");
		return 1;
	}

	fm_assets_attach(fm_project_get_asset_path(project));

	scanner = fm_scanner_create();
	program = fm_config_program_alloc();

	if (cmd->nvalues != 0) {
		if (project->targets.count > 0)
			printf("Command line overrides scan targets from the project config\n");
		for (k = 0; k < cmd->nvalues; ++k) {
			const char *spec = cmd->values[k];

			if (!fm_scanner_add_target_from_spec(scanner, spec))
				fm_log_fatal("Cannot parse address or network \"%s\"\n", spec);
		}
	} else
	if (project->targets.count > 0) {
		for (k = 0; k < project->targets.count; ++k) {
			const char *spec = project->targets.entries[k];

			if (!fm_scanner_add_target_from_spec(scanner, spec))
				fm_log_fatal("Cannot parse address or network \"%s\"\n", spec);
		}
	}

	if (scan_options.logfile != NULL) {
		fm_report_t *report;

		report = fm_scanner_get_report(scanner);
		fm_report_add_logfile(report, scan_options.logfile);
	}

	if (cmd->cmdid == FM_CMDID_TOPO_SCAN) {
		set_stage(program, FM_SCAN_STAGE_TOPO, project->topology_scan);
	} else
	if (cmd->cmdid == FM_CMDID_HOST_SCAN) {
		set_stage(program, FM_SCAN_STAGE_HOST, project->host_scan);
	} else
	if (cmd->cmdid == FM_CMDID_PORT_SCAN) {
		set_stage(program, FM_SCAN_STAGE_PORT, project->port_scan);
	} else {
		set_stage(program, FM_SCAN_STAGE_HOST, project->host_scan);
		set_stage(program, FM_SCAN_STAGE_PORT, project->port_scan);
	}

	assert(scan_options.first_stage < __FM_SCAN_STAGE_MAX);

	if (!fm_config_program_set_service_catalog(program, "default"))
		fm_log_fatal("Unknown service catalog \"%s\"", "default");

	if (scan_options.dump)
		fm_config_program_dump(program);

	if (!fm_config_program_compile(program, scanner))
		fm_log_fatal("Failed to compile scan program");

	if (scan_options.dump)
		fm_scanner_dump_program(scanner);

	if (!fm_scanner_ready(scanner, scan_options.first_stage)) {
		fm_log_error("scanner is not fully configured");
		return 1;
	}

	while (true) {
		fm_time_t timeout;

		if (fm_scanner_transmit(scanner, &timeout)) {
			fm_socket_poll_all(timeout);
		} else
		if (fm_scanner_next_stage(scanner)) {
			fm_log_notice("Proceeding to stage %d\n", scanner->current_stage->stage_id);
		} else {
			fm_log_notice("All probes completed (%.2f msec)\n",
					fm_scanner_elapsed(scanner));
			break;
		}

	}

	return 0;
}
