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
};

static struct fm_cmd_scan_options scan_options;

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
	fm_cmdparser_add_subcommand(parser, "topology-scan", FM_CMDID_TOPO_SCAN, NULL, scan_long_options, handle_scan_options);
	fm_cmdparser_add_subcommand(parser, "host-scan", FM_CMDID_HOST_SCAN, NULL, scan_long_options, handle_scan_options);
	fm_cmdparser_add_subcommand(parser, "port-scan", FM_CMDID_PORT_SCAN, NULL, scan_long_options, handle_scan_options);
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
		program = fm_config_program_build("scan",
				project->topology_probe?: "traceroute",
				NULL,
				NULL);
	} else
	if (cmd->cmdid == FM_CMDID_HOST_SCAN) {
		program = fm_config_program_build("scan",
				NULL,
				project->reachability_probe?: "default",
				NULL);
	} else
	if (cmd->cmdid == FM_CMDID_PORT_SCAN) {
		program = fm_config_program_build("scan",
				NULL,
				NULL,
				project->service_probe?: "default");
	} else
	if (scan_options.program != NULL) {
		fm_log_fatal("the entire program mess is gone.");
	} else {
		program = fm_config_program_build("scan",
				NULL,
				project->reachability_probe?: "default",
				project->service_probe?: "default");
		if (program == NULL)
			fm_log_fatal("Could not build scan program");
	}

	if (!fm_config_program_set_service_catalog(program, "default"))
		fm_log_fatal("Unknown service catalog \"%s\"", "default");

	if (scan_options.dump)
		fm_config_program_dump(program);

	if (!fm_config_program_compile(program, scanner))
		fm_log_fatal("Failed to compile scan program");

	if (scan_options.dump)
		fm_scanner_dump_program(scanner);

	if (!fm_scanner_ready(scanner)) {
		fprintf(stderr, "scanner is not fully configured\n");
		return 1;
	}

	while (true) {
		struct timeval timeout;

		if (fm_scanner_transmit(scanner, &timeout)) {
			fm_socket_poll_all(&timeout);
		} else
		if (fm_scanner_next_stage(scanner)) {
			fm_log_notice("Proceeding to stage %d\n", scanner->current_stage);
		} else {
			fm_log_notice("All probes completed (%.2f msec)\n",
					fm_scanner_elapsed(scanner));
			break;
		}

	}

	return 0;
}
