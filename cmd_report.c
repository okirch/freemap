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
#include "assets.h"

static fm_long_option_t report_long_options[] = {
	{ NULL },
};

struct fm_cmd_report_options {
	bool		dummy;
};

static struct fm_cmd_report_options report_options;

static bool
handle_report_options(int c, const char *arg_value)
{
	switch (c) {
	default:
		return false;
	}

	return true;
}

void
fm_command_register_report(fm_cmdparser_t *parser)
{
	fm_cmdparser_add_subcommand(parser, "report", FM_CMDID_REPORT, NULL, report_long_options, handle_report_options);
}

int
fm_command_perform_report(fm_command_t *cmd)
{
	fm_project_t *project;
	fm_host_asset_iterator_t iter;
	fm_host_asset_t *host;

	project = fm_project_load();
	if (project == NULL) {
		fm_log_error("could not detect scan project, please initialize first\n");
		return 1;
	}

	fm_assets_attach_readonly(fm_project_get_asset_path(project));

	fm_host_asset_cache_prime();

	fm_host_asset_iterator_init(&iter);
	while ((host = fm_host_asset_iterator_next(&iter)) != NULL) {
		printf("ASSET %s\n", fm_address_format(&host->address));
	}

	return 0;
}
