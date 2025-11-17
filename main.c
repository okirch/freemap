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
#include "commands.h"
#include "protocols.h"

static fm_long_option_t main_long_options[] = {
	{ "ipv4",		FM_ARG_NONE,		OPT_IPV4_ONLY,	},
	{ "ipv6",		FM_ARG_NONE,		OPT_IPV6_ONLY,	},
	{ "all-addresses",	FM_ARG_NONE,		OPT_ALL_ADDRS,	},
	{ "debug",		FM_ARG_NONE,		'd',	},
	{ "help",		FM_ARG_NONE,		'h',	},
	{ NULL },
};

struct fm_cmd_main_options {
	int		ipv4_only;
	int		ipv6_only;
	int		all_addrs;
};

static struct fm_cmd_main_options main_options;

static bool
handle_main_options(int c, const char *arg_value)
{
	/* printf("%s(%d, %s)\n", __func__, c, arg_value); */

	switch (c) {
	case 'd':
		fm_debug_level += 1;
		break;

	case OPT_IPV4_ONLY:
		main_options.ipv4_only = true;
		break;

	case OPT_IPV6_ONLY:
		main_options.ipv6_only = true;
		break;

	case OPT_ALL_ADDRS:
		main_options.all_addrs = true;
		break;

	default:
		return false;
	}

	return true;
}

static void
apply_main_options(void)
{
	if (main_options.ipv4_only + main_options.ipv6_only > 1)
		fm_cmdparser_fatal("Options --ipv4 and --ipv6 are mutually exclusive\n");

	if (main_options.ipv4_only)
		fm_global.address_generation.only_family = AF_INET;

	if (main_options.ipv6_only)
		fm_global.address_generation.only_family = AF_INET6;

	if (main_options.all_addrs)
		fm_global.address_generation.try_all = true;
}

int
main(int argc, char **argv)
{
	fm_cmdparser_t *parser;
	fm_command_t *cmd;

#if 1
	if (mcheck_pedantic(NULL) < 0)
		printf("Tried but failed to enable pedantic memory checking\n");
#endif

	parser = fm_cmdparser_main("freemap", FM_CMDID_MAIN, "d", main_long_options, handle_main_options);

	/* register all subcommands */
	fm_command_register_scan(parser);
	fm_command_register_project(parser);
	fm_command_register_report(parser);

	cmd = fm_cmdparser_process_args(parser, argc, argv);
	if (cmd == NULL) {
		fm_cmdparser_usage(NULL);
		return 1;
	}

	fm_config_init_defaults(&fm_global);

	if (!fm_config_load(&fm_global, "/etc/freemap.conf"))
		fm_log_fatal("Unable to parse global config file\n");

	/* This location will change once we move to project subdirs */
	if (!fm_config_load(&fm_global, "./freemap.conf"))
		fm_log_fatal("Unable to parse local config file\n");

	/* Now apply any options for the main command */
	apply_main_options();

	switch (cmd->cmdid) {
	case FM_CMDID_SCAN:
	case FM_CMDID_TOPO_SCAN:
	case FM_CMDID_HOST_SCAN:
	case FM_CMDID_PORT_SCAN:
		return fm_command_perform_scan(cmd);

	case FM_CMDID_DISCOVERY_SCAN:
		return fm_command_perform_discovery(cmd);

	case FM_CMDID_INIT:
		return fm_command_perform_init(cmd);

	case FM_CMDID_ADD_TARGETS:
		return fm_command_perform_add_targets(cmd);

	case FM_CMDID_CONFIGURE:
		return fm_command_perform_configure(cmd);

	case FM_CMDID_REPORT:
		return fm_command_perform_report(cmd);

	default:
		fm_log_fatal("Cannot execute command %s", cmd->fullname);
	}

	return 1;
}
