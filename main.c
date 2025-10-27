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

enum {
	FM_CMDID_MAIN = 1,
	FM_CMDID_SCAN,
};

enum {
	OPT_PROGRAM,
	OPT_DUMP,
	OPT_IPV4_ONLY,
	OPT_IPV6_ONLY,
	OPT_ALL_ADDRS,
};

static fm_long_option_t main_long_options[] = {
	{ "ipv4",		FM_ARG_NONE,		OPT_IPV4_ONLY,	},
	{ "ipv6",		FM_ARG_NONE,		OPT_IPV6_ONLY,	},
	{ "all-addresses",	FM_ARG_NONE,		OPT_ALL_ADDRS,	},
	{ "debug",		FM_ARG_NONE,		'd',	},
	{ "help",		FM_ARG_NONE,		'h',	},
	{ NULL },
};

static fm_long_option_t scan_long_options[] = {
	{ "logfile",		FM_ARG_REQUIRED,	'L',	},
	{ "program",		FM_ARG_REQUIRED,	OPT_PROGRAM,	},
	{ "dump",		FM_ARG_NONE,		OPT_DUMP },
	{ NULL },
};

struct fm_cmd_main_options {
	int		ipv4_only;
	int		ipv6_only;
	int		all_addrs;
};

struct fm_cmd_scan_options {
	const char *	logfile;
	const char *	program;
	bool		dump;
};

static void		bad_option(const char *fmt, ...);
static void		usage(int);

static struct fm_cmd_main_options main_options;
static struct fm_cmd_scan_options scan_options;

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
		bad_option("Options --ipv4 and --ipv6 are mutually exclusive\n");

	if (main_options.ipv4_only)
		fm_global.address_generation.only_family = AF_INET;

	if (main_options.ipv6_only)
		fm_global.address_generation.only_family = AF_INET6;

	if (main_options.all_addrs)
		fm_global.address_generation.try_all = true;
}

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

static int	perform_cmd_scan(int argc, char **argv);

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

	fm_cmdparser_add_subcommand(parser, "scan", FM_CMDID_SCAN, NULL, scan_long_options, handle_scan_options);

	cmd = fm_cmdparser_process_args(parser, argc, argv);
	if (cmd == NULL)
		return 1;

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
		return perform_cmd_scan(cmd->nvalues, cmd->values);
	default:
		fm_log_fatal("Cannot execute command %d", cmd->cmdid);
	}

}

int
perform_cmd_scan(int nvalues, char **values)
{
	const fm_scan_program_t *program = NULL;
	fm_scanner_t *scanner;

	if (nvalues == 0) {
		fm_log_error("Missing scan target(s)\n");
		usage(1);
	}

	scanner = fm_scanner_create();

	while (nvalues--) {
		fm_target_manager_t *mgr = scanner->target_manager;
		fm_address_enumerator_t *agen;
		const char *name = *values++;

		if (strchr(name, '/')) {
			agen = fm_create_cidr_address_enumerator(name);
		} else {
			agen = fm_create_simple_address_enumerator(name);
		}

		if (agen == NULL)
			fm_log_fatal("Cannot parse address or network \"%s\"\n", name);

		fm_target_manager_add_address_generator(mgr, agen);
	}

	if (scan_options.logfile != NULL) {
		fm_report_t *report;

		report = fm_scanner_get_report(scanner);
		fm_report_add_logfile(report, scan_options.logfile);
	}

	if (scan_options.program == NULL)
		scan_options.program = "default";

	program = fm_scan_library_load_program(scan_options.program);
	if (program == NULL)
		fm_log_fatal("Could not find scan program \"%s\"\n", scan_options.program);
	if (scan_options.dump)
		fm_scan_program_dump(program);

	if (!fm_scan_program_compile(program, scanner))
		fm_log_fatal("Failed to compile scan program");

	if (scan_options.dump)
		fm_scanner_dump_program(scanner);

	if (!fm_scanner_ready(scanner)) {
		fprintf(stderr, "scanner is not fully configured\n");
		return 1;
	}

	while (true) {
		if (!fm_scanner_transmit(scanner)) {
			printf("All probes completed (%.2f msec)\n",
					fm_scanner_elapsed(scanner));
			break;
		}

		fm_socket_poll_all();
	}

	return 0;
}


static void
usage(int exval)
{
	fprintf(exval? stderr : stdout,
		"Usage: freemap [options] target ...\n"
		"Options:\n"
		"   -L PATH, --logfile PATH\n"
		"      Log scan results to file at PATH\n"
		"   -d, --debug\n"
		"      Increase debug verbosity.\n"
		"   -h, --help\n"
		"      Print this message.\n");
	exit(exval);
}

static void
bad_option(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	usage(1);
}
