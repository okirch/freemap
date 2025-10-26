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
#include <getopt.h>
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

static struct option main_long_options[] = {
	{ "program",		required_argument,	NULL,	OPT_PROGRAM,	},
	{ "logfile",		required_argument,	NULL,	'L',	},
	{ "ipv4",		no_argument,		NULL,	OPT_IPV4_ONLY,	},
	{ "ipv6",		no_argument,		NULL,	OPT_IPV6_ONLY,	},
	{ "all-addresses",	no_argument,		NULL,	OPT_ALL_ADDRS,	},
	{ "debug",		no_argument,		NULL,	'd',	},
	{ "help",		no_argument,		NULL,	'h',	},
	{ "dump",		no_argument,		NULL,	OPT_DUMP },
	{ NULL },
};

struct fm_cmd_main_options {
	int		ipv4_only;
	int		ipv6_only;
	int		all_addrs;

	const char *	logfile;
	const char *	program;
	bool		dump;
};

static void		bad_option(const char *fmt, ...);
static void		usage(int);

static struct fm_cmd_main_options main_options;

static bool
handle_main_options(int c, const char *arg_value)
{
	/* printf("%s(%d, %s)\n", __func__, c, arg_value); */

	switch (c) {
	case 'd':
		fm_debug_level += 1;
		break;

	case 'L':
		main_options.logfile = optarg;
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

	case OPT_DUMP:
		main_options.dump = true;
		break;

	case OPT_PROGRAM:
		if (main_options.program)
			fm_log_fatal("duplicate program option given");
		main_options.program = optarg;
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
	/* No options so far */
	return false;
}

int
main(int argc, char **argv)
{
	const fm_scan_program_t *program = NULL;
	fm_scanner_t *scanner;
	fm_cmdparser_t *parser;
	unsigned int cmdid;

#if 1
	if (mcheck_pedantic(NULL) < 0)
		printf("Tried but failed to enable pedantic memory checking\n");
#endif

	parser = fm_cmdparser_main("freemap", FM_CMDID_MAIN, "d", main_long_options, handle_main_options);

	fm_cmdparser_subcommand(parser, "scan", FM_CMDID_SCAN, NULL, NULL, handle_scan_options);

	cmdid = fm_cmdparser_process_args(parser, argc, argv);
	if (cmdid == 0)
		return 1;

	fm_config_init_defaults(&fm_global);

	if (!fm_config_load(&fm_global, "/etc/freemap.conf"))
		fm_log_fatal("Unable to parse global config file\n");

	/* This location will change once we move to project subdirs */
	if (!fm_config_load(&fm_global, "./freemap.conf"))
		fm_log_fatal("Unable to parse local config file\n");

	/* Now apply any options for the main command */
	apply_main_options();

	if (cmdid != FM_CMDID_SCAN)
		fm_log_fatal("Cannot execute command %u", cmdid);

	if (optind >= argc) {
		fm_log_error("Missing scan target(s)\n");
		usage(1);
	}

	scanner = fm_scanner_create();

	while (optind < argc) {
		fm_target_manager_t *mgr = scanner->target_manager;
		fm_address_enumerator_t *agen;
		const char *name = argv[optind++];

		if (strchr(name, '/')) {
			agen = fm_create_cidr_address_enumerator(name);
		} else {
			agen = fm_create_simple_address_enumerator(name);
		}

		if (agen == NULL)
			fm_log_fatal("Cannot parse address or network \"%s\"\n", name);

		fm_target_manager_add_address_generator(mgr, agen);
	}

	if (main_options.logfile != NULL) {
		fm_report_t *report;

		report = fm_scanner_get_report(scanner);
		fm_report_add_logfile(report, main_options.logfile);
	}

	if (main_options.program == NULL)
		main_options.program = "default";

	program = fm_scan_library_load_program(main_options.program);
	if (program == NULL)
		fm_log_fatal("Could not find scan program \"%s\"\n", main_options.program);
	if (main_options.dump)
		fm_scan_program_dump(program);

	if (!fm_scan_program_compile(program, scanner))
		fm_log_fatal("Failed to compile scan program");

	if (main_options.dump)
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
