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

enum {
	OPT_PROGRAM,
	OPT_DUMP,
	OPT_IPV4_ONLY,
	OPT_IPV6_ONLY,
	OPT_ALL_ADDRS,
};

static struct option long_options[] = {
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

static void		bad_option(const char *fmt, ...);
static void		usage(int);

int
main(int argc, char **argv)
{
	const char *opt_logfile = NULL;
	const char *opt_program = NULL;
	bool opt_dump = false;
	fm_addr_gen_options_t addr_gen_opts;
	const fm_scan_program_t *program = NULL;
	fm_scanner_t *scanner;
	int c;

#if 1
	if (mcheck_pedantic(NULL) < 0)
		printf("Tried but failed to enable pedantic memory checking\n");
#endif

	memset(&addr_gen_opts, 0, sizeof(addr_gen_opts));

	while ((c = getopt_long(argc, argv, "dh", long_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			fm_debug_level += 1;
			break;

		case 'L':
			opt_logfile = optarg;
			break;

		case OPT_IPV4_ONLY:
			if (addr_gen_opts.only_family != AF_UNSPEC)
				bad_option("Options --ipv4 and --ipv6 are mutually exclusive\n");
			addr_gen_opts.only_family = AF_INET;
			break;

		case OPT_IPV6_ONLY:
			if (addr_gen_opts.only_family != AF_UNSPEC)
				bad_option("Options --ipv4 and --ipv6 are mutually exclusive\n");
			addr_gen_opts.only_family = AF_INET6;
			break;

		case OPT_ALL_ADDRS:
			addr_gen_opts.all_addrs = true;
			break;

		case OPT_DUMP:
			opt_dump = true;
			break;

		case OPT_PROGRAM:
			if (opt_program)
				fm_log_fatal("duplicate program option given");
			opt_program = optarg;
			break;

		case 'h':
			usage(0);

		case '?':
			usage(1);
		}
	}

	fm_config_init_defaults(&fm_global);

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
			agen = fm_create_cidr_address_enumerator(name, &addr_gen_opts);
		} else {
			agen = fm_create_simple_address_enumerator(name, &addr_gen_opts);
		}

		if (agen == NULL)
			fm_log_fatal("Cannot parse address or network \"%s\"\n", name);

		fm_target_manager_add_address_generator(mgr, agen);
	}

	if (opt_logfile != NULL) {
		fm_report_t *report;

		report = fm_scanner_get_report(scanner);
		fm_report_add_logfile(report, opt_logfile);
	}

	if (opt_program == NULL)
		opt_program = "default";

	program = fm_scan_library_load_program(opt_program);
	if (program == NULL)
		fm_log_fatal("Could not find scan program \"%s\"\n", opt_program);
	if (opt_dump)
		fm_scan_program_dump(program);

	if (!fm_scan_program_compile(program, scanner))
		fm_log_fatal("Failed to compile scan program");

	if (opt_dump)
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
