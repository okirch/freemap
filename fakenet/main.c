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

#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>

#include "fakenet.h"
#include "scanner.h"
#include "commands.h"
#include "protocols.h"
#include "socket.h"
#include "routing.h"
#include "packet.h"
#include "buffer.h"
#include "filefmt.h"
#include "logging.h"

static fm_long_option_t main_long_options[] = {
	{ "trace",		FM_ARG_REQUIRED,	OPT_TRACE_FACILITY },
	{ "debug",		FM_ARG_NONE,		'd',	},
	{ "help",		FM_ARG_NONE,		'h',	},
	{ NULL },
};

struct fm_cmd_main_options {
	int dummy;
};

static struct fm_cmd_main_options main_options;

static bool
handle_main_options(int c, const char *arg_value)
{
	char *copy, *next;

	switch (c) {
	case 'd':
		fm_debug_level += 1;
		break;

	case OPT_TRACE_FACILITY:
		copy = alloca(strlen(arg_value) + 1);
		strcpy(copy, arg_value);

		for (; copy; copy = next) {
			if ((next = strchr(copy, ',')) != NULL) {
				while (*next == ',')
					*next++ = '\0';
			}

			if (!fm_enable_debug_facility(copy))
				return false;
		}
		break;

	default:
		return false;
	}

	return true;
}

int
main(int argc, char **argv)
{
	fm_cmdparser_t *parser;
	fm_command_t *cmd;
	const char *cfgpath;
	fm_fake_config_t config;
	fm_tunnel_t *tunnel;

#if 1
	if (mcheck_pedantic(NULL) < 0)
		printf("Tried but failed to enable pedantic memory checking\n");
#endif

	parser = fm_cmdparser_main("testserver", FM_CMDID_MAIN, "d", main_long_options, handle_main_options);

	cmd = fm_cmdparser_process_args(parser, argc, argv);
	if (cmd == NULL) {
		fm_cmdparser_usage(NULL);
		return 1;
	}

	/* silence warning while we don't use that yet */
	(void) main_options.dummy;

	if (cmd->nvalues != 1)
		fm_log_fatal("Usage: fakenet config-file");

	cfgpath = cmd->values[0];

	memset(&config, 0, sizeof(config));
	if (!fm_fake_config_load(&config, cfgpath))
		fm_log_fatal("Cannot load configuration from %s", cfgpath);

	if (!(tunnel = fm_fakenet_attach_interface())
	 || !fm_fakenet_configure_interface(tunnel, &config))
		fm_log_fatal("Cannot create tunnel interface");

	if (!fm_fake_network_set_egress(&config, tunnel)
	 || !fm_fake_network_build(&config))
		fm_log_fatal("Cannot build fake network");

	fm_fakenet_run(tunnel, &config);

	return 1;
}
