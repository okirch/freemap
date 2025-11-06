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
#include "addresses.h"

static fm_long_option_t report_long_options[] = {
	{ "skip-noresponse",	FM_ARG_NONE,		OPT_SKIP_NORESPONSE },
	{ "skip-unreachable",	FM_ARG_NONE,		OPT_SKIP_UNREACHABLE },

	{ NULL },
};

struct fm_cmd_report_options {
	bool		skip_noresponse;
	bool		skip_unreachable;
};

static struct fm_cmd_report_options report_options;

static bool
handle_report_options(int c, const char *arg_value)
{
	switch (c) {
	case OPT_SKIP_NORESPONSE:
		report_options.skip_noresponse = true;
		break;

	case OPT_SKIP_UNREACHABLE:
		report_options.skip_unreachable = true;
		break;

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

static inline bool
fm_report_skip_state(fm_asset_state_t state)
{
	if (state == FM_ASSET_STATE_UNDEF)
		return true;

	if (report_options.skip_noresponse && state <= FM_ASSET_STATE_PROBE_SENT)
		return true;

	if (report_options.skip_unreachable && state <= FM_ASSET_STATE_CLOSED)
		return true;

	return false;
}

/*
 * Map state to string
 */
static const char *
fm_report_asset_state(fm_asset_state_t state)
{
	switch (state) {
	case FM_ASSET_STATE_UNDEF:
		return "undefined";

	case FM_ASSET_STATE_PROBE_SENT:
		return "noresponse";

	case FM_ASSET_STATE_CLOSED:
		return "unreachable";

	case FM_ASSET_STATE_OPEN:
		return "open";
	}
	return "BAD";
}

static void
fm_report_route(const fm_host_asset_t *host, const fm_route_asset_ondisk_t *route, int family)
{
	unsigned int ttl;
	bool reached = false;

	if (route == NULL || route->last_ttl == 0)
		return;

	printf("   %s route (found %u hops)\n", fm_addrfamily_name(family), route->last_ttl);

	printf("     %4s %8s %s\n", "ttl", "rtt/ms", "address");

	for (ttl = 1; ttl <= route->last_ttl; ++ttl) {
		fm_address_t hop_address;

		if (!fm_address_set_raw_addr(&hop_address, family, route->address[ttl], sizeof(route->address[ttl]))) {
			printf("     %3u:        * <bad address>\n", ttl);
			continue;
		}

		if (!(route->present[ttl/32] & (1 << (ttl % 32)))) {
			printf("     %3u:        * ?\n", ttl);
		} else {
			printf("     %3u: %8.5f %s", ttl,
							route->rtt[ttl] * 1e-6,
							fm_address_format(&hop_address));

			if (route->flapping[ttl/32] & (1 << (ttl % 32)))
				printf(", flapping route");

			if (fm_address_equal(&hop_address, &host->address, false)) {
				printf("; REACHED");
				reached = true;
			}

			printf("\n");
		}
	}

	if (!reached)
		printf("     *** losing its trail in the mists of the net\n");
	printf("\n");
}

/*
 * This visitor pattern is ugly; we should use an iterator
 */
static bool
fm_report_port_visitor(const fm_host_asset_t *host, const char *proto, unsigned int port, fm_asset_state_t state, void *user_data)
{
	if (!fm_report_skip_state(state))
		printf("   %s/%u %s\n", proto, port, fm_report_asset_state(state));
	return true;
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
		fm_asset_state_t state;

		if (!fm_host_iterator_hot_map(host))
			continue;

		state = fm_host_asset_get_state(host);

		if (fm_report_skip_state(state))
			continue;

		printf("== %s ==\n", fm_address_format(&host->address));
		printf("   host: %s\n", fm_report_asset_state(state));

		fm_report_route(host, host->ipv4_route, AF_INET);
		fm_report_route(host, host->ipv6_route, AF_INET6);

		fm_host_asset_report_ports(host, fm_report_port_visitor, NULL);

		printf("\n");
	}

	return 0;
}
