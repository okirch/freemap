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
#include <libgen.h>
#include <unistd.h>
#include <mcheck.h>

#include <curlies.h>

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


/*
 * Create a new network/router object
 */
static void *
fm_fake_config_create_network(curly_node_t *node, void *data)
{
	fm_fake_network_array_t *array = data;

	return fm_fake_network_alloc(array);
}

static void *
fm_fake_config_create_router(curly_node_t *node, void *data)
{
	fm_fake_router_array_t *array = data;
	fm_fake_router_t *router;

	router = fm_fake_router_alloc(NULL, array);
	return &router->config;
}

static void *
fm_fake_config_create_service(curly_node_t *node, void *data)
{
	fm_fake_service_array_t *array = data;

	return fm_fake_service_alloc(array);
}

static void *
fm_fake_config_create_host_profile(curly_node_t *node, void *data)
{
	fm_fake_host_profile_array_t *array = data;

	return fm_fake_host_profile_alloc(array);
}

static void *
fm_fake_config_create_host_group(curly_node_t *node, void *data)
{
	fm_fake_host_group_array_t *array = data;

	return fm_fake_host_group_alloc(array);
}

static void *
fm_fake_config_create_host(curly_node_t *node, void *data)
{
	fm_fake_host_array_t *array = data;

	return fm_fake_host_alloc(array);
}

static void *
fm_fake_config_create_firewall(curly_node_t *node, void *data)
{
	fm_fake_fwconfig_array_t *array = data;

	return fm_fake_firewall_alloc(array);
}

static bool
fm_fake_config_set_rate(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	const char *value = curly_attr_get_value(attr, 0);
	fm_ratelimit_t *rl = attr_data;
	unsigned int pps;
	char *end;

	pps = strtoul(value, &end, 0);
	if (*end)
		return false;

	fm_ratelimit_init(rl, pps, pps);
	return true;
}

/*
 * Process an include statement. This does not "set" anything, it loads the referenced
 * file and processes it
 */
static bool
fm_fake_config_include(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	fm_fake_config_t *config = attr_data;
	char *including_filename, *dname;
	unsigned int i;
	bool ok = true;

	including_filename = strdup(curly_node_get_source_file(node));
	if (!(dname = dirname(including_filename))) {
		free(including_filename);
		return false;
	}

	for (i = 0; i < curly_attr_get_count(attr) && ok; ++i) {
		char *include_filename = NULL;
		const char *relative_name;

		relative_name = curly_attr_get_value(attr, i);
		if (relative_name == NULL)
			continue;
		if (relative_name[0] != '/') {
			asprintf(&include_filename, "%s/%s", dname, relative_name);
			relative_name = include_filename;
		}

		fm_log_debug("Processing included file %s", relative_name);
		ok = fm_fake_config_load(config, relative_name);

		drop_string(&include_filename);
	}

	drop_string(&including_filename);
	return ok;
}

static fm_config_proc_t	fm_config_host_node = {
	.name = ATTRIB_STRING(fm_fake_host_t, name),
	.attributes = {
		{ "profile",		offsetof(fm_fake_host_t, cfg_profile),		FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
	},
};

static fm_config_proc_t	fm_config_host_group_node = {
	.name = ATTRIB_STRING(fm_fake_host_group_t, name),
	.attributes = {
		{ "profile",		offsetof(fm_fake_host_group_t, cfg_profile),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "count",		offsetof(fm_fake_host_group_t, cfg_count),	FM_CONFIG_ATTR_TYPE_INT },
	},
};

static fm_config_proc_t	fm_config_network_node = {
	.name = ATTRIB_STRING(fm_fake_network_t, name),
	.attributes = {
		{ "router",		offsetof(fm_fake_network_t, router_name),	FM_CONFIG_ATTR_TYPE_STRING },
	},
	.children = {
		{ "host-group",		offsetof(fm_fake_network_t, cfg_host_groups),	&fm_config_host_group_node, .alloc_child = fm_fake_config_create_host_group },
		{ "host",		offsetof(fm_fake_network_t, hosts),		&fm_config_host_node, .alloc_child = fm_fake_config_create_host },
	}
};

static fm_config_proc_t	fm_config_router_node = {
	.name = ATTRIB_STRING(fm_fake_router_config_t, name),
	.attributes = {
		{ "address",		offsetof(fm_fake_router_config_t, address),	FM_CONFIG_ATTR_TYPE_STRING },
		{ "previous",		offsetof(fm_fake_router_config_t, prev_name),	FM_CONFIG_ATTR_TYPE_STRING },
		{ "firewall",		offsetof(fm_fake_router_config_t, firewall),	FM_CONFIG_ATTR_TYPE_STRING },
	},
};

static fm_config_proc_t	fm_config_service_node = {
	.name = ATTRIB_STRING(fm_fake_service_t, name),
	.attributes = {
		{ "ports",		offsetof(fm_fake_service_t, cfg_ports),		FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "requires",		offsetof(fm_fake_service_t, cfg_requires),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
	},
};

static fm_config_proc_t	fm_config_host_profile_node = {
	.name = ATTRIB_STRING(fm_fake_host_profile_t, name),
	.attributes = {
		{ "services",		offsetof(fm_fake_host_profile_t, cfg_services),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "icmp_ratelimit",	offsetof(fm_fake_host_profile_t, icmp_rate),	FM_CONFIG_ATTR_TYPE_SPECIAL, .setfn = fm_fake_config_set_rate },
	},
};

static fm_config_proc_t	fm_config_firewall_node = {
	.name = ATTRIB_STRING(fm_fake_firewall_t, name),
	.attributes = {
		{ "rules",		offsetof(fm_fake_fwconfig_t, rules),		FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
	},
};

static fm_config_proc_t	fm_config_doc_root = {
	.attributes = {
		{ "include",		0,						FM_CONFIG_ATTR_TYPE_SPECIAL, .setfn = fm_fake_config_include },
		{ "address",		offsetof(fm_fake_config_t, addresses),		FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "backbone_pool",	offsetof(fm_fake_config_t, backbone_pool),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
	},
	.children = {
		{ "network",		offsetof(fm_fake_config_t, networks),		&fm_config_network_node, .alloc_child = fm_fake_config_create_network },
		{ "router",		offsetof(fm_fake_config_t, routers),		&fm_config_router_node, .alloc_child = fm_fake_config_create_router },
		{ "service",		offsetof(fm_fake_config_t, services),		&fm_config_service_node, .alloc_child = fm_fake_config_create_service },
		{ "host-profile",	offsetof(fm_fake_config_t, host_profiles),	&fm_config_host_profile_node, .alloc_child = fm_fake_config_create_host_profile },
		{ "firewall",		offsetof(fm_fake_config_t, firewalls),		&fm_config_firewall_node, .alloc_child = fm_fake_config_create_firewall },
	},
};


static bool
fm_fake_config_process(fm_fake_config_t *config, curly_node_t *node)
{
	if (!fm_config_process_node(node, &fm_config_doc_root, config)) {
		fm_config_complain(node, "unable to parse test network definition");
		return false;
	}

	return true;
}

/*
 * Load the curlies file, then process it
 */
bool
fm_fake_config_load(fm_fake_config_t *config, const char *path)
{
	curly_node_t *top;
	bool rv;

	if (access(path, F_OK) < 0)
		return true;

	top = curly_node_read(path);
	if (top == NULL) {
		fm_log_error("Unable to parse config file %s", path);
		return false;
	}

	rv = fm_fake_config_process(config, top);

	curly_node_free(top);

	return rv;
}

