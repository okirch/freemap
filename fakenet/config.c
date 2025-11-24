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
	fm_fake_network_t *net;

	net = fm_fake_network_alloc(array);
	return &net->config;
}

static void *
fm_fake_config_create_router(curly_node_t *node, void *data)
{
	fm_fake_router_array_t *array = data;
	fm_fake_router_t *router;

	router = fm_fake_router_alloc(NULL, array);
	return &router->config;
}

static fm_config_proc_t	fm_config_network_node = {
	.name = ATTRIB_STRING(fm_fake_network_config_t, address),
	.attributes = {
		{ "router",		offsetof(fm_fake_network_config_t, router),		FM_CONFIG_ATTR_TYPE_STRING },
	},
};

static fm_config_proc_t	fm_config_router_node = {
	.name = ATTRIB_STRING(fm_fake_router_config_t, name),
	.attributes = {
		{ "address",		offsetof(fm_fake_router_config_t, address),		FM_CONFIG_ATTR_TYPE_STRING },
		{ "previous",		offsetof(fm_fake_router_config_t, prev_name),		FM_CONFIG_ATTR_TYPE_STRING },
	},
};

static fm_config_proc_t	fm_config_doc_root = {
	.attributes = {
		{ "address",		offsetof(fm_fake_config_t, addresses),		FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "backbone_pool",	offsetof(fm_fake_config_t, backbone_pool),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
	},
	.children = {
		{ "network",		offsetof(fm_fake_config_t, networks),		&fm_config_network_node, .alloc_child = fm_fake_config_create_network },
		{ "router",		offsetof(fm_fake_config_t, routers),		&fm_config_router_node, .alloc_child = fm_fake_config_create_router },
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

