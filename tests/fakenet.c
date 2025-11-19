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

static fm_tunnel_t *	fm_fakenet_attach_interface(void);
static bool		fm_fake_config_load(fm_fake_config_t *config, const char *path);
static bool		fm_fakenet_configure_interface(fm_tunnel_t *tunnel, fm_fake_config_t *config);
static bool		fm_fake_config_process(fm_fake_config_t *config, curly_node_t *);
static bool		fm_fakenet_run(fm_tunnel_t *tunnel, const fm_fake_config_t *config);
static bool		fm_fake_network_build(fm_fake_config_t *config);
static fm_fake_router_t *fm_fake_router_alloc(const char *name, fm_fake_router_array_t *array);

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

	if (!fm_fake_config_load(&config, cfgpath))
		fm_log_fatal("Cannot load configuration from %s", cfgpath);

	if (!(tunnel = fm_fakenet_attach_interface())
	 || !fm_fakenet_configure_interface(tunnel, &config))
		fm_log_fatal("Cannot create tunnel interface");

	fm_fakenet_run(tunnel, &config);

	return 1;
}

static fm_tunnel_t *
fm_fakenet_attach_interface()
{
	struct ifreq ifr;
	fm_tunnel_t *tunnel;
	int fd;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		fm_log_error("failed to open /dev/net/tun: %m");
		return false;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "fake%d");
	ifr.ifr_flags = IFF_TUN;

	if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
		fm_log_error("could not create tunnel device: %m");
		return false;
	}

	tunnel = calloc(1, sizeof(*tunnel));

	tunnel->ifname = strdup(ifr.ifr_name);
	tunnel->fd = fd;

	fm_log_notice("Using tunnel device %s", tunnel->ifname);
	return tunnel;
}

static bool
fm_fakenet_run(fm_tunnel_t *tunnel, const fm_fake_config_t *config)
{
	fm_buffer_t *bp;

	bp = fm_buffer_alloc(8192);
	while (true) {
		uint16_t flags, ptype;
		fm_pkt_t pkt;
		unsigned int next_proto;
		fm_parsed_pkt_t *cooked;
		int n;

		bp->rpos = bp->wpos = 0;

		n = read(tunnel->fd, fm_buffer_tail(bp), fm_buffer_tailroom(bp));
		if (n < 0) {
			fm_log_fatal("read: %m");
			return false;
		}

		bp->wpos += n;

		if (!fm_buffer_get16(bp, &flags)
		 || !fm_buffer_get16(bp, &ptype))
			continue;

		flags = ntohs(flags);
		ptype = ntohs(ptype);

		memset(&pkt, 0, sizeof(pkt));
		pkt.payload = bp;

		switch (ptype) {
		case ETH_P_IP:
			pkt.family = AF_INET;
			next_proto = FM_PROTO_IP;
			break;

		case ETH_P_IPV6:
			pkt.family = AF_INET6;
			next_proto = FM_PROTO_IPV6;
			break;

		default:
			if (fm_debug_level > 1)
				fm_log_debug("received unknown packet type %04x flags=0x%x", ptype, flags);
			continue;
		}

		if (fm_debug_facilities & FM_DEBUG_FACILITY_DATA) {
			fm_log_debug("received %s packet flags=0x%x", fm_protocol_id_to_string(next_proto), flags);
			fm_buffer_dump(bp, NULL);
		}

		cooked = fm_packet_parser_inspect_any(&pkt, next_proto);
		if (cooked == NULL)
			continue;

		free(cooked);
	}

	return true;
}

static bool
fm_fakenet_configure_interface(fm_tunnel_t *tunnel, fm_fake_config_t *config)
{
	struct ifreq ifr;
	int fd = -1;
	unsigned int i;

	if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		fm_log_error("socket: %m");
		return false;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, tunnel->ifname);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		fm_log_error("failed to set flags for %s: %m", tunnel->ifname);
		return false;
	}
	tunnel->ifindex = ifr.ifr_ifindex;
	printf("ifindex=%u\n", ifr.ifr_ifindex);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		fm_log_error("failed to get flags for %s: %m", tunnel->ifname);
		return false;
	}

	printf("ifflags=0x%x\n", ifr.ifr_flags);
	ifr.ifr_flags |= IFF_UP;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		fm_log_error("failed to set flags for %s: %m", tunnel->ifname);
		return false;
	}

	fm_log_debug("Configure %s", tunnel->ifname);
	for (i = 0; i < config->addresses.count; ++i) {
		const char *addrstring = config->addresses.entries[i];
		fm_address_prefix_t prefix;
		unsigned int pfxlen;

		if (!fm_address_prefix_parse(addrstring, &prefix)) {
			fm_log_error("Cannot parse route \"%s\"", addrstring);
			return false;
		}

		if (prefix.address.family == AF_INET)
			pfxlen = 32;
		else
			pfxlen = 128;

		if (!netlink_send_newaddr(tunnel->ifindex, &prefix.address, pfxlen)) {
			fm_log_error("failed to add address %s/%u for %s",
					fm_address_format(&prefix.address),
					pfxlen, tunnel->ifname);
			return false;
		}

		fm_log_debug("%s: added address %s/%u", tunnel->ifname,
					fm_address_format(&prefix.address),
					pfxlen);

		if (!netlink_send_newroute(tunnel->ifindex, &prefix)) {
			fm_log_error("failed to add route %s for %s", addrstring, tunnel->ifname);
			return false;
		}

		fm_log_debug("%s: added route %s", tunnel->ifname, addrstring);
	}

	close(fd);
	return true;
}


static bool
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

	if (rv)
		rv = fm_fake_network_build(config);

	return rv;
}

/*
 * Primitives
 */
static fm_fake_router_t *
fm_fake_router_alloc(const char *name, fm_fake_router_array_t *array)
{
	fm_fake_router_t *router;

	router = calloc(1, sizeof(*router));
	if (name)
		router->config.name = strdup(name);

	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = router;

	return router;
}

static void
fm_fake_network_array_append(fm_fake_network_array_t *array, fm_fake_network_t *net)
{
	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = net;
}

/*
 * Follow the chain of routers
 */
static fm_fake_router_t *
fm_fake_router_find(const fm_fake_config_t *config, const char *name, unsigned int label)
{
	unsigned int i;

	for (i = 0; i < config->routers.count; ++i) {
		fm_fake_router_t *router = config->routers.entries[i];

		if (router->config.name && !strcmp(router->config.name, name)) {
			if (router->label == label) {
				fm_log_error("seems we have a routing loop involving %s", name);
				return NULL;
			}

			if (router->label != 0)
				return router; /* we've handled this one before */

			if (router->config.prev_name == NULL) {
				fm_log_error("router %s does not have a previous hop", router->config.name);
			} else if (router->prev == NULL) {
				router->prev = fm_fake_router_find(config, router->config.prev_name, label);
				if (router->prev == NULL)
					return NULL; /* hard error */

				router->ttl = router->prev->ttl + 1;
			}

			return router;
		}
	}

	fm_log_error("router %s not found", name);
	return NULL;
}

/*
 * Given the configuration setup, try to build the network in-memory
 */
static bool
fm_fake_network_build(fm_fake_config_t *config)
{
	unsigned int i, router_label = 1;
	bool ok = true;

	config->egress_router = fm_fake_router_alloc("egress", &config->routers);
	config->egress_router->label = router_label++;
	config->egress_router->ttl = 1;

	for (i = 0; i < config->networks.count; ++i) {
		fm_fake_network_t *net = config->networks.entries[i];

		/* can't happen */
		assert(net->config.address != NULL);

		if (!fm_address_prefix_parse(net->config.address, &net->prefix)) {
			fm_log_error("network %s: cannot parse prefix", net->config.address);
			ok = false;
			continue;
		}

		if (net->config.router == NULL) {
			fm_log_error("network %s: no router specified", net->config.address);
			continue;
		}

		net->router = fm_fake_router_find(config, net->config.router, router_label++);
		if (net->router == NULL)
			ok = false;

		{
			fm_fake_router_t *router;

			fm_log_debug("network %s", net->config.address);
			for (router = net->router; router; router = router->prev)
				fm_log_debug("  %u %s", router->ttl, router->config.name);
		}

	}

	abort();
	return ok;
}

/*
 * Create a new network/router object
 */
static void *
fm_fake_config_create_network(curly_node_t *node, void *data)
{
	fm_fake_network_array_t *array = data;
	fm_fake_network_t *net;

	net = calloc(1, sizeof(*net));
	fm_fake_network_array_append(array, net);

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
