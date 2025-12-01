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

/*
 * Primitives
 */
fm_fake_router_t *
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

fm_address_t *
fm_fake_router_addr(fm_fake_router_t *router, int family)
{
	if (family == AF_INET)
		return &router->ipv4_address;
	if (family == AF_INET6)
		return &router->ipv6_address;
	return NULL;
}

bool
fm_fake_router_has_address(fm_fake_router_t *router, int family)
{
	const fm_address_t *addr;

	if (!(addr = fm_fake_router_addr(router, family)))
		return false;
	return addr->family == family;
}

const fm_address_t *
fm_fake_router_get_address(fm_fake_router_t *router, int family)
{
	return fm_fake_router_addr(router, family);
}

bool
fm_fake_router_set_address(fm_fake_router_t *router, int family, const fm_address_t *new_addr)
{
	if (new_addr->family != family)
		return false;

	if (family == AF_INET)
		router->ipv4_address = *new_addr;
	else if (family == AF_INET6)
		router->ipv6_address = *new_addr;
	else
		return false;
	return true;
}

fm_fake_network_t *
fm_fake_network_alloc(fm_fake_network_array_t *array)
{
	fm_fake_network_t *network;

	network = calloc(1, sizeof(*network));

	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = network;

	return network;
}

fm_fake_service_t *
fm_fake_service_alloc(fm_fake_service_array_t *array)
{
	fm_fake_service_t *service;

	service = calloc(1, sizeof(*service));

	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = service;

	return service;
}

fm_fake_host_profile_t *
fm_fake_host_profile_alloc(fm_fake_host_profile_array_t *array)
{
	fm_fake_host_profile_t *profile;

	profile = calloc(1, sizeof(*profile));

	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = profile;

	return profile;
}

fm_fake_host_group_t *
fm_fake_host_group_alloc(fm_fake_host_group_array_t *array)
{
	fm_fake_host_group_t *group;

	group = calloc(1, sizeof(*group));

	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = group;

	return group;
}

fm_fake_host_t *
fm_fake_host_alloc(fm_fake_host_array_t *array)
{
	fm_fake_host_t *host;

	host = calloc(1, sizeof(*host));

	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = host;

	return host;
}

fm_fake_port_t *
fm_fake_port_array_add(fm_fake_port_array_t *array, unsigned int proto_id, unsigned int port)
{
	fm_fake_port_t *port_obj;

	maybe_realloc_array(array->entries, array->count, 4);
	port_obj = &array->entries[array->count++];
	memset(port_obj, 0, sizeof(*port_obj));

	port_obj->proto_id = proto_id;
	port_obj->port = port;

	return port_obj;
}

void
fm_fake_service_array_append(fm_fake_service_array_t *array, fm_fake_service_t *service)
{
	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = service;
}

bool
fm_fake_service_array_contains(fm_fake_service_array_t *array, const fm_fake_service_t *service)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		if (array->entries[i] == service)
			return true;
	}

	return false;
}


/*
 * Follow the chain of routers
 */
static fm_fake_router_t *
fm_fake_router_build_chain(const fm_fake_config_t *config, const char *name, unsigned int label)
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

			router->label = label;

			if (router->config.prev_name == NULL) {
				fm_log_error("router %s does not have a previous hop", router->config.name);
			} else if (router->prev == NULL) {
				router->prev = fm_fake_router_build_chain(config, router->config.prev_name, label);
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
 * Manage a pool of addresses we can use for routers (and maybe other entities).
 */
static fm_fake_address_pool_t *
fm_fake_address_pool_alloc(const fm_address_prefix_t *prefix)
{
	fm_fake_address_pool_t *pool;
	const unsigned char *raw_addr;
	unsigned int nbits, value_bits;

	if (!(raw_addr = fm_address_get_raw_addr(&prefix->address, &nbits))
	 || nbits > 128
	 || prefix->pfxlen >= nbits)
		return NULL;

	pool = calloc(1, sizeof(*pool));
	pool->family = prefix->address.family;
	pool->pfxlen = prefix->pfxlen;
	pool->addrbits = nbits;
	pool->shift = 0;
	memcpy(pool->raw_addr, raw_addr, nbits / 8);

	if (prefix->address.family == AF_INET6) {
		if (prefix->pfxlen >= 64)
			return NULL;
		value_bits = 64 - prefix->pfxlen;
		pool->shift = 64;

		memset(pool->raw_addr + 8, 0, 8);
		pool->raw_addr[15] = 0x1;
	} else {
		value_bits = nbits - prefix->pfxlen;
		pool->shift = 0;
	}

	if (value_bits > 16)
		value_bits = 16;
	pool->max_value = (1 << value_bits) - 1;

	pool->next_value = 1;

	return pool;
}

static bool
fm_fake_address_pool_get_next(fm_fake_address_pool_t *pool, fm_address_t *addr)
{
	unsigned char raw_addr[16];
	unsigned int k;
	uint32_t value;

	if (pool == NULL)
		return false;

	if (pool->next_value >= pool->max_value)
		return false;

	/* For now, hand out addresses consecutively. Alternative
	 * strategies might involve 4-bit subnets or similar */
	value = pool->next_value++;

	memcpy(raw_addr, pool->raw_addr, pool->addrbits / 8);

	k = (pool->addrbits - pool->shift) / 8;
	raw_addr[--k] |= value & 0xFF;

	value >>= 8;
	raw_addr[--k] |= value & 0xFF;

	fm_address_set_raw_addr(addr, pool->family, raw_addr, pool->addrbits / 8);

	return true;
}

static bool
fm_fake_network_create_backbone_pools(const fm_string_array_t *array, struct hlist_head *head)
{
	hlist_insertion_iterator_t tail;
	unsigned int i;

	hlist_insertion_iterator_init(&tail, head);
	for (i = 0; i < array->count; ++i) {
		const char *addrstring = array->entries[i];
		fm_address_prefix_t prefix;
		fm_fake_address_pool_t *pool;

		if (!fm_address_prefix_parse(addrstring, &prefix)) {
			fm_log_error("Unable to parse backbone pool prefix %s", addrstring);
			continue;
		}

		if ((pool = fm_fake_address_pool_alloc(&prefix)) == NULL)
			continue;

		hlist_insertion_iterator_insert_and_advance(&tail, &pool->link);
	}

	return true;
}

/*
 * Make sure router has a suitable address assigned
 */
static bool
fm_fake_router_assign_addresses(fm_fake_router_t *router, int family, struct hlist_head *pool_head)
{
	fm_address_t new_addr;

	while (router && !fm_fake_router_has_address(router, family)) {
		fm_fake_address_pool_t *pool;
		hlist_iterator_t iter;
		bool found = false;

		hlist_iterator_init(&iter, pool_head);
		while (!found && (pool = hlist_iterator_next(&iter)) != NULL) {
			if (pool->family == family)
				found = fm_fake_address_pool_get_next(pool, &new_addr);
		}

		if (!found)
			return false;

		fm_log_debug("router %s assign address %s", router->config.name, fm_address_format(&new_addr));
		fm_fake_router_set_address(router, family, &new_addr);

		router = router->prev;
	}

	return true;
}

/*
 * Configure our "egress" router.
 */
bool
fm_fake_network_set_egress(fm_fake_config_t *config, const fm_tunnel_t *tunnel)
{
	fm_fake_router_t *router;

	if (config->egress_router != NULL)
		return true;

	router = fm_fake_router_alloc("egress", &config->routers);
	router->ipv4_address = tunnel->ipv4_address;
	router->ipv6_address = tunnel->ipv6_address;
	router->label = 1;
	router->ttl = 1;

	config->egress_router = router;
	return true;
}

/*
 * Query host profiles, services etc
 */
static fm_fake_host_profile_t *
fm_fake_config_get_profile(const fm_fake_config_t *config, const char *name)
{
	unsigned int i;

	for (i = 0; i < config->host_profiles.count; ++i) {
		fm_fake_host_profile_t *profile = config->host_profiles.entries[i];

		if (!strcmp(profile->name, name))
			return profile;
	}

	return NULL;
}

static fm_fake_service_t *
fm_fake_config_get_service(const fm_fake_config_t *config, const char *name)
{
	unsigned int i;

	for (i = 0; i < config->services.count; ++i) {
		fm_fake_service_t *service = config->services.entries[i];

		if (!strcmp(service->name, name))
			return service;
	}

	return NULL;
}

fm_fake_network_t *
fm_fake_config_get_network_by_addr(const fm_fake_config_t *config, const fm_address_t *addr)
{
	unsigned int i;

	for (i = 0; i < config->networks.count; ++i) {
		fm_fake_network_t *net = config->networks.entries[i];

		if (fm_address_prefix_match_address(&net->prefix, addr, net->prefix_mask, (net->prefix.pfxlen + 7) / 8))
			return net;
	}

	return NULL;
}

fm_fake_host_t *
fm_fake_network_get_host_by_addr(const fm_fake_network_t *net, const fm_address_t *addr)
{
	unsigned int i;

	for (i = 0; i < net->hosts.count; ++i) {
		fm_fake_host_t *host = net->hosts.entries[i];

		if (fm_address_equal(&host->address, addr, false))
			return host;
	}

	return NULL;
}

fm_fake_host_t *
fm_fake_config_get_host_by_addr(const fm_fake_config_t *config, const fm_address_t *addr)
{
	fm_fake_network_t *net = NULL;
	unsigned int i;

	if (!(net = fm_fake_config_get_network_by_addr(config, addr)))
		return NULL;

	for (i = 0; i < net->hosts.count; ++i) {
		fm_fake_host_t *host = net->hosts.entries[i];

		if (fm_address_equal(&host->address, addr, false))
			return host;
	}

	return NULL;
}

/*
 * Chase service names
 */
static bool
fm_fake_config_resolve_services(const char *context_type, const char *context_name, const fm_string_array_t *name_array, const fm_fake_config_t *config, fm_fake_service_array_t *result)
{
	fm_fake_service_t *service;
	unsigned int i;
	bool ok = true;

	for (i = 0; i < name_array->count; ++i) {
		const char *service_name = name_array->entries[i];

		service = fm_fake_config_get_service(config, service_name);
		if (service == NULL) {
			fm_log_error("%s %s references unknown service name %s", context_type, context_name, service_name);
			return false;
		}

		if (fm_fake_service_array_contains(result, service))
			continue;

		fm_fake_service_array_append(result, service);

		if (!fm_fake_config_resolve_services("service", service->name, &service->cfg_requires, config, result))
			ok = false;
	}

	return ok;
}

static bool
fm_fake_config_resolve_profile(fm_fake_host_profile_t *profile, const fm_fake_config_t *config)
{
	return fm_fake_config_resolve_services("host-profile", profile->name, &profile->cfg_services, config, &profile->services);
}

/*
 * Parse port spec
 */
static inline fm_fake_port_t *
fm_fake_port_parse(const char *portspec, fm_fake_port_array_t *port_array)
{
	int proto_id, port;
	const char *end;

	if (!strncmp(portspec, "udp/", 4)) {
		proto_id = FM_PROTO_UDP;
	} else
	if (!strncmp(portspec, "tcp/", 4)) {
		proto_id = FM_PROTO_TCP;
	} else {
		return NULL;
	}

	if (!strcmp(portspec + 4, "priv")) {
		port = 0;
	} else {
		port = strtoul(portspec + 4, (char **) &end, 0);
		if (*end)
			return NULL;

		if (port <= 0 || 65535 < port)
			return NULL;
	}

	return fm_fake_port_array_add(port_array, proto_id, port);
}

static bool
fm_fake_config_resolve_service(fm_fake_service_t *service)
{
	unsigned int i;
	bool ok = true;

	for (i = 0; i < service->cfg_ports.count; ++i) {
		char *portspec = service->cfg_ports.entries[i];

		if (!fm_fake_port_parse(portspec, &service->ports)) {
			fm_log_error("service %s: cannot parse port spec %s", service->name, portspec);
			ok = false;
		}
	}

	return ok;
}

static void
fm_fake_host_add_services(fm_fake_host_t *host, fm_fake_service_array_t *services)
{
	unsigned int i, j, priv_port = 1023;

	for (i = 0; i < services->count; ++i) {
		const fm_fake_service_t *service = services->entries[i];

		for (j = 0; j < service->ports.count; ++j) {
			const fm_fake_port_t *port = &service->ports.entries[j];
			unsigned short port_num;

			if ((port_num = port->port) == 0)
				port_num = priv_port--; /* FIXME: check for used ports */

			fm_fake_port_array_add(&host->ports, port->proto_id, port_num);
		}
	}
}

static bool
fm_fake_host_apply_profiles(fm_fake_host_t *host, const fm_string_array_t *names, const fm_fake_config_t *config)
{
	unsigned int i;

	for (i = 0; i < names->count; ++i) {
		const char *name = names->entries[i];
		fm_fake_host_profile_t *profile;

		profile = fm_fake_config_get_profile(config, name);
		if (profile == NULL) {
			fm_log_error("net %s host %s uses unknown profile %s", host->network->name, host->name, name);
			return false;
		}

		fm_fake_host_add_services(host, &profile->services);
	}

	return true;
}

static const char *
fm_fake_port_array_render(const fm_fake_port_array_t *array)
{
	static char buf[1024];
	unsigned int k, pos = 0;

	if (array->count == 0)
		return "(no ports)";

	for (k = 0; k < array->count; ++k) {
		const fm_fake_port_t *port = &array->entries[k];

		if (pos && pos < sizeof(buf))
			buf[pos++] = ' ';

		snprintf(buf + pos, sizeof(buf) - pos, "%s/%u", fm_protocol_id_to_string(port->proto_id), port->port);
		pos += strlen(buf + pos);
	}

	return buf;
}

/*
 * Build the list of hosts for a given network
 */
static bool
fm_fake_network_build_hosts(fm_fake_network_t *net, const fm_fake_config_t *config)
{
	unsigned int i, j;
	bool ok = true;

	/* You can have a single host entry within a network: 
	 *  host blah {
	 *	profile "mailserver";
	 *  }
	 * This will create host "blah" and use the ports specified by the given profile.
	 */
	for (i = 0; i < net->hosts.count; ++i) {
		fm_fake_host_t *host = net->hosts.entries[i];

		if (!fm_fake_host_apply_profiles(host, &host->cfg_profile, config))
			ok = false;
	}

	/* You can also define a host group within a network: 
	 *  host-group blah {
	 *	profile "linux-desktop";
	 *	count 12;
	 *  }
	 * This will create hosts blah0, blah1, ... blah11 using the specified profile.
	 */
	for (i = 0; i < net->cfg_host_groups.count; ++i) {
		fm_fake_host_group_t *group = net->cfg_host_groups.entries[i];
		unsigned int index = 0;

		if (group->cfg_count == 0)
			continue;

		for (j = 0; j < group->cfg_count; ++j) {
			fm_fake_host_t *host;

			host = fm_fake_host_alloc(&net->hosts);
			asprintf(&host->name, "%s%u", group->name, index++);

			if (!fm_fake_host_apply_profiles(host, &group->cfg_profile, config))
				ok = false;
		}
	}

	for (i = 0; i < net->hosts.count; ++i) {
		fm_fake_host_t *host = net->hosts.entries[i];

		if (host->address.family == AF_UNSPEC
		 && !fm_fake_address_pool_get_next(net->host_address_pool, &host->address)) {
			fm_log_error("net %s: cannot assign address to host %s", net->name, host->name);
			ok = false;
		}

		host->ttl = net->router->ttl + 1;
		host->network = net;

		fm_ratelimit_init(&host->icmp_rate, 20, 20);
	}

	return ok;
}

/*
 * Given the configuration setup, try to build the network in-memory
 */
bool
fm_fake_network_build(fm_fake_config_t *config)
{
	unsigned int i, router_label = 16;
	bool ok = true;

	config->egress_router = fm_fake_router_alloc("egress", &config->routers);
	config->egress_router->label = router_label++;
	config->egress_router->ttl = 1;

	if (!fm_fake_network_create_backbone_pools(&config->backbone_pool, &config->bpool))
		return false;

	for (i = 0; i < config->host_profiles.count; ++i) {
		fm_fake_host_profile_t *profile = config->host_profiles.entries[i];

		if (!fm_fake_config_resolve_profile(profile, config))
			ok = false;
	}

	for (i = 0; i < config->services.count; ++i) {
		fm_fake_service_t *service = config->services.entries[i];

		if (!fm_fake_config_resolve_service(service))
			ok = false;
	}

	for (i = 0; i < config->networks.count; ++i) {
		fm_fake_network_t *net = config->networks.entries[i];

		/* can't happen */
		assert(net->name != NULL);

		if (!fm_address_prefix_parse(net->name, &net->prefix)) {
			fm_log_error("network %s: cannot parse prefix", net->name);
			ok = false;
			continue;
		}

		if (!fm_address_mask_from_prefixlen(net->prefix.address.family, net->prefix.pfxlen, net->prefix_mask, sizeof(net->prefix_mask))) {
			fm_log_error("network %s: cannot build prefix mask", net->name);
			ok = false;
			continue;
		}

		if (net->router_name == NULL) {
			fm_log_error("network %s: no router specified", net->name);
			continue;
		}

		net->router = fm_fake_router_build_chain(config, net->router_name, router_label++);
		if (net->router == NULL) {
			ok = false;
			continue;
		}

		fm_fake_router_assign_addresses(net->router, net->prefix.address.family, &config->bpool);

		/* Set up the host address pool and allocate hosts */
		net->host_address_pool = fm_fake_address_pool_alloc(&net->prefix);

		if (!fm_fake_network_build_hosts(net, config))
			ok = false;

		{
			fm_fake_router_t *router;
			unsigned k;

			fm_log_debug("network %s", net->name);
			for (router = net->router; router; router = router->prev) {
				const fm_address_t *addr = fm_fake_router_get_address(router, net->prefix.address.family);

				fm_log_debug("  %u %s; addr=%s", router->ttl, router->config.name, 
						fm_address_format(addr));
			}

			for (k = 0; k < net->hosts.count; ++k) {
				fm_fake_host_t *host = net->hosts.entries[k];

				fm_log_debug("    host %s (%s): %s", host->name, fm_address_format(&host->address),
						fm_fake_port_array_render(&host->ports));
			}
		}

	}

	return ok;
}
