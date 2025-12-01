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

#ifndef FREEMAP_FAKENET_H
#define FREEMAP_FAKENET_H

#include "freemap.h"
#include "addresses.h"
#include "lists.h"

typedef struct fm_fake_address_pool {
	struct hlist		link;

	int			family;

	unsigned int		pfxlen;
	unsigned int		addrbits;
	unsigned int		shift;
	unsigned int		next_value;
	unsigned int		max_value;
	unsigned char		raw_addr[16];
} fm_fake_address_pool_t;

typedef struct fm_fake_router_config {
	char *			name;
	char *			address;
	char *			prev_name;
} fm_fake_router_config_t;

typedef struct fm_fake_router	fm_fake_router_t;
struct fm_fake_router {
	fm_address_t		ipv4_address;
	fm_address_t		ipv6_address;
	fm_fake_router_t *	prev;

	unsigned int		ttl;
	unsigned int		label;		/* used for loop detection only */
	fm_ratelimit_t		icmp_rate;

	struct fm_fake_delay *	link_delay;

	fm_fake_router_config_t	config;
};

typedef struct fm_fake_port {
	unsigned short		proto_id;
	unsigned short		port;		/* a value of 0 means assign a random port in the 512..1023 range */
} fm_fake_port_t;

typedef struct fm_fake_port_array {
	unsigned int		count;
	fm_fake_port_t *	entries;
} fm_fake_port_array_t;

typedef struct fm_fake_service {
	char *			name;

	fm_fake_port_array_t	ports;		/* resolved */

	fm_string_array_t	cfg_ports;
	fm_string_array_t	cfg_requires;
} fm_fake_service_t;

typedef struct fm_fake_service_array {
	unsigned int		count;
	fm_fake_service_t **	entries;
} fm_fake_service_array_t;

typedef struct fm_fake_host_profile {
	char *			name;
	fm_fake_service_array_t	services;	/* resolved */
	fm_ratelimit_t		icmp_rate;

	fm_string_array_t	cfg_services;	/* names from config file */
} fm_fake_host_profile_t;

typedef struct fm_fake_host_profile_array {
	unsigned int		count;
	fm_fake_host_profile_t **entries;
} fm_fake_host_profile_array_t;

typedef struct fm_fake_host_group {
	char *			name;
	fm_string_array_t	cfg_profile;
	unsigned int		cfg_count;
} fm_fake_host_group_t;

typedef struct fm_fake_host_group_array {
	unsigned int		count;
	fm_fake_host_group_t **entries;
} fm_fake_host_group_array_t;

typedef struct fm_fake_host {
	char *			name;
	fm_address_t		address;
	struct fm_fake_network *network;

	unsigned int		ttl;
	fm_fake_port_array_t	ports;

	fm_ratelimit_t		icmp_rate;

	fm_string_array_t	cfg_profile;
} fm_fake_host_t;

typedef struct fm_fake_host_array {
	unsigned int		count;
	fm_fake_host_t **	entries;
} fm_fake_host_array_t;

typedef struct fm_fake_network {
	char *			name;		/* set from config */
	char *			router_name;	/* set from config */

	fm_fake_router_t *	router;
	fm_address_prefix_t	prefix;
	unsigned char		prefix_mask[16];

	fm_fake_host_group_array_t cfg_host_groups;

	fm_fake_address_pool_t *host_address_pool;
	fm_fake_host_array_t	hosts;
} fm_fake_network_t;

typedef struct fm_fake_router_array {
	unsigned int		count;
	fm_fake_router_t **	entries;
} fm_fake_router_array_t;

typedef struct fm_fake_network_array {
	unsigned int		count;
	fm_fake_network_t **	entries;
} fm_fake_network_array_t;

typedef struct fm_fake_config {
	fm_string_array_t	addresses;
	fm_string_array_t	backbone_pool;

	fm_fake_router_t *	egress_router;

	fm_fake_router_array_t	routers;
	fm_fake_network_array_t	networks;
	fm_fake_service_array_t	services;
	fm_fake_host_profile_array_t host_profiles;

	fm_fake_host_profile_t	*default_profile;
	fm_fake_host_profile_t	*default_host_profile;
	fm_fake_host_profile_t	*default_router_profile;

	struct hlist_head	bpool;
} fm_fake_config_t;

typedef struct fm_fake_response {
	struct hlist		link;

	double			when;
	fm_buffer_t *		packet;
} fm_fake_response_t;

typedef struct fm_tunnel {
	char *			ifname;
	int			fd;
	int			ifindex;

	fm_address_t		ipv4_address;
	fm_address_t		ipv6_address;
} fm_tunnel_t;

/* Primitives */
extern fm_fake_network_t *	fm_fake_network_alloc(fm_fake_network_array_t *);
extern fm_fake_router_t *	fm_fake_router_alloc(const char *, fm_fake_router_array_t *);
extern fm_fake_service_t *	fm_fake_service_alloc(fm_fake_service_array_t *array);
extern fm_fake_host_profile_t *	fm_fake_host_profile_alloc(fm_fake_host_profile_array_t *array);
extern fm_fake_host_group_t *	fm_fake_host_group_alloc(fm_fake_host_group_array_t *array);
extern fm_fake_host_t *		fm_fake_host_alloc(fm_fake_host_array_t *array);

extern fm_fake_network_t *	fm_fake_config_get_network_by_addr(const fm_fake_config_t *, const fm_address_t *);
extern fm_fake_host_t *		fm_fake_config_get_host_by_addr(const fm_fake_config_t *, const fm_address_t *);
extern fm_fake_host_t *		fm_fake_network_get_host_by_addr(const fm_fake_network_t *, const fm_address_t *);

extern fm_address_t *		fm_fake_router_addr(fm_fake_router_t *, int family);
extern bool			fm_fake_router_has_address(fm_fake_router_t *router, int family);
extern const fm_address_t *	fm_fake_router_get_address(fm_fake_router_t *router, int family);
extern bool			fm_fake_router_set_address(fm_fake_router_t *router, int family, const fm_address_t *new_addr);

extern void			fm_fake_service_array_append(fm_fake_service_array_t *, fm_fake_service_t *);
extern bool			fm_fake_service_array_contains(fm_fake_service_array_t *, const fm_fake_service_t *);

extern bool			fm_fake_config_load(fm_fake_config_t *config, const char *path);
extern bool			fm_fake_network_build(fm_fake_config_t *config);
extern bool			fm_fake_network_set_egress(fm_fake_config_t *config, const fm_tunnel_t *tunnel);

extern fm_tunnel_t *		fm_fakenet_attach_interface(void);
extern bool			fm_fakenet_configure_interface(fm_tunnel_t *tunnel, fm_fake_config_t *config);
extern bool			fm_fakenet_run(fm_tunnel_t *tunnel, const fm_fake_config_t *config);
extern fm_fake_response_t *	fm_fakenet_process_packet(fm_parsed_pkt_t *cooked, const fm_fake_config_t *config, fm_buffer_t *payload);

extern double			fm_gaussian(double mu, double sigma);
extern double			fm_n_gaussians(unsigned int nsamples, double mu, double sigma);

#endif /* FREEMAP_FAKENET_H */
