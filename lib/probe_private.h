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

#ifndef FREEMAP_PROBE_PRIVATE_H
#define FREEMAP_PROBE_PRIVATE_H

#include <linux/if_packet.h> /* for sockaddr_ll */

#include "probe.h"
#include "rawpacket.h"

/*
 * This struct holds some per-target scanning state for the
 * protocol drivers.
 */
struct fm_target_control {
	int			family;

	fm_target_t *		target;
	fm_address_t		src_addr;
	fm_address_t		dst_addr;
	fm_socket_t *		sock;

	fm_ip_header_info_t	ip_info;

	union {
		struct {
			uint32_t		src_ipaddr;
			uint32_t		dst_ipaddr;
			struct sockaddr_ll	src_lladdr;
			struct sockaddr_ll	dst_lladdr;
		} arp;
		struct {
			fm_buffer_t *		packet_header;
			fm_csum_partial_t	csum;
			/* counter for icmp seq generation: */
			uint16_t		retries;
		} icmp;
	};
};

struct fm_host_tasklet {
	struct hlist		link;

	double			timeout;

	char *			name;
	fm_target_t *		target;
	fm_host_asset_t *	host_asset;
	fm_ratelimit_t *	ratelimit;

	fm_target_control_t	control;

	unsigned int		probe_index;

	unsigned int		num_tasks;
	fm_tasklet_t *		tasklets;
};


#endif /* FREEMAP_PROBE_PRIVATE_H */

