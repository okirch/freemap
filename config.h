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

#ifndef FREEMAP_CONFIG_H
#define FREEMAP_CONFIG_H

#include <stdbool.h>
#include "types.h"

struct fm_config {
	struct fm_config_target_pool {
		unsigned int	initial_size;
		unsigned int	max_size;

		/* how often we try to grow the target pool, in seconds */
		unsigned int	resize_interval;
	} target_pool;

	struct fm_config_scanner {
		/* The max number of packets we are allowed to generate, globally. */
		unsigned int	global_packet_rate;

		/* The rate of packets per target we're allowed to generate. */
		unsigned int	target_packet_rate;
	} scanner;

	struct fm_config_ipv4 {
		unsigned int	ttl;
		unsigned int	tos;
	} ipv4;
	struct fm_config_ipv6 {
		unsigned int	ttl;
		unsigned int	tos;
	} ipv6;
	struct fm_config_udp {
		unsigned int	application_delay;
	} udp;
	struct fm_config_tcp {
		unsigned int	application_delay;
	} tcp;
	struct fm_config_icmp {
		unsigned int	retries;

		/* delay, in ms, between sending two packets */
		unsigned int	packet_spacing;

		/* timeout for response to arrive */
		unsigned int	timeout;
	} icmp;
	struct fm_config_arp {
		unsigned int	retries;

		/* delay, in ms, between sending two packets */
		unsigned int	packet_spacing;

		/* timeout for response to arrive */
		unsigned int	timeout;
	} arp;
};

extern fm_config_t		fm_global;

#define FM_DEFAULT_GLOBAL_PACKET_RATE	fm_global.scanner.global_packet_rate
#define FM_DEFAULT_HOST_PACKET_RATE	fm_global.scanner.target_packet_rate

#define FM_INITIAL_TARGET_POOL_SIZE	fm_global.target_pool.initial_size
#define FM_TARGET_POOL_MAX_SIZE		fm_global.target_pool.max_size
#define FM_TARGET_POOL_RESIZE_TIME	fm_global.target_pool.resize_interval

#define FM_ICMP_PROBE_RETRIES		fm_global.icmp.retries
#define FM_ICMP_PACKET_SPACING		fm_global.icmp.packet_spacing
#define FM_ICMP_RESPONSE_TIMEOUT	fm_global.icmp.timeout

#define FM_ARP_PROBE_RETRIES		fm_global.arp.retries
#define FM_ARP_PACKET_SPACING		fm_global.arp.packet_spacing
#define FM_ARP_RESPONSE_TIMEOUT		fm_global.arp.timeout


#endif /* FREEMAP_CONFIG_H */

