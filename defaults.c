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

#include "config.h"

fm_config_t		fm_global;

void
fm_config_init_defaults(fm_config_t *conf)
{
	conf->address_generation.only_family = AF_UNSPEC;
	conf->address_generation.try_all = true;
	conf->address_generation.randomize = false;

	/* the target pool starts out with 16 slots, and we increase its
	 * size every 4 seconds until it has reached its maximum size of 1023 slots.
	 */
	conf->target_pool.initial_size = 16;
	conf->target_pool.max_size = 1023;
	conf->target_pool.resize_interval = 4;

	conf->scanner.global_packet_rate = 1000;
	conf->scanner.target_packet_rate = 10;

	/* For the time being, assume that any TCP service may take up to .5 sec for the
         * queued TCP connection to be accepted. */
	conf->tcp.application_delay = 500;

	/* For the time being, assume that any UDP service may take up to .5 sec for the
         * queued UDP connection to be accepted. */
	conf->udp.application_delay = 500;

	/* ICMP reachability probe. We transmit 3 echo requests,
	 * 250 msec apart, then wait for up to 1 second for a response. */
	conf->icmp.retries = 3;
	conf->icmp.packet_spacing = 250;
	conf->icmp.timeout = 1000;

	/* ARP reachability probe. We transmit 3 ARP requests,
	 * 250 msec apart, then wait for up to 1 second for a response. */
	conf->arp.retries = 3;
	conf->arp.packet_spacing = 250;
	conf->arp.timeout = 1000;
}
