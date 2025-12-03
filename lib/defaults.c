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
#include "xconfig.h"

fm_config_t		fm_global;

void
fm_config_init_defaults(fm_config_t *conf)
{
	fm_string_array_append(&conf->library.search_path, FREEMAP_PROBES_PATH);
#ifdef FREEMAP_DEVELOPMENT
	fm_string_array_append(&conf->library.search_path, "./probes");
#endif

	conf->address_generation.only_family = AF_UNSPEC;
	conf->address_generation.try_all = false;
	conf->address_generation.randomize = false;

	/* the target pool starts out with 16 slots, and we increase its
	 * size every 4 seconds until it has reached its maximum size of 1023 slots.
	 */
	conf->target_pool.initial_size = 16;
	conf->target_pool.max_size = 1023;
	conf->target_pool.resize_interval = 4;

	/* Various bits in the Linux stack seem to be tuned to the magic number of
	 * 1000 packets by default. Since we're not the only ones sending packets,
	 * we may want to stay a bit shy of that rate. */
	conf->scanner.global_packet_rate = 1000;
	conf->scanner.target_packet_rate = 10;

	conf->ipv4.ttl = 64;
	conf->ipv4.tos = 0x10;

	conf->ipv6.ttl = 64;
	conf->ipv6.tos = 0;	/* actually it's called traffic class */

	/* For the time being, assume that any TCP service may take up to .5 sec for the
         * queued TCP connection to be accepted. */
	conf->tcp.application_delay = 500;
	conf->tcp.retries = 3;
	conf->tcp.packet_spacing = 250;
	conf->tcp.timeout = 1000;

	/* For the time being, assume that any UDP service may take up to .5 sec for the
         * queued UDP connection to be accepted. */
	conf->udp.application_delay = 500;
	conf->udp.retries = 3;
	conf->udp.packet_spacing = 250;
	conf->udp.timeout = 1000;

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
