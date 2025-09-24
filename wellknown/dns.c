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
 *
 * Simple UDP scanning functions
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>

#include "freemap.h"
#include "wellknown.h"

/*
 * DNS query for "."
 * Some servers accept this query; some respond with a FormErr - possibly
 * because we do not include the EDNS OPT RR as additional query record.
 */
static uint8_t		dns_root_query[] = {
	0xca, 0xfe,	/* ID */
	0, 0,		/* query, no flags */
	0, 1,		/* 1 query */
	0, 0,		/* 0 answers */
	0, 0,		/* 0 SOA records */
	0, 0,		/* 0 additional records */

	/* question string: */
	0,		/* 0-octet name component for root "." */
	0, 1,		/* qtype: A */
	0, 1,		/* qclass: IN */
};

static fm_probe_packet_t	dns_root_probe = {
	.data =		dns_root_query,
	.len =		sizeof(dns_root_query),
};

fm_wellknown_service_t	dns_service = {
	.id		= "DNS",
	.probe_packet	= &dns_root_probe,
};

/*
 * mDNS query for some common PTR record(s)
 * Not all mDNS servers will reply to a unicast query (and much less
 * so when receiving the query from a non-local source).
 * Some reply to a unicast query by multicasting the answer to
 * 224.0.0.1:5353
 */
static uint8_t		mdns_ptr_query[] = {
	0xca, 0xfe,	/* ID */
	0, 0,		/* query, no flags */
	0, 1,		/* 1 query */
	0, 0,		/* 0 answers */
	0, 0,		/* 0 SOA records */
	0, 0,		/* 0 additional records */

#if 1
	/* question string: _services._dns-sd._udp.local */
	9, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
	7, '_', 'd', 'n', 's', '-', 's', 'd',
	4, '_', 'u', 'd', 'p',
	5, 'l', 'o', 'c', 'a', 'l',
	0,
#else
	/* question string: _workstation._tcp.local */
	12, '_', 'w', 'o', 'r', 'k', 's', 't', 'a', 't', 'i', 'o', 'n',
	4, '_', 't', 'c', 'p',
	5, 'l', 'o', 'c', 'a', 'l',
	0,
#endif

	0, 12,		/* qtype: PTR */
	0, 1,		/* qclass: IN */
};

static fm_probe_packet_t	mdns_ptr_probe = {
	.data =		mdns_ptr_query,
	.len =		sizeof(mdns_ptr_query),
};

fm_wellknown_service_t	mdns_service = {
	.id		= "mDNS",
	.probe_packet	= &mdns_ptr_probe,
};
