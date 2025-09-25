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
 * Simple ICMP reachability functions
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

#include "scanner.h"
#include "protocols.h"
#include "target.h" /* for fm_probe_t */

static fm_probe_t *	fm_icmp_create_host_probe(fm_protocol_engine_t *proto, fm_target_t *target, unsigned int retries);
static fm_rtt_stats_t *	fm_icmp_create_rtt_estimator(const fm_protocol_engine_t *proto, int ipproto, unsigned int netid);

struct fm_icmp_engine_default {
	fm_protocol_engine_t	base;
};

static struct fm_protocol_ops	fm_icmp_engine_default_ops = {
	.obj_size	= sizeof(struct fm_icmp_engine_default),
	.name		= "icmp",

	.create_rtt_estimator = fm_icmp_create_rtt_estimator,
	.create_host_probe = fm_icmp_create_host_probe,
};

fm_protocol_engine_t *
fm_icmp_engine_create(void)
{
	return fm_protocol_engine_create(&fm_icmp_engine_default_ops);
}

static fm_rtt_stats_t *
fm_icmp_create_rtt_estimator(const fm_protocol_engine_t *proto, int ipproto, unsigned int netid)
{
	return fm_rtt_stats_create(ipproto, netid, FM_ICMP_PACKET_SPACING / 5, 5);
}

/*
 * ICMP port probes using standard BSD sockets
 */
struct fm_icmp_host_probe {
	fm_probe_t	base;

	fm_address_t	host_address;
	unsigned int	retries;
	int		ipproto;
	uint32_t	ident;
	uint32_t	seq;
	fm_socket_t *	sock;
};

static void
fm_icmp_host_probe_destroy(fm_probe_t *probe)
{
	struct fm_icmp_host_probe *icmp = (struct fm_icmp_host_probe *) probe;

	if (icmp->sock != NULL) {
		fm_socket_set_callback(icmp->sock, NULL, NULL);
		fm_socket_free(icmp->sock);
		icmp->sock = NULL;
	}
}

static void
fm_icmp_host_probe_callback(fm_socket_t *sock, int bits, void *user_data)
{
	struct fm_icmp_host_probe *icmp = user_data;

	assert(icmp->sock == sock);

	/* FIXME actually receive the packet and make sure it's the response we
	 * were looking for. */
	if (bits & POLLIN) {
		fm_log_debug("ICMP probe %s: reachable\n", fm_address_format(&icmp->host_address));
		fm_probe_mark_host_reachable(&icmp->base, "icmp");
	}
	if (bits & POLLERR) {
		fm_log_debug("ICMP probe %s: unreachable\n", fm_address_format(&icmp->host_address));
		fm_probe_mark_host_unreachable(&icmp->base, "icmp");
	}

	fm_probe_reply_received(&icmp->base);
	fm_socket_close(sock);
}

static unsigned int
fm_icmp_build_echo_request(int af, uint32_t ident, uint32_t seq, unsigned char *buf, size_t bufsz)
{
	unsigned int rsize = 0;

	if (af == AF_INET) {
		struct icmp *icmp = (struct icmp *) buf;

		if (bufsz < sizeof(*icmp))
			return 0;

		icmp->icmp_type = ICMP_ECHO;
		icmp->icmp_code = 0;
		icmp->icmp_cksum = 0;
		icmp->icmp_id = htons(ident);
		icmp->icmp_seq = htons(seq);

		icmp->icmp_cksum = in_csum(icmp, sizeof(*icmp));
		rsize = sizeof(*icmp);
        } else if (af == AF_INET6) {
		struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) buf;

		icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
		icmp6->icmp6_code = 0;
		icmp6->icmp6_cksum = 0;
		icmp6->icmp6_id = htons(ident);
		icmp6->icmp6_seq = htons(seq);

		/* Kernel takes care of checksums */
		rsize = sizeof(*icmp6);
        }

	return rsize;
}

static fm_fact_t *
fm_icmp_host_probe_send(fm_probe_t *probe)
{
	struct fm_icmp_host_probe *icmp = (struct fm_icmp_host_probe *) probe;
	int af = icmp->host_address.ss_family;
	unsigned char pktbuf[128];
	size_t pktlen;

	if (icmp->sock == NULL) {
		icmp->sock = fm_socket_create(af, SOCK_DGRAM, icmp->ipproto);
		if (icmp->sock == NULL) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to create ICMP socket for %s: %m",
					fm_address_format(&icmp->host_address));
		}

		fm_socket_enable_recverr(icmp->sock);

		fm_socket_set_callback(icmp->sock, fm_icmp_host_probe_callback, probe);

		if (!fm_socket_connect(icmp->sock, &icmp->host_address)) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to connect ICMP socket for %s: %m",
					fm_address_format(&icmp->host_address));
		}
	}

	pktlen = fm_icmp_build_echo_request(af, icmp->ident, icmp->seq++, pktbuf, sizeof(pktbuf));
	if (pktlen == 0)
		return fm_fact_create_error(FM_FACT_SEND_ERROR, "Don't know hot to build ICMP packet for address family %d", af);

	if (!fm_socket_send(icmp->sock, NULL, pktbuf, pktlen))
		return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to send ICMP packet: %m");

	if (icmp->retries > 0)
		icmp->retries -= 1;

	/* We send several packets in rapid succession, and then we wait for a bit longer.
	 * The actual values are set in create_rtt_estimator */
	if (icmp->retries == 0)
		probe->timeout = FM_ICMP_RESPONSE_TIMEOUT;

	/* If retries > 0, we let the caller pick a timeout based on the rtt estimate */

	return NULL;
}

static bool
fm_icmp_host_probe_should_resend(fm_probe_t *probe)
{
	const struct fm_icmp_host_probe *icmp = (struct fm_icmp_host_probe *) probe;

	/* This is overly aggressive - icmp/echo may be just one of several reachability probes */
	if (icmp->retries == 0) {
		fm_probe_mark_host_unreachable(probe, probe->name);
		return false;
	}

	return true;
}

static struct fm_probe_ops fm_icmp_host_probe_ops = {
	.obj_size	= sizeof(struct fm_icmp_host_probe),
	.name 		= "icmp",

	.default_timeout= 1000,	/* FM_ICMP_RESPONSE_TIMEOUT */

	.destroy	= fm_icmp_host_probe_destroy,
	.send		= fm_icmp_host_probe_send,
	.should_resend	= fm_icmp_host_probe_should_resend,
};

static fm_probe_t *
fm_icmp_create_host_probe(fm_protocol_engine_t *proto, fm_target_t *target, unsigned int retries)
{
	struct fm_icmp_host_probe *probe;
	int ipproto;

	if (retries == 0)
		retries = FM_ICMP_PROBE_RETRIES;

	switch (target->address.ss_family) {
	case AF_INET:
		ipproto = IPPROTO_ICMP;
		break;

	case AF_INET6:
		ipproto = IPPROTO_ICMPV6;
		break;

	default:
		fm_log_error("Cannot create ICMP probe for %s", fm_address_format(&target->address));
		return NULL;
	}

	probe = (struct fm_icmp_host_probe *) fm_probe_alloc("icmp/echo", &fm_icmp_host_probe_ops, ipproto, target);

	probe->sock = NULL;

	probe->host_address = target->address;
	probe->ipproto = ipproto;
	probe->ident = 0x1234;
	probe->seq = target->host_probe_seq;
	probe->retries = retries;
	target->host_probe_seq += retries;

	/* Make this a blocking probe, ie do not send any other packets to this host until
	 * the icmp probe has completed. */
	probe->base.blocking = true;

	fm_log_debug("Created ICMP socket probe for %s\n", fm_address_format(&probe->host_address));
	return &probe->base;
}
