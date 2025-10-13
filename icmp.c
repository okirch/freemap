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
#include "utils.h"

struct icmp_host_probe_params {
	fm_address_t	host_address;
	unsigned int	retries;
	int		ipproto;
	int		icmp_type;
	int		icmp6_type;
	uint32_t	ident;
	uint32_t	seq;

	const char *	type_name;
};

static fm_scan_action_t *fm_icmp_create_host_probe_action(fm_protocol_t *proto, const fm_string_array_t *args);
static fm_rtt_stats_t *	fm_icmp_create_rtt_estimator(const fm_protocol_t *proto, unsigned int netid);
static int		fm_icmp_protocol_for_family(int af);

static struct fm_protocol_ops	fm_icmp_bsdsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "icmp",
	.id		= FM_PROTO_ICMP,

	.create_rtt_estimator = fm_icmp_create_rtt_estimator,
	.create_host_probe_action = fm_icmp_create_host_probe_action,
};

fm_protocol_t *
fm_icmp_bsdsock_create(void)
{
	return fm_protocol_create(&fm_icmp_bsdsock_ops);
}

static fm_rtt_stats_t *
fm_icmp_create_rtt_estimator(const fm_protocol_t *proto, unsigned int netid)
{
	return fm_rtt_stats_create(proto->ops->id, netid, FM_ICMP_PACKET_SPACING / 5, 5);
}

/*
 * ICMP param block.
 * We do this in two steps - early on, we parse the arguments given by the user, leaving
 * everything blank that is related to the target or the target address family.
 * In a second step, when we create a probe for a specific target, we fill in these
 * blanks.
 */
static inline bool
fm_icmp_build_params(struct icmp_host_probe_params *params, const fm_string_array_t *args)
{
	unsigned int i;

	memset(params, 0, sizeof(*params));

	for (i = 0; i < args->count; ++i) {
		const char *arg = args->entries[i];
		unsigned int value;

		if (fm_parse_numeric_argument(arg, "retries", &value)) {
			params->retries = value;
		} else if (fm_parse_string_argument(arg, "type", &params->type_name)) {
			/* pass */
		} else {
			fm_log_error("Cannot create ICMP host probe: invalid argument \"%s\"", arg);
			return false;
		}
	}

	if (params->retries == 0)
		params->retries = FM_ICMP_PROBE_RETRIES;

	if (params->type_name == NULL)
		params->type_name = "echo";

	if (!strcasecmp(params->type_name, "echo")) {
		params->icmp_type = ICMP_ECHO;
		params->icmp6_type = ICMP6_ECHO_REQUEST;
	} else if (!strcasecmp(params->type_name, "timestamp")) {
		params->icmp_type = ICMP_TIMESTAMP;
		params->icmp6_type = -1;
	} else if (!strcasecmp(params->type_name, "info")) {
		params->icmp_type = ICMP_INFO_REQUEST;
		params->icmp6_type = -1;
	} else {
		fm_log_error("ICMP type %s not supported\n", params->type_name);
		return false;
	}

	return true;
}

static inline bool
fm_icmp_instantiate_params(struct icmp_host_probe_params *params, fm_target_t *target)
{
	params->host_address = target->address;

	/* allocate a block of sequence numbers from the target's pool */
	params->seq = target->host_probe_seq;
	target->host_probe_seq += params->retries;

	params->ipproto = fm_icmp_protocol_for_family(target->address.ss_family);
	if (params->ipproto < 0) {
		fm_log_error("Cannot create ICMP probe for %s", fm_address_format(&target->address));
		return false;
	}

	params->ident = 0x1234;
	return true;
}

int
fm_icmp_protocol_for_family(int af)
{
	switch (af) {
	case AF_INET:
		return IPPROTO_ICMP;

	case AF_INET6:
		return IPPROTO_ICMPV6;

	default:
		return -1;
	}
}

/*
 * ICMP port probes using standard BSD sockets
 */
struct fm_icmp_host_probe {
	fm_probe_t	base;

	struct icmp_host_probe_params params;
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
		fm_log_debug("ICMP probe %s: reachable\n", fm_address_format(&icmp->params.host_address));
		fm_probe_mark_host_reachable(&icmp->base, "icmp");
	}
	if (bits & POLLERR) {
		fm_log_debug("ICMP probe %s: unreachable\n", fm_address_format(&icmp->params.host_address));
		fm_probe_mark_host_unreachable(&icmp->base, "icmp");
	}

	fm_probe_reply_received(&icmp->base);
	fm_socket_close(sock);
}

static unsigned int
fm_icmp_build_echo_request(int af, const struct icmp_host_probe_params *params, unsigned char *buf, size_t bufsz)
{
	unsigned int rsize = 0;

	if (af == AF_INET) {
		struct icmp *icmp = (struct icmp *) buf;

		if (bufsz < sizeof(*icmp))
			return 0;

		icmp->icmp_type = params->icmp_type;
		icmp->icmp_code = 0;
		icmp->icmp_cksum = 0;
		icmp->icmp_id = htons(params->ident);
		icmp->icmp_seq = htons(params->seq);

		icmp->icmp_cksum = in_csum(icmp, sizeof(*icmp));
		rsize = sizeof(*icmp);
        } else if (af == AF_INET6) {
		struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) buf;

		icmp6->icmp6_type = params->icmp6_type;
		icmp6->icmp6_code = 0;
		icmp6->icmp6_cksum = 0;
		icmp6->icmp6_id = htons(params->ident);
		icmp6->icmp6_seq = htons(params->seq);

		/* Kernel takes care of checksums */
		rsize = sizeof(*icmp6);
        }

	return rsize;
}

static fm_fact_t *
fm_icmp_host_probe_send(fm_probe_t *probe)
{
	struct fm_icmp_host_probe *icmp = (struct fm_icmp_host_probe *) probe;
	int af = icmp->params.host_address.ss_family;
	unsigned char pktbuf[128];
	size_t pktlen;

	if (icmp->sock == NULL) {
		icmp->sock = fm_socket_create(af, SOCK_DGRAM, icmp->params.ipproto);
		if (icmp->sock == NULL) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to create ICMP socket for %s: %m",
					fm_address_format(&icmp->params.host_address));
		}

		fm_socket_enable_recverr(icmp->sock);

		fm_socket_set_callback(icmp->sock, fm_icmp_host_probe_callback, probe);

		if (!fm_socket_connect(icmp->sock, &icmp->params.host_address)) {
			return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to connect ICMP socket for %s: %m",
					fm_address_format(&icmp->params.host_address));
		}
	}

	pktlen = fm_icmp_build_echo_request(af, &icmp->params, pktbuf, sizeof(pktbuf));
	if (pktlen == 0)
		return fm_fact_create_error(FM_FACT_SEND_ERROR, "Don't know hot to build ICMP packet for address family %d", af);

	icmp->params.seq += 1;

	if (!fm_socket_send(icmp->sock, NULL, pktbuf, pktlen))
		return fm_fact_create_error(FM_FACT_SEND_ERROR, "Unable to send ICMP packet: %m");

	if (icmp->params.retries > 0)
		icmp->params.retries -= 1;

	/* We send several packets in rapid succession, and then we wait for a bit longer.
	 * The actual values are set in create_rtt_estimator */
	if (icmp->params.retries == 0)
		probe->timeout = FM_ICMP_RESPONSE_TIMEOUT;

	/* If retries > 0, we let the caller pick a timeout based on the rtt estimate */

	return NULL;
}

static bool
fm_icmp_host_probe_should_resend(fm_probe_t *probe)
{
	const struct fm_icmp_host_probe *icmp = (struct fm_icmp_host_probe *) probe;

	/* This is overly aggressive - icmp/echo may be just one of several reachability probes */
	if (icmp->params.retries == 0) {
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
fm_icmp_create_host_probe(fm_protocol_t *proto, fm_target_t *target, const struct icmp_host_probe_params *icmp_args)
{
	struct fm_icmp_host_probe *probe;

	probe = (struct fm_icmp_host_probe *) fm_probe_alloc("icmp/echo", &fm_icmp_host_probe_ops, proto, target);

	probe->sock = NULL;
	probe->params = *icmp_args;

	if (!fm_icmp_instantiate_params(&probe->params, target))
		return NULL;

	fm_log_debug("Created ICMP socket probe for %s\n", fm_address_format(&probe->params.host_address));
	return &probe->base;
}

/*
 * This provides the template for later probes.
 */
struct fm_icmp_host_scan {
	fm_scan_action_t	base;

	fm_protocol_t *		proto;
	struct icmp_host_probe_params params;
};

static fm_probe_t *
fm_icmp_host_scan_get_next_probe(const fm_scan_action_t *action, fm_target_t *target, unsigned int index)
{
	struct fm_icmp_host_scan *hostscan = (struct fm_icmp_host_scan *) action;

	if (index != 0)
		return NULL;

	return fm_icmp_create_host_probe(hostscan->proto, target, &hostscan->params);
}

static const struct fm_scan_action_ops	fm_icmp_host_scan_ops = {
	.obj_size	= sizeof(struct fm_icmp_host_scan),
	.get_next_probe	= fm_icmp_host_scan_get_next_probe,
};

fm_scan_action_t *
fm_icmp_create_host_probe_action(fm_protocol_t *proto, const fm_string_array_t *args)
{
	struct fm_icmp_host_scan *hostscan;
	struct icmp_host_probe_params icmp_args;
	char id[64];

	if (!fm_icmp_build_params(&icmp_args, args))
		return false;

	snprintf(id, sizeof(id), "icmp/%s", icmp_args.type_name);

	hostscan = (struct fm_icmp_host_scan *) fm_scan_action_create(&fm_icmp_host_scan_ops, id);
	hostscan->proto = proto;
	hostscan->params = icmp_args;

	hostscan->base.nprobes = 1;

	return &hostscan->base;
}
