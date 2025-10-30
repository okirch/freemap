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
#include <linux/errqueue.h>

#include "scanner.h"
#include "protocols.h"
#include "target.h" /* for fm_probe_t */
#include "buffer.h"
#include "utils.h"

struct icmp_params {
	fm_address_t	host_address;
	int		ipproto;
	int		icmp_type;
	int		icmp6_type;
	uint32_t	ident;
	uint32_t	seq;

	const char *	type_name;
};

static fm_socket_t *	fm_icmp_create_bsd_socket(fm_protocol_t *proto, int ipproto);
static bool		fm_icmp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt);
static bool		fm_icmp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt);
static fm_socket_t *	fm_icmp_create_raw_socket(fm_protocol_t *proto, int ipproto);
static fm_socket_t *	fm_icmp_create_shared_raw_socket(fm_protocol_t *proto, fm_target_t *target);

static fm_socket_t *	fm_icmp_create_connected_socket(fm_protocol_t *proto, const fm_address_t *addr);
static bool		fm_icmp_finalize_action(fm_protocol_t *, fm_scan_action_t *, const fm_string_array_t *);
static fm_probe_t *	fm_icmp_create_host_probe(fm_protocol_t *, fm_target_t *, const fm_probe_params_t *params, const void *extra_params);
static int		fm_icmp_protocol_for_family(int af);
static fm_extant_t *	fm_icmp_locate_probe(const struct sockaddr_storage *target_addr, fm_pkt_t *pkt, bool is_response, bool ignore_id);

static struct fm_protocol_ops	fm_icmp_bsdsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "icmp",
	.id		= FM_PROTO_ICMP,

	.supported_parameters =
			  FM_PROBE_PARAM_MASK(TTL) |
			  FM_PROBE_PARAM_MASK(TOS) |
			  FM_PROBE_PARAM_MASK(RETRIES),

	.create_socket	= fm_icmp_create_bsd_socket,
	.process_packet	= fm_icmp_process_packet,
	.process_error	= fm_icmp_process_error,

	.finalize_action = fm_icmp_finalize_action,
	.create_parameterized_probe = fm_icmp_create_host_probe,
};

static struct fm_protocol_ops	fm_icmp_rawsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "icmp-raw",
	.id		= FM_PROTO_ICMP,
	.require_raw	= true,

	.supported_parameters =
			  FM_PROBE_PARAM_MASK(TTL) |
			  FM_PROBE_PARAM_MASK(TOS) |
			  FM_PROBE_PARAM_MASK(RETRIES),

	.create_socket	= fm_icmp_create_raw_socket,
	.create_host_shared_socket = fm_icmp_create_shared_raw_socket,
	.process_packet	= fm_icmp_process_packet,
	.process_error	= fm_icmp_process_error,

	.finalize_action = fm_icmp_finalize_action,
	.create_parameterized_probe = fm_icmp_create_host_probe,
};

FM_PROTOCOL_REGISTER(fm_icmp_bsdsock_ops);
FM_PROTOCOL_REGISTER(fm_icmp_rawsock_ops);

static fm_socket_t *
fm_icmp_create_bsd_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;
	int ipproto;

	/* This should not fail; the caller should have taken care of this check already */
	ipproto = fm_icmp_protocol_for_family(af);
	if (ipproto < 0)
		return NULL;

	sock = fm_socket_create(af, SOCK_DGRAM, ipproto, proto);
	if (sock != NULL) {
		fm_socket_enable_ttl(sock);
		fm_socket_enable_tos(sock);
	}
	return sock;
}

static bool
fm_icmp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	fm_extant_t *extant = NULL;
	bool ignore_id = false;

	fm_log_debug("received ICMP reply from %s", fm_address_format(&pkt->peer_addr));
	/* fm_print_hexdump(pkt->data, pkt->len); */

	fm_host_asset_update_state_by_address(&pkt->peer_addr, FM_ASSET_STATE_OPEN);

	if (proto->ops == &fm_icmp_bsdsock_ops) {
		/* When using dgram/icmp sockets, the kernel will overwrite the icmp sequence
		 * number that we picked. So ignore that in our search for a matching
		 * probe */
		ignore_id = true;
	} else
	if (pkt->family == AF_INET) {
		fm_ip_info_t ip;

		/* PF_RAW sockets will always give us the IPv4 header.
		 * Funnily, IPv6 packets always come with the header stripped. */
		if (!fm_pkt_pull_ip_hdr(pkt, &ip)) {
			fm_log_debug("%s: bad IP header", proto->ops->name);
			return false;
		}

		if (ip.ipproto != IPPROTO_ICMP)  {
			fm_log_debug("%s: %s -> %s: unexpected protocol %d", __func__,
					fm_address_format(&ip.src_addr),
					fm_address_format(&ip.dst_addr),
					ip.ipproto);
			return false;
		}
	}

	extant = fm_icmp_locate_probe(&pkt->peer_addr, pkt, true, ignore_id);
	if (extant != NULL) {
		/* Mark the probe as successful, and update the RTT estimate */
		fm_extant_received_reply(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

bool
fm_icmp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt)
{
	const struct sock_extended_err *ee;
	fm_extant_t *extant = NULL;
	bool ignore_id = false;

	/* fm_print_hexdump(pkt->data, pkt->len); */

	if (proto->ops == &fm_icmp_bsdsock_ops) {
		/* When using dgram/icmp sockets, the kernel will overwrite the icmp sequence
		 * number that we picked. So ignore that in our search for a matching
		 * probe */
		ignore_id = true;
	}

	if ((ee = pkt->info.ee) == NULL)
		return false;

	if (pkt->family == AF_INET && ee->ee_origin == SO_EE_ORIGIN_ICMP) {
		if (ee->ee_type != ICMP_DEST_UNREACH) {
			fm_log_debug("%s ignoring icmp packet with type %d.%d",
					fm_address_format(&pkt->peer_addr),
					ee->ee_type, ee->ee_code);
			return false;
		}

		fm_log_debug("%s destination unreachable (code %d)\n",
				fm_address_format(&pkt->peer_addr), ee->ee_code);

		/* update asset state right away */
		fm_host_asset_update_state_by_address(&pkt->peer_addr, FM_ASSET_STATE_CLOSED);
		if (pkt->info.offender != NULL)
			fm_host_asset_update_state_by_address(pkt->info.offender, FM_ASSET_STATE_OPEN);

		/* The errqueue stuff is a bit non-intuitive at times. When receiving an
		 * ICMP packet, the "from" address is the IP we originally sent the packet
		 * to, and the offender is the address of the host that generated the
		 * ICMP packet. */
		extant = fm_icmp_locate_probe(&pkt->peer_addr, pkt, false, ignore_id);

		/* TODO: record the gateway that generated this error code;
		 * we could build a rough sketch of the network topo and avoid swamping
		 * the gateway with too many packets (which would result in ICMP errors
		 * being dropped). */
	}

	if (extant != NULL) {
		/* Mark the probe as failed, and update the RTT estimate */
		fm_extant_received_error(extant, pkt);
		fm_extant_free(extant);
	}

	return true;
}

/*
 * Raw sockets
 */
static fm_socket_t *
fm_icmp_create_raw_socket(fm_protocol_t *proto, int af)
{
	fm_socket_t *sock;
	int ipproto;

	/* This should not fail; the caller should have taken care of this check already */
	ipproto = fm_icmp_protocol_for_family(af);
	if (ipproto < 0)
		return NULL;

	sock = fm_socket_create(af, SOCK_RAW, ipproto, proto);
	if (sock != NULL) {
		fm_socket_enable_ttl(sock);
		fm_socket_enable_tos(sock);
	}
	return sock;
}

static fm_socket_t *
fm_icmp_create_shared_raw_socket(fm_protocol_t *proto, fm_target_t *target)
{
	const fm_address_t *addr = &target->address;
	fm_socket_t **sharedp;

	if (addr->ss_family == AF_INET)
		sharedp = &target->raw_icmp4_sock;
	else if (addr->ss_family == AF_INET6)
		sharedp = &target->raw_icmp4_sock;
	else
		return NULL;

	if (*sharedp == NULL)
		*sharedp = fm_icmp_create_connected_socket(proto, addr);

	return *sharedp;
}

/*
 * ICMP param block.
 * We do this in two steps - early on, we parse the arguments given by the user, leaving
 * everything blank that is related to the target or the target address family.
 * In a second step, when we create a probe for a specific target, we fill in these
 * blanks.
 */
static inline bool
fm_icmp_build_params(struct icmp_params *params, const fm_string_array_t *args)
{
	unsigned int i;

	memset(params, 0, sizeof(*params));

	for (i = 0; i < args->count; ++i) {
		const char *arg = args->entries[i];

		if (fm_parse_string_argument(arg, "type", &params->type_name)) {
			/* pass */
		} else {
			fm_log_error("Cannot create ICMP host probe: invalid argument \"%s\"", arg);
			return false;
		}
	}

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
fm_icmp_instantiate_params(struct icmp_params *params, fm_target_t *target)
{
	params->host_address = target->address;

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
 * ICMP probes using standard BSD sockets
 */
struct fm_icmp_host_probe {
	fm_probe_t		base;

	fm_probe_params_t	probe_params;
	struct icmp_params	icmp_params;
	fm_socket_t *		sock;
};

static void
fm_icmp_host_probe_destroy(fm_probe_t *probe)
{
	struct fm_icmp_host_probe *icmp = (struct fm_icmp_host_probe *) probe;

	if (icmp->sock != NULL) {
		fm_socket_free(icmp->sock);
		icmp->sock = NULL;
	}
}

static fm_pkt_t *
fm_icmp_build_echo_request(int af, const struct icmp_params *params)
{
	fm_pkt_t *pkt = fm_pkt_alloc(af, 64);
	fm_buffer_t *bp = pkt->payload;

	if (af == AF_INET) {
		struct icmp *icmp;

		icmp = fm_buffer_push(bp, sizeof(*icmp));
		icmp->icmp_type = params->icmp_type;
		icmp->icmp_code = 0;
		icmp->icmp_cksum = 0;
		icmp->icmp_id = htons(params->ident);
		icmp->icmp_seq = htons(params->seq);

		icmp->icmp_cksum = in_csum(icmp, sizeof(*icmp));
        } else if (af == AF_INET6) {
		struct icmp6_hdr *icmp6;

		icmp6 = fm_buffer_push(bp, sizeof(*icmp6));
		icmp6->icmp6_type = params->icmp6_type;
		icmp6->icmp6_code = 0;
		icmp6->icmp6_cksum = 0;
		icmp6->icmp6_id = htons(params->ident);
		icmp6->icmp6_seq = htons(params->seq);

		/* Kernel takes care of checksums */
        }

	return pkt;
}

/*
 * Build the response match
 */
static inline int
get_icmp4_response_type(int type)
{
	switch (type) {
	case ICMP_ECHO:
		return ICMP_ECHOREPLY;
	case ICMP_TIMESTAMP:
		return ICMP_TIMESTAMPREPLY;
	case ICMP_INFO_REQUEST:
		return ICMP_INFO_REPLY;
	}
	return -1;
}

static inline int
get_icmp6_response_type(int type)
{
	switch (type) {
	case ICMP6_ECHO_REQUEST:
		return ICMP6_ECHO_REPLY;
	}
	return -1;
}

struct icmp_extant_info {
	struct icmp		sent_hdr;
	struct icmp		expect_hdr;
};

struct icmp6_extant_info {
	struct icmp6_hdr	sent_hdr;
	struct icmp6_hdr	expect_hdr;
};

static bool
fm_icmp4_expect_response(const void *sent_data, unsigned int sent_len, fm_probe_t *probe)
{
	struct icmp_extant_info info;
	int expect_type = -1;

	if (sent_len < sizeof(info.sent_hdr))
		return false;

	memcpy(&info.sent_hdr, sent_data, sizeof(info.sent_hdr));

	if ((expect_type = get_icmp4_response_type(info.sent_hdr.icmp_type)) < 0)
		return false;

	info.expect_hdr = info.sent_hdr;
	info.expect_hdr.icmp_type = expect_type;

	fm_extant_alloc(probe, AF_INET, IPPROTO_ICMP, &info, sizeof(info));
	return true;
}

static bool
fm_icmp6_expect_response(const void *sent_data, unsigned int sent_len, fm_probe_t *probe)
{
	struct icmp6_extant_info info;
	int expect_type = -1;

	if (sent_len < sizeof(info.sent_hdr))
		return false;

	memcpy(&info.sent_hdr, sent_data, sizeof(info.sent_hdr));

	if ((expect_type = get_icmp6_response_type(info.sent_hdr.icmp6_type)) < 0)
		return false;

	info.expect_hdr = info.sent_hdr;
	info.expect_hdr.icmp6_type = expect_type;

	fm_extant_alloc(probe, AF_INET6, IPPROTO_ICMPV6, &info, sizeof(info));
	return true;
}

static bool
fm_icmp_expect_response(const fm_pkt_t *pkt, fm_probe_t *probe)
{
	fm_buffer_t *bp = pkt->payload;
	unsigned int sent_len = fm_buffer_available(bp);
	const void *sent_data = fm_buffer_head(bp);

	if (pkt->family == AF_INET) {
		return fm_icmp4_expect_response(sent_data, sent_len, probe);
	} else if (pkt->family == AF_INET6) {
		return fm_icmp6_expect_response(sent_data, sent_len, probe);
	}

	return false;
}

fm_extant_t *
fm_icmp4_locate_probe(fm_target_t *target, fm_pkt_t *pkt, bool is_response, bool ignore_id)
{
	const struct icmp *icmph;
	hlist_iterator_t iter;
	fm_extant_t *extant;

	if (!(icmph = fm_pkt_pull(pkt, sizeof(*icmph))))
		return NULL;

        fm_extant_iterator_init(&iter, &target->expecting);
        while ((extant = fm_extant_iterator_match(&iter, AF_INET, IPPROTO_ICMP)) != NULL) {
		const struct icmp_extant_info *ei = (struct icmp_extant_info *) (extant + 1);
		const struct icmp *match = is_response? &ei->expect_hdr : &ei->sent_hdr;

		if (!ignore_id && match->icmp_id != icmph->icmp_id)
			continue;

		if (match->icmp_type == icmph->icmp_type
		 && match->icmp_seq == icmph->icmp_seq)
			return extant;
        }

	return NULL;
}

static fm_extant_t *
fm_icmp6_locate_probe(fm_target_t *target, fm_pkt_t *pkt, bool is_response, bool ignore_id)
{
	const struct icmp6_hdr *icmph;
	hlist_iterator_t iter;
	fm_extant_t *extant;

	if (!(icmph = fm_pkt_pull(pkt, sizeof(*icmph))))
		return NULL;

        fm_extant_iterator_init(&iter, &target->expecting);
        while ((extant = fm_extant_iterator_match(&iter, AF_INET6, IPPROTO_ICMPV6)) != NULL) {
		const struct icmp6_extant_info *ei = (struct icmp6_extant_info *) (extant + 1);
		const struct icmp6_hdr *match = is_response? &ei->expect_hdr : &ei->sent_hdr;

		if (!ignore_id && match->icmp6_id != icmph->icmp6_id)
			continue;

		if (match->icmp6_type == icmph->icmp6_type
		 && match->icmp6_seq == icmph->icmp6_seq)
			return extant;
        }

	return NULL;
}

fm_extant_t *
fm_icmp_locate_probe(const struct sockaddr_storage *target_addr, fm_pkt_t *pkt, bool is_response, bool ignore_id)
{
	fm_target_t *target;

	if (pkt->family != target_addr->ss_family)
		return NULL;

	target = fm_target_pool_find(target_addr);
	if (target == NULL)
		return NULL;

	if (pkt->family == AF_INET)
		return fm_icmp4_locate_probe(target, pkt, is_response, ignore_id);
	if (pkt->family == AF_INET6)
		return fm_icmp6_locate_probe(target, pkt, is_response, ignore_id);

	return NULL;
}

static fm_socket_t *
fm_icmp_create_connected_socket(fm_protocol_t *proto, const fm_address_t *addr)
{
	fm_socket_t *sock;

	sock = fm_protocol_create_socket(proto, addr->ss_family);
	if (sock == NULL)
		return NULL;

	fm_socket_enable_recverr(sock);

	if (!fm_socket_connect(sock, addr)) {
		fm_socket_free(sock);
		return NULL;
	}

	return sock;
}

static fm_error_t
fm_icmp_host_probe_send(fm_probe_t *probe)
{
	fm_target_t *target = probe->target;
	fm_socket_t *sock;
	struct fm_icmp_host_probe *icmp = (struct fm_icmp_host_probe *) probe;
	int af = icmp->icmp_params.host_address.ss_family;
	fm_pkt_t *pkt;

	/* When using raw sockets, create a single ICMP socket per target host */
	sock = fm_protocol_create_host_shared_socket(probe->proto, probe->target);

	if (sock == NULL) {
		if (icmp->sock == NULL) {
			icmp->sock = fm_icmp_create_connected_socket(probe->proto, &target->address);
		}
		if (icmp->sock == NULL) {
			fm_log_error("Unable to create ICMP socket for %s: %m",
					fm_address_format(&target->address));
			return FM_SEND_ERROR;
		}

		sock = icmp->sock;
	}

	icmp->icmp_params.seq = target->host_probe_seq++;

	pkt = fm_icmp_build_echo_request(af, &icmp->icmp_params);
	if (pkt == NULL) {
		fm_log_error("Don't know how to build ICMP packet for address family %d", af);
		return FM_SEND_ERROR;
	}

	/* apply ttl and tos */
	fm_pkt_apply_probe_params(pkt, &icmp->probe_params, probe->proto->ops->supported_parameters);

	/* inform the ICMP response matching code that we're waiting for a response to this packet */
	fm_icmp_expect_response(pkt, probe);

	if (!fm_socket_send_pkt_and_burn(sock, pkt)) {
		fm_log_error("Unable to send ICMP packet: %m");
		return FM_SEND_ERROR;
	}

	if (icmp->probe_params.retries > 0)
		icmp->probe_params.retries -= 1;

	/* We send several packets in rapid succession, and then we wait for a bit longer.
	 * The actual values are set in create_rtt_estimator */
	if (icmp->probe_params.retries == 0)
		probe->timeout = FM_ICMP_RESPONSE_TIMEOUT;

	/* If retries > 0, we let the caller pick a timeout based on the rtt estimate */

	/* Update the asset state */
	fm_target_update_host_state(target, FM_PROTO_ICMP, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

static bool
fm_icmp_host_probe_should_resend(fm_probe_t *probe)
{
	const struct fm_icmp_host_probe *icmp = (struct fm_icmp_host_probe *) probe;

	/* This is overly aggressive - icmp/echo may be just one of several reachability probes */
	if (icmp->probe_params.retries == 0) {
		fm_probe_timed_out(probe);
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
fm_icmp_create_host_probe(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	const struct icmp_params *icmp_args = extra_params;
	struct fm_icmp_host_probe *probe;

	probe = (struct fm_icmp_host_probe *) fm_probe_alloc("icmp/echo", &fm_icmp_host_probe_ops, proto, target);

	probe->sock = NULL;
	probe->icmp_params = *icmp_args;

	probe->probe_params = *params;
	if (probe->probe_params.retries == 0)
		probe->probe_params.retries = FM_ICMP_PROBE_RETRIES;

	if (!fm_icmp_instantiate_params(&probe->icmp_params, target))
		return NULL;

	fm_log_debug("Created ICMP socket probe for %s\n", fm_address_format(&probe->icmp_params.host_address));
	return &probe->base;
}

/*
 * After we've created a generic hostscan action, come here for some polishing
 */
static bool
fm_icmp_finalize_action(fm_protocol_t *proto, fm_scan_action_t *action, const fm_string_array_t *extra_args)
{
	struct icmp_params *icmp_params;

	icmp_params = calloc(1, sizeof(*icmp_params));
	if (!fm_icmp_build_params(icmp_params, extra_args)) {
		free(icmp_params);
		return false;
	}

	action->extra_params = icmp_params;
	return true;
}
