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
#include "icmp.h"

static fm_socket_t *	fm_icmp_create_bsd_socket(fm_protocol_t *proto, int ipproto);
static bool		fm_icmp_process_packet(fm_protocol_t *proto, fm_pkt_t *pkt);
static bool		fm_icmp_process_error(fm_protocol_t *proto, fm_pkt_t *pkt);
static fm_socket_t *	fm_icmp_create_raw_socket(fm_protocol_t *proto, int ipproto);
static fm_socket_t *	fm_icmp_create_shared_raw_socket(fm_protocol_t *proto, fm_target_t *target);

static fm_socket_t *	fm_icmp_create_connected_socket(fm_protocol_t *proto, const fm_address_t *addr);
static void *		fm_icmp_process_extra_parameters(fm_protocol_t *, const fm_string_array_t *);
static fm_probe_t *	fm_icmp_create_host_probe(fm_protocol_t *, fm_target_t *, const fm_probe_params_t *params, const void *extra_params);
static int		fm_icmp_protocol_for_family(int af);
static fm_extant_t *	fm_icmp_locate_probe(const struct sockaddr_storage *target_addr, fm_pkt_t *pkt, bool is_response, bool ignore_id);

static fm_icmp_request_t *fm_icmp_probe_get_request(const fm_probe_t *probe);
static void		fm_icmp_probe_set_request(fm_probe_t *probe, fm_icmp_request_t *icmp);

static struct fm_protocol_ops	fm_icmp_bsdsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "icmp",
	.id		= FM_PROTO_ICMP,

	.supported_parameters =
			  FM_PARAM_TYPE_PORT_MASK |	/* we use the port parameter to seq the icmp_id */
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK |
			  FM_FEATURE_STATUS_CALLBACK_MASK,

	.create_socket	= fm_icmp_create_bsd_socket,
	.process_packet	= fm_icmp_process_packet,
	.process_error	= fm_icmp_process_error,

	.process_extra_parameters = fm_icmp_process_extra_parameters,
	.create_parameterized_probe = fm_icmp_create_host_probe,
	.process_extra_parameters = fm_icmp_process_extra_parameters,
};

static struct fm_protocol_ops	fm_icmp_rawsock_ops = {
	.obj_size	= sizeof(fm_protocol_t),
	.name		= "icmp-raw",
	.id		= FM_PROTO_ICMP,
	.require_raw	= true,

	.supported_parameters =
			  FM_PARAM_TYPE_PORT_MASK |	/* we use the port parameter to seq the icmp_id */
			  FM_PARAM_TYPE_TTL_MASK |
			  FM_PARAM_TYPE_TOS_MASK |
			  FM_PARAM_TYPE_RETRIES_MASK |
			  FM_FEATURE_STATUS_CALLBACK_MASK,

	.create_socket	= fm_icmp_create_raw_socket,
	.create_host_shared_socket = fm_icmp_create_shared_raw_socket,
	.process_packet	= fm_icmp_process_packet,
	.process_error	= fm_icmp_process_error,

	.process_extra_parameters = fm_icmp_process_extra_parameters,
	.create_parameterized_probe = fm_icmp_create_host_probe,
	.process_extra_parameters = fm_icmp_process_extra_parameters,
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

/*
 * Create a DGRAM socket and connect it.
 * Used for PF_PACKET sockets only
 */
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
 * Choose the ICMP type to use.
 * As we don't know how long the type_name string passed as argument will be valid,
 * we replace it with a const string.
 */
static bool
fm_icmp_extra_params_set_type(fm_icmp_extra_params_t *params, const char *type_name)
{
	params->ipv4.send_type = -1;
	params->ipv4.response_type = -1;
	params->ipv6.send_type = -1;
	params->ipv6.response_type = -1;

	if (!strcasecmp(type_name, "echo")) {
		params->type_name = "echo";
		params->ipv4.send_type = ICMP_ECHO;
		params->ipv4.response_type = ICMP_ECHOREPLY;
		params->ipv6.send_type = ICMP6_ECHO_REQUEST;
		params->ipv6.response_type = ICMP6_ECHO_REPLY;
	} else if (!strcasecmp(type_name, "timestamp")) {
		params->type_name = "timestamp";
		params->ipv4.send_type = ICMP_TIMESTAMP;
		params->ipv4.response_type = ICMP_TIMESTAMPREPLY;
	} else if (!strcasecmp(type_name, "info")) {
		params->type_name = "info";
		params->ipv4.send_type = ICMP_INFO_REQUEST;
		params->ipv4.response_type = ICMP_INFO_REPLY;
	} else {
		return false;
	}

	return true;
}


/*
 * Create an ICMP request block
 */
fm_icmp_request_t *
fm_icmp_request_alloc(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const fm_icmp_extra_params_t *extra_params)
{
	fm_icmp_request_t *icmp;

	icmp = calloc(1, sizeof(*icmp));
	icmp->proto = proto;
	icmp->target = target;
	icmp->params = *params;

	if (extra_params != NULL)
		icmp->extra_params = *extra_params;

	if (icmp->params.retries == 0)
		icmp->params.retries = fm_global.icmp.retries;

	if (icmp->extra_params.type_name == NULL)
		fm_icmp_extra_params_set_type(&icmp->extra_params, "echo");

	icmp->family = target->address.ss_family;
	icmp->host_address = target->address;

	return icmp;
}

/*
 * Free an existing request
 */
static void
fm_icmp_request_free(fm_icmp_request_t *icmp)
{
	if (icmp->sock != NULL && !icmp->sock_is_shared)
		fm_socket_free(icmp->sock);

	icmp->sock = NULL;
	free(icmp);
}

/*
 * Set the shared socket (for traceroute)
 */
static void
fm_icmp_request_set_socket(fm_icmp_request_t *icmp, fm_socket_t *sock)
{
	icmp->sock = sock;
	icmp->sock_is_shared = true;
}

/*
 * Do the scheduling
 */
static fm_error_t
fm_icmp_request_schedule(fm_icmp_request_t *icmp, struct timeval *expires)
{
	if (icmp->params.retries == 0)
		return FM_TIMED_OUT;

	/* After sending the last probe, we wait until the full timeout has expired.
	 * For any earlier probe, we wait for the specified packet spacing */
	if (icmp->params.retries == 1)
		fm_timestamp_set_timeout(expires, fm_global.icmp.timeout);
	else
		fm_timestamp_set_timeout(expires, fm_global.icmp.packet_spacing);
	return 0;
}


static inline bool
fm_icmp_instantiate_params(struct icmp_params *params, fm_target_t *target)
{
	/* params->host_address = target->address; */

	params->ipproto = fm_icmp_protocol_for_family(target->address.ss_family);
	if (params->ipproto < 0) {
		fm_log_error("Cannot create ICMP probe for %s", fm_address_format(&target->address));
		return false;
	}

	/* params->ident = 0x1234; */
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

static fm_pkt_t *
fm_icmp_request_build_packet(const fm_icmp_request_t *icmp)
{
	fm_pkt_t *pkt = fm_pkt_alloc(icmp->family, 64);
	fm_buffer_t *bp = pkt->payload;

	pkt->peer_addr = icmp->host_address;
	if (icmp->family == AF_INET) {
		struct icmp *icmph;

		icmph = fm_buffer_push(bp, sizeof(*icmph));
		icmph->icmp_type = icmp->extra_params.ipv4.send_type;
		icmph->icmp_code = 0;
		icmph->icmp_cksum = 0;
		icmph->icmp_id = htons(icmp->icmp.ident);
		icmph->icmp_seq = htons(icmp->icmp.seq);

		icmph->icmp_cksum = in_csum(icmph, sizeof(*icmph));
        } else if (icmp->family == AF_INET6) {
		struct icmp6_hdr *icmph;

		icmph = fm_buffer_push(bp, sizeof(*icmph));
		icmph->icmp6_type = icmp->extra_params.ipv6.send_type;
		icmph->icmp6_code = 0;
		icmph->icmp6_cksum = 0;
		icmph->icmp6_id = htons(icmp->icmp.ident);
		icmph->icmp6_seq = htons(icmp->icmp.seq);

		/* Kernel takes care of checksums */
        }

	/* apply ttl, tos etc */
	fm_pkt_apply_probe_params(pkt, &icmp->params, icmp->proto->ops->supported_parameters);

	return pkt;
}

/*
 * Build the response match
 */
typedef struct fm_icmp_extant_info {
	struct {
		unsigned int	len;
		union {
			struct icmp		icmp4;
			struct icmp6_hdr	icmp6;
			unsigned char		raw[64];
		};
	} sent_hdr, expect_hdr;
} fm_icmp_extant_info_t;

static void
fm_icmp_request_build_extant_info(const fm_icmp_request_t *icmp, const fm_pkt_t *pkt, fm_icmp_extant_info_t *info)
{
	unsigned int len = fm_buffer_available(pkt->payload);
	const void *raw = fm_buffer_head(pkt->payload);

	if (len > sizeof(info->sent_hdr.raw))
		len = sizeof(info->sent_hdr.raw);
	memcpy(info->sent_hdr.raw, raw, len);
	info->sent_hdr.len = len;

	/* The response we expect is exactly what we sent, just with the response type */
	info->expect_hdr = info->sent_hdr;

	if (icmp->family == AF_INET)
		info->expect_hdr.icmp4.icmp_type = icmp->extra_params.ipv4.response_type;
	else if (icmp->family == AF_INET6)
		info->expect_hdr.icmp6.icmp6_type = icmp->extra_params.ipv6.response_type;
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
		fm_icmp_extant_info_t *ei = (fm_icmp_extant_info_t *) (extant + 1);
		const struct icmp *match = is_response? &ei->expect_hdr.icmp4 : &ei->sent_hdr.icmp4;

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
		fm_icmp_extant_info_t *ei = (fm_icmp_extant_info_t *) (extant + 1);
		const struct icmp6_hdr *match = is_response? &ei->expect_hdr.icmp6 : &ei->sent_hdr.icmp6;

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

/*
 * Send the icmp request.
 * The probe argument is only here because we need to notify it when done.
 */
static fm_error_t
fm_icmp_request_send(fm_icmp_request_t *icmp, fm_icmp_extant_info_t *extant_info)
{
	fm_socket_t *sock;
	fm_pkt_t *pkt;

	if ((sock = icmp->sock) != NULL) {
		/* pass */
	} else {
		/* When using raw sockets, create a single ICMP socket per target host */
		sock = fm_protocol_create_host_shared_socket(icmp->proto, icmp->target);
	}

	if (sock == NULL) {
		icmp->sock = fm_icmp_create_connected_socket(icmp->proto, &icmp->host_address);
		if (icmp->sock == NULL) {
			fm_log_error("Unable to create ICMP socket for %s: %m",
					fm_address_format(&icmp->host_address));
			return FM_SEND_ERROR;
		}

		sock = icmp->sock;
	}

	pkt = fm_icmp_request_build_packet(icmp);

	fm_icmp_request_build_extant_info(icmp, pkt, extant_info);

	if (!fm_socket_send_pkt_and_burn(sock, pkt)) {
		fm_log_error("Unable to send ICMP packet: %m");
		return FM_SEND_ERROR;
	}

	icmp->params.retries -= 1;

	/* update the asset state */
	fm_target_update_host_state(icmp->target, FM_PROTO_ICMP, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

/*
 * The ICMP host probe
 */
struct fm_icmp_host_probe {
	fm_probe_t		base;
	fm_icmp_request_t *	icmp;
};

/*
 * Check whether we're clear to send. If so, set the probe timer
 */
static fm_error_t
fm_icmp_host_probe_schedule(fm_probe_t *probe)
{
	fm_icmp_request_t *icmp = fm_icmp_probe_get_request(probe);

	if (icmp == NULL)
		return FM_NOT_SUPPORTED;

	return fm_icmp_request_schedule(icmp, &probe->expires);
}


/*
 * Send the probe.
 */
static fm_error_t
fm_icmp_host_probe_send(fm_probe_t *probe)
{
	fm_icmp_request_t *icmp = fm_icmp_probe_get_request(probe);
	fm_icmp_extant_info_t extant_info;
	fm_error_t error;

	error = fm_icmp_request_send(icmp, &extant_info);
	if (error == 0)
		fm_extant_alloc(probe, icmp->family, icmp->icmp.ipproto, &extant_info, sizeof(extant_info));

	return error;
}

static fm_error_t
fm_icmp_host_probe_set_socket(fm_probe_t *probe, fm_socket_t *sock)
{
	fm_icmp_request_t *icmp = fm_icmp_probe_get_request(probe);

	if (icmp == NULL)
		return FM_NOT_SUPPORTED;

	fm_icmp_request_set_socket(icmp, sock);
	return 0;
}

static void
fm_icmp_host_probe_destroy(fm_probe_t *probe)
{
	fm_icmp_probe_set_request(probe, NULL);
}

static struct fm_probe_ops fm_icmp_host_probe_ops = {
	.obj_size	= sizeof(struct fm_icmp_host_probe),
	.name 		= "icmp",

	.default_timeout= 1000,	/* FM_ICMP_RESPONSE_TIMEOUT */

	.destroy	= fm_icmp_host_probe_destroy,
	.schedule	= fm_icmp_host_probe_schedule,
	.send		= fm_icmp_host_probe_send,
	.set_socket	= fm_icmp_host_probe_set_socket,
};

static fm_icmp_request_t *
fm_icmp_probe_get_request(const fm_probe_t *probe)
{
	if (probe->ops != &fm_icmp_host_probe_ops)
		return NULL;

	return ((struct fm_icmp_host_probe *) probe)->icmp;
}

static void
fm_icmp_probe_set_request(fm_probe_t *probe, fm_icmp_request_t *icmp)
{
	struct fm_icmp_host_probe *icmp_probe;

	if (probe->ops != &fm_icmp_host_probe_ops)
		return;

	icmp_probe = (struct fm_icmp_host_probe *) probe;
	if (icmp_probe->icmp != NULL)
		fm_icmp_request_free(icmp_probe->icmp);
	icmp_probe->icmp = icmp;
}

static void *
fm_icmp_process_extra_parameters(fm_protocol_t *proto, const fm_string_array_t *extra_args)
{
	fm_icmp_extra_params_t *extra_params;
	const char *type_name = NULL;
	unsigned int i;

	extra_params = calloc(1, sizeof(*extra_params));

	for (i = 0; i < extra_args->count; ++i) {
		const char *arg = extra_args->entries[i];

		if (fm_parse_string_argument(arg, "type", &type_name)) {
			/* pass */
		} else {
			fm_log_error("Cannot create ICMP host probe: invalid argument \"%s\"", arg);
			return false;
		}
	}

	if (type_name == NULL)
		type_name = "echo";

	if (!fm_icmp_extra_params_set_type(extra_params, type_name)) {
		fm_log_error("ICMP type %s not supported\n", type_name);
		free(extra_params);
		return NULL;
	}

	return extra_params;

}


static fm_probe_t *
fm_icmp_create_host_probe(fm_protocol_t *proto, fm_target_t *target, const fm_probe_params_t *params, const void *extra_params)
{
	fm_icmp_request_t *icmp;
	fm_probe_t *probe;
	char name[32];

	icmp = fm_icmp_request_alloc(proto, target, params, extra_params);
	if (icmp == NULL)
		return NULL;

	snprintf(name, sizeof(name), "icmp/%s", icmp->extra_params.type_name);
	probe = fm_probe_alloc(name, &fm_icmp_host_probe_ops, proto, target);

	fm_icmp_probe_set_request(probe, icmp);

	fm_log_debug("Created ICMP socket probe for %s\n", fm_address_format(&icmp->host_address));
	return probe;
}
