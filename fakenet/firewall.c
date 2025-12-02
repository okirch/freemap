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

#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>

#include "fakenet.h"
#include "scanner.h"
#include "commands.h"
#include "protocols.h"
#include "socket.h"
#include "routing.h"
#include "packet.h"
#include "buffer.h"
#include "rawpacket.h"
#include "logging.h"

/*
 * Primitives
 */
fm_fake_fwconfig_t *
fm_fake_firewall_alloc(fm_fake_fwconfig_array_t *array)
{
	fm_fake_fwconfig_t *firewall;

	firewall = calloc(1, sizeof(*firewall));

	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = firewall;

	return firewall;
}

fm_fake_filter_rule_t *
fm_fake_filter_rule_alloc(fm_fake_filter_rule_array_t *array)
{
	fm_fake_filter_rule_t *rule;

	maybe_realloc_array(array->entries, array->count, 4);
	rule = &array->entries[array->count++];
	memset(rule, 0, sizeof(*rule));

	rule->action = __FM_FAKE_FW_UNDEF;

	return rule;
}

void
fm_fake_firewall_publish_port(fm_fake_firewall_t *firewall, const fm_address_t *host_address, const fm_fake_port_t *port)
{
	fm_fake_filter_rule_t *rule;

	rule = fm_fake_filter_rule_alloc(&firewall->rules);
	rule->action = FM_FAKE_FW_ALLOW;
	rule->proto_id = port->proto_id;
	rule->dst_port_range.first = port->port;
	rule->dst_port_range.last = port->port;
	rule->dst_addr = *host_address;
}

/*
 * Build firewall configuration
 */
static bool
fm_fake_filter_rule_parse(fm_fake_filter_rule_t *rule, const char *spec)
{
	char *copy = strdupa(spec), *token;

	if (!(token = strtok(copy, ":")))
		return false;

	if (!strcmp(token, "accept"))
		rule->action = FM_FAKE_FW_ALLOW;
	else if (!strcmp(token, "drop"))
		rule->action = FM_FAKE_FW_DROP;
	else if (!strcmp(token, "reject"))
		rule->action = FM_FAKE_FW_REJECT;
	else
		return false;

	if (!(token = strtok(NULL, ":")))
		return true;

	rule->proto_id = fm_protocol_string_to_id(token);
	if (rule->proto_id == FM_PROTO_NONE)
		return false;

	while ((token = strtok(NULL, ":")) != NULL) {
		if (!strncmp(token, "src-port=", 9)) {
			if (!fm_parse_port_range(token + 9, &rule->src_port_range))
				return false;
		} else if (!strncmp(token, "dst-port=", 9)) {
			if (!fm_parse_port_range(token + 9, &rule->dst_port_range))
				return false;
		} else if (!strncmp(token, "tcp-flags=", 10)) {
			char *s, *next;

			for (s = token + 10; s != NULL; s = next) {
				int isset = 1, flag_value = 0;

				if ((next = strchr(s, ',')) != NULL)
					*next++ = '\0';

				if (*s == '!') {
					isset = 0;
					++s;
				}

				if (!strcmp(s, "syn"))
					flag_value = TH_SYN;
				else if (!strcmp(s, "ack"))
					flag_value = TH_ACK;
				else if (!strcmp(s, "rst"))
					flag_value = TH_RST;
				else
					return false;

				rule->tcp_flag_mask |= flag_value;
				rule->tcp_flag_set |= isset * flag_value;
			}
		} else if (!strncmp(token, "msg-type=", 9)) {
			fm_icmp_msg_type_t *msg_type;

			if (!(msg_type = fm_icmp_msg_type_by_name(token + 9))) {
				fm_log_error("unknown icmp message type %s", token + 9);
				return false;
			}
			rule->icmp_type = msg_type;
		} else {
			fm_log_error("unsupported rule token \"%s\"", token);
			return false;
		}
	}

	return true;
}

bool
fm_fake_firewall_parse_rule(fm_fake_firewall_t *firewall, const char *rule_spec)
{
	fm_fake_filter_rule_t *rule;

	rule = fm_fake_filter_rule_alloc(&firewall->rules);
	if (!fm_fake_filter_rule_parse(rule, rule_spec)) {
		fm_log_error("firewall config %s: unable to parse rule: \"%s\"",
				firewall->name, rule_spec);
		rule->action = FM_FAKE_FW_DROP;
		return false;
	}

	return true;
}

/*
 * Rule matching engine
 */
typedef struct fm_fake_filter_packet_info {
	fm_address_t		dst_addr;

	unsigned int		proto_id;
	unsigned int		tcp_flags;
	unsigned int		src_port;
	unsigned int		dst_port;
	const struct fm_icmp_msg_type *icmp_type;
} fm_fake_filter_packet_info_t;

static bool fm_fake_filter_rule_match(const fm_fake_filter_rule_t *rule, const fm_fake_filter_packet_info_t *pi)
{
	if (rule->dst_addr.family != AF_UNSPEC
	 && !fm_address_equal(&rule->dst_addr, &pi->dst_addr, false))
		return false;

	if (rule->proto_id == FM_PROTO_NONE)
		return true;

	if (rule->proto_id != pi->proto_id)
		return false;

	if (fm_port_range_valid(&rule->src_port_range)
	 && !fm_port_range_contains(&rule->src_port_range, pi->src_port))
		return false;

	if (fm_port_range_valid(&rule->dst_port_range)
	 && !fm_port_range_contains(&rule->dst_port_range, pi->dst_port))
		return false;

	if ((rule->tcp_flag_mask & pi->tcp_flags) != rule->tcp_flag_set)
		return false;

	if (rule->icmp_type && rule->icmp_type != pi->icmp_type)
		return false;

	return true;
}

/*
 * Firewall to inspect an incoming packet
 * returns one of ALLOW, DROP, REJECT.
 */
int
fm_firewall_inspect_packet(const fm_fake_firewall_t *firewall, fm_parsed_pkt_t *cooked, const fm_parsed_hdr_t *hip)
{
	fm_fake_filter_packet_info_t filter_packet;
	const fm_parsed_hdr_t *htrans;
	unsigned int i;

	memset(&filter_packet, 0, sizeof(filter_packet));
	filter_packet.dst_addr = hip->ip.dst_addr;

	htrans = fm_parsed_packet_peek_next_header(cooked);
	if (htrans == NULL) {
		filter_packet.proto_id = FM_PROTO_NONE;
	} else {
		filter_packet.proto_id = htrans->proto_id;
		if (htrans->proto_id == FM_PROTO_TCP) {
			filter_packet.src_port = htrans->tcp.src_port;
			filter_packet.dst_port = htrans->tcp.dst_port;
			filter_packet.tcp_flags = htrans->tcp.flags;
		} else
		if (htrans->proto_id == FM_PROTO_UDP) {
			filter_packet.src_port = htrans->udp.src_port;
			filter_packet.dst_port = htrans->udp.dst_port;
		} else
		if (htrans->proto_id == FM_PROTO_ICMP) {
			filter_packet.icmp_type = htrans->icmp.msg_type;
		}
	}

	for (i = 0; i < firewall->rules.count; ++i) {
		fm_fake_filter_rule_t *rule = &firewall->rules.entries[i];

		if (fm_fake_filter_rule_match(rule, &filter_packet))
			return rule->action;
	}

	return FM_FAKE_FW_ALLOW;
}
