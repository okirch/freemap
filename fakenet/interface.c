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
#include <netinet/ip_icmp.h>
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
#include "rawpacket.h"
#include "packet.h"
#include "buffer.h"
#include "logging.h"


static fm_buffer_t *		fm_fakenet_receive(fm_parsed_pkt_t *cooked, const fm_fake_config_t *config, fm_buffer_t *payload);

/*
 * Create the tunnel interface that we will serve.
 */
fm_tunnel_t *
fm_fakenet_attach_interface(void)
{
	struct ifreq ifr;
	fm_tunnel_t *tunnel;
	int fd;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		fm_log_error("failed to open /dev/net/tun: %m");
		return false;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "fake%d");
	ifr.ifr_flags = IFF_TUN;

	if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
		fm_log_error("could not create tunnel device: %m");
		return false;
	}

	tunnel = calloc(1, sizeof(*tunnel));

	tunnel->ifname = strdup(ifr.ifr_name);
	tunnel->fd = fd;

	fm_log_notice("Using tunnel device %s", tunnel->ifname);
	return tunnel;
}

bool
fm_fakenet_configure_interface(fm_tunnel_t *tunnel, fm_fake_config_t *config)
{
	struct ifreq ifr;
	int fd = -1;
	unsigned int i;

	if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		fm_log_error("socket: %m");
		return false;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, tunnel->ifname);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		fm_log_error("failed to set flags for %s: %m", tunnel->ifname);
		return false;
	}
	tunnel->ifindex = ifr.ifr_ifindex;

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		fm_log_error("failed to get flags for %s: %m", tunnel->ifname);
		return false;
	}

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		fm_log_error("failed to set flags for %s: %m", tunnel->ifname);
		return false;
	}

	fm_log_debug("Configure %s", tunnel->ifname);
	for (i = 0; i < config->addresses.count; ++i) {
		const char *addrstring = config->addresses.entries[i];
		fm_address_prefix_t prefix;
		unsigned int pfxlen;

		if (!fm_address_prefix_parse(addrstring, &prefix)) {
			fm_log_error("Cannot parse route \"%s\"", addrstring);
			return false;
		}

		if (prefix.address.family == AF_INET)
			pfxlen = 32;
		else
			pfxlen = 128;

		if (!netlink_send_newaddr(tunnel->ifindex, &prefix.address, pfxlen)) {
			fm_log_error("failed to add address %s/%u for %s",
					fm_address_format(&prefix.address),
					pfxlen, tunnel->ifname);
			return false;
		}

		if (prefix.address.family == AF_INET && tunnel->ipv4_address.family == AF_UNSPEC)
			tunnel->ipv4_address = prefix.address;
		else if (prefix.address.family == AF_INET6 && tunnel->ipv6_address.family == AF_UNSPEC)
			tunnel->ipv6_address = prefix.address;

		fm_log_debug("%s: added address %s/%u", tunnel->ifname,
					fm_address_format(&prefix.address),
					pfxlen);

		if (!netlink_send_newroute(tunnel->ifindex, &prefix)) {
			fm_log_error("failed to add route %s for %s", addrstring, tunnel->ifname);
			return false;
		}

		fm_log_debug("%s: added route %s", tunnel->ifname, addrstring);
	}

	close(fd);
	return true;
}

bool
fm_fakenet_run(fm_tunnel_t *tunnel, const fm_fake_config_t *config)
{
	fm_buffer_t *bp;

	bp = fm_buffer_alloc(8192);
	while (true) {
		uint16_t flags, ptype;
		fm_pkt_t pkt;
		unsigned int next_proto;
		fm_parsed_pkt_t *cooked;
		fm_buffer_t *reply;
		int n;

		bp->rpos = bp->wpos = 0;

		n = read(tunnel->fd, fm_buffer_tail(bp), fm_buffer_tailroom(bp));
		if (n < 0) {
			fm_log_fatal("read: %m");
			return false;
		}

		bp->wpos += n;

		if (!fm_buffer_get16(bp, &flags)
		 || !fm_buffer_get16(bp, &ptype))
			continue;

		flags = ntohs(flags);
		ptype = ntohs(ptype);

		memset(&pkt, 0, sizeof(pkt));
		pkt.payload = bp;

		switch (ptype) {
		case ETH_P_IP:
			pkt.family = AF_INET;
			next_proto = FM_PROTO_IP;
			break;

		case ETH_P_IPV6:
			pkt.family = AF_INET6;
			next_proto = FM_PROTO_IPV6;
			break;

		default:
			if (fm_debug_level > 1)
				fm_log_debug("received unknown packet type %04x flags=0x%x", ptype, flags);
			continue;
		}

		if (fm_debug_facilities & FM_DEBUG_FACILITY_DATA) {
			fm_log_debug("received %s packet flags=0x%x", fm_protocol_id_to_string(next_proto), flags);
			fm_buffer_dump(bp, NULL);
		}

		cooked = fm_packet_parser_inspect_any(&pkt, next_proto);
		if (cooked == NULL)
			continue;

		/* Get the IP header, find the destination network, and possibly the host */
		reply = fm_fakenet_receive(cooked, config, pkt.payload);
		if (reply != NULL) {
			uint16_t *frame;

			assert(reply->rpos == 4);
			reply->rpos = 0;
			frame = (uint16_t *) reply->data;
			frame[0] = htons(0);
			frame[1] = htons(ptype);

			if (fm_debug_facilities & FM_DEBUG_FACILITY_DATA) {
				fm_buffer_dump(reply, "sending response");
			}

			write(tunnel->fd, fm_buffer_head(reply), fm_buffer_available(reply));
			fm_buffer_free(reply);
		}

		free(cooked);
	}

	return true;
}

static fm_buffer_t *
fm_fake_host_prepare_response(fm_fake_host_t *host, const fm_ip_header_info_t *ip, unsigned int transport_len, fm_ip_header_info_t *reply_info)
{
	fm_buffer_t *reply;

	memset(reply_info, 0, sizeof(*reply_info));
	reply_info->src_addr = ip->dst_addr;
	reply_info->dst_addr = ip->src_addr;
	reply_info->ipproto = ip->ipproto;
	reply_info->ttl = 64;
	reply_info->tos = 0;

	reply = fm_buffer_alloc(128);
	reply->rpos = reply->wpos = 4;

	if (!fm_raw_packet_add_ip_header(reply, reply_info, transport_len)) {
		fm_buffer_free(reply);
		return NULL;
	}

	return reply;
}

static fm_buffer_t *
fm_fake_host_receive_icmp(fm_fake_host_t *host, fm_parsed_pkt_t *cooked, const fm_ip_header_info_t *ip, const fm_icmp_header_info_t *icmp, fm_buffer_t *payload)
{
	fm_buffer_t *reply;
	fm_ip_header_info_t ip_reply_info;
	fm_icmp_header_info_t icmp_reply_info;
	fm_icmp_msg_type_t *reply_type;
	unsigned int transport_len = 0;

	if (icmp->msg_type == NULL) {
		fm_log_debug("   unidentified ICMP packet");
		return NULL;
	}

	fm_log_debug("   ICMP %s packet", icmp->msg_type->desc);

	reply_type = fm_icmp_msg_type_get_reply(icmp->msg_type);
	if (reply_type == NULL)
		return NULL;

	/* For now, all I can do is ping */
	if (reply_type->v4_type != ICMP_ECHOREPLY)
		return NULL;

	transport_len = 8 + fm_buffer_available(payload);

	reply = fm_fake_host_prepare_response(host, ip, transport_len, &ip_reply_info);
	if (reply == NULL)
		return NULL;

	icmp_reply_info = *icmp;
	icmp_reply_info.msg_type = reply_type;

	if (!fm_raw_packet_add_icmp_header(reply, &icmp_reply_info, &ip_reply_info, payload)) {
		fm_buffer_free(reply);
		return NULL;
	}

	return reply;
}

static fm_buffer_t *
fm_fake_host_receive(fm_fake_host_t *host, fm_parsed_pkt_t *cooked, const fm_ip_header_info_t *ip, fm_buffer_t *payload)
{
	fm_parsed_hdr_t *hdr;

	if (!(hdr = fm_parsed_packet_next_header(cooked)))
		return NULL; /* no next protocol that we'd understand; or just an IPv6 packet with extension headers */

	switch (hdr->proto_id) {
	case FM_PROTO_ICMP:
		return fm_fake_host_receive_icmp(host, cooked, ip, &hdr->icmp, payload);
	}

	return NULL;
}

static fm_buffer_t *
fm_fakenet_receive(fm_parsed_pkt_t *cooked, const fm_fake_config_t *config, fm_buffer_t *payload)
{
	fm_parsed_hdr_t *hdr;
	fm_fake_network_t *net;
	fm_fake_host_t *host;
	fm_buffer_t *reply;

	if (!(hdr = fm_parsed_packet_find_next(cooked, FM_PROTO_IP)))
		return NULL;

	net = fm_fake_config_get_network_by_addr(config, &hdr->ip.dst_addr);
	if (net == NULL)
		return NULL; /* We don't know you. FIXME: we should provide more realistic routing. */

	/* TBD: perform filtering along the way */

	if (hdr->ip.ttl <= net->router->ttl) {
		/* TBD: find the proper router, send time exceeded */
		return NULL;
	}

	host = fm_fake_network_get_host_by_addr(net, &hdr->ip.dst_addr);
	if (host == NULL)
		return NULL;

	fm_log_debug("packet to %s (net %s)", host->name, host->network->name);

	/* TBD: perform filtering at the host */

	reply = fm_fake_host_receive(host, cooked, &hdr->ip, payload);
	if (reply == NULL)
		return reply;

	/* TBD: compute a suitable delay */
	return reply;
}
