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
#include "logging.h"


static void		fm_fakenet_receive(fm_parsed_pkt_t *cooked);

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
		fm_fakenet_receive(cooked);

		free(cooked);
	}

	return true;
}

static void
fm_fakenet_receive(fm_parsed_pkt_t *cooked)
{
}
