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
 * Scanning IP protocols
 */

#ifndef FREEMAP_RAWPACKET_H
#define FREEMAP_RAWPACKET_H

#include <stdint.h>
#include <assert.h>

#include "freemap.h"
#include "packet.h"

/*
 * Ethernet header information
 */
typedef struct fm_eth_header_info {
	uint16_t		eth_proto;
	unsigned char		src_addr[6];
	unsigned char		dst_addr[6];
	unsigned int		next_proto;
} fm_eth_header_info_t;

/*
 * IP header information
 */
#define FM_IP_MAX_EXTENSIONS	4
typedef struct fm_ip_header_info {
	fm_address_t		src_addr, dst_addr;
	int			ipproto;
	unsigned int		ttl, tos;
	unsigned int		num_ext_headers;
	struct fm_ip_extension_hdr {
		int		ipproto;
		unsigned int	len;
		void *		data;
	} ext_header[FM_IP_MAX_EXTENSIONS];
} fm_ip_header_info_t;

/*
 * We could use fm_address_t's for all hw and network addresses, but this
 * would seriously bloat this structure
 */
typedef struct fm_arp_header_info {
	uint16_t		op;
	uint16_t		hwtype;
	uint16_t		nwtype;
	unsigned char		src_hwaddr[6];
	unsigned char		dst_hwaddr[6];
	struct in_addr		src_ipaddr;
	struct in_addr		dst_ipaddr;
} fm_arp_header_info_t;

/*
 * ICMP type info
 */
typedef const struct fm_icmp_msg_type {
	const char *		desc;
	int			v4_type, v4_code;
	int			v6_type, v6_code;
	bool			with_seq_id;
	bool			with_error;
	bool			is_request;
} fm_icmp_msg_type_t;

/*
 * The ICMP header info covers both ICMPv4 and ICMPv6.
 * v6 types and codes are mapped to their v4 counterparts where posssible.
 */
typedef struct fm_icmp_header_info {
	unsigned char		type, code;
	unsigned char		v4_type, v4_code;
	uint16_t		seq;
	uint16_t		id;

	fm_icmp_msg_type_t *	msg_type;

	bool			include_error_pkt;

	/* payload */
	struct {
		unsigned int	len;
		const void *	data;
	} payload;
} fm_icmp_header_info_t;

typedef struct fm_udp_header_info {
	uint16_t		src_port;
	uint16_t		dst_port;

	/* payload */
	struct {
		unsigned int	len;
		const void *	data;
	} payload;
} fm_udp_header_info_t;

typedef struct fm_tcp_header_info {
	unsigned char		flags;
	uint32_t		seq;
	uint32_t		ack_seq;
	uint32_t		window;
	uint16_t		mss;
	uint16_t		mtu;

	/* not yet implemented */
	uint16_t		option_mask;

	/* payload */
	struct {
		unsigned int	len;
		const void *	data;
	} payload;

	/* internal use only: */
	uint16_t		src_port;
	uint16_t		dst_port;
} fm_tcp_header_info_t;

typedef struct fm_parsed_hdr {
	unsigned int		proto_id;

	struct {
		const void *	data;
		unsigned int	hdr_len;
		unsigned int	tot_len;
	} raw;
	union {
		unsigned char	data[1];
		fm_eth_header_info_t eth;
		fm_ip_header_info_t ip;
		fm_arp_header_info_t arp;
		fm_icmp_header_info_t icmp;
		fm_udp_header_info_t udp;
		fm_tcp_header_info_t tcp;
	};
} fm_parsed_hdr_t;

typedef struct fm_parsed_pkt {
	unsigned int		next_header;	/* used when we step through the packet */

	unsigned int		num_headers;
	fm_parsed_hdr_t *	headers[FM_PARSED_PACKET_MAX_PROTOS];
} fm_parsed_pkt_t;


extern fm_parsed_hdr_t *fm_parsed_packet_find_next(fm_parsed_pkt_t *, unsigned int proto_id);

extern bool		fm_raw_packet_add_link_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr);
extern bool		fm_raw_packet_add_ipv4_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
					int ipproto, unsigned int ttl, unsigned int tos,
					unsigned int transport_len);
extern bool		fm_raw_packet_add_ipv6_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
					int ipproto, unsigned int ttl, unsigned int tos,
					unsigned int transport_len);
extern bool		fm_raw_packet_add_network_header(fm_buffer_t *bp, const fm_address_t *src_addr, const fm_address_t *dst_addr,
					int ipproto, unsigned int ttl, unsigned int tos,
					unsigned int transport_len);
extern bool		fm_raw_packet_add_ip_header(fm_buffer_t *bp, const fm_ip_header_info_t *ip, unsigned int transport_len);
extern bool		fm_raw_packet_add_icmp_header(fm_buffer_t *, const fm_ip_header_info_t *ip_info,
					const fm_icmp_header_info_t *icmp_info);
extern bool		fm_raw_packet_pull_eth_hdr(fm_pkt_t *pkt, fm_eth_header_info_t *info);
extern bool		fm_raw_packet_pull_ip_hdr(fm_pkt_t *pkt, fm_ip_header_info_t *info);
extern bool		fm_raw_packet_add_tcp_header(fm_buffer_t *bp, const fm_ip_header_info_t *ip_info,
					const fm_tcp_header_info_t *tcp_info);
extern bool		fm_raw_packet_add_udp_header(fm_buffer_t *bp, const fm_ip_header_info_t *ip_info,
					const fm_udp_header_info_t *udp_info);
extern bool		fm_raw_packet_pull_tcp_header(fm_buffer_t *bp, fm_tcp_header_info_t *tcp);
extern bool		fm_raw_packet_pull_udp_header(fm_buffer_t *bp, fm_udp_header_info_t *udp);
extern bool		fm_raw_packet_pull_icmp_header(fm_buffer_t *bp, fm_icmp_header_info_t *icmp);
extern bool		fm_raw_packet_pull_icmpv6_header(fm_buffer_t *bp, fm_icmp_header_info_t *icmp);
extern bool		fm_raw_packet_pull_arp_header(fm_buffer_t *bp, fm_arp_header_info_t *arp);

extern bool		fm_icmp_header_is_host_unreachable(const fm_icmp_header_info_t *icmp_info);
extern void		fm_raw_packet_map_icmpv6_codes(fm_icmp_header_info_t *icmp_info, unsigned int type, unsigned int code);
extern fm_icmp_msg_type_t *fm_icmp_msg_type_by_name(const char *name);
extern fm_icmp_msg_type_t *fm_icmp_msg_type_get_reply(fm_icmp_msg_type_t *req);

extern bool		fm_ipv6_transport_csum_partial(fm_csum_partial_t *, const fm_address_t *, const fm_address_t *, unsigned int next_header);

/*
 * Functions for applying config options to protocol probes
 */
extern bool		fm_ip_process_config_arg(fm_ip_header_info_t *, const char *);
extern bool		fm_tcp_process_config_arg(fm_tcp_header_info_t *, const char *);
extern bool		fm_udp_process_config_arg(fm_udp_header_info_t *, const char *);
extern bool		fm_icmp_process_config_arg(fm_icmp_header_info_t *, const char *);

/* These functions can be used to apply parameters before sending a packet.
 * If the parameter is applicable, returns a pointer to a local (static) copy with the parameter applied.
 * If the parameter is not applicable, just returns the pointer that was passed in.
 */
extern void		fm_ip_header_info_apply_defaults(fm_ip_header_info_t *ip, int family);
extern const fm_ip_header_info_t *fm_ip_header_info_finalize(const fm_ip_header_info_t *ip, int param_type, int param_value);
extern const fm_tcp_header_info_t *fm_tcp_header_info_finalize(const fm_tcp_header_info_t *tcp, int param_type, int param_value);
extern const fm_udp_header_info_t *fm_udp_header_info_finalize(const fm_udp_header_info_t *udp, int param_type, int param_value, const fm_buffer_t *payload);
extern fm_icmp_header_info_t *fm_icmp_header_info_finalize(const fm_icmp_header_info_t *icmp, int param_type, int param_value, const fm_buffer_t *payload);

extern unsigned int	fm_ip_compute_len(const fm_ip_header_info_t *ip);
extern unsigned int	fm_tcp_compute_len(const fm_tcp_header_info_t *tcp);
extern unsigned int	fm_udp_compute_len(const fm_udp_header_info_t *udp);
extern unsigned int	fm_icmp_compute_len(const fm_icmp_header_info_t *icmp);

static inline fm_parsed_hdr_t *
fm_parsed_packet_peek_next_header(fm_parsed_pkt_t *cooked)
{
        unsigned int k = cooked->next_header;

        if (k >= cooked->num_headers)
                return NULL;

        return cooked->headers[k];
}

static inline void
fm_csum_partial_update(fm_csum_partial_t *cp, const void *data, size_t noctets)
{
        const uint16_t *p = (const uint16_t *) data;
	unsigned int nwords = noctets / 2;

	assert((noctets % 2) == 0);

        while (nwords--)
		cp->value += *p++;
}

static inline void
fm_csum_partial_u16(fm_csum_partial_t *cp, uint16_t word)
{
	word = htons(word);
	fm_csum_partial_update(cp, &word, 2);
}

static inline void
fm_csum_partial_u32(fm_csum_partial_t *cp, uint32_t word)
{
	word = htonl(word);
	fm_csum_partial_update(cp, &word, 4);
}

static inline uint16_t
fm_csum_fold(const fm_csum_partial_t *cp)
{
	uint32_t csum = cp->value;
	uint16_t res;

        csum = (csum >> 16) + (csum & 0xffff);
        csum += (csum >> 16);

        res = ~csum;
        if (!res)
		res = ~0;

        return res;
}


static inline uint16_t
in_csum(const void *data, size_t noctets)
{
        const uint16_t *p = (const uint16_t *) data;
        size_t nwords = noctets / 2;
        uint32_t csum = 0;
        uint16_t res;

        while (nwords--)
		csum += *p++;

        if (noctets & 0x1)
		csum += htons (*((unsigned char *) p) << 8);

        csum = (csum >> 16) + (csum & 0xffff);
        csum += (csum >> 16);

        res = ~csum;
        if (!res)
		res = ~0;

        return res;
}

#endif /* FREEMAP_RAWPACKET_H */
