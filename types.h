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

#ifndef FREEMAP_TYPES_H
#define FREEMAP_TYPES_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>

typedef struct fm_config  fm_config_t;
typedef struct fm_project fm_project_t;
typedef struct fm_address_enumerator fm_address_enumerator_t;
typedef struct fm_target fm_target_t;
typedef struct fm_interface fm_interface_t;
typedef struct fm_network fm_network_t;
typedef struct fm_gateway fm_gateway_t;
typedef struct fm_target_manager fm_target_manager_t;
typedef struct fm_target_pool fm_target_pool_t;
typedef struct fm_scheduler fm_scheduler_t;
typedef struct fm_scanner fm_scanner_t;
typedef struct fm_scan_action	fm_scan_action_t;
typedef struct fm_scan_program	fm_scan_program_t;
typedef struct fm_scan_exec fm_scan_exec_t;
typedef struct fm_protocol fm_protocol_t;
typedef const struct fm_protocol_engine fm_protocol_engine_t;
typedef struct fm_probe fm_probe_t;
typedef struct fm_socket fm_socket_t;
typedef struct fm_report fm_report_t;
typedef struct fm_fact_log fm_fact_log_t;
typedef const struct fm_wellknown_service fm_wellknown_service_t;
typedef struct fm_string_array fm_string_array_t;
typedef struct fm_uint_array fm_uint_array_t;
typedef struct fm_neighbor fm_neighbor_t;
typedef struct fm_neighbor_cache fm_neighbor_cache_t;
typedef struct fm_event_listener fm_event_listener_t;
typedef struct fm_host_asset fm_host_asset_t;
typedef struct fm_protocol_asset fm_protocol_asset_t;

/* For now, fm_address is just a sockaddr_storage */
typedef struct sockaddr_storage	fm_address_t;

/* Events are identified by a 32bit id. */
typedef unsigned int fm_event_t;
typedef bool fm_event_callback_t(fm_probe_t *, fm_event_t);

/* so that we don't have to include linux/if_packet.h all the time */
struct sockaddr_ll;

/* Protocol IDs, used internally */
enum {
	FM_PROTO_NONE = 0,
	FM_PROTO_IP,
	FM_PROTO_IPV6,
	FM_PROTO_ARP,
	FM_PROTO_ICMP,
	FM_PROTO_UDP,
	FM_PROTO_TCP,

	__FM_PROTO_MAX
};

/*
 * Network stats. For now, we use it to build a reasonable RTT estimate
 */
typedef struct fm_rtt_stats {
	unsigned long		rtt;		/* millisec */
	unsigned int		multiple;	/* rtt * multiple => timeout */
	unsigned long		timeout;

	unsigned int		nsamples;
	double			rtt_sum;	/* seconds */
} fm_network_stats_t, fm_rtt_stats_t;

/*
 * Rate limiting.
 */
typedef struct fm_ratelimit fm_ratelimit_t;

struct fm_ratelimit {
	unsigned int		rate;
	unsigned int		max_burst;
	double			value;
	struct timeval		last_ts;
};

/*
 * A simple port range
 */
typedef struct fm_port_range {
	unsigned int		first, last;
} fm_port_range_t;

/*
 * Information about a packet received from somewhere
 */
typedef struct fm_socket_timestamp {
	/* For now, use old timestamps with msec resolution and using
	 * the wall clock. */
	struct timeval		when;
} fm_socket_timestamp_t;

typedef struct fm_pkt_info {
	fm_socket_timestamp_t	recv_time;
	int			recv_ttl;

	int			error_class;

	struct sock_extended_err *ee;
	const struct sockaddr_storage *offender;
	unsigned char		eebuf[256];
} fm_pkt_info_t;

typedef struct fm_pkt {
	int			family;
	struct sockaddr_storage recv_addr;

	fm_pkt_info_t		info;
	size_t			len;
	unsigned int		rpos;

	unsigned char		data[0];
} fm_pkt_t;

/*
 * This is used when doing a full routing lookup for PF_PACKET packets.
 * Fill in dst.network_address and call fm_routing_lookup() to have it
 * populate everything you need, including link level addresses.
 *
 * If neighbor lookup is needed, incomplete_neighbor_entry will be
 * set. In this case, wait for FM_EVENT_ID_NEIGHBOR_CACHE events and
 * recheck.
 */
typedef struct fm_routing_info {
	struct {
		fm_address_t	network_address;
		fm_address_t	link_address;
	} src, dst, nh;

	fm_interface_t *	nic;

	fm_neighbor_t *		incomplete_neighbor_entry;
} fm_routing_info_t;

/*
 * Trivial event mechanism
 */
enum {
	FM_EVENT_ID_NONE = 0,
	FM_EVENT_ID_NEIGHBOR_CACHE,
	FM_EVENT_ID_ASSET_CHANGED,
};

/*
 * Internal error codes.
 * For now, very stupid.
 */
typedef enum {
	FM_SUCCESS = 0,
	FM_SEND_ERROR = -1,
} fm_error_t;

/*
 * Representation of errors, and information about a target
 */
typedef enum {
	FM_FACT_NONE,

	FM_FACT_SEND_ERROR,
	FM_FACT_PROBE_TIMED_OUT,
	FM_FACT_HOST_REACHABLE,
	FM_FACT_HOST_UNREACHABLE,
	FM_FACT_PORT_REACHABLE,
	FM_FACT_PORT_UNREACHABLE,
	FM_FACT_PORT_HEISENBERG,
	FM_FACT_PORT_MAYBE_REACHABLE,

} fm_fact_type_t;

typedef struct fm_fact	fm_fact_t;

struct fm_fact {
	fm_fact_type_t		type;
	double			elapsed;
	const struct fm_fact_ops {
		size_t		obj_size;
		const char *	(*render)(const fm_fact_t *);
		void		(*destroy)(fm_fact_t *);
		bool		(*check_protocol)(const fm_fact_t *, const char *);
	} *ops;
};

typedef struct fm_fact_log {
	unsigned int		count;
	fm_fact_t **		entries;
} fm_fact_log_t;

typedef enum fm_asset_state {
	FM_ASSET_STATE_UNDEF		= 0x00,	/* no probe sent */
	FM_ASSET_STATE_PROBE_SENT	= 0x01,	/* sent, no answer yet */
	FM_ASSET_STATE_CLOSED		= 0x02, /* negative response */
	FM_ASSET_STATE_OPEN		= 0x03,	/* positive response */
} fm_asset_state_t;

#endif /* FREEMAP_TYPES_H */

