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

typedef struct fm_address_enumerator fm_address_enumerator_t;
typedef struct fm_target fm_target_t;
typedef struct fm_target_manager fm_target_manager_t;
typedef struct fm_target_pool fm_target_pool_t;
typedef struct fm_scheduler fm_scheduler_t;
typedef struct fm_scanner fm_scanner_t;
typedef struct fm_scan_action	fm_scan_action_t;
typedef struct fm_scan_program	fm_scan_program_t;
typedef struct fm_scan_exec fm_scan_exec_t;
typedef struct fm_protocol fm_protocol_t;
typedef struct fm_protocol_engine fm_protocol_engine_t;
typedef struct fm_probe fm_probe_t;
typedef struct fm_socket fm_socket_t;
typedef struct fm_report fm_report_t;
typedef struct fm_fact_log fm_fact_log_t;
typedef const struct fm_wellknown_service fm_wellknown_service_t;
typedef struct fm_string_array fm_string_array_t;

typedef struct sockaddr_storage	fm_address_t;

static const unsigned int	FM_INITIAL_TARGET_POOL_SIZE = 16;
static const unsigned int	FM_DEFAULT_GLOBAL_PACKET_RATE = 1000;
static const unsigned int	FM_DEFAULT_HOST_PACKET_RATE = 10;
static const unsigned int	FM_TARGET_POOL_RESIZE_TIME = 4; /* grow the pool every 4 seconds */
static const unsigned int	FM_TARGET_POOL_MAX_SIZE = 1023;

/* ICMP reachability probe. We transmit 3 echo requests, 250 msec apart, then wait
 * for up to 1 second for a response. */
static const unsigned int	FM_ICMP_PROBE_RETRIES = 3;
static const unsigned int	FM_ICMP_PACKET_SPACING = 250;
static const unsigned int	FM_ICMP_RESPONSE_TIMEOUT = 1000;

/*
 * Network stats. For now, we use it to build a reasonable RTT estimate
 */
typedef struct fm_rtt_stats {
	int			ipproto;
	unsigned int		netid;

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


#endif /* FREEMAP_TYPES_H */

