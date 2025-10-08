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

#ifndef FREEMAP_FREEMAP_H
#define FREEMAP_FREEMAP_H

#include <time.h>
#include <stdio.h>
#include "types.h"

extern fm_address_enumerator_t *fm_create_simple_address_enumerator(const char *addr_string);
extern fm_address_enumerator_t *fm_create_cidr_address_enumerator(const char *addr_string);

extern fm_report_t *	fm_report_create(void);
extern void		fm_report_write(const fm_report_t *, const fm_target_t *);
extern void		fm_report_enable_standard_output(fm_report_t *, bool);
extern bool		fm_report_add_logfile(fm_report_t *, const char *path);
extern void		fm_report_flush(fm_report_t *);
extern void		fm_report_free(fm_report_t *);

extern const char *	fm_address_enumerator_name(const fm_address_enumerator_t *);
extern unsigned int	fm_address_enumerator_get_one(fm_address_enumerator_t *, fm_address_t *);
extern void		fm_address_enumerator_destroy(fm_address_enumerator_t *);

extern const char *	fm_address_format(const fm_address_t *);

extern void		fm_timestamp_init(struct timeval *ts);
extern double		fm_timestamp_update(struct timeval *ts);
extern double		fm_timestamp_since(struct timeval *ts);
extern void		fm_timestamp_set_timeout(struct timeval *ts, long milliseconds);
extern bool		fm_timestamp_older(const struct timeval *expiry, const struct timeval *now);
extern const struct timeval *fm_timestamp_now(void);

extern void		fm_ratelimit_init(fm_ratelimit_t *rl, unsigned int rate, unsigned int max_burst);
extern void		fm_ratelimit_update(fm_ratelimit_t *rl);
extern bool		fm_ratelimit_okay(fm_ratelimit_t *rl);
extern unsigned int	fm_ratelimit_available(const fm_ratelimit_t *rl);
extern void		fm_ratelimit_consume(fm_ratelimit_t *rl, unsigned int ntokens);

extern fm_target_manager_t *fm_target_manager_create(void);
extern void		fm_target_manager_add_address_generator(fm_target_manager_t *, fm_address_enumerator_t *);
extern bool		fm_target_manager_replenish_pool(fm_target_manager_t *mgr, fm_target_pool_t *pool);

extern fm_target_pool_t *fm_target_pool_create(unsigned int size);
extern fm_target_t *	fm_target_pool_get_next(fm_target_pool_t *pool, unsigned int *);
extern bool		fm_target_pool_remove(fm_target_pool_t *pool, fm_target_t *);
extern bool		fm_target_pool_reap_completed(fm_target_pool_t *pool);
extern void		fm_target_pool_auto_resize(fm_target_pool_t *pool, unsigned int max_size);

extern fm_scanner_t *	fm_scanner_create(void);
extern bool		fm_scanner_ready(fm_scanner_t *);
extern fm_report_t *	fm_scanner_get_report(fm_scanner_t *);
extern fm_target_pool_t *fm_scanner_get_target_pool(fm_scanner_t *);
extern void		fm_scanner_insert_barrier(fm_scanner_t *);
extern fm_scan_action_t *fm_scanner_add_host_probe(fm_scanner_t *, const char *proto, const fm_string_array_t *args);
extern fm_scan_action_t *fm_scanner_add_port_probe(fm_scanner_t *, const char *proto, const fm_string_array_t *args);
extern fm_scan_action_t *fm_scanner_add_reachability_check(fm_scanner_t *);
extern bool		fm_scanner_transmit(fm_scanner_t *);
extern double		fm_scanner_elapsed(fm_scanner_t *);
extern void		fm_scanner_dump_program(fm_scanner_t *);
extern fm_scan_action_t *fm_scanner_get_action(fm_scanner_t *, unsigned int);
extern fm_probe_t *	fm_scan_action_get_next_probe(fm_scan_action_t *action, fm_target_t *target, unsigned int index);
extern bool		fm_scan_action_validate(fm_scan_action_t *, fm_target_t *);
extern const char *	fm_scan_action_id(const fm_scan_action_t *action);

extern const fm_scan_program_t *fm_scan_library_load_program(const char *);
extern fm_scan_exec_t *	fm_scan_program_call_routine(fm_scan_program_t *program, const char *name);
extern void		fm_scan_exec_set_abort_on_fail(fm_scan_exec_t *, bool);
extern void		fm_scan_program_dump(const fm_scan_program_t *program);
extern bool		fm_scan_program_compile(const fm_scan_program_t *, fm_scanner_t *);

extern void		fm_scheduler_transmit_some(fm_scheduler_t *, unsigned int);
extern fm_probe_t *	fm_scheduler_get_next_probe(fm_scheduler_t *, fm_target_t *);
extern bool		fm_scheduler_attach_target(fm_scheduler_t *, fm_target_t *);
extern void		fm_scheduler_detach_target(fm_scheduler_t *, fm_target_t *);
extern fm_scheduler_t *	fm_linear_scheduler_create(fm_scanner_t *);

extern fm_target_t *	fm_target_create(const fm_address_t *, unsigned int netid);
extern void		fm_target_free(fm_target_t *);
extern const char *	fm_target_get_id(const fm_target_t *);
extern bool		fm_target_is_done(const fm_target_t *);
extern unsigned int	fm_target_get_send_quota(fm_target_t *);
extern void		fm_target_send_probe(fm_target_t *, fm_probe_t *);
extern unsigned int	fm_target_process_timeouts(fm_target_t *, unsigned int quota);

extern fm_fact_t *	fm_probe_send(fm_probe_t *);
extern void		fm_probe_free(fm_probe_t *);

extern fm_protocol_engine_t *fm_tcp_engine_create(void);
extern fm_protocol_engine_t *fm_udp_engine_create(void);
extern fm_protocol_engine_t *fm_icmp_engine_create(void);

extern fm_rtt_stats_t *	fm_rtt_stats_get(int proto_id, unsigned int netid);
extern fm_rtt_stats_t *	fm_rtt_stats_create(int proto_id, unsigned int netid, unsigned long initial_rtt, unsigned int multiple);
extern void		fm_rtt_stats_update(fm_rtt_stats_t *, double rtt);

extern void		fm_fact_log_append(fm_fact_log_t *, fm_fact_t *);
extern void		fm_fact_log_destroy(fm_fact_log_t *);
extern void		fm_fact_free(fm_fact_t *);
extern const char *	fm_fact_render(const fm_fact_t *fact);
extern bool		fm_fact_check_protocol(const fm_fact_t *fact, const char *protocol_id);
extern const fm_fact_t *fm_fact_log_find(const fm_fact_log_t *, fm_fact_type_t);
extern const fm_fact_t *fm_fact_log_find_iter(const fm_fact_log_t *, fm_fact_type_t, unsigned int *);

extern bool		fm_address_set_port(fm_address_t *address, unsigned short port);
extern unsigned int	fm_addrfamily_sockaddr_size(int family);

extern fm_socket_t *	fm_socket_create(int family, int type, int proto);
extern void		fm_socket_free(fm_socket_t *);
extern void		fm_socket_set_callback(fm_socket_t *,
				void (*callback)(fm_socket_t *, int, void *user_data),
				void *user_data);
extern bool		fm_socket_connect(fm_socket_t *, const fm_address_t *);
extern bool		fm_socket_enable_recverr(fm_socket_t *);
extern bool		fm_socket_send(fm_socket_t *sock, const fm_address_t *dstaddr, const void *pkt, size_t len);
extern void		fm_socket_close(fm_socket_t *);
extern bool		fm_socket_poll_all(void);

extern void		fm_probe_reply_received(fm_probe_t *);
extern void		fm_probe_mark_port_reachable(fm_probe_t *, const char *proto, unsigned int port);
extern void		fm_probe_mark_port_unreachable(fm_probe_t *, const char *proto, unsigned int port);
extern void		fm_probe_mark_port_heisenberg(fm_probe_t *, const char *proto, unsigned int port);
extern void		fm_probe_mark_host_reachable(fm_probe_t *, const char *proto);
extern void		fm_probe_mark_host_unreachable(fm_probe_t *, const char *proto);

extern void		fm_set_logfile(FILE *fp);
extern void		fm_trace(const char *fmt, ...);
extern void		fm_log_fatal(const char *fmt, ...);
extern void		fm_log_error(const char *fmt, ...);
extern void		fm_log_warning(const char *fmt, ...);

extern unsigned int	fm_debug_level;

#define fm_log_debug(fmt ...) do { \
		if (fm_debug_level > 0) fm_trace(fmt); \
	} while (0)

extern fm_wellknown_service_t *fm_wellknown_service_for_port(const char *protool_id, unsigned int port);

#endif /* FREEMAP_FREEMAP_H */
