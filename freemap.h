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
#include <netinet/in.h>
#include "types.h"
#include "config.h"

extern void		fm_config_init_defaults(fm_config_t *);
extern bool		fm_config_load(fm_config_t *, const char *path);

const char *		fm_strerror(fm_error_t);

extern fm_address_enumerator_t *fm_create_simple_address_enumerator(const char *addr_string);
extern fm_address_enumerator_t *fm_create_cidr_address_enumerator(const char *addr_string);

extern fm_report_t *	fm_report_create(void);
extern void		fm_report_write(const fm_report_t *, const fm_target_t *);
extern void		fm_report_enable_standard_output(fm_report_t *, bool);
extern bool		fm_report_add_logfile(fm_report_t *, const char *path);
extern void		fm_report_flush(fm_report_t *);
extern void		fm_report_free(fm_report_t *);

extern const char *	fm_address_enumerator_name(const fm_address_enumerator_t *);
extern bool		fm_address_enumerator_get_one(fm_address_enumerator_t *, fm_address_t *);
extern void		fm_address_enumerator_destroy(fm_address_enumerator_t *);

extern const char *	fm_address_format(const fm_address_t *);
extern bool		fm_address_equal(const fm_address_t *, const fm_address_t *, bool with_port);

extern void		fm_routing_discover(void);
extern fm_network_t *	fm_network_for_host(const fm_address_t *);
extern bool		fm_routing_lookup(fm_routing_info_t *);
extern bool		fm_routing_lookup_complete(fm_routing_info_t *rtinfo);

extern const fm_interface_t *fm_interface_by_name(const char *ifname);
extern const fm_interface_t *fm_interface_by_index(unsigned int ifindex);
extern const fm_interface_t *fm_interface_by_address(const fm_address_t *);
extern const char *	fm_interface_get_name(const fm_interface_t *);
extern bool		fm_interface_get_lladdr(const fm_interface_t *nic, struct sockaddr_ll *sll);
extern bool		fm_interface_get_network_address(const fm_interface_t *nic, int af, fm_address_t *ret_addr);
extern fm_neighbor_t *	fm_interface_get_neighbor(const fm_interface_t *nic, const fm_address_t *network_address, bool create);
extern bool		fm_neighbor_initiate_discovery(fm_neighbor_t *);
extern bool		fm_neighbor_get_link_address(const fm_neighbor_t *neigh, fm_address_t *link_address);

extern void		fm_timestamp_init(struct timeval *ts);
extern double		fm_timestamp_update(struct timeval *ts);
extern double		fm_timestamp_since(struct timeval *ts);
extern double		fm_timestamp_expires_when(const struct timeval *, const struct timeval *);
extern void		fm_timestamp_clear(struct timeval *ts);
extern bool		fm_timestamp_is_set(const struct timeval *ts);
extern void		fm_timestamp_set_timeout(struct timeval *ts, long milliseconds);
extern bool		fm_timestamp_older(const struct timeval *expiry, const struct timeval *now);
extern const struct timeval *fm_timestamp_now(void);

extern void		fm_ratelimit_init(fm_ratelimit_t *rl, unsigned int rate, unsigned int max_burst);
extern void		fm_ratelimit_update(fm_ratelimit_t *rl);
extern bool		fm_ratelimit_okay(fm_ratelimit_t *rl);
extern unsigned int	fm_ratelimit_available(const fm_ratelimit_t *rl);
extern void		fm_ratelimit_consume(fm_ratelimit_t *rl, unsigned int ntokens);
extern double		fm_ratelimit_wait_until(const fm_ratelimit_t *rl, unsigned int ntokens);

extern fm_target_manager_t *fm_target_manager_create(void);
extern void		fm_target_manager_add_address_generator(fm_target_manager_t *, fm_address_enumerator_t *);
extern bool		fm_target_manager_replenish_pool(fm_target_manager_t *mgr, fm_target_pool_t *pool);

extern fm_target_pool_t *fm_target_pool_create(unsigned int size);
extern fm_target_t *	fm_target_pool_get_next(fm_target_pool_t *pool, unsigned int *);
extern bool		fm_target_pool_remove(fm_target_pool_t *pool, fm_target_t *);
extern bool		fm_target_pool_reap_completed(fm_target_pool_t *pool);
extern void		fm_target_pool_auto_resize(fm_target_pool_t *pool, unsigned int max_size);

extern fm_scanner_t *	fm_scanner_create(void);
extern bool		fm_scanner_add_target_from_spec(fm_scanner_t *, const char *);
extern bool		fm_scanner_ready(fm_scanner_t *);
extern fm_report_t *	fm_scanner_get_report(fm_scanner_t *);
extern fm_target_pool_t *fm_scanner_get_target_pool(fm_scanner_t *);
extern void		fm_scanner_insert_barrier(fm_scanner_t *);
extern fm_scan_action_t *fm_scanner_add_topo_probe(fm_scanner_t *, const char *proto, int flags, const fm_string_array_t *args);
extern fm_scan_action_t *fm_scanner_add_host_probe(fm_scanner_t *, const char *proto, int flags, const fm_string_array_t *args);
extern fm_scan_action_t *fm_scanner_add_port_probe(fm_scanner_t *, const char *proto, int flags, const fm_string_array_t *args);
extern fm_scan_action_t *fm_scanner_add_reachability_check(fm_scanner_t *);
extern bool		fm_scanner_transmit(fm_scanner_t *);
extern double		fm_scanner_elapsed(fm_scanner_t *);
extern void		fm_scanner_dump_program(fm_scanner_t *);
extern fm_scan_action_t *fm_scanner_get_action(fm_scanner_t *, unsigned int);
extern fm_probe_t *	fm_scan_action_get_next_probe(fm_scan_action_t *action, fm_target_t *target, unsigned int index);
extern bool		fm_scan_action_validate(fm_scan_action_t *, fm_target_t *);
extern const char *	fm_scan_action_id(const fm_scan_action_t *action);

extern const fm_scan_program_t *fm_scan_library_load_program(const char *);
extern fm_scan_exec_t *	fm_scan_program_call_routine(fm_scan_program_t *program, int type, const char *name);
extern void		fm_scan_exec_set_abort_on_fail(fm_scan_exec_t *, bool);
extern void		fm_scan_program_dump(const fm_scan_program_t *program);
extern bool		fm_scan_program_compile(const fm_scan_program_t *, fm_scanner_t *);

extern void		fm_scheduler_transmit_some(fm_scheduler_t *, unsigned int);
extern fm_probe_t *	fm_scheduler_get_next_probe(fm_scheduler_t *, fm_target_t *);
extern bool		fm_scheduler_attach_target(fm_scheduler_t *, fm_target_t *);
extern void		fm_scheduler_detach_target(fm_scheduler_t *, fm_target_t *);
extern fm_scheduler_t *	fm_linear_scheduler_create(fm_scanner_t *);

extern fm_target_t *	fm_target_create(const fm_address_t *, fm_network_t *);
extern void		fm_target_free(fm_target_t *);
extern const char *	fm_target_get_id(const fm_target_t *);
extern bool		fm_target_is_done(const fm_target_t *);
extern unsigned int	fm_target_get_send_quota(fm_target_t *);
extern fm_error_t	fm_target_send_new_probe(fm_target_t *, fm_probe_t *);
extern unsigned int	fm_target_process_timeouts(fm_target_t *, unsigned int quota);
extern bool		fm_target_get_local_bind_address(fm_target_t *, fm_address_t *);
extern void		fm_target_update_port_state(fm_target_t *, unsigned int proto_id, unsigned int port, fm_asset_state_t state);
extern void		fm_target_update_host_state(fm_target_t *target, unsigned int proto_id, fm_asset_state_t state);

extern fm_error_t	fm_probe_send(fm_probe_t *);
extern void		fm_probe_free(fm_probe_t *);
extern void		fm_probe_set_expiry(fm_probe_t *probe, double seconds);

extern bool		fm_probe_wait_for_event(fm_probe_t *, fm_event_callback_t *, fm_event_t);
extern void		fm_probe_finish_waiting(fm_probe_t *);
extern void		fm_event_post(fm_event_t event);
extern void		fm_event_process_all(void);

extern void		fm_rtt_stats_init(fm_rtt_stats_t *, unsigned long initial_rtt, unsigned int multiple);
extern void		fm_rtt_stats_update(fm_rtt_stats_t *, double rtt);

extern fm_host_asset_t *fm_host_asset_get(const fm_address_t *addr, bool create);
extern fm_asset_state_t	fm_host_asset_get_state(const fm_host_asset_t *host);
extern bool		fm_host_asset_update_state(fm_host_asset_t *host, fm_asset_state_t state);;
extern fm_asset_state_t	fm_host_asset_get_port_state(fm_host_asset_t *host, unsigned int proto_id, unsigned int port, fm_asset_state_t state);
extern bool		fm_host_asset_update_port_state(fm_host_asset_t *host, unsigned int proto_id, unsigned int port, fm_asset_state_t state);
extern bool		fm_host_asset_update_state_by_address(const fm_address_t *addr, fm_asset_state_t state);
extern void		fm_host_asset_report_ports(const fm_host_asset_t *host,
				bool (*visitor)(const fm_host_asset_t *host, const char *proto_name, unsigned int port, fm_asset_state_t state, void *user_data),
				void *user_data);

extern void		fm_address_set_ipv4(struct sockaddr_storage *ss, u_int32_t raw_addr);
extern bool		fm_address_get_ipv4(const fm_address_t *addr, u_int32_t *ip_addr);
extern void		fm_address_set_ipv6(struct sockaddr_storage *ss, const struct in6_addr *raw_addr);
extern bool		fm_address_get_ipv6(const fm_address_t *addr, struct in6_addr *raw_addr);
extern bool		fm_address_set_port(fm_address_t *address, unsigned short port);
extern unsigned short	fm_address_get_port(const struct sockaddr_storage *ss);
extern unsigned int	fm_addrfamily_sockaddr_size(int family);
extern const char *	fm_addrfamily_name(int family);

extern fm_socket_t *	fm_socket_create(int family, int type, int proto, fm_protocol_t *driver);
extern void		fm_socket_free(fm_socket_t *);
extern bool		fm_socket_connect(fm_socket_t *, const fm_address_t *);
extern bool		fm_socket_bind(fm_socket_t *, const fm_address_t *);
extern bool		fm_socket_get_local_address(const fm_socket_t *, fm_address_t *);
extern bool		fm_socket_enable_recverr(fm_socket_t *);
extern bool		fm_socket_enable_hdrincl(fm_socket_t *sock);
extern bool		fm_socket_enable_ttl(fm_socket_t *sock);
extern bool		fm_socket_enable_tos(fm_socket_t *sock);
extern bool		fm_socket_enable_timestamp(fm_socket_t *);
extern bool		fm_socket_enable_pktinfo(fm_socket_t *);
extern bool		fm_socket_set_send_ttl(fm_socket_t *sock, unsigned int ttl);
extern bool		fm_socket_send(fm_socket_t *sock, const fm_address_t *dstaddr, const void *pkt, size_t len);
extern bool		fm_socket_send_buffer(fm_socket_t *sock, const fm_address_t *dstaddr, fm_buffer_t *data);
extern bool		fm_socket_send_pkt(fm_socket_t *sock, fm_pkt_t *pkt);
extern bool		fm_socket_send_pkt_and_burn(fm_socket_t *sock, fm_pkt_t *pkt);
extern void		fm_socket_close(fm_socket_t *);
extern bool		fm_socket_poll_all(void);
extern void		fm_socket_timestamp_update(fm_socket_timestamp_t *);
extern double		fm_pkt_rtt(const fm_pkt_t *pkt, const fm_socket_timestamp_t *send_ts);

extern fm_socket_t *	fm_raw_socket_get(const fm_address_t *addr, fm_protocol_t *driver, int sotype);
extern const char *	fm_arp_type_to_string(int hatype);
extern bool		fm_arp_discover(fm_protocol_t *proto, fm_target_t *target, int retries);

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
