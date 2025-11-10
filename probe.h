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

#ifndef FREEMAP_PROBE_H
#define FREEMAP_PROBE_H

#include <linux/if_packet.h> /* for sockaddr_ll - ugly */
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "freemap.h"
#include "lists.h"
#include "addresses.h"
#include "scheduler.h"
#include "extant.h"

typedef bool			fm_probe_status_callback_t(const fm_probe_t *probe,
						const fm_pkt_t *, double rtt,
						void *user_data);
typedef bool			fm_multiprobe_status_callback_t(const fm_multiprobe_t *multiprobe,
						const fm_pkt_t *, double rtt,
						void *user_data);

struct fm_probe_class {
	const char *		name;
	int			action_flags;
	int			modes;		/* bitwise OR of FM_PROBE_MODE_ values */
	int			features;	/* usually a copy of proto->supported_parameters */

	unsigned int		family;
	unsigned int		proto_id;
	fm_protocol_t *		proto;

	void *			(*process_extra_parameters)(const fm_probe_class_t *, const fm_string_array_t *extra_args);
	fm_probe_t *		(*create_probe)(const fm_probe_class_t *, fm_target_t *, const fm_probe_params_t *params, const void *extra_params);

	bool			(*configure)(const fm_probe_class_t *, fm_multiprobe_t *, const void *extra_params);
};

#define FM_PROBE_CLASS_REGISTER(ops) \
__attribute__((constructor)) \
static void \
fm_probe_class_register_ ## ops(void) \
{ \
        fm_probe_class_register(&ops); \
}

struct fm_probe_ops {
	const char *		name;
	size_t			obj_size;

	/* do we still use this? */
	long			default_timeout;

	void			(*destroy)(fm_probe_t *);
	fm_error_t		(*schedule)(fm_probe_t *);
	fm_error_t		(*send)(fm_probe_t *);
	fm_error_t		(*set_socket)(fm_probe_t *probe, fm_socket_t *);
	fm_error_t		(*set_service)(fm_probe_t *, fm_service_probe_t *);
};

struct fm_probe {
	fm_job_t		job;

	/* name of the probe, like udp/53 or icmp/echo */
	char *			name;

	/* Nothing outside the code in probe.c should touch this. */
	fm_target_t *		_target;

	const struct fm_probe_ops *ops;

	fm_rtt_stats_t *	rtt;

	/* Used by traceroute to receive callbacks when there is something to be
	 * learned. */
	struct {
		fm_probe_status_callback_t *cb;
		void *		user_data;
	} status_callback;

	/* When probing eg UDP based services, we need to slap some
	 * constant value on the timeout derived from the RTT estimate,
	 * because the RTT will be largely based on the network timing;
	 * but for us to receive a UDP response, we need to take into
	 * account the time it takes the server to actually cook up a
	 * response.
	 */
	unsigned int		rtt_application_bias;

	struct timeval		sent;
};

#define FM_TASKLET_MAX_PACKETS	16

enum {
	FM_TASKLET_STATE_FREE,
	FM_TASKLET_STATE_BUSY,
	FM_TASKLET_STATE_DONE,
};

typedef struct fm_tasklet {
	fm_host_tasklet_t *	host;

	/* for tasklets with parameter, something like "/port=NN" */
	char *			detail;

	double			timeout;
	struct timeval		send_ts;

	char			state;

	unsigned short		probe_index;
	unsigned short		max_packets;

	unsigned short		send_retries;
	unsigned short		resp_received;
	unsigned short		resp_required;

	short			param_type;
	short			param_value;

	fm_extant_t *		extants[FM_TASKLET_MAX_PACKETS];
} fm_tasklet_t;

/*
 * This struct holds some per-target scanning state for the
 * protocol drivers.
 */
typedef struct fm_target_control {
	int			family;
	fm_target_t *		target;
	fm_address_t		local_address;
	fm_address_t		address;
	fm_socket_t *		sock;

	union {
		struct {
			uint32_t		src_ipaddr;
			uint32_t		dst_ipaddr;
			struct sockaddr_ll	src_lladdr;
			struct sockaddr_ll	dst_lladdr;
		} arp;
		struct {
			fm_buffer_t *		packet_header;
			struct fm_csum_hdr *	csum_header;
			uint16_t		retries;
		} icmp;
	};
} fm_target_control_t;

struct fm_host_tasklet {
	struct hlist		link;

	double			timeout;

	char *			name;
	fm_target_t *		target;
	fm_host_asset_t *	host_asset;

	fm_target_control_t	control;

	unsigned int		probe_index;

	unsigned int		num_tasks;
	fm_tasklet_t *		tasklets;
};

typedef const struct fm_multiprobe_ops {
	bool			(*add_target)(fm_multiprobe_t *, fm_host_tasklet_t *, fm_target_t *);
	bool			(*add_broadcast)(fm_multiprobe_t *, fm_host_tasklet_t *,
						const fm_address_t *src_link_addr,
						const fm_address_t *dst_link_addr,
						const fm_address_t *src_network_addr,
						const fm_address_t *dst_network_addr);
	fm_error_t		(*transmit)(fm_multiprobe_t *, fm_host_tasklet_t *,
						int param_type, int param_value,
						fm_extant_t **extant_ret,
						double *timeout_ret);
	void			(*destroy_host)(fm_multiprobe_t *, fm_host_tasklet_t *);
	void			(*destroy)(fm_multiprobe_t *);
} fm_multiprobe_ops_t;

struct fm_multiprobe {
	fm_job_t		job;

	fm_scan_action_t *	action;
	const char *		name;
	int			probe_mode;

	struct {
		double		packet_spacing;
		double		timeout;
	} timings;

	/* Used by traceroute to receive callbacks when there is something to be
	 * learned. */
	struct {
		fm_multiprobe_status_callback_t *cb;
		void *		user_data;
	} status_callback;

	fm_probe_params_t	params;

	void *			control;

	fm_multiprobe_ops_t *	ops;

	struct {
		unsigned int	param_type;
		unsigned int	count;
		const fm_uint_array_t *array;
	} bucket_list;

	struct hlist_head	ready;
	struct hlist_head	waiting;
	struct hlist_head	done;
};

extern void		fm_probe_class_register(struct fm_probe_class *);
extern fm_probe_class_t *fm_probe_class_find(const char *name, int mode);
extern fm_probe_class_t *fm_probe_class_by_proto_id(unsigned int proto_id, int mode);

extern fm_multiprobe_t *fm_multiprobe_alloc_action(fm_scan_action_t *action);
extern fm_multiprobe_t *fm_multiprobe_alloc(int probe_mode, const char *name);
extern bool		fm_multiprobe_add_target(fm_multiprobe_t *, fm_target_t *);
extern bool		fm_multiprobe_add_link_level_broadcast(fm_multiprobe_t *multiprobe, int af,
					const fm_interface_t *nic, const fm_address_t *net_src_addr);
extern bool		fm_multiprobe_is_idle(const fm_multiprobe_t *);
extern void		fm_multiprobe_transmit(fm_multiprobe_t *, fm_sched_stats_t *sched_stats);
extern fm_error_t	fm_multiprobe_transmit_ttl_probe(fm_multiprobe_t *multiprobe, fm_target_control_t *target_control,
					unsigned int ttl, fm_extant_t **, double *timeout_ret);
extern bool		fm_multiprobe_configure(fm_multiprobe_t *, fm_probe_class_t *, const fm_probe_params_t *, const void *);
extern fm_target_t *	fm_multiprobe_get_completed(fm_multiprobe_t *);
extern void		fm_multiprobe_install_status_callback(fm_multiprobe_t *, fm_multiprobe_status_callback_t *, void *);
extern void		fm_multiprobe_free(fm_multiprobe_t *);

extern void		fm_target_control_destroy(fm_target_control_t *);
extern void		fm_tasklet_extant_done(fm_tasklet_t *tasklet, fm_extant_t *extant);

extern fm_probe_t *	fm_create_host_probe(const fm_probe_class_t *, fm_target_t *, const fm_probe_params_t *, const void *extra_params);
extern fm_probe_t *	fm_create_port_probe(const fm_probe_class_t *, fm_target_t *, uint16_t, const fm_probe_params_t *);

extern fm_probe_t *	fm_probe_alloc(const char *id,
				const struct fm_probe_ops *ops,
				fm_target_t *target);
extern const char *	fm_probe_mode_to_string(int mode);

extern void		fm_probe_set_rtt_estimator(fm_probe_t *, fm_rtt_stats_t *);
extern void		fm_probe_received_reply(fm_probe_t *, double *rtt);
extern void		fm_probe_received_error(fm_probe_t *, double *rtt);
extern void		fm_probe_timed_out(fm_probe_t *);
extern void		fm_probe_set_error(fm_probe_t *, fm_error_t);
extern void		fm_probe_mark_complete(fm_probe_t *);
extern fm_completion_t *fm_probe_wait_for_completion(fm_probe_t *probe, void (*func)(const fm_job_t *, void *), void *);
extern void		fm_probe_cancel_completion(fm_probe_t *probe, const fm_completion_t *);
extern void		fm_completion_free(fm_completion_t *);
extern void		fm_probe_install_status_callback(fm_probe_t *, fm_probe_status_callback_t *, void *);
extern fm_error_t	fm_probe_set_socket(fm_probe_t *probe, fm_socket_t *sock);
extern fm_error_t	fm_probe_set_service(fm_probe_t *probe, fm_service_probe_t *);

extern fm_probe_t *	fm_probe_from_job(fm_job_t *job);

extern bool		fm_sched_stats_update_timeout_min(fm_sched_stats_t *, fm_time_t, const char *);
extern bool		fm_sched_stats_update_timeout_max(fm_sched_stats_t *, fm_time_t, const char *);
extern void		fm_sched_stats_update_from_nested(fm_sched_stats_t *, const fm_sched_stats_t *);

/* kludge */
extern void		fm_probe_update_rtt_estimate(fm_probe_t *probe, double *rtt);
extern bool		fm_probe_invoke_status_callback(const fm_probe_t *probe, const fm_pkt_t *pkt, double rtt);

static inline bool
fm_probe_class_supports(const fm_probe_class_t *pclass, fm_param_type_t type)
{
	return !!(pclass->features & (1 << type));
}

static inline const char *
fm_probe_name(const fm_probe_t *probe)
{
	return probe->job.fullname;
}

#endif /* FREEMAP_PROBE_H */
