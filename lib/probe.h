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

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "freemap.h"
#include "lists.h"
#include "addresses.h"
#include "scheduler.h"
#include "extant.h"

typedef bool			fm_multiprobe_status_callback_t(const fm_multiprobe_t *multiprobe,
						const fm_pkt_t *, double rtt,
						void *user_data);

/* This is defined in probe_private.h in all its glory */
typedef struct fm_target_control fm_target_control_t;

struct fm_probe_class {
	const char *		name;
	int			action_flags;
	int			modes;		/* bitwise OR of FM_PROBE_MODE_ values */
	int			features;	/* usually a copy of proto->supported_parameters */

	unsigned int		family;
	unsigned int		proto_id;
	fm_protocol_t *		proto;

	bool			(*configure)(const fm_probe_class_t *, fm_multiprobe_t *, const fm_string_array_t *extra_args);
};

#define FM_PROBE_CLASS_REGISTER(ops) \
__attribute__((constructor)) \
static void \
fm_probe_class_register_ ## ops(void) \
{ \
        fm_probe_class_register(&ops); \
}

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

	unsigned short		num_sent;
	unsigned short		send_retries;
	unsigned short		resp_received;
	unsigned short		resp_required;

	short			param_type;
	short			param_value;

	const fm_service_probe_t *service_probe;

	fm_extant_t *		extants[FM_TASKLET_MAX_PACKETS];
} fm_tasklet_t;

typedef const struct fm_multiprobe_ops {
	bool			(*add_target)(fm_multiprobe_t *, fm_host_tasklet_t *, fm_target_t *);
	bool			(*add_broadcast)(fm_multiprobe_t *, fm_host_tasklet_t *,
						const fm_interface_t *nic,
						const fm_address_t *src_link_addr,
						const fm_address_t *dst_link_addr,
						const fm_address_t *src_network_addr,
						const fm_address_t *dst_network_addr);
	fm_service_probe_t *	(*lookup_service)(fm_multiprobe_t *,
						int param_type, int param_value,
						const fm_service_catalog_t *);
	fm_error_t		(*transmit)(fm_multiprobe_t *, fm_host_tasklet_t *,
						int param_type, int param_value,
						const fm_buffer_t *application_payload,
						fm_extant_t **extant_ret,
						double *timeout_ret);
	void			(*destroy_host)(fm_multiprobe_t *, fm_host_tasklet_t *);
	void			(*destroy)(fm_multiprobe_t *);
} fm_multiprobe_ops_t;

struct fm_multiprobe {
	fm_job_t		job;

	fm_probe_class_t *	probe_class;
	char *			name;
	int			probe_mode;
	int			action_flags;

	/* This is where the probe receives its targets from */
	fm_target_pool_t *	target_queue;

	/* The service catalog tells us what application packets to send to a
	 * datagram based service */
	const fm_service_catalog_t *service_catalog;

	unsigned int		retries;
	struct {
		double		packet_spacing;
		double		timeout;
	} timings;

	struct {
		void		(*callback)(const fm_pkt_t *pkt, void *user_data);
		void *		user_data;
	} data_tap;

	void *			control;

	fm_multiprobe_ops_t *	ops;

	struct {
		unsigned int	param_type;
		unsigned int	count;
		fm_uint_array_t	array;
	} bucket_list;

	struct hlist_head	ready;
	struct hlist_head	waiting;
	struct hlist_head	done;
};

extern void		fm_probe_class_register(struct fm_probe_class *);
extern fm_probe_class_t *fm_probe_class_find(const char *name, int mode);
extern fm_probe_class_t *fm_probe_class_by_proto_id(unsigned int proto_id, int mode);

extern fm_multiprobe_t *fm_multiprobe_from_config(fm_probe_class_t *pclass, const fm_config_probe_t *config);
extern fm_multiprobe_t *fm_multiprobe_alloc(int probe_mode, const char *name);
extern bool		fm_multiprobe_add_target(fm_multiprobe_t *, fm_target_t *);
extern bool		fm_multiprobe_add_link_level_broadcast(fm_multiprobe_t *multiprobe, int af,
					const fm_interface_t *nic, const fm_address_t *net_src_addr);
extern bool		fm_multiprobe_is_idle(const fm_multiprobe_t *);
extern void		fm_multiprobe_transmit(fm_multiprobe_t *, fm_sched_stats_t *sched_stats);
extern fm_error_t	fm_multiprobe_transmit_ttl_probe(fm_multiprobe_t *multiprobe, fm_target_control_t *target_control,
					unsigned int ttl, fm_extant_t **, double *timeout_ret);
extern bool		fm_multiprobe_configure(fm_multiprobe_t *, fm_probe_class_t *, const void *);
extern fm_target_t *	fm_multiprobe_get_completed(fm_multiprobe_t *);
extern void		fm_multiprobe_install_status_callback(fm_multiprobe_t *, fm_multiprobe_status_callback_t *, void *);
extern void		fm_multiprobe_install_data_tap(fm_multiprobe_t *,
					void (*callback)(const fm_pkt_t *, void *), void *);
extern bool		fm_multiprobe_set_service_catalog(fm_multiprobe_t *, const fm_service_catalog_t *);
extern void		fm_multiprobe_free(fm_multiprobe_t *);

extern void		fm_target_control_destroy(fm_target_control_t *);
extern void		fm_tasklet_extant_done(fm_tasklet_t *tasklet, fm_extant_t *extant);

extern const char *	fm_probe_mode_to_string(int mode);

extern void		fm_completion_free(fm_completion_t *);

extern bool		fm_sched_stats_update_timeout_min(fm_sched_stats_t *, fm_time_t, const char *);
extern bool		fm_sched_stats_update_timeout_max(fm_sched_stats_t *, fm_time_t, const char *);
extern void		fm_sched_stats_update_from_nested(fm_sched_stats_t *, const fm_sched_stats_t *);

static inline bool
fm_probe_class_supports(const fm_probe_class_t *pclass, fm_param_type_t type)
{
	return !!(pclass->features & (1 << type));
}

/*
 * This is probably just temporary
 */
typedef struct fm_multiprobe_array {
	unsigned int		count;
	fm_multiprobe_t **	entries;
} fm_multiprobe_array_t;

extern void		fm_multiprobe_array_append(fm_multiprobe_array_t *array, fm_multiprobe_t *);

#endif /* FREEMAP_PROBE_H */
