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

typedef bool			fm_probe_status_callback_t(const fm_probe_t *probe,
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

extern void		fm_probe_class_register(struct fm_probe_class *);
extern fm_probe_class_t *fm_probe_class_find(const char *name, int mode);
extern fm_probe_class_t *fm_probe_class_by_proto_id(unsigned int proto_id, int mode);

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
