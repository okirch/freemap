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

typedef bool			fm_probe_status_callback_t(const fm_probe_t *probe,
						const fm_pkt_t *, double rtt,
						void *user_data);

struct fm_probe_class {
	const char *		name;
	int			action_flags;
	int			features;	/* usually a copy of proto->supported_parameters */
	bool			disabled;

	unsigned int		proto_id;
	fm_protocol_t *		proto;

	void *			(*process_extra_parameters)(const fm_probe_class_t *, const fm_string_array_t *extra_args);
	fm_probe_t *		(*create_probe)(const fm_probe_class_t *, fm_target_t *, const fm_probe_params_t *params, const void *extra_params);
//	bool			(*set_probe_socket)(const fm_probe_class_t *, fm_probe_t *, fm_socket_t *);
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
};

struct fm_probe {
	struct hlist		link;

	fm_target_t *		target;

	/* name of the probe, like udp/53 or icmp/echo */
	char *			name;

	const struct fm_probe_ops *ops;

	bool			blocking;

	fm_rtt_stats_t *	rtt;

	/* Used when waiting for some event to occur (such as other
	 * probes finishing, or a neighbor lookup completing).
	 */
	fm_event_listener_t *	event_listener;

	/* Used to notify someone who is waiting for this probe to complete */
	fm_completion_t *	completion;

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

	long			timeout;

	struct timeval		sent;
	struct timeval		expires;

	/* for probes that have completed */
	bool			done;
	fm_error_t		error;
};

struct fm_probe_list {
	struct hlist_head	hlist;
};

/*
 * completions can be used to wait for a probe to finish.
 * They're owned by the caller and are theirs to disponse of after use.
 */
struct fm_completion {
	void			(*callback)(const fm_probe_t *, void *user_data);
	void *			user_data;
};

/*
 * Hold the state of an extant request
 */
typedef struct fm_extant {
	struct hlist		link;

	int			family;
	int			ipproto;

	fm_socket_timestamp_t	timestamp;
	fm_probe_t *		probe;
} fm_extant_t;

struct fm_extant_list {
	struct hlist_head	hlist;
};

extern void		fm_probe_class_register(struct fm_probe_class *);
extern fm_probe_class_t *fm_probe_class_find(const char *name);
extern fm_probe_class_t *fm_probe_class_by_proto_id(unsigned int proto_id);

extern fm_probe_t *	fm_create_host_probe(const fm_probe_class_t *, fm_target_t *, const fm_probe_params_t *, const void *extra_params);
extern fm_probe_t *	fm_create_port_probe(const fm_probe_class_t *, fm_target_t *, uint16_t, const fm_probe_params_t *);

extern fm_probe_t *	fm_probe_alloc(const char *id,
				const struct fm_probe_ops *ops,
				fm_target_t *target);


extern fm_extant_t *	fm_extant_alloc(fm_probe_t *, int af, int ipproto,
				const void *payload, size_t payload_size);
extern void		fm_extant_free(fm_extant_t *extant);

extern void		fm_probe_set_rtt_estimator(fm_probe_t *, fm_rtt_stats_t *);
extern void		fm_probe_received_reply(fm_probe_t *, double *rtt);
extern void		fm_probe_received_error(fm_probe_t *, double *rtt);
extern void		fm_probe_timed_out(fm_probe_t *);
extern void		fm_probe_set_error(fm_probe_t *, fm_error_t);
extern void		fm_probe_mark_complete(fm_probe_t *);
extern fm_completion_t *fm_probe_wait_for_completion(fm_probe_t *probe, void (*func)(const fm_probe_t *, void *), void *);
extern void		fm_probe_cancel_completion(fm_probe_t *probe, const fm_completion_t *);
extern void		fm_completion_free(fm_completion_t *);
extern void		fm_probe_install_status_callback(fm_probe_t *, fm_probe_status_callback_t *, void *);
extern fm_error_t	fm_probe_set_socket(fm_probe_t *probe, fm_socket_t *sock);

extern void		fm_extant_received_reply(fm_extant_t *extant, const fm_pkt_t *pkt);
extern void		fm_extant_received_error(fm_extant_t *extant, const fm_pkt_t *pkt);

static inline bool
fm_probe_class_supports(const fm_probe_class_t *pclass, fm_param_type_t type)
{
	return !!(pclass->features & (1 << type));
}

static inline void
fm_probe_insert(struct fm_probe_list *list, fm_probe_t *probe)
{
	hlist_insert(&list->hlist, &probe->link);
}

static inline void
fm_probe_append(struct fm_probe_list *list, fm_probe_t *probe)
{
	hlist_append(&list->hlist, &probe->link);
}

static inline void
fm_probe_unlink(fm_probe_t *probe)
{
	hlist_remove(&probe->link);
}

static inline fm_probe_t *
fm_probe_list_get_first(struct fm_probe_list *list)
{
	fm_probe_t *probe;

	if ((probe = (fm_probe_t *) list->hlist.first) != NULL)
		fm_probe_unlink(probe);
	return probe;
}

static inline bool
fm_probe_list_is_empty(const struct fm_probe_list *list)
{
	return list->hlist.first == NULL;
}

#define fm_probe_foreach(list, iter_var) \
	for (iter_var = (fm_probe_t *) ((list)->hlist.first); iter_var != NULL; iter_var = (fm_probe_t *) (iter_var->next))

static inline void
fm_extant_append(struct fm_extant_list *list, fm_extant_t *extant)
{
	hlist_append(&list->hlist, &extant->link);
}

static inline void
fm_extant_unlink(fm_extant_t *extant)
{
	hlist_remove(&extant->link);
}

static inline void
fm_extant_iterator_init(hlist_iterator_t *iter, struct fm_extant_list *list)
{
	hlist_iterator_init(iter, &list->hlist);
}

static inline fm_extant_t *
fm_extant_iterator_first(hlist_iterator_t *iter, struct fm_extant_list *list)
{
	return (fm_extant_t *) hlist_iterator_first(iter, &list->hlist);
}

static inline fm_extant_t *
fm_extant_iterator_next(hlist_iterator_t *iter)
{
	return (fm_extant_t *) hlist_iterator_next(iter);
}

static inline fm_extant_t *
fm_extant_iterator_match(hlist_iterator_t *iter, int af, int ipproto)
{
	fm_extant_t *extant;

	while ((extant = fm_extant_iterator_next(iter)) != NULL
	    && extant->family != af && extant->ipproto != ipproto)
		;
	return extant;
}

#endif /* FREEMAP_PROBE_H */
