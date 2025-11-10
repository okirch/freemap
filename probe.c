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

#include <string.h>
#include <stdio.h>
#include "target.h"
#include "network.h"
#include "utils.h"
#include "lists.h"
#include "protocols.h"
#include "events.h"
#include "scanner.h"

#undef FM_PROBE_DEBUG
#ifdef FM_PROBE_DEBUG
# define debugmsg	fm_log_debug
#else
# define debugmsg(fmt ...) do { } while (0)
#endif

static void		fm_multiprobe_destroy(fm_multiprobe_t *multiprobe);

/*
 * Handle registration of probe classes
 */
#define FM_PROBE_CLASS_MAX	128
static unsigned int		probe_class_count;
static struct fm_probe_class *	probe_class_registry[FM_PROBE_CLASS_MAX];

void
fm_probe_class_register(struct fm_probe_class *probe_class)
{
	assert(probe_class_count < FM_PROBE_CLASS_MAX);
	probe_class_registry[probe_class_count++] = probe_class;
}

static void
fm_probe_classes_init(void)
{
	static bool initialized = false;
	struct fm_probe_class *pclass;
	unsigned int i;

	if (!initialized) {
		for (i = 0; i < probe_class_count; ++i) {
			fm_protocol_t *proto;

			pclass = probe_class_registry[i];

			if (pclass->proto_id == 0)
				continue;

			proto = fm_protocol_by_id(pclass->proto_id);
			if (proto == NULL) {
				fm_log_debug("probe class %s requires protocol %s, which is not available",
						pclass->name, fm_protocol_id_to_string(pclass->proto_id));

				/* disable by cleaning out the mask of supported modes */
				pclass->modes = 0;
				continue;
			}

			pclass->proto = proto;
			pclass->features |= proto->supported_parameters;
		}
		initialized = true;
	}
}

const fm_probe_class_t *
fm_probe_class_find(const char *name, int mode)
{
	struct fm_probe_class *pclass;
	unsigned int i;

	fm_probe_classes_init();
	for (i = 0; i < probe_class_count; ++i) {
		pclass = probe_class_registry[i];

		if (!(pclass->modes & mode))
			continue;

		if (!strcmp(pclass->name, name))
			return pclass;
	}

	return NULL;
}

fm_probe_class_t *
fm_probe_class_by_proto_id(unsigned int proto_id, int mode)
{
	struct fm_probe_class *pclass;
	unsigned int i;

	fm_probe_classes_init();
	for (i = 0; i < probe_class_count; ++i) {
		pclass = probe_class_registry[i];

		if (!(pclass->modes & mode))
			continue;

		if (pclass->proto_id == proto_id)
			return pclass;
	}

	return NULL;
}

/*
 * probe modes
 */
const char *
fm_probe_mode_to_string(int mode)
{
	switch (mode) {
	case FM_PROBE_MODE_TOPO:
		return "topo";
	case FM_PROBE_MODE_HOST:
		return "host";
	case FM_PROBE_MODE_PORT:
		return "port";
	}
	return "bad";
}

/*
 * Throw away a probe.
 */
void
fm_probe_destroy(fm_probe_t *probe)
{
	/* When we get here, the job part of this should have been pretty much torn already. */
	assert(probe->job.group == NULL);

	if (probe->ops->destroy)
		probe->ops->destroy(probe);

	if (probe->_target != NULL)
		fm_target_forget_pending(probe->_target, probe);
}

void
fm_probe_free(fm_probe_t *probe)
{
	fm_probe_destroy(probe);
	free(probe);
}

/*
 * Add a probe to the global scheduler queue
 */
void
fm_probe_run_globally(fm_probe_t *probe)
{
	fm_job_group_add_new(fm_scheduler_create_global_queue(), &probe->job);
}

/*
 * The probe<->job glue
 */
static fm_error_t
fm_probe_job_run(fm_job_t *job, fm_sched_stats_t *stats)
{
	fm_probe_t *probe = (fm_probe_t *) job;
	fm_error_t error;
	bool first_transmission;

	first_transmission = !fm_timestamp_is_set(&probe->sent);

	error = fm_probe_send(probe);
	if (error == FM_TRY_AGAIN) {
		/* the probe asked to be postponed. */
	} else {
		if (error != FM_SEND_ERROR)
			stats->num_sent += 1;

		if (error != 0) {
			/* complain about probes that are so broken they don't even manage to
			 * send a single package. */
			if (first_transmission)
				fm_log_warning("%s: probe is DOA", probe->job.fullname);
		} else if (first_transmission)
			fm_timestamp_init(&probe->sent);
	}

	return error;
}

static void
fm_probe_job_destroy(fm_job_t *job)
{
	fm_probe_t *probe = (fm_probe_t *) job;

	fm_probe_destroy(probe);
}

static fm_job_ops_t	fm_probe_job_ops = {
	.run		= fm_probe_job_run,
	.destroy	= fm_probe_job_destroy,
};

fm_probe_t *
fm_probe_from_job(fm_job_t *job)
{
	if (job->ops != &fm_probe_job_ops)
		return NULL;

	return (fm_probe_t *) job;
}

/*
 * The multiprobe<->job glue
 */
static fm_error_t
fm_multiprobe_job_run(fm_job_t *job, fm_sched_stats_t *stats)
{
	fm_multiprobe_t *multiprobe = (fm_multiprobe_t *) job;

	fm_multiprobe_transmit(multiprobe, stats);

	if (fm_multiprobe_is_idle(multiprobe)) {
		debugmsg("job %s is waiting for more targets", job->fullname);
		job->expires = fm_time_now() + 60;
	} else
	if (job->expires == 0) {
		fm_log_warning("%s: timeout = 0! This should not happen.", job->fullname);
	}

	return FM_TRY_AGAIN;
}

static void
fm_multiprobe_job_destroy(fm_job_t *job)
{
	fm_multiprobe_t *multiprobe = (fm_multiprobe_t *) job;

	fm_multiprobe_destroy(multiprobe);
}

static fm_job_ops_t	fm_multiprobe_job_ops = {
	.run		= fm_multiprobe_job_run,
	.destroy	= fm_multiprobe_job_destroy,
};

fm_multiprobe_t *
fm_multiprobe_from_job(fm_job_t *job)
{
	if (job->ops != &fm_multiprobe_job_ops)
		return NULL;

	return (fm_multiprobe_t *) job;
}

/*
 * Probe objects
 */
fm_probe_t *
fm_probe_alloc(const char *id, const struct fm_probe_ops *ops, fm_target_t *target)
{
	fm_probe_t *probe;

	if (ops->schedule == NULL)
		fm_log_fatal("BUG: probe implementation %s lacks a schedule() function", ops->name);

	assert(ops->obj_size >= sizeof(*probe));
	probe = calloc(1, ops->obj_size);
	probe->_target = target;
	probe->name = strdup(id);
	probe->ops = ops;

	fm_job_init(&probe->job, &fm_probe_job_ops, probe->name);

	return probe;
}

void
fm_probe_set_expiry(fm_probe_t *probe, double seconds)
{
	fm_job_set_expiry(&probe->job, seconds);
}

/*
 * used by traceroute
 */
fm_error_t
fm_probe_set_socket(fm_probe_t *probe, fm_socket_t *sock)
{
	if (probe->ops->set_socket == NULL) {
		fm_log_error("%s: %s does not support shared sockets", __func__, probe->name);
		return FM_NOT_SUPPORTED;
	}

	return probe->ops->set_socket(probe, sock);
}

/*
 * Associate a service probe with a port probe.
 * The service probe provides a list of payloads to send.
 */
fm_error_t
fm_probe_set_service(fm_probe_t *probe, fm_service_probe_t *service_probe)
{
	if (probe->ops->set_service == NULL) {
		fm_log_error("%s: %s does not support service probes", __func__, probe->name);
		return FM_NOT_SUPPORTED;
	}

	return probe->ops->set_service(probe, service_probe);
}

/*
 * This kicks the probe to make it send another packet (if it feels like it)
 */
fm_error_t
fm_probe_send(fm_probe_t *probe)
{
	fm_error_t error;

	/* In theory, we could fold schedule() and send() into one, and some
	 * probe implementations actually do this (eg traceroute). But in most
	 * cases, the code looks just cleaner if we don't conflate these two steps. */
	error = probe->ops->schedule(probe);
	if (error == 0)
		error = probe->ops->send(probe);

	return error;
}

/*
 * Probe completion
 */
fm_completion_t *
fm_probe_wait_for_completion(fm_probe_t *probe, void (*func)(const fm_job_t *, void *), void *user_data)
{
	return fm_job_wait_for_completion(&probe->job, func, user_data);
}

void
fm_probe_cancel_completion(fm_probe_t *probe, const fm_completion_t *completion)
{
	fm_job_cancel_completion(&probe->job, completion);
}

/*
 * Another set of callbacks; this time for inspecting packets received
 * an errors encountered.
 * Returns true if the probe should keep going, false if is considered complete.
 */
void
fm_probe_install_status_callback(fm_probe_t *probe, fm_probe_status_callback_t *cb, void *user_data)
{
	probe->status_callback.cb = cb;
	probe->status_callback.user_data = user_data;
}

bool
fm_probe_invoke_status_callback(const fm_probe_t *probe, const fm_pkt_t *pkt, double rtt)
{
	if (!probe->status_callback.cb)
		return false;

	return probe->status_callback.cb(probe, pkt, rtt, probe->status_callback.user_data);
}

void
fm_probe_mark_complete(fm_probe_t *probe)
{
	fm_job_mark_complete(&probe->job);
}

void
fm_probe_set_rtt_estimator(fm_probe_t *probe, fm_rtt_stats_t *rtt)
{
	probe->rtt = rtt;
}

void
fm_probe_update_rtt_estimate(fm_probe_t *probe, double *rtt)
{
	if (probe->rtt) {
		if (rtt == NULL || *rtt < 0) {
			/* This fallback should probably go away soon */
			fm_rtt_stats_update(probe->rtt, fm_timestamp_since(&probe->sent));
		} else {
			fm_rtt_stats_update(probe->rtt, *rtt);
		}

	}
}

void
fm_probe_received_reply(fm_probe_t *probe, double *rtt)
{
	fm_probe_update_rtt_estimate(probe, rtt);
	fm_probe_mark_complete(probe);
}

void
fm_probe_received_error(fm_probe_t *probe, double *rtt)
{
	fm_probe_update_rtt_estimate(probe, rtt);
	fm_probe_mark_complete(probe);
}

void
fm_probe_timed_out(fm_probe_t *probe)
{
	fm_probe_mark_complete(probe);
}

/*
 * Handle probe event listening
 */
bool
fm_probe_wait_for_event(fm_probe_t *probe, fm_event_callback_t *callback, fm_event_t event)
{
	return fm_job_wait_for_event(&probe->job, callback, event);
}

void
fm_probe_finish_waiting(fm_probe_t *probe)
{
	fm_job_finish_waiting(&probe->job);
}

/*
 * Multiprobe stuff
 */
static fm_host_tasklet_t *
fm_host_tasklet_alloc(fm_target_t *target, unsigned int num_tasks)
{
	fm_host_tasklet_t *host_task;

	host_task = calloc(1, sizeof(*host_task));

	host_task->target = target;
	if (target != NULL)
		host_task->host_asset = target->host_asset;

	host_task->num_tasks = num_tasks;
	host_task->tasklets = calloc(num_tasks, sizeof(host_task->tasklets[0]));

	return host_task;
}

void
fm_target_control_destroy(fm_target_control_t *host_state)
{
	/* careful with that axe, Eugene. */
	if (host_state->sock != NULL) {
		fm_socket_free(host_state->sock);
		host_state->sock = NULL;
	}
}

static void
fm_host_tasklet_free(fm_host_tasklet_t *host_task)
{
	hlist_remove(&host_task->link);
	drop_string(&host_task->name);
	free(host_task->tasklets);
	free(host_task);
}

/*
 * Creeate a multiprobe
 */
fm_multiprobe_t *
fm_multiprobe_alloc(int probe_mode, const char *name)
{
	fm_multiprobe_t *multiprobe;

	multiprobe = calloc(1, sizeof(*multiprobe));
	multiprobe->name = name;

	multiprobe->bucket_list.count = 1;
	multiprobe->bucket_list.param_type = FM_PARAM_TYPE_NONE;

	fm_job_init(&multiprobe->job, &fm_multiprobe_job_ops, name);
	return multiprobe;
}

fm_multiprobe_t *
fm_multiprobe_alloc_action(fm_scan_action_t *action)
{
	fm_multiprobe_t *multiprobe;

	multiprobe = fm_multiprobe_alloc(action->mode, action->id);
	multiprobe->action = action;

	if (action->mode == FM_PROBE_MODE_PORT) {
		multiprobe->bucket_list.array = &action->numeric_params;
		multiprobe->bucket_list.count = action->numeric_params.count;
		multiprobe->bucket_list.param_type = FM_PARAM_TYPE_PORT;
	}

	return multiprobe;
}


void
fm_multiprobe_free(fm_multiprobe_t *multiprobe)
{
	assert(multiprobe->job.group == NULL);
	free(multiprobe);
}

static void
fm_multiprobe_destroy(fm_multiprobe_t *multiprobe)
{
	fm_host_tasklet_t *host_task;

	while ((host_task = hlist_head_get_first(&multiprobe->ready)) != NULL)
		fm_host_tasklet_free(host_task);

	while ((host_task = hlist_head_get_first(&multiprobe->waiting)) != NULL)
		fm_host_tasklet_free(host_task);

	/* protocol tear-down */
	multiprobe->ops->destroy(multiprobe);

	/* The actual freeing of the structure happens in fm_job_free() */
}

bool
fm_multiprobe_configure(fm_multiprobe_t *multiprobe, fm_probe_class_t *pclass, const fm_probe_params_t *params, const void *extra_params)
{
	if (pclass->configure == NULL) {
		fm_log_error("probe class %s does not support multiprobe", pclass->name);
		return false;
	}

	multiprobe->params = *params;

	if (!pclass->configure(pclass, multiprobe, extra_params))
		return false;

	if (multiprobe->timings.packet_spacing == 0)
		multiprobe->timings.packet_spacing = 0.5;
	if (multiprobe->timings.timeout == 0)
		multiprobe->timings.timeout = 0.5;
	if (multiprobe->params.retries == 0)
		multiprobe->params.retries = 3;

	return true;
}

/*
 * Add another target to the probe
 */
bool
fm_multiprobe_add_target(fm_multiprobe_t *multiprobe, fm_target_t *target)
{
	fm_host_tasklet_t *host_task;

	/* This action may not be applicable for the target, eg an ARP probe
	 * makes no sense for IPv6 (well, unless there's a v6 stack out there broken
	 * enough to response to such queries....)
	 */
	if (multiprobe->action && !fm_scan_action_validate(multiprobe->action, target))
		return false;

	host_task = fm_host_tasklet_alloc(target, 1);
	asprintf(&host_task->name, "%s/%s", multiprobe->name, target->id);

	hlist_insert(&multiprobe->ready, &host_task->link);

	if (!multiprobe->ops->add_target || !multiprobe->ops->add_target(multiprobe, host_task, target)) {
		fm_log_error("%s: unable to add target %s", multiprobe->name, target->id);
		fm_host_tasklet_free(host_task);
		return false;
	}

	debugmsg("%s added target %s", multiprobe->name, target->id);
	return true;
}

/*
 * Add a link-level broadcast target to the probe.
 * Used for things like ICMP local discovery for IPv6
 */
bool
fm_multiprobe_add_link_level_broadcast(fm_multiprobe_t *multiprobe, int af,
			const fm_interface_t *nic, const fm_address_t *net_src_addr)
{
	fm_host_tasklet_t *host_task;
	fm_address_t network_broadcast;
	fm_address_t lladdr, llbcast;
	const char *ifname;

	if (multiprobe->ops->add_broadcast == NULL) {
		fm_log_error("%s: cannot add a broadcast probe: not supported", multiprobe->name);
		return false;
	}

	ifname = fm_interface_get_name(nic);

	/* Note, for IPv6 over ethernet, the get_llbroadcast function will actually return the
	 * all-nodes MAC multicast address 33:33:00:00:00:01.
	 * I wonder what this does for IPv4... */
	if (!fm_interface_get_lladdr(nic, (struct sockaddr_ll *) &lladdr)
	 || !fm_address_link_update_upper_protocol(&lladdr, af))
		return false;

	if (!fm_interface_get_llbroadcast(nic, (struct sockaddr_ll *) &llbcast)
	 || !fm_address_link_update_upper_protocol(&llbcast, af))
		return false;

	if (af == AF_INET) {
		fm_address_set_ipv4_local_broadcast(&network_broadcast);
	} else if (af == AF_INET6) {
		fm_address_set_ipv6_all_hosts_multicast(&network_broadcast);
	} else {
		return false;
	}

	host_task = fm_host_tasklet_alloc(NULL, 17);
	asprintf(&host_task->name, "%s/%s/broadcast", multiprobe->name, ifname);

	hlist_insert(&multiprobe->ready, &host_task->link);

	if (!multiprobe->ops->add_broadcast(multiprobe, host_task, &lladdr, &llbcast, net_src_addr, &network_broadcast)) {
		fm_log_error("%s: unable to add brodcast via %s", multiprobe->name, ifname);
		fm_host_tasklet_free(host_task);
		return false;
	}

	return true;
}

static bool
fm_multiprobe_create_tasklet(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_tasklet_t *tasklet, fm_sched_stats_t *sched_stats)
{
	int param_type;

	assert(tasklet->state == FM_TASKLET_STATE_FREE);
	assert(host_task->probe_index < multiprobe->bucket_list.count);

	tasklet->state = FM_TASKLET_STATE_BUSY;
	tasklet->host = host_task;
	tasklet->probe_index = host_task->probe_index++;
	tasklet->timeout = fm_time_now();
	tasklet->send_retries = 3;
	tasklet->resp_required = 1;

	param_type = multiprobe->bucket_list.param_type;
	if (param_type != FM_PARAM_TYPE_NONE) {
		if (multiprobe->bucket_list.array == NULL)
			return false;

		tasklet->param_type = param_type;
		tasklet->param_value = fm_uint_array_get(multiprobe->bucket_list.array, tasklet->probe_index);

		switch (param_type) {
		case FM_PARAM_TYPE_PORT:
			asprintf(&tasklet->detail, "/port=%u", tasklet->param_value);
			break;
		case FM_PARAM_TYPE_TTL:
			asprintf(&tasklet->detail, "/ttl=%u", tasklet->param_value);
			break;
		case FM_PARAM_TYPE_TOS:
			asprintf(&tasklet->detail, "/tos=%u", tasklet->param_value);
			break;
		}
	}

	if (tasklet->detail == NULL)
		tasklet->detail = strdup("");

	debugmsg("%s: created probe #%u%s", host_task->name, tasklet->probe_index, tasklet->detail);

	return true;
}

static void
fm_fm_multiprobe_tasklet_add_extant(fm_tasklet_t *tasklet, fm_extant_t *extant)
{
	unsigned int k;

	for (k = 0; k < FM_TASKLET_MAX_PACKETS; ++k) {
		if (tasklet->extants[k] == NULL) {
			tasklet->extants[k] = extant;
			return;
		}
	}

	fm_log_fatal("too many extants in tasklet");
}

/*
 * Callback from the extant handling code.
 * We received some sort of response to our packet
 */
void
fm_tasklet_extant_done(fm_tasklet_t *tasklet, fm_extant_t *extant)
{
	unsigned int k;

	for (k = 0; k < FM_TASKLET_MAX_PACKETS; ++k) {
		if (tasklet->extants[k] == extant) {
			if (++(tasklet->resp_received) >= tasklet->resp_required) {
				/* We can stop now: */
				tasklet->state = FM_TASKLET_STATE_DONE;
				/* FIXME: wake up host task */
			}
			debugmsg("%s%s received reply", tasklet->host->name, tasklet->detail, tasklet->probe_index);
			tasklet->extants[k] = NULL;
			return;
		}
	}
}

/*
 * We're done with this tasklet, clean up
 */
static void
fm_tasklet_zap(fm_tasklet_t *tasklet)
{
	unsigned int k;

	for (k = 0; k < FM_TASKLET_MAX_PACKETS; ++k) {
		fm_extant_t *extant = tasklet->extants[k];

		if (extant != NULL)
			fm_extant_free(extant);
	}

	memset(tasklet, 0, sizeof(*tasklet));
	tasklet->state = FM_TASKLET_STATE_FREE;
}

static fm_error_t
fm_multiprobe_transmit_tasklet(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
		fm_tasklet_t *tasklet, fm_sched_stats_t *stats)
{
	fm_extant_t *extant = NULL;
	fm_error_t error;
	bool first_transmission;
	double timeout = 0;

	debugmsg("%s%s: transmit probe", host_task->name, tasklet->detail);
	first_transmission = !fm_timestamp_is_set(&tasklet->send_ts);

	error = multiprobe->ops->transmit(multiprobe, host_task,
				tasklet->param_type, tasklet->param_value,
				&extant, &timeout);

	if (extant != NULL) {
		if (first_transmission)
			fm_timestamp_init(&tasklet->send_ts);

		/* attach us to the extant */
		fm_fm_multiprobe_tasklet_add_extant(tasklet, extant);
		extant->tasklet = tasklet;
	}

	if (error == 0) {
		/* good */
		tasklet->send_retries -= 1;

		if (tasklet->send_retries)
			tasklet->timeout = fm_time_now() + multiprobe->timings.packet_spacing;
		else
			tasklet->timeout = fm_time_now() + multiprobe->timings.timeout;

		stats->num_sent += 1;
	} else if (error == FM_TRY_AGAIN) {
		/* the probe asked to be postponed... for now, warn about it */
		if (timeout == 0) {
			fm_log_warning("%s: probe returned TRY_AGAIN but timeout is 0", host_task->name);
			timeout = fm_time_now() + 1;
		}
		tasklet->timeout = timeout;
	} else
	if (first_transmission) {
		/* complain about probes that are so broken they don't even manage to
		 * send a single package. */
		fm_log_warning("%s%s: probe is DOA", host_task->name, tasklet->detail);
		tasklet->state = FM_TASKLET_STATE_DONE;
	}

	return error;
}

fm_error_t
fm_multiprobe_transmit_ttl_probe(fm_multiprobe_t *multiprobe, fm_target_control_t *target_control, unsigned int ttl, fm_extant_t **extant_ret, double *timeout_ret)
{
	fm_host_tasklet_t fake_host_task;
	fm_error_t error;

	assert(target_control->sock);

	fake_host_task.name = (char *) multiprobe->name;
	fake_host_task.control = *target_control;
	fake_host_task.target = target_control->target;

	debugmsg("%s%s/ttl=%u: transmit probe", multiprobe->name, target_control->target->id, ttl);
	error = multiprobe->ops->transmit(multiprobe, &fake_host_task,
				FM_PARAM_TYPE_TTL, ttl,
				extant_ret, timeout_ret);
	return error;
}

static bool
fm_multiprobe_transmit_tasklets(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_sched_stats_t *sched_stats)
{
	fm_tasklet_t *tasklet = host_task->tasklets;
	unsigned int k, num_busy = 0;
	fm_error_t error;
	double now, timeout = 0, throttle_timeout;

	now = fm_time_now();

	for (k = 0; k < host_task->num_tasks; ++k, ++tasklet) {
		if (tasklet->state == FM_TASKLET_STATE_DONE)
			fm_tasklet_zap(tasklet);

		if (tasklet->state == FM_TASKLET_STATE_FREE
		 && host_task->probe_index < multiprobe->bucket_list.count)
			fm_multiprobe_create_tasklet(multiprobe, host_task, tasklet, sched_stats);

		if (tasklet->state != FM_TASKLET_STATE_BUSY)
			continue;

		assert(tasklet->timeout != 0);
		num_busy += 1;

		if (tasklet->timeout <= now) {
			/* This tasklet is ready to proceed. */
			if (tasklet->send_retries == 0) {
				/* It's dead, Jim */
				debugmsg("%s%s timed out", host_task->name, tasklet->detail);
				tasklet->state = FM_TASKLET_STATE_DONE;
				continue;
			}

			/* FIXME why not a loop? */
			if (fm_ratelimit_available(&host_task->target->host_rate_limit)) {
				error = fm_multiprobe_transmit_tasklet(multiprobe, host_task, tasklet, sched_stats);
				if (error == 0) {
					fm_ratelimit_consume(&host_task->target->host_rate_limit, 1);
				}
			}
		}

		if (timeout == 0 || tasklet->timeout < timeout)
			timeout = tasklet->timeout;
	}

	throttle_timeout = now + fm_ratelimit_wait_until(&host_task->target->host_rate_limit, 1);
	if (timeout == 0 || throttle_timeout > timeout)
		timeout = throttle_timeout;

	host_task->timeout = timeout;

	debugmsg("%s: expires=%f (relative %f)", host_task->name, host_task->timeout, host_task->timeout - now);

	return num_busy == 0;
}

static double
fm_multiprobe_get_waiting_timeout(fm_multiprobe_t *multiprobe)
{
	hlist_iterator_t iter;
	fm_host_tasklet_t *host_task;
	double timeout = 0, now;

	now = fm_time_now();

	hlist_iterator_init(&iter, &multiprobe->waiting);
	while ((host_task = hlist_iterator_next(&iter)) != NULL) {
		if (host_task->timeout <= now) {
			hlist_remove(&host_task->link);
			hlist_insert(&multiprobe->ready, &host_task->link);
		} else
		if (timeout == 0 || host_task->timeout < timeout)
			timeout = host_task->timeout;
	}

	return timeout;
}

bool
fm_multiprobe_is_idle(const fm_multiprobe_t *multiprobe)
{
	return hlist_is_empty(&multiprobe->ready) && hlist_is_empty(&multiprobe->waiting);
}

void
fm_multiprobe_transmit(fm_multiprobe_t *multiprobe, fm_sched_stats_t *sched_stats)
{
	double timeout = 0;
	fm_host_tasklet_t *host_task;

	timeout = fm_multiprobe_get_waiting_timeout(multiprobe);

	while ((host_task = hlist_head_get_first(&multiprobe->ready)) != NULL) {
		bool done;

		done = fm_multiprobe_transmit_tasklets(multiprobe, host_task, sched_stats);

		hlist_remove(&host_task->link);

		if (done) {
			debugmsg("%s is complete", host_task->name);
			hlist_insert(&multiprobe->done, &host_task->link);
			continue;
		}

		assert(host_task->timeout != 0);

		if (timeout == 0 || host_task->timeout < timeout)
			timeout = host_task->timeout;

		hlist_insert(&multiprobe->waiting, &host_task->link);
	}

	multiprobe->job.expires = timeout;
}

/*
 * Loop over completed host tasklets and return the subject target.
 * This is used by the target manager to remove completed targets from the pool
 */
fm_target_t *
fm_multiprobe_get_completed(fm_multiprobe_t *multiprobe)
{
	fm_host_tasklet_t *host_task;

	if ((host_task = hlist_head_get_first(&multiprobe->done)) != NULL) {
		fm_target_t *target = host_task->target;

		fm_host_tasklet_free(host_task);
		return target;
	}

	return NULL;
}

/*
 * Tracking of extant requests per probe - will go away at some point
 */
fm_extant_t *
fm_extant_alloc(fm_probe_t *probe, int af, int ipproto, const void *payload, size_t payload_size)
{
	fm_target_t *target;

	if ((target = probe->_target) == NULL) {
		/* Dont do that */
		fm_log_warning("%s: cannot allocate an extant because the probe is not associated with a specific target",
				fm_probe_name(probe));
		return NULL;
	}

	return fm_extant_alloc_list(probe, af, ipproto, payload, payload_size, &target->expecting);
}
