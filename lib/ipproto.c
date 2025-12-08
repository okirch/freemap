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
 * Scanning for IP protocols
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "scanner.h"
#include "protocols.h"
#include "target.h"
#include "socket.h"
#include "services.h"
#include "probe_private.h"
#include "rawip.h"
#include "logging.h"
#include "buffer.h"

typedef struct fm_ipproto_control {
	fm_protocol_t *		proto;

	fm_socket_t *		sock;

	fm_ip_header_info_t	ip_info;

	struct {
		const unsigned char *	data;
		unsigned int		len;
	} payload;
} fm_ipproto_control_t;

/*
 * rawip action
 */
static void
fm_ipproto_control_free(fm_ipproto_control_t *control)
{
	if (control->sock != NULL)
		fm_socket_release(control->sock);

	control->sock = NULL;
	free(control);
}

static fm_ipproto_control_t *
fm_ipproto_control_alloc(fm_protocol_t *proto)
{
	static const unsigned char empty_dummy[64] = {};
	fm_ipproto_control_t *control;

	control = calloc(1, sizeof(*control));
	control->proto = proto;

	control->ip_info.ipproto = 66;
	control->ip_info.ttl = 64;
	control->ip_info.tos = 0;

	control->payload.data = empty_dummy;
	control->payload.len = sizeof(empty_dummy);

	return control;
}

/*
 * Initialize protocol-specific part of target control.
 * When we get here, most of the generic members have already been set.
 */
static bool
fm_ipproto_control_init_target(const fm_ipproto_control_t *control, fm_target_control_t *target_control, fm_target_t *target)
{
	fm_socket_t *sock = NULL;

	sock = fm_rawip_create_shared_socket(target, control->ip_info.ipproto);
	if (sock == NULL)
		return false;

	target_control->sock = sock;

	target_control->ip_info = control->ip_info;
	target_control->ip_info.src_addr = target_control->src_addr;
	target_control->ip_info.dst_addr = target_control->dst_addr;

	return true;
}

/*
 * Build the packet.
 */
static fm_pkt_t *
fm_ipproto_build_packet(const fm_ipproto_control_t *control, fm_target_control_t *target_control,
		const fm_ip_header_info_t *ip_info)
{
	fm_pkt_t *pkt;

	pkt = fm_pkt_alloc(target_control->family, 256);
	fm_pkt_set_peer_address_raw(pkt, &target_control->dst_addr, control->ip_info.ipproto);

	if (!fm_raw_packet_add_ip_header(pkt->payload, ip_info, control->payload.len)
	 || !fm_buffer_append(pkt->payload, control->payload.data, control->payload.len)) {
		fm_pkt_free(pkt);
		return NULL;
	}

	return pkt;
}

/*
 * Send the control request.
 * The probe argument is only here because we need to notify it when done.
 */
static fm_error_t
fm_ipproto_request_send(const fm_ipproto_control_t *control, fm_target_control_t *target_control, int param_type, int param_value,
		const fm_buffer_t *application_payload,
		fm_extant_t **extant_ret)
{
	fm_rawip_extant_info_t extant_info;
	const fm_ip_header_info_t *ip_info;
	fm_target_t *target = target_control->target;
	fm_socket_t *sock;
	fm_pkt_t *pkt;
	fm_error_t err;

	ip_info = fm_ip_header_info_finalize(&target_control->ip_info, param_type, param_value);

	sock = target_control->sock;
	if (sock == NULL) {
		fm_log_error("Unable to create rawip socket for %s: %m", target->id);
		return FM_SEND_ERROR;
	}

	pkt = fm_ipproto_build_packet(control, target_control, ip_info);

	err = fm_socket_send_pkt_and_burn(sock, pkt);
	if (err < 0) {
		fm_log_error("Unable to send rawip packet: %m");
		return FM_SEND_ERROR;
	}

	fm_rawip_extant_info_build(ip_info->ipproto, &extant_info);
	*extant_ret = fm_socket_add_extant(sock, target->host_asset,
			target_control->family, ip_info->ipproto,
			&extant_info, sizeof(extant_info));

	assert(*extant_ret);

	/* update the asset state */
	fm_target_update_host_state(target, FM_PROTO_IP, FM_ASSET_STATE_PROBE_SENT);

	return 0;
}

/*
 * New multiprobe implementation
 */
static bool
fm_ipproto_multiprobe_add_target(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task, fm_target_t *target)
{
	const fm_ipproto_control_t *control = multiprobe->control;

	return fm_ipproto_control_init_target(control, &host_task->control, target);
}

static fm_error_t
fm_ipproto_multiprobe_transmit(fm_multiprobe_t *multiprobe, fm_host_tasklet_t *host_task,
		int param_type, int param_value,
		const fm_buffer_t *application_payload,
		fm_extant_t **extant_ret, double *timeout_ret)
{
	const fm_ipproto_control_t *control = multiprobe->control;

	return fm_ipproto_request_send(control, &host_task->control,
			param_type, param_value,
			application_payload, extant_ret);
}

static void
fm_ipproto_multiprobe_destroy(fm_multiprobe_t *multiprobe)
{
	fm_ipproto_control_t *control = multiprobe->control;

	multiprobe->control = NULL;
	fm_ipproto_control_free(control);
}

static fm_multiprobe_ops_t	fm_ipproto_multiprobe_ops = {
	.add_target		= fm_ipproto_multiprobe_add_target,
	.transmit		= fm_ipproto_multiprobe_transmit,
	.destroy		= fm_ipproto_multiprobe_destroy,
};

static bool
fm_ipproto_configure_probe(const fm_probe_class_t *pclass, fm_multiprobe_t *multiprobe, const fm_string_array_t *extra_args)
{
	fm_ipproto_control_t *control;
	unsigned int i;

	if (multiprobe->control != NULL) {
		fm_log_error("cannot reconfigure probe %s", multiprobe->name);
		return false;
	}

	/* Set the default timings and retries */
	multiprobe->timings.packet_spacing = fm_global.rawip.packet_spacing * 1e-3;
	multiprobe->timings.timeout = fm_global.rawip.timeout * 1e-3;
	if (multiprobe->params.retries == 0)
		multiprobe->params.retries = fm_global.rawip.retries;

	control = fm_ipproto_control_alloc(pclass->proto);
	if (control == NULL)
		return false;

	/* process extra_args if given */
	for (i = 0; i < extra_args->count; ++i) {
		const char *arg = extra_args->entries[i];

#ifdef notyet
		if (!strncmp(arg, "rawip-", 6) && fm_rawip_process_config_arg(&control->udp_info, arg))
			continue;
#endif

		if (!strncmp(arg, "ip-", 3) && fm_ip_process_config_arg(&control->ip_info, arg))
			continue;

		fm_log_error("%s: unsupported or invalid option %s", multiprobe->name, arg);
		return false;
	}

	multiprobe->ops = &fm_ipproto_multiprobe_ops;
	multiprobe->control = control;
	return true;
}

static struct fm_probe_class fm_ipproto_port_probe_class = {
	.name		= "ipproto",
	.proto_id	= FM_PROTO_NONE,
	.modes		= FM_PROBE_MODE_TOPO|FM_PROBE_MODE_HOST,
	.configure	= fm_ipproto_configure_probe,
};

FM_PROBE_CLASS_REGISTER(fm_ipproto_port_probe_class)
