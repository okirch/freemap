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
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include "freemap.h"
#include "utils.h"

void
fm_fact_log_append(fm_fact_log_t *log, fm_fact_t *fact)
{
	static const unsigned int chunk = 10;

	if ((log->count % chunk) == 0) {
		log->entries = realloc(log->entries, (log->count + chunk) * sizeof(log->entries[0]));
		assert(log->entries != NULL);
	}

	log->entries[log->count++] = fact;
}

void
fm_fact_log_destroy(fm_fact_log_t *log)
{
	unsigned int i;

	for (i = 0; i < log->count; ++i)
		fm_fact_free(log->entries[i]);

	free(log->entries);
	memset(log, 0, sizeof(*log));
}

fm_fact_t *
fm_fact_create(const struct fm_fact_ops *ops, fm_fact_type_t type)
{
	fm_fact_t *fact;

	fact = calloc(1, ops->obj_size);
	fact->type = type;
	fact->ops = ops;
	return fact;
}

void
fm_fact_free(fm_fact_t *fact)
{
	if (fact->ops->destroy)
		fact->ops->destroy(fact);
	memset(fact, 0, sizeof(*fact));
	free(fact);
}

const char *
fm_fact_type_to_string(fm_fact_type_t type)
{
	switch (type) {
	case FM_FACT_NONE:
		return "<no status>";

	case FM_FACT_SEND_ERROR:
		return "could not send probe";

	case FM_FACT_PROBE_TIMED_OUT:
		return "timeout";

	case FM_FACT_HOST_REACHABLE:
		return "host reachable";

	case FM_FACT_HOST_UNREACHABLE:
		return "host unreachable";

	case FM_FACT_PORT_REACHABLE:
		return "port open";

	case FM_FACT_PORT_UNREACHABLE:
		return "port closed";

	case FM_FACT_PORT_HEISENBERG:
		return "port in heisenberg state";

	case FM_FACT_PORT_MAYBE_REACHABLE:
		return "port maybe reachable";
	}
	return "<bad status>";
}

const char *
fm_fact_render(const fm_fact_t *fact)
{
	static char msgbuf[256];

	if (fact->elapsed) {
		snprintf(msgbuf, sizeof(msgbuf), "%s: %s (%.2f msec)",
				fact->ops->render(fact),
				fm_fact_type_to_string(fact->type),
				1000 * fact->elapsed);
	} else {
		snprintf(msgbuf, sizeof(msgbuf), "%s: %s",
				fact->ops->render(fact),
				fm_fact_type_to_string(fact->type));
	}

	return msgbuf;
}

bool
fm_fact_check_protocol(const fm_fact_t *fact, const char *protocol_id)
{
	if (fact->ops->check_protocol == NULL)
		return false;
	return fact->ops->check_protocol(fact, protocol_id);
}

/*
 * Port reachability
 */
struct fm_fact_port_status {
	fm_fact_t	base;
	const char *	proto;
	unsigned int	port;
};

static const char *
fm_fact_port_status_render(const fm_fact_t *fact)
{
	struct fm_fact_port_status *error = (struct fm_fact_port_status *) fact;
	static char msgbuf[64];

	if (error->port == 0)
		return error->proto;

	snprintf(msgbuf, sizeof(msgbuf), "%u/%s", error->port, error->proto);
	return msgbuf;
}

static bool
fm_fact_port_status_check_protocol(const fm_fact_t *fact, const char *protocol_id)
{
	struct fm_fact_port_status *error = (struct fm_fact_port_status *) fact;

	if (error->proto == NULL || protocol_id == NULL)
		return false;
	return strcmp(error->proto, protocol_id) == 0;
}

static const struct fm_fact_ops fm_fact_port_status_ops = {
	.obj_size	= sizeof(struct fm_fact_port_status),
	.render		= fm_fact_port_status_render,
	.check_protocol	= fm_fact_port_status_check_protocol,
};

static fm_fact_t *
fm_fact_create_port_status(fm_fact_type_t type, const char *proto_id, unsigned int port)
{
	struct fm_fact_port_status *error;

	error = (struct fm_fact_port_status *) fm_fact_create(&fm_fact_port_status_ops, type);

	error->proto = proto_id;
	error->port = port;

	return &error->base;
}

fm_fact_t *
fm_fact_create_host_reachable(const char *proto_id)
{
	return fm_fact_create_port_status(FM_FACT_HOST_REACHABLE, proto_id, 0);
}

fm_fact_t *
fm_fact_create_host_unreachable(const char *proto_id)
{
	return fm_fact_create_port_status(FM_FACT_HOST_UNREACHABLE, proto_id, 0);
}

fm_fact_t *
fm_fact_create_port_reachable(const char *proto_id, unsigned int port)
{
	return fm_fact_create_port_status(FM_FACT_PORT_REACHABLE, proto_id, port);
}

fm_fact_t *
fm_fact_create_port_unreachable(const char *proto_id, unsigned int port)
{
	return fm_fact_create_port_status(FM_FACT_PORT_UNREACHABLE, proto_id, port);
}

fm_fact_t *
fm_fact_create_port_heisenberg(const char *proto_id, unsigned int port)
{
	return fm_fact_create_port_status(FM_FACT_PORT_HEISENBERG, proto_id, port);
}

/*
 * Error messages
 */
struct fm_fact_error {
	fm_fact_t	base;
	char *		message;
};

static void
fm_fact_error_destroy(fm_fact_t *fact)
{
	struct fm_fact_error *error = (struct fm_fact_error *) fact;

	drop_string(&error->message);
}

static const char *
fm_fact_error_render(const fm_fact_t *fact)
{
	struct fm_fact_error *error = (struct fm_fact_error *) fact;

	return error->message;
}

static const struct fm_fact_ops fm_fact_error_ops = {
	.obj_size	= sizeof(struct fm_fact_error),
	.destroy	= fm_fact_error_destroy,
	.render		= fm_fact_error_render,
};

extern fm_fact_t *
fm_fact_create_error(fm_fact_type_t type, const char *fmt, ...)
{
	struct fm_fact_error *error;
	va_list ap;

	error = (struct fm_fact_error *) fm_fact_create(&fm_fact_error_ops, type);

	va_start(ap, fmt);
	vasprintf(&error->message, fmt, ap);
	va_end(ap);

	return &error->base;
}

