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
 * Simple UDP scanning functions
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>

#include "freemap.h"
#include "target.h"

typedef struct fm_report_sink fm_report_sink_t;

struct fm_report_sink {
	const struct fm_report_sink_ops {
		size_t	obj_size;
		void	(*write)(fm_report_sink_t *, const fm_target_t *);
		void	(*destroy)(fm_report_sink_t *);
		void	(*flush)(fm_report_sink_t *);
	} *ops;
};

struct fm_report_sink_array {
	unsigned int	count;
	fm_report_sink_t **sink;
};

struct fm_report {
	fm_report_sink_t *	stdio;
	struct fm_report_sink_array other;
};

static void			fm_report_sink_write(fm_report_sink_t *, const fm_target_t *);
static void			fm_report_sink_flush(fm_report_sink_t *);
static void			fm_report_sink_free(fm_report_sink_t *);
static fm_report_sink_t	*	fm_report_create_stdio_sink(void);
static fm_report_sink_t	*	fm_report_create_logfile_sink(const char *);

static void			fm_report_sink_array_append(struct fm_report_sink_array *, fm_report_sink_t *);
static void			fm_report_sink_array_destroy(struct fm_report_sink_array *);

fm_report_t *
fm_report_create(void)
{
	fm_report_t *report;

	report = calloc(1, sizeof(*report));
	report->stdio = fm_report_create_stdio_sink();
	return report;
}

bool
fm_report_add_logfile(fm_report_t *report, const char *path)
{
	fm_report_sink_t *sink;

	sink = fm_report_create_logfile_sink(path);
	if (sink == NULL)
		return false;

	fm_report_sink_array_append(&report->other, sink);
	return true;
}

void
fm_report_write(const fm_report_t *report, const fm_target_t *target)
{
	unsigned int i;

	if (report->stdio != NULL)
		fm_report_sink_write(report->stdio, target);

	for (i = 0; i < report->other.count; ++i) {
		fm_report_sink_t *sink = report->other.sink[i];

		fm_report_sink_write(sink, target);
	}
}

void
fm_report_flush(fm_report_t *report)
{
	unsigned int i;

	if (report->stdio != NULL)
		fm_report_sink_flush(report->stdio);

	for (i = 0; i < report->other.count; ++i) {
		fm_report_sink_t *sink = report->other.sink[i];

		fm_report_sink_flush(sink);
	}
}

void
fm_report_free(fm_report_t *report)
{
	if (report->stdio != NULL)
		fm_report_sink_flush(report->stdio);

	fm_report_sink_array_destroy(&report->other);
	free(report);
}

static const char *
fm_report_asset_state(fm_asset_state_t state)
{
	switch (state) {
	case FM_ASSET_STATE_UNDEF:
		return "undefined";

	case FM_ASSET_STATE_PROBE_SENT:
		return "noresponse";

	case FM_ASSET_STATE_CLOSED:
		return "unreachable";

	case FM_ASSET_STATE_OPEN:
		return "open";
	}
	return "BAD";
}

/*
 * Functions for report sinks
 */
static fm_report_sink_t *
fm_report_sink_create(const struct fm_report_sink_ops *ops)
{
	fm_report_sink_t *sink;

	assert(ops->write != NULL);

	sink = calloc(1, ops->obj_size);
	sink->ops = ops;
	return sink;
}

static void
fm_report_sink_free(fm_report_sink_t *sink)
{
	if (sink->ops->destroy)
		sink->ops->destroy(sink);
	free(sink);
}

static void
fm_report_sink_write(fm_report_sink_t *sink, const fm_target_t *target)
{
	sink->ops->write(sink, target);
}

void
fm_report_sink_flush(fm_report_sink_t *sink)
{
	if (sink->ops->flush != NULL)
		sink->ops->flush(sink);
}

/*
 * sink arrays
 */
void
fm_report_sink_array_append(struct fm_report_sink_array *array, fm_report_sink_t *sink)
{
	array->sink = realloc(array->sink, (array->count + 1) * sizeof(array->sink[0]));
	array->sink[array->count++] = sink;
}

void
fm_report_sink_array_destroy(struct fm_report_sink_array *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i)
		fm_report_sink_free(array->sink[i]);
	if (array->sink)
		free(array->sink);
}

/*
 * Write target results to some stdio file
 */
struct fm_file_sink_callback_data {
	unsigned int num_ports;
	FILE *fp;
};
static bool
fm_file_sink_port_callback(const fm_host_asset_t *host, const char *proto, unsigned int port, fm_asset_state_t state, void *user_data)
{
	struct fm_file_sink_callback_data *data = user_data;

	fprintf(data->fp, "   %s/%u %s\n", proto, port, fm_report_asset_state(state));
	data->num_ports += 1;
	return true;
}

static void
fm_file_sink_write(fm_report_sink_t *sink, const fm_target_t *target, FILE *fp)
{
	struct fm_file_sink_callback_data callback_data = { 0 };
	fm_host_asset_t *host;
	fm_asset_state_t state;

	if ((host = target->host_asset) == NULL) {
		fprintf(fp, "== %s ==\n", fm_address_format(&target->address));
		fprintf(fp, "   No assets recorded\n");
		return;
	}

	state = fm_host_asset_get_state(host);
	if (state == FM_ASSET_STATE_UNDEF)
		return;

	fprintf(fp, "== %s ==\n", fm_address_format(&target->address));
	fprintf(fp, "   host: %s\n", fm_report_asset_state(state));

	callback_data.fp = fp;
	fm_host_asset_report_ports(host, fm_file_sink_port_callback, &callback_data);

	if (callback_data.num_ports == 0)
		fprintf(fp, "   (no port scan results)\n");

	fprintf(fp, "\n");
}


/*
 * stdout sink
 */
static void
fm_stdio_sink_write(fm_report_sink_t *sink, const fm_target_t *target)
{
	fm_file_sink_write(sink, target, stdout);
}

static struct fm_report_sink_ops fm_stdio_sink_ops = {
	.obj_size = sizeof(fm_report_sink_t),
	.write	= fm_stdio_sink_write,
};

fm_report_sink_t *
fm_report_create_stdio_sink(void)
{
	return fm_report_sink_create(&fm_stdio_sink_ops);
}

/*
 * plain logfile
 */
struct fm_logfile_sink {
	fm_report_sink_t base;

	FILE		*fp;
};

static void
fm_logfile_sink_write(fm_report_sink_t *sink, const fm_target_t *target)
{
	struct fm_logfile_sink *lf = (struct fm_logfile_sink *) sink;

	fm_file_sink_write(sink, target, lf->fp);
}

static void
fm_logfile_sink_flush(fm_report_sink_t *sink)
{
	struct fm_logfile_sink *lf = (struct fm_logfile_sink *) sink;

	fflush(lf->fp);
}

static void
fm_logfile_sink_destroy(fm_report_sink_t *sink)
{
	struct fm_logfile_sink *lf = (struct fm_logfile_sink *) sink;

	if (lf->fp != NULL) {
		fclose(lf->fp);
		lf->fp = NULL;
	}
}

static struct fm_report_sink_ops fm_logfile_sink_ops = {
	.obj_size = sizeof(struct fm_logfile_sink),
	.write = fm_logfile_sink_write,
	.flush = fm_logfile_sink_flush,
	.destroy = fm_logfile_sink_destroy,
};

fm_report_sink_t *
fm_report_create_logfile_sink(const char *path)
{
	struct fm_logfile_sink *sink;
	FILE *fp;

	if (!(fp = fopen(path, "w")))
		return NULL;

	sink = (struct fm_logfile_sink *) fm_report_sink_create(&fm_logfile_sink_ops);
	sink->fp = fp;

	return &sink->base;
}
