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

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>

#include "freemap.h"
#include "logging.h"

static FILE *	fm_log_file = NULL;

unsigned int	fm_debug_level = 0;
unsigned long	fm_debug_facilities = 0;

void
fm_set_logfile(FILE *fp)
{
	if (fm_log_file)
		fclose(fm_log_file);
	fm_log_file = fp;
}

static inline FILE *
fm_logfp(void)
{
	return fm_log_file?: stderr;
}

static const char *
fm_timestamp_string(void)
{
	static double t0 = 0;
	static char buffer[32];
	double dt;

	if (t0 == 0)
		t0 = fm_time_now();

	dt = fm_time_now() - t0;

	snprintf(buffer, sizeof(buffer), "[%02u:%02u:%02u.%03u]",
			(unsigned int) (dt / 3600),
			(unsigned int) (dt / 60) % 60,
			(unsigned int) dt % 60,
			(unsigned int) (dt * 1000) % 1000);

	return buffer;
}

void
fm_trace(const char *fmt, ...)
{
	FILE *fp = fm_logfp();
	va_list ap;

	va_start(ap, fmt);
	fprintf(fp, "%s: ", fm_timestamp_string());
	vfprintf(fp, fmt, ap);
	if (strchr(fmt, '\n') == NULL)
		fputc('\n', fp);
	va_end(ap);
}

void
fm_log_fatal(const char *fmt, ...)
{
	FILE *fp = fm_logfp();
	va_list ap;

	va_start(ap, fmt);
	fprintf(fp, "%s: FATAL: ", fm_timestamp_string());
	vfprintf(fp, fmt, ap);
	if (strchr(fmt, '\n') == NULL)
		fputc('\n', fp);
	va_end(ap);

	exit(1);
}

void
fm_log_error(const char *fmt, ...)
{
	FILE *fp = fm_logfp();
	va_list ap;

	va_start(ap, fmt);
	fprintf(fp, "%s: Error: ", fm_timestamp_string());
	vfprintf(fp, fmt, ap);
	if (strchr(fmt, '\n') == NULL)
		fputc('\n', fp);
	va_end(ap);
}

void
fm_log_warning(const char *fmt, ...)
{
	FILE *fp = fm_logfp();
	va_list ap;

	va_start(ap, fmt);
	fprintf(fp, "%s: Warning: ", fm_timestamp_string());
	vfprintf(fp, fmt, ap);
	if (strchr(fmt, '\n') == NULL)
		fputc('\n', fp);
	va_end(ap);
}

void
fm_log_notice(const char *fmt, ...)
{
	FILE *fp = fm_logfp();
	va_list ap;

	fprintf(fp, "%s: ", fm_timestamp_string());
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	if (strchr(fmt, '\n') == NULL)
		fputc('\n', fp);
	va_end(ap);
}

#define FM_MAX_ERROR_INDEX 18 /* for now */
static const char *strings[FM_MAX_ERROR_INDEX] = {
	[0] = "Succcess",
	[-FM_SEND_ERROR] = "Unable to send packet",
	[-FM_TIMED_OUT] = "Timed out",
	[-FM_TRY_AGAIN] = "Try again",
	[-FM_NOT_SUPPORTED] = "Not supported",
	[-FM_NO_ROUTE_TO_HOST] = "No route to host",
	[-FM_TASK_COMPLETE] = "Probe task complete",
	[-FM_THROTTLE_SEND_RATE] = "Going to fast, slow down with those packets",
};

const char *
fm_strerror(fm_error_t error)
{
	static char msgbuf[64];
	const char *ret = NULL;
	int index;

	index = -error;
	if (index >= 0 && index < FM_MAX_ERROR_INDEX)
		ret = strings[index];

	if (ret == NULL) {
		snprintf(msgbuf, sizeof(msgbuf), "Invalid error code %d", error);
		ret = msgbuf;
	}

	return ret;
}

/*
 * Enable debug facility
 * Prefix matching is supported, but it must be unique (you cannot use "p" to enable
 * both packet and probe tracing).
 */
static unsigned long
fm_debug_facility_name_to_mask(const char *name)
{
	static struct {
		const char *	name;
		unsigned long	mask;
	} map[] = {
		{ "scheduler",	FM_DEBUG_FACILITY_SCHEDULER },
		{ "probe",	FM_DEBUG_FACILITY_PROBE },
		{ "packet",	FM_DEBUG_FACILITY_PACKET },
		{ "addrpool",	FM_DEBUG_FACILITY_ADDRPOOL },
		{ "data",	FM_DEBUG_FACILITY_DATA },
		{ NULL }
	};
	unsigned int i, len;
	unsigned long mask = 0;

	if (!strcmp(name, "all"))
		return ~0UL;

	if (!strcmp(name, "list")) {
		printf("List of supported debug facilities:\n");
		for (i = 0; map[i].name; ++i)
			printf("   %s\n", map[i].name);
		exit(0);
	}

	len = strlen(name);
	for (i = 0; map[i].name; ++i) {
		if (!strncmp(map[i].name, name, len))
			mask |= map[i].mask;
	}

	if (mask == 0) {
		fm_log_error("Unknown debug facility \"%s\"", name);
	} else
	if (mask & (mask - 1)) {
		/* more than one bit set -> ambiguous */
		fm_log_error("Ambiguous debug facility name \"%s\"", name);
		mask = 0;
	}

	return mask;
}

bool
fm_enable_debug_facility(const char *name)
{
	unsigned long mask;

	if (!(mask = fm_debug_facility_name_to_mask(name)))
		return false;

	fm_debug_facilities |= mask;
	return true;
}
