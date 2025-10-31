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

static FILE *	fm_log_file = NULL;

unsigned int	fm_debug_level = 0;

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

void
fm_trace(const char *fmt, ...)
{
	FILE *fp = fm_logfp();
	va_list ap;

	va_start(ap, fmt);
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
	fprintf(fp, "FATAL: ");
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
	fprintf(fp, "Error: ");
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
	fprintf(fp, "Warning: ");
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
