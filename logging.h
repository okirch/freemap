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

#ifndef FREEMAP_LOGGING_H
#define FREEMAP_LOGGING_H

#include "freemap.h"


extern void		fm_set_logfile(FILE *fp);
extern void		fm_trace(const char *fmt, ...);
extern void		fm_log_fatal(const char *fmt, ...);
extern void		fm_log_error(const char *fmt, ...);
extern void		fm_log_warning(const char *fmt, ...);
extern void		fm_log_notice(const char *fmt, ...);

extern unsigned int	fm_debug_level;

#define fm_log_debug(fmt ...) do { \
		if (fm_debug_level > 0) fm_trace(fmt); \
	} while (0)

#endif /* FREEMAP_LOGGING_H */
