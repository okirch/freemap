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

#define FM_PRINTF_DECORATOR __attribute__ ((format (printf, 1, 2)))

extern void		fm_set_logfile(FILE *fp);
extern void		fm_trace(const char *fmt, ...) FM_PRINTF_DECORATOR;
extern void		fm_log_fatal(const char *fmt, ...) FM_PRINTF_DECORATOR;
extern void		fm_log_error(const char *fmt, ...) FM_PRINTF_DECORATOR;
extern void		fm_log_warning(const char *fmt, ...) FM_PRINTF_DECORATOR;
extern void		fm_log_notice(const char *fmt, ...) FM_PRINTF_DECORATOR;
extern bool		fm_enable_debug_facility(const char *);

#define FM_DEBUG_FACILITY_SCHEDULER		0x00000001
#define FM_DEBUG_FACILITY_PROBE			0x00000002
#define FM_DEBUG_FACILITY_PACKET		0x00000004
#define FM_DEBUG_FACILITY_ADDRPOOL		0x00000008
#define FM_DEBUG_FACILITY_DATA			0x00000010

extern unsigned int	fm_debug_level;
extern unsigned long	fm_debug_facilities;

#define fm_log_debug(fmt ...) do { \
		if (fm_debug_level > 0) fm_trace(fmt); \
	} while (0)

#define fm_debug_scheduler(fmt ...) do { \
		if (fm_debug_facilities & FM_DEBUG_FACILITY_SCHEDULER) fm_trace(fmt); \
	} while (0)
#define fm_debug_probe(fmt ...) do { \
		if (fm_debug_facilities & FM_DEBUG_FACILITY_PROBE) fm_trace(fmt); \
	} while (0)
#define fm_debug_packet(fmt ...) do { \
		if (fm_debug_facilities & FM_DEBUG_FACILITY_PACKET) fm_trace(fmt); \
	} while (0)
#define fm_debug_addrpool(fmt ...) do { \
		if (fm_debug_facilities & FM_DEBUG_FACILITY_ADDRPOOL) fm_trace(fmt); \
	} while (0)
#define fm_debug_data(fmt ...) do { \
		if (fm_debug_facilities & FM_DEBUG_FACILITY_DATA) fm_trace(fmt); \
	} while (0)

#endif /* FREEMAP_LOGGING_H */
