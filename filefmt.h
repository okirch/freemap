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

#ifndef FREEMAP_FILEFMT_H
#define FREEMAP_FILEFMT_H

#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>

#include "freemap.h"
#include "program.h"
#include "scanner.h"

struct file_scanner;


extern struct file_scanner *	file_scanner_open(const char *path);
extern void			file_scanner_close(struct file_scanner *fs);
extern void			file_scanner_free(struct file_scanner *fs);
extern bool			file_scanner_error(struct file_scanner *fs, const char *fmt, ...);
extern char *			file_scanner_next_entry(struct file_scanner *fs);
extern char *			file_scanner_continue_entry(struct file_scanner *fs);
extern bool			file_scanner_has_error(const struct file_scanner *fs);

#endif /* FREEMAP_FILEFMT_H */
