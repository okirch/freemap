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

#ifndef FREEMAP_COMMANDS_H
#define FREEMAP_COMMANDS_H

#include "subcommand.h"

enum {
	FM_CMDID_MAIN = 1,
	FM_CMDID_SCAN,
};

enum {
	OPT_PROGRAM,
	OPT_DUMP,
	OPT_IPV4_ONLY,
	OPT_IPV6_ONLY,
	OPT_ALL_ADDRS,
};

extern void	fm_command_register_scan(fm_cmdparser_t *);
extern int	fm_command_perform_scan(fm_command_t *);

#endif /* FREEMAP_COMMANDS_H */
