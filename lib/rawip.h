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

#ifndef FREEMAP_RAWIP_H
#define FREEMAP_RAWIP_H

#include "rawpacket.h"

typedef struct fm_rawip_extant_info {
	int		ipproto;
	/* maybe add function pointer to implement proto specific checks */
} fm_rawip_extant_info_t;

extern void		fm_rawip_extant_info_build(int ipproto, fm_rawip_extant_info_t *extant_info);
extern fm_socket_t *	fm_rawip_create_shared_socket(fm_target_t *target, int ipproto);

#endif /* FREEMAP_RAWIP_H */
