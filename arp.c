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

#include "freemap.h"
#include <linux/if_arp.h>

const char *
fm_arp_type_to_string(int hatype)
{
	static char buf[16];

	switch (hatype) {
	case ARPHRD_ETHER:
		return "ether";
	case ARPHRD_LOOPBACK:
		return "loopback";
	case ARPHRD_TUNNEL:
		return "tunnel";
	}

	snprintf(buf, sizeof(buf), "arp%u", hatype);
	return buf;
}

