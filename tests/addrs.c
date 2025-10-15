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
#include "freemap.h"

static void
render_all(fm_address_enumerator_t *agen)
{
	static unsigned int run = 0;
	fm_address_t addr;

	printf("RUN%u %s\n", run++, fm_address_enumerator_name(agen));
	while (fm_address_enumerator_get_one(agen, &addr)) {
		printf("  %s\n", fm_address_format(&addr));
	}

	fm_address_enumerator_destroy(agen);
}

int
main(int argc, char **argv)
{
	render_all(fm_create_simple_address_enumerator("192.168.1.1"));
	render_all(fm_create_cidr_address_enumerator("192.168.1.0/24"));

	/* Note that the host part of this addr is not zero. The generator
	 * should generate addresses starting from .129 */
	render_all(fm_create_cidr_address_enumerator("192.168.1.131/26"));
	return 0;
}
