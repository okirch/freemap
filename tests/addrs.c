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
#include "scanner.h"
#include "addresses.h"
#include "target.h"

static void
render_generated_addresses(fm_target_manager_t *mgr)
{
	fm_address_enumerator_array_t *array = &mgr->address_generators;
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		fm_address_enumerator_t *agen = array->entries[i];
		fm_address_t addr;
		fm_error_t error;

		printf("Using address generator %s\n", fm_address_enumerator_name(agen));
		while (true) {
			error = fm_address_enumerator_get_one(agen, &addr);
			if (error < 0)
				break;
			printf("  %s\n", fm_address_format(&addr));
		}
	}

	/* fm_target_manager_free(mgr); */
}

static void
render_all(const char *spec)
{
	static unsigned int run = 0;
	fm_scanner_t dummy;

	dummy.target_manager = fm_target_manager_create();

	printf("RUN%u\n", run++);
	if (!fm_scanner_add_target_from_spec(&dummy, spec)) {
		printf("FAIL: cannot parse addr spec");
		return;
	}

	render_generated_addresses(dummy.target_manager);
}

int
main(int argc, char **argv)
{
	render_all("192.168.1.1");
	render_all("192.168.1.0/24");

	/* Note that the host part of this addr is not zero. The generator
	 * should generate addresses starting from .129 */
	render_all("192.168.1.131/26");
	return 0;
}
