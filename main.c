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

#include <string.h>
#include <stdio.h>
#include <mcheck.h>

#include "freemap.h"
#include "scanner.h"

int
main(int argc, char **argv)
{
	fm_scanner_t *scanner;
	fm_target_manager_t *mgr;

#if 1
	if (mcheck_pedantic(NULL) < 0)
		printf("Tried but failed to enable pedantic memory checking\n");
#endif

	scanner = fm_scanner_create();

	mgr = scanner->target_manager;

#if 0
	fm_target_manager_add_address_generator(mgr, 
			fm_create_cidr_address_enumerator("192.168.178.0/24"));
#else
	fm_target_manager_add_address_generator(mgr, 
			fm_create_simple_address_enumerator("192.168.178.1"));
	fm_target_manager_add_address_generator(mgr, 
			fm_create_simple_address_enumerator("192.168.178.93"));
	fm_target_manager_add_address_generator(mgr, 
			fm_create_simple_address_enumerator("192.168.178.162"));
#endif
	fm_target_manager_add_address_generator(mgr, 
			fm_create_simple_address_enumerator("192.168.172.1"));
	fm_target_manager_add_address_generator(mgr, 
			fm_create_simple_address_enumerator("52.28.168.184"));

	fm_scanner_add_host_reachability_check(scanner, "icmp", true);
	fm_scanner_add_single_port_scan(scanner, "tcp", 22);
	fm_scanner_add_single_port_scan(scanner, "udp", 111);
	fm_scanner_add_single_port_scan(scanner, "udp", 53);
	fm_scanner_add_single_port_scan(scanner, "udp", 1);

	if (!fm_scanner_ready(scanner)) {
		fprintf(stderr, "scanner is not fully configured\n");
		return 1;
	}

	while (true) {
		if (!fm_scanner_transmit(scanner)) {
			printf("All probes completed (%.2f msec)\n",
					fm_scanner_elapsed(scanner));
			break;
		}

		fm_socket_poll_all();
	}

	return 0;
}
