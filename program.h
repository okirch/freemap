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

/*
 * This represents a rather simple way of defining a scan via a
 * file format.
 * This will have to become richer.
 */

#ifndef FREEMAP_PROGRAM_H
#define FREEMAP_PROGRAM_H

#include "utils.h"

extern const char *		fm_library_path;

/* A single action that is part of a scan. Ultimately,
 * this will be translated into an fm_scan_action object.
 *
 * Right now, we support host-probe and port-probe steps.
 */
enum {
	FM_SCAN_STEP_HOST_PROBE,
	FM_SCAN_STEP_PORT_PROBE,
};

typedef struct fm_scan_step {
	char *			proto;
	int			type;
	fm_string_array_t	args;
} fm_scan_step_t;

/*
 * A scan program is a tree of executable objects,
 * which can be either a single probe, or a routine (ie
 * sequence of executable objects).
 */
typedef struct fm_scan_exec fm_scan_exec_t;

typedef struct fm_scan_exec_array {
	unsigned int		count;
	fm_scan_exec_t *	entries;
} fm_scan_exec_array_t;

typedef struct fm_scan_routine {
	const char *		name;

	/* scan scheduler is allowed to execute requests in random order. */
	bool			allow_random_order;

	/* scan scheduler is allowed to mix requests from this program
	 * with requests from other programs. */
	bool			allow_parallel_scan;

	fm_scan_exec_array_t	body;
} fm_scan_routine_t;

enum {
	FM_SCAN_EXEC_STEP,
	FM_SCAN_EXEC_ROUTINE,
};

struct fm_scan_exec {
	int			type;

	/* abort the program when this routine fails */
	bool			abort_on_fail;

	union {
		const fm_scan_step_t *step;
		const fm_scan_routine_t *routine;
	};
};

typedef struct fm_scan_library {
	fm_scan_exec_array_t	routines;
} fm_scan_library_t;

struct fm_scan_program {
	fm_scan_exec_array_t	body;
};


#endif /* FREEMAP_PROGRAM_H */
