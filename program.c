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
#include "filefmt.h"

#if 0
static void		fm_scan_step_free(fm_scan_step_t *);
#endif

const char *		fm_library_path = "lib/library.scan";

/*
 * unit of execution
 */
static fm_scan_exec_t *
fm_scan_exec_array_append(fm_scan_exec_array_t *array, int type)
{
	static const unsigned int chunk = 16;
	fm_scan_exec_t *exec;

	if ((array->count % chunk) == 0)
		array->entries = realloc(array->entries, (array->count + chunk) * sizeof(array->entries[0]));

	exec = &array->entries[array->count++];

	memset(exec, 0, sizeof(*exec));
	exec->type = type;

	return exec;
}

void
fm_scan_exec_array_destroy(fm_scan_exec_array_t *array)
{
	/* Right now, we do not do refcounting of steps and routines, so
	 * we cannot tell when it's okay to delete the referenced object.
	 * So we leak that memory... which is not too bad as this is relatively
	 * low overhead. */
	drop_pointer(&array->entries);
	array->count = 0;
}

static fm_scan_exec_t *
fm_scan_routine_append_step(fm_scan_routine_t *routine, const fm_scan_step_t *step)
{
	fm_scan_exec_t *exec;

	exec = fm_scan_exec_array_append(&routine->body, FM_SCAN_EXEC_STEP);
	exec->step = step;
	return exec;
}

static fm_scan_exec_t *
fm_scan_program_append_routine(fm_scan_program_t *program, const fm_scan_routine_t *routine)
{
	fm_scan_exec_t *exec;

	exec = fm_scan_exec_array_append(&program->body, FM_SCAN_EXEC_ROUTINE);
	exec->routine = routine;
	return exec;
}

static fm_scan_exec_t *
fm_scan_library_append_routine(fm_scan_library_t *library, const fm_scan_routine_t *routine)
{
	fm_scan_exec_t *exec;

	exec = fm_scan_exec_array_append(&library->routines, FM_SCAN_EXEC_ROUTINE);
	exec->routine = routine;
	return exec;
}

static fm_scan_exec_t *
fm_scan_library_append_program(fm_scan_library_t *library, const fm_scan_program_t *program)
{
	fm_scan_exec_t *exec;

	exec = fm_scan_exec_array_append(&library->routines, FM_SCAN_EXEC_PROGRAM);
	exec->program = program;
	return exec;
}

void
fm_scan_exec_set_abort_on_fail(fm_scan_exec_t *exec, bool value)
{
	exec->abort_on_fail = value;
}

static inline const fm_scan_exec_t *
fm_scan_exec_array_find_routine(const fm_scan_exec_array_t *array, const char *name)
{
	unsigned int i;

	if (name == NULL)
		return NULL;

	for (i = 0; i < array->count; ++i) {
		fm_scan_exec_t *exec = &array->entries[i];
		const fm_scan_routine_t *routine;

		if (exec->type == FM_SCAN_EXEC_ROUTINE) {
			routine = exec->routine;
		
			if (!strcmp(routine->name, name))
				return exec;
		}
	}

	return NULL;
}

static inline const fm_scan_exec_t *
fm_scan_exec_array_find_program(struct fm_scan_exec_array *array, const char *name)
{
	unsigned int i;

	if (name == NULL)
		return NULL;

	for (i = 0; i < array->count; ++i) {
		fm_scan_exec_t *exec = &array->entries[i];
		const fm_scan_program_t *program;

		if (exec->type == FM_SCAN_EXEC_PROGRAM) {
			program = exec->program;
		
			if (!strcmp(program->name, name))
				return exec;
		}
	}

	return NULL;
}

fm_scan_routine_t *
fm_scan_routine_new(const char *name)
{
	fm_scan_routine_t *ret;

	ret = calloc(1, sizeof(*ret));
	ret->name = strdup(name);
	return ret;
}

static fm_scan_step_t *
fm_scan_step_alloc(int type, const char *proto)
{
	fm_scan_step_t *step;

	step = calloc(1, sizeof(*step));
	step->proto = strdup(proto);
	step->type = type;
	return step;
}

void
fm_scan_step_free(fm_scan_step_t *step)
{
	fm_string_array_destroy(&step->args);
	drop_string(&step->proto);
	free(step);
}

static fm_scan_step_t *
parse_step_definition(struct file_scanner *fs, int type)
{
	fm_scan_step_t *step = NULL;
	char *arg;

	while ((arg = file_scanner_continue_entry(fs)) != NULL) {
		if (!strcmp(arg, ";"))
			break;

		if (step == NULL) {
			step = fm_scan_step_alloc(type, arg);
		} else {
			fm_string_array_append(&step->args, arg);
		}
	}

	return step;
}

static fm_scan_exec_t *
parse_call(struct file_scanner *fs, const fm_scan_library_t *lib, fm_scan_program_t *program)
{
	fm_scan_exec_t *exec = NULL;
	char *arg;

	while ((arg = file_scanner_continue_entry(fs)) != NULL) {
		if (!strcmp(arg, ";"))
			break;

		if (exec == NULL) {
			const fm_scan_exec_t *callee;

			callee = fm_scan_exec_array_find_routine(&lib->routines, arg);
			if (callee == NULL) {
				file_scanner_error(fs, "program %s calls unknown routine \"%s\": %s\n",
						program->name, arg);
				return NULL;
			}

			/* NOTE: routine ends up being shared between to exec objects */
			exec = fm_scan_program_append_routine(program, callee->routine);
		} else if (!strcmp(arg, "onfail=abort")) {
			exec->abort_on_fail = true;
		} else {
			file_scanner_error(fs, "invalid argument in call of routine \"%s\": %s\n",
					exec->routine->name, arg);
			return NULL;
		}
	}

	if (exec == NULL)
		file_scanner_error(fs, "missing routine name in call (program %s)\n", program->name);

	return exec;
}

static bool
parse_routine_definition(struct file_scanner *fs, fm_scan_library_t *lib)
{
	fm_scan_routine_t *routine;
	fm_scan_exec_t *exec;
	char *name, *arg;

	if (!(name = file_scanner_continue_entry(fs)))
		return file_scanner_error(fs, "missing name in \"routine\" declaration\n");

	if (fm_scan_exec_array_find_routine(&lib->routines, name) != NULL)
		return file_scanner_error(fs, "duplicate routine name \"%s\"\n", name);

	routine = fm_scan_routine_new(name);
	exec = fm_scan_library_append_routine(lib, routine);
	(void) exec;

	// printf("NEW ROUTINE %s\n", routine->name);

	/* routine <name> [<attr> ...]: */
	while ((arg = file_scanner_continue_entry(fs)) != NULL) {
		if (!strcmp(arg, ":"))
			break;

		if (!strcmp(arg, "serialize=strict")) {
			routine->allow_random_order = true;
			routine->allow_parallel_scan = true;
		} else {
			return file_scanner_error(fs, "unsupported routine argument \"%s\"\n", arg);
		}
	}

	while ((arg = file_scanner_continue_entry(fs)) != NULL) {
		fm_scan_step_t *step = NULL;

		if (!strcmp(arg, "host-probe")) {
			step = parse_step_definition(fs, FM_SCAN_STEP_HOST_PROBE);
		} else if (!strcmp(arg, "port-probe")) {
			step = parse_step_definition(fs, FM_SCAN_STEP_PORT_PROBE);
		} else {
			file_scanner_error(fs, "unsupported routine argument \"%s\"\n", arg);
			break;
		}

		if (step)
			fm_scan_routine_append_step(routine, step);
	}

	return true;
}

static bool
parse_program_definition(struct file_scanner *fs, fm_scan_library_t *lib)
{
	fm_scan_program_t *program;
	fm_scan_exec_t *exec;
	char *name, *arg;

	if (!(name = file_scanner_continue_entry(fs)))
		return file_scanner_error(fs, "missing name in \"program\" declaration\n");

	if (fm_scan_exec_array_find_program(&lib->routines, name) != NULL)
		return file_scanner_error(fs, "duplicate program name \"%s\"\n", name);

	program = fm_scan_program_alloc(name);
	exec = fm_scan_library_append_program(lib, program);
	(void) exec;

	// printf("NEW PROGRAM %s\n", program->name);

	/* program <name> [<attr> ...]: */
	while ((arg = file_scanner_continue_entry(fs)) != NULL) {
		if (!strcmp(arg, ":"))
			break;

		return file_scanner_error(fs, "unsupported program argument \"%s\"\n", arg);
	}

	while ((arg = file_scanner_continue_entry(fs)) != NULL) {
		if (!strcmp(arg, "call")) {
			if (!parse_call(fs, lib, program))
				return file_scanner_error(fs, "program argument \"%s\"\n", arg);
		} else {
			return file_scanner_error(fs, "unsupported program argument \"%s\"\n", arg);
		}
	}

	return true;
}

static fm_scan_library_t *
__fm_scan_library_load(const char *path)
{
	fm_scan_library_t *lib;
	struct file_scanner *fs;
	char *cmd;

	if ((fs = file_scanner_open(path)) == NULL) {
		fm_log_error("Cannot load library from %s: %m\n", path);
		return NULL;
	}

	lib = calloc(1, sizeof(*lib));
	while ((cmd = file_scanner_next_entry(fs)) != NULL) {
		if (!strcmp(cmd, "routine"))
			parse_routine_definition(fs, lib);
		else if (!strcmp(cmd, "program"))
			parse_program_definition(fs, lib);
		else
			file_scanner_error(fs, "unsupported command %s\n", cmd);
	}

	if (file_scanner_has_error(fs)) {
		// fm_scan_library_free(lib);
		lib = NULL;
	}

	file_scanner_free(fs);
	return lib;
}


static fm_scan_library_t *
fm_scan_library_load(void)
{
	static fm_scan_library_t *fm_scan_library = NULL;

	if (fm_scan_library == NULL) {
		fm_scan_library = __fm_scan_library_load(fm_library_path);
		if (fm_scan_library == NULL)
			fm_log_fatal("Unable to load scan library\n");
	}
	return fm_scan_library;
}

const fm_scan_exec_t *
fm_scan_library_load_routine(const char *name)
{
	fm_scan_library_t *lib;

	lib = fm_scan_library_load();
	return fm_scan_exec_array_find_routine(&lib->routines, name);
}

const fm_scan_program_t *
fm_scan_library_load_program(const char *name)
{
	fm_scan_library_t *lib;
	const fm_scan_exec_t *exec;

	lib = fm_scan_library_load();
	if (!(exec = fm_scan_exec_array_find_program(&lib->routines, name)))
		return NULL;

	return exec->program;
}

/*
 * fm_scan_program objects
 */
fm_scan_program_t *
fm_scan_program_alloc(const char *name)
{
	fm_scan_program_t *ret;

	ret = calloc(1, sizeof(*ret));
	ret->name = strdup(name);
	return ret;
}

void
fm_scan_program_free(fm_scan_program_t *program)
{
	fm_scan_exec_array_destroy(&program->body);
	free(program);
}

fm_scan_exec_t *
fm_scan_program_call_routine(fm_scan_program_t *program, const char *name)
{
	fm_scan_library_t *lib;
	const fm_scan_exec_t *exec;

	lib = fm_scan_library_load();

	exec = fm_scan_exec_array_find_routine(&lib->routines, name);
	if (exec == NULL) {
		fm_log_error("Unable to find scan routine \"%s\"\n", name);
		return NULL;
	}

	return fm_scan_program_append_routine(program, exec->routine);
}

/*
 * Convert a program into a sequence of scan actions
 */
static bool
fm_scan_step_compile(const fm_scan_exec_t *exec, fm_scanner_t *scanner)
{
	const fm_scan_step_t *step = exec->step;
	fm_scan_action_t *action;
	unsigned int i;

	switch (step->type) {
	case FM_SCAN_STEP_HOST_PROBE:
		return fm_scanner_add_host_probe(scanner, step->proto);

	case FM_SCAN_STEP_PORT_PROBE:
		for (i = 0; i < step->args.count; ++i) {
			const char *arg = step->args.entries[i];
			unsigned int range0, range1;

			if (!fm_parse_port_range(arg, &range0, &range1)) {
				fm_log_error("Unable to parse port range \"%s\"", arg);
				return false;
			}

			if (range1 < range0 || range1 > 65535) {
				fm_log_error("Invalid port range \"%s\"", arg);
				return false;
			}

			action = fm_scanner_add_port_range_scan(scanner, step->proto, range0, range1);
			if (!action)
				return false;
		}
		return true;
	}
	return false;
}

static bool
fm_scan_exec_array_compile(const fm_scan_exec_array_t *array, fm_scanner_t *scanner)
{
	unsigned int i;
	bool ok = true;

	for (i = 0; ok && i < array->count; ++i) {
		fm_scan_exec_t *exec = &array->entries[i];

		if (exec->type == FM_SCAN_EXEC_STEP) {
			ok = fm_scan_step_compile(exec, scanner);
		} else if (exec->type == FM_SCAN_EXEC_ROUTINE) {
			const fm_scan_routine_t *routine = exec->routine;

			if (!routine->allow_parallel_scan)
				fm_scanner_insert_barrier(scanner);

			ok = fm_scan_exec_array_compile(&routine->body, scanner);

			if (!routine->allow_parallel_scan)
				fm_scanner_insert_barrier(scanner);

			if (exec->abort_on_fail) {
				fm_scanner_insert_barrier(scanner);
				fm_scanner_add_reachability_check(scanner);
			}
		} else {
			fm_log_error("%s: unsupported type %d\n", __func__, exec->type);
			ok = false;
		}
	}

	return ok;
}

bool
fm_scan_program_compile(const fm_scan_program_t *program, fm_scanner_t *scanner)
{
	return fm_scan_exec_array_compile(&program->body, scanner);
}

/*
 * Debugging function: display the contents of a scan program
 */
static inline const char *
fm_scan_step_type_to_string(int type)
{
	switch (type) {
	case FM_SCAN_STEP_HOST_PROBE:
		return "host-probe";
	case FM_SCAN_STEP_PORT_PROBE:
		return "port-probe";
	}

	return "???";
}

void
fm_scan_exec_array_dump(const fm_scan_exec_array_t *array, unsigned int indent)
{
	char nest_indent[256];
	unsigned int i, j;

	snprintf(nest_indent, sizeof(nest_indent), "  %*.*s", indent, indent, "");
	for (i = 0; i < array->count; ++i) {
		fm_scan_exec_t *exec = &array->entries[i];
		const fm_scan_routine_t *routine;
		const fm_scan_step_t *step;

		printf("%s%2u:", nest_indent, i);

		switch (exec->type) {
		case FM_SCAN_EXEC_STEP:
			step = exec->step;

			printf(" %s %s", fm_scan_step_type_to_string(step->type),
					step->proto);
			for (j = 0; j < step->args.count; ++j)
				printf(" %s", step->args.entries[j]);

			if (exec->abort_on_fail)
				printf("; onfail=abort");
			printf("\n");
			break;

		case FM_SCAN_EXEC_ROUTINE:
			routine = exec->routine;

			printf(" call %s", routine->name?: "<unnamed>");
			if (routine->allow_random_order)
				printf(" random-order=ok");
			if (routine->allow_parallel_scan)
				printf(" parallel-scan=ok");

			if (exec->abort_on_fail)
				printf("; onfail=abort");
			printf("\n");
			fm_scan_exec_array_dump(&routine->body, indent + 4);
			break;

		default:
			printf(" ???\n");
			break;
		}
	}
}

void
fm_scan_program_dump(const fm_scan_program_t *program)
{
	printf("SCAN PROGRAM DUMP\n");
	fm_scan_exec_array_dump(&program->body, 2);
}
