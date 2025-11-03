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

#include <limits.h>
#include <unistd.h>

#include <curlies.h>

#include "freemap.h"
#include "program.h"
#include "scanner.h"
#include "filefmt.h"
#include "probe.h"
#include "utils.h"
#include "filefmt.h"

#if 0
static void		fm_scan_step_free(fm_scan_step_t *);
#endif


typedef struct fm_config_probe_array {
	unsigned int		count;
	fm_config_probe_t **	entries;
} fm_config_probe_array_t;

struct fm_new_routine {
	const char *		name;
	int			mode;

	bool			processed;
	bool			bad;

	curly_node_t *		unparsed;
	struct fm_new_routine_parsed {
		char *			name;
		bool			optional;
		fm_config_probe_array_t	probes;
	} parsed;
};

struct fm_new_library {
	fm_string_array_t		search_path;
	fm_string_array_t		modules;
	fm_new_routine_array_t		routines;
};


const char *		fm_library_path = "lib/library.scan";

static bool		fm_new_routine_process(fm_new_routine_t *routine);


/*
 * These are global entry points for the application
 */
fm_new_library_t *
fm_config_load_library(void)
{
	static fm_new_library_t *the_library;

	if (the_library == NULL) {
		the_library = fm_new_library_alloc(NULL);

		if (!fm_new_library_load_module(the_library, "standard"))
			the_library = NULL;
	}
	return the_library;
}

fm_new_routine_t *
fm_config_load_routine(int mode, const char *name)
{
	fm_new_library_t *lib;

	if (name == NULL)
		return NULL;

	if ((lib = fm_config_load_library()) == NULL)
		return NULL;

	return fm_new_library_get_routine(lib, mode, name);
}

/*
 * fm_routine creation
 */
void
fm_new_routine_array_append(fm_new_routine_array_t *array, fm_new_routine_t *routine)
{
	maybe_realloc_array(array->entries, array->count, 32);
	array->entries[array->count++] = routine;
}

static fm_new_routine_t *
fm_new_program_find_routine(fm_new_library_t *lib, int mode, const char *name)
{
	unsigned int i;

	for (i = 0; i < lib->routines.count; ++i) {
		fm_new_routine_t *routine = lib->routines.entries[i];
		if (routine->mode == mode && !strcmp(routine->name, name))
			return routine;
	}
	return NULL;
}

/*
 * Handling of routine objects
 */
static fm_new_routine_t *
fm_new_routine_alloc(int mode, const char *name, curly_node_t *curly)
{
	fm_new_routine_t *routine;

	routine = calloc(1, sizeof(*routine));
	routine->mode = mode;
	routine->name = strdup(name);
	routine->unparsed = curly;

	return routine;
}

/*
 * Create a library object
 */
fm_new_library_t *
fm_new_library_alloc(const char * const *search_paths)
{
	fm_new_library_t *lib;
	const char *path;

	lib = calloc(1, sizeof(*lib));

	/* FIXME: getenv() some variable */

	if (search_paths != NULL) {
		if ((path = *search_paths++) != NULL)
			fm_string_array_append(&lib->search_path, path);
	} else {
		fm_string_array_t *conf_path = &fm_global.library.search_path;
		unsigned int i;

		for (i = 0; i < conf_path->count; ++i) {
			const char *path = conf_path->entries[i];
			fm_string_array_append(&lib->search_path, path);
		}
	}

	return lib;
}

extern fm_new_routine_t *
fm_new_library_get_routine(fm_new_library_t *lib, int mode, const char *name)
{
	fm_new_routine_t *routine;

	if (!(routine = fm_new_program_find_routine(lib, mode, name)))
		return NULL;

	if (routine->processed) {
		if (routine->bad)
			return NULL;
		return routine;
	}

	routine->processed = true;
	if (!fm_new_routine_process(routine)) {
		routine->bad = true;
		return NULL;
	}

	return routine;
}


/*
 * Load a collection of routines into our library
 */
bool
fm_new_library_load_file(fm_new_library_t *lib, const char *path)
{
	curly_node_t *top, *node;
	curly_iter_t *iter;
	bool rv;

	if (access(path, F_OK) < 0)
		return true;

	top = curly_node_read(path);
	if (top == NULL) {
		fm_log_error("Unable to parse config file %s", path);
		return false;
	}

	/* Silently ignore empty module files. */
	if ((iter = curly_node_iterate(top)) == NULL) {
		curly_node_free(top);
		return true;
	}

	if (curly_iter_next_attr(iter) != NULL) {
		fm_config_complain(top, "unexpected attributes in top-level node");
		return false;
	}

	rv = true;
	while ((node = curly_iter_next_node(iter)) != NULL) {
		const char *type = curly_node_type(node);
		const char *name = curly_node_name(node);
		fm_new_routine_t *routine, *other;
		int mode;

		if (name == NULL) {
			fm_config_complain(node, "missing name");
			rv = false;
			continue;
		}

		if (!strcmp(type, "topology-scan")) {
			mode = FM_PROBE_MODE_TOPO;
		} else
		if (!strcmp(type, "host-scan")) {
			mode = FM_PROBE_MODE_HOST;
		} else
		if (!strcmp(type, "port-scan")) {
			mode = FM_PROBE_MODE_PORT;
		} else {
			fm_config_complain(node, "unsupported routine type \"%s\"", type);
			rv = false;
			continue;
		}

		if ((other = fm_new_program_find_routine(lib, mode, name)) != NULL) {
			fm_config_complain(node, "duplicated definition of %s routine %s (already have one from %s:%u)",
					type, name,
					curly_node_get_source_file(other->unparsed),
					curly_node_get_source_line(other->unparsed));
			rv = false;
			continue;
		}

		routine = fm_new_routine_alloc(mode, name, node);
		fm_new_routine_array_append(&lib->routines, routine);
	}

	curly_iter_free(iter);

	/* As we keep references to unparsed nodes from the config file,
	 * destroying the top node is somewhat counter-productive.
	 * Just leak the top node. */
	/* curly_node_free(top); */

	return rv;
}

bool
fm_new_library_load_module(fm_new_library_t *lib, const char *module_name)
{
	char full_path[PATH_MAX];
	unsigned int i;

	if (fm_string_array_contains(&lib->modules, module_name))
		return true;

	for (i = 0; i < lib->search_path.count; ++i) {
		const char *dir = lib->search_path.entries[i];

		snprintf(full_path, sizeof(full_path), "%s/%s.lib", dir, module_name);
		if (access(full_path, F_OK) >= 0) {
			if (fm_new_library_load_file(lib, full_path))
				return true;

			fm_log_error("Failed to load module \"%s\" from \"%s\"", module_name, full_path);
			return false;
		}
	}

	fm_log_error("Could not find module \"%s\" anywhere in my search path", module_name);
	return false;
}

static void
fm_config_probe_array_append(fm_config_probe_array_t *array, fm_config_probe_t *parsed_probe)
{
	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = parsed_probe;
}

/*
 * Callback when eg host-probe is encountered
 */
static void *
fm_config_probe_root_create(curly_node_t *node, void *data)
{
	fm_config_probe_array_t *array = (fm_config_probe_array_t *) data;
	const char *name = curly_node_name(node);
	const char *type = curly_node_type(node);
	fm_config_probe_t *parsed_probe;
	int mode;

	if (!strcmp(type, "topo-probe"))
		mode = FM_PROBE_MODE_TOPO;
	else if (!strcmp(type, "host-probe"))
		mode = FM_PROBE_MODE_HOST;
	else if (!strcmp(type, "port-probe"))
		mode = FM_PROBE_MODE_PORT;
	else
		fm_log_fatal("BUG: don't know about %s", type);

	parsed_probe = calloc(1, sizeof(*parsed_probe));
	parsed_probe->name = strdup(name);
	parsed_probe->mode = mode;
	fm_config_probe_array_append(array, parsed_probe);

	return parsed_probe;
}

/*
 * Handle unknown attributes - convert them to foo=bar notation and store them as strings
 * probe->extra_args.
 *
 * For now, this supports only one value per attribute.
 * If we need more one day, this should probably represent them as foobar=1,2,4,7
 * or, for easier coding, as foobar=1 foobar=2 foobar=3 ...
 */
static bool
fm_config_probe_set_extra(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	fm_string_array_t *extra_args = attr_data;
	const char *attr_name = curly_attr_get_name(attr);
	char argbuf[128];

	if (curly_attr_get_count(attr) != 1) {
		fm_config_complain(node, "unsupported number of values in attribute %s", attr_name);
	}

	snprintf(argbuf, sizeof(argbuf), "%s=%s", attr_name, curly_attr_get_value(attr, 0));
	fm_string_array_append(extra_args, argbuf);

	return true;
}


/*
 * curly file structure for library
 */
static fm_config_proc_t	fm_config_probe_root = {
	.name = ATTRIB_STRING(fm_config_probe_t, name),
	.attributes = {
		{ "optional",	offsetof(fm_config_probe_t, optional),			FM_CONFIG_ATTR_TYPE_BOOL },
		{ "random",	offsetof(fm_config_probe_t, random),			FM_CONFIG_ATTR_TYPE_BOOL },
		{ "port",	offsetof(fm_config_probe_t, string_ports),		FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "ttl",	offsetof(fm_config_probe_t, probe_params.ttl),		FM_CONFIG_ATTR_TYPE_INT },
		{ "retries",	offsetof(fm_config_probe_t, probe_params.retries),	FM_CONFIG_ATTR_TYPE_INT },
		{ "tos",	offsetof(fm_config_probe_t, probe_params.tos),		FM_CONFIG_ATTR_TYPE_INT },

		{ "*",		offsetof(fm_config_probe_t, extra_args),		FM_CONFIG_ATTR_TYPE_SPECIAL, .setfn = fm_config_probe_set_extra }
	},
};

static fm_config_proc_t	fm_config_routine_root = {
	.name = ATTRIB_STRING(struct fm_new_routine_parsed, name),
	.attributes = {
		ATTRIB_BOOL(struct fm_new_routine_parsed, optional),
	},
	.children = {
		{ "topo-probe",		offsetof(struct fm_new_routine_parsed, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
		{ "host-probe",		offsetof(struct fm_new_routine_parsed, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
		{ "port-probe",		offsetof(struct fm_new_routine_parsed, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
	},
};

static bool
fm_new_routine_process(fm_new_routine_t *routine)
{
	struct fm_new_routine_parsed *parsed_data = &routine->parsed;
	curly_node_t *node = routine->unparsed;

	fm_log_debug("Trying to compile %s routine %s",
			fm_probe_mode_to_string(routine->mode), routine->name);

	if (!fm_config_process_node(node, &fm_config_routine_root, parsed_data)) {
		fm_config_complain(node, "unable to parse routine definition");
		return false;
	}

	if (false) {
		unsigned int i, k;
		fm_log_debug("name=%s", parsed_data->name);
		fm_log_debug("optional=%d", parsed_data->optional);

		for (i = 0; i < parsed_data->probes.count; ++i) {
			fm_config_probe_t *probe = parsed_data->probes.entries[i];

			fm_log_debug("probe mode %d name %s", probe->mode, probe->name);
			fm_log_debug("	ttl:     %u", probe->probe_params.ttl);
			fm_log_debug("	ports:   %u entries", probe->string_ports.count);

			for (k = 0; k < probe->extra_args.count; ++k)
				fm_log_debug("	arg%d:    %s", k, probe->extra_args.entries[k]);
		}
	}

	return true;
}

fm_scan_program_t *
fm_scan_program_build(const char *name, const char *topology_scan, const char *host_scan, const char *port_scan)
{
	fm_scan_program_t *program;

	program = calloc(1, sizeof(*program));
	if (topology_scan != NULL
	 && !(program->topo_scan = fm_config_load_routine(FM_PROBE_MODE_TOPO, topology_scan)))
		goto fail;

	if (host_scan != NULL
	 && !(program->host_scan = fm_config_load_routine(FM_PROBE_MODE_HOST, host_scan)))
		goto fail;

	if (port_scan != NULL
	 && !(program->port_scan = fm_config_load_routine(FM_PROBE_MODE_PORT, port_scan)))
		goto fail;

	return program;

fail:
	fm_scan_program_free(program);
	return NULL;
}

void
fm_scan_program_free(fm_scan_program_t *program)
{
	free(program);
}

void
fm_scan_program_dump(const fm_scan_program_t *program)
{
	/* this does not do anything right now */
}

/*
 * Convert a program into a sequence of scan actions
 */
static bool
fm_scan_routine_compile(const fm_new_routine_t *routine, fm_scanner_t *scanner)
{
	unsigned int i;
	bool ok = true;

	for (i = 0; ok && i < routine->parsed.probes.count; ++i) {
		fm_config_probe_t *parsed_probe = routine->parsed.probes.entries[i];

		ok = fm_scanner_add_probe(scanner, parsed_probe) && ok;

		if (routine->mode == FM_PROBE_MODE_HOST) {
			fm_scanner_insert_barrier(scanner);
			fm_scanner_add_reachability_check(scanner);
		}
	}

	return ok;
}

bool
fm_scan_program_compile(const fm_scan_program_t *program, fm_scanner_t *scanner)
{
	return fm_scan_routine_compile(program->topo_scan, scanner)
	    && fm_scan_routine_compile(program->host_scan, scanner)
	    && fm_scan_routine_compile(program->port_scan, scanner);
}


#if 0
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
fm_scan_exec_array_find_routine(const fm_scan_exec_array_t *array, int type, const char *name)
{
	unsigned int i;

	if (name == NULL)
		return NULL;

	for (i = 0; i < array->count; ++i) {
		fm_scan_exec_t *exec = &array->entries[i];
		const fm_scan_routine_t *routine;

		if (exec->type == FM_SCAN_EXEC_ROUTINE) {
			routine = exec->routine;
		
			if (routine->type == type && !strcmp(routine->name, name))
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
fm_scan_routine_new(int type, const char *name)
{
	fm_scan_routine_t *ret;

	ret = calloc(1, sizeof(*ret));
	ret->type = type;
	ret->name = strdup(name);
	return ret;
}

const char *
fm_scan_routine_type_to_name(int type)
{
	switch (type) {
	case FM_SCAN_ROUTINE_TOPOLOGY:
		return "topology";

	case FM_SCAN_ROUTINE_HOSTS:
		return "hosts";

	case FM_SCAN_ROUTINE_SERVICES:
		return "services";
	}
	return "unknown";
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
		} else if (!strcmp(arg, "optional")) {
			step->action_flags |= FM_SCAN_ACTION_FLAG_OPTIONAL;
		} else {
			fm_string_array_append(&step->args, arg);
		}
	}

	return step;
}

static fm_scan_exec_t *
parse_call(struct file_scanner *fs, const fm_scan_library_t *lib, fm_scan_program_t *program, int routine_type)
{
	fm_scan_exec_t *exec = NULL;
	char *arg;

	while ((arg = file_scanner_continue_entry(fs)) != NULL) {
		if (!strcmp(arg, ";"))
			break;

		if (exec == NULL) {
			const fm_scan_exec_t *callee;

			callee = fm_scan_exec_array_find_routine(&lib->routines, routine_type, arg);
			if (callee == NULL) {
				file_scanner_error(fs, "program %s calls unknown %s scan \"%s\": %s\n",
						program->name, fm_scan_routine_type_to_name(routine_type), arg);
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
parse_routine_definition(struct file_scanner *fs, fm_scan_library_t *lib, int type)
{
	fm_scan_routine_t *routine;
	fm_scan_exec_t *exec;
	char *name, *arg;

	if (!(name = file_scanner_continue_entry(fs)))
		return file_scanner_error(fs, "missing name in \"routine\" declaration\n");

	if (fm_scan_exec_array_find_routine(&lib->routines, type, name) != NULL)
		return file_scanner_error(fs, "duplicate %s routine name \"%s\"\n",
				fm_scan_routine_type_to_name(type), name);

	routine = fm_scan_routine_new(type, name);
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

		if (!strcmp(arg, "topo-scan")) {
			step = parse_step_definition(fs, FM_SCAN_STEP_TOPO_PROBE);
		} else
		if (!strcmp(arg, "host-scan")) {
			step = parse_step_definition(fs, FM_SCAN_STEP_HOST_PROBE);
		} else if (!strcmp(arg, "port-scan")) {
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
		bool okay;

		if (!strcmp(arg, "topology-scan")) {
			okay = parse_call(fs, lib, program, FM_SCAN_ROUTINE_TOPOLOGY);
		} else
		if (!strcmp(arg, "hosts-scan")) {
			okay = parse_call(fs, lib, program, FM_SCAN_ROUTINE_HOSTS);
		} else
		if (!strcmp(arg, "services-scan")) {
			okay = parse_call(fs, lib, program, FM_SCAN_ROUTINE_SERVICES);
		} else {
			return file_scanner_error(fs, "unsupported program argument \"%s\"\n", arg);
		}

		if (!okay)
			return file_scanner_error(fs, "could not handle call to \"%s\"\n", arg);
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
		if (!strcmp(cmd, "topology-scan"))
			parse_routine_definition(fs, lib, FM_SCAN_ROUTINE_TOPOLOGY);
		else if (!strcmp(cmd, "hosts-scan"))
			parse_routine_definition(fs, lib, FM_SCAN_ROUTINE_HOSTS);
		else if (!strcmp(cmd, "services-scan"))
			parse_routine_definition(fs, lib, FM_SCAN_ROUTINE_SERVICES);
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

#if 0
const fm_scan_exec_t *
fm_scan_library_load_routine(const char *name)
{
	fm_scan_library_t *lib;

	lib = fm_scan_library_load();
	return fm_scan_exec_array_find_routine(&lib->routines, name);
}
#endif

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
fm_scan_program_call_routine(fm_scan_program_t *program, int type, const char *name)
{
	fm_scan_library_t *lib;
	const fm_scan_exec_t *exec;

	lib = fm_scan_library_load();

	exec = fm_scan_exec_array_find_routine(&lib->routines, type, name);
	if (exec == NULL) {
		fm_log_error("Unable to find %s scan routine \"%s\"\n",
				fm_scan_routine_type_to_name(type), name);
		return NULL;
	}

	return fm_scan_program_append_routine(program, exec->routine);
}

/*
 * Convenience function for assembling a program from a reachability and a service scan
 */
static bool
fm_scan_program_attach(fm_scan_program_t *program, int type, const char *routine_name, bool abort_on_fail)
{
	fm_scan_exec_t *exec;

	exec = fm_scan_program_call_routine(program, type, routine_name);
	if (exec == NULL) {
		fm_log_error("Could not attach %s scan routine \"%s\"",
				fm_scan_routine_type_to_name(type), routine_name);
		return false;
	}

	if (abort_on_fail)
		exec->abort_on_fail = true;
	return true;
}

extern fm_scan_program_t *
fm_scan_program_build(const char *name, const char *topology_scan, const char *reachability_scan, const char *service_scan)
{
	fm_scan_program_t *program;

	program = fm_scan_program_alloc(name);
	if (topology_scan != NULL
	 && !fm_scan_program_attach(program, FM_SCAN_ROUTINE_TOPOLOGY, topology_scan, true))
		goto fail;

	if (reachability_scan != NULL
	 && !fm_scan_program_attach(program, FM_SCAN_ROUTINE_HOSTS, reachability_scan, true))
		goto fail;

	if (service_scan != NULL
	 && !fm_scan_program_attach(program, FM_SCAN_ROUTINE_SERVICES, service_scan, false))
		goto fail;

	return program;

fail:
	fm_scan_program_free(program);
	return NULL;
}

/*
 * Convert a program into a sequence of scan actions
 */
static bool
fm_scan_step_compile(const fm_scan_exec_t *exec, fm_scanner_t *scanner)
{
	const fm_scan_step_t *step = exec->step;

	switch (step->type) {
	case FM_SCAN_STEP_TOPO_PROBE:
		return fm_scanner_add_topo_probe(scanner, step->proto, step->action_flags, &step->args);

	case FM_SCAN_STEP_HOST_PROBE:
		return fm_scanner_add_host_probe(scanner, step->proto, step->action_flags, &step->args);

	case FM_SCAN_STEP_PORT_PROBE:
		return fm_scanner_add_port_probe(scanner, step->proto, step->action_flags, &step->args);
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
	case FM_SCAN_STEP_TOPO_PROBE:
		return "topo-probe";
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
#endif
