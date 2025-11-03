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
