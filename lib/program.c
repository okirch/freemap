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
#include "buffer.h"
#include "logging.h"
#include "services.h"

enum {
	EMPTY, LOADED, FAILED
};

typedef struct fm_config_catalog {
	/* We need a back pointer to the module, so that we can
	 * interpret relative names */
	const fm_config_module_t *containing_module;

	const char *		name;
	const char *		extend;
	fm_string_array_t	names;
} fm_config_catalog_t;

typedef struct fm_config_catalog_array {
	unsigned int		count;
	fm_config_catalog_t **	entries;
} fm_config_catalog_array_t;

struct fm_config_module {
	const char *		name;
	int			state;
	fm_config_probe_array_t	probes;

	fm_config_routine_definition_array_t routines;
	fm_config_service_array_t services;
	fm_config_catalog_array_t service_catalogs;
	fm_config_preset_array_t presets;
};

struct fm_config_routine_definition {
	const fm_config_module_t *containing_module;

	const char *		name;
	int			stage;		/* FM_SCAN_STAGE_xxx */

	fm_string_array_t	broadcast_probes;
	fm_string_array_t	topology_probes;
	fm_string_array_t	host_probes;
	fm_string_array_t	port_probes;
};

struct fm_config_library {
	fm_string_array_t	search_path;
	fm_config_module_t *	standard;
	fm_config_module_array_t modules;
};


static fm_config_catalog_t *fm_config_catalog_alloc(const char *name, const fm_config_module_t *module, fm_config_catalog_array_t *array);
static bool		fm_config_module_process(fm_config_module_t *module, curly_node_t *node);
static fm_config_module_t *fm_config_library_find_module(fm_config_library_t *lib, const char *name, bool load_if_missing);
static bool		fm_config_module_load(fm_config_module_t *module, const char *path);
static fm_config_probe_t *fm_config_library_resolve_probe(fm_config_library_t *lib, int mode, const char *name, const fm_config_module_t *context);


/*
 * These are global entry points for the application
 */
fm_config_library_t *
fm_config_load_library(void)
{
	static fm_config_library_t *the_library;

	if (the_library == NULL) {
		the_library = fm_config_library_alloc(NULL);

		the_library->standard = fm_config_library_find_module(the_library, "standard", true);
	}

	if (the_library->standard == NULL)
		return NULL;

	return the_library;
}

fm_config_preset_t *
fm_config_load_preset(const char *name)
{
	fm_config_library_t *lib;

	if (name == NULL)
		return NULL;

	if ((lib = fm_config_load_library()) == NULL)
		return NULL;

	return fm_config_library_resolve_preset(lib, name);
}

const fm_config_preset_array_t *
fm_config_list_presets(void)
{
	fm_config_library_t *lib;

	if ((lib = fm_config_load_library()) == NULL
	 || lib->standard == NULL)
		return NULL;

	return &lib->standard->presets;
}

fm_config_routine_t *
fm_config_load_routine(int stage, const char *name)
{
	fm_config_library_t *lib;

	if (name == NULL)
		return NULL;

	if ((lib = fm_config_load_library()) == NULL)
		return NULL;

	return fm_config_library_resolve_routine(lib, stage, name, NULL);
}

fm_config_catalog_t *
fm_config_load_service_catalog(const char *name, fm_config_module_t *context)
{
	fm_config_library_t *lib;

	if (name == NULL)
		return NULL;

	if ((lib = fm_config_load_library()) == NULL)
		return NULL;

	return fm_config_library_resolve_service_catalog(lib, name, context);
}

/*
 * fm_routine creation
 */
static void
fm_config_routine_definition_array_append(fm_config_routine_definition_array_t *array, fm_config_routine_definition_t *routine_definition)
{
	maybe_realloc_array(array->entries, array->count, 32);
	array->entries[array->count++] = routine_definition;
}

static fm_config_routine_definition_t *
fm_config_routine_definition_array_find(const fm_config_routine_definition_array_t *array, int stage, const char *name)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		fm_config_routine_definition_t *routine_definition = array->entries[i];
		if (routine_definition->stage == stage && !strcmp(routine_definition->name, name))
			return routine_definition;
	}
	return NULL;
}

static void
fm_config_probe_array_append(fm_config_probe_array_t *array, fm_config_probe_t *parsed_probe)
{
	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = parsed_probe;
}

static fm_config_probe_t *
fm_config_probe_array_find(const fm_config_probe_array_t *array, int mode, const char *name)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		fm_config_probe_t *probe = array->entries[i];
		if (probe->mode == mode && !strcmp(probe->name, name))
			return probe;
	}
	return NULL;
}

void
fm_config_module_array_append(fm_config_module_array_t *array, fm_config_module_t *module)
{
	maybe_realloc_array(array->entries, array->count, 32);
	array->entries[array->count++] = module;
}

void
fm_config_packet_array_append(fm_config_packet_array_t *array, fm_config_packet_t *packet)
{
	maybe_realloc_array(array->entries, array->count, 32);
	array->entries[array->count++] = packet;
}

void
fm_config_service_array_append(fm_config_service_array_t *array, fm_config_service_t *service)
{
	maybe_realloc_array(array->entries, array->count, 32);
	array->entries[array->count++] = service;
}

static fm_config_service_t *
fm_config_service_array_find(const fm_config_service_array_t *array, const char *name)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		fm_config_service_t *service = array->entries[i];
		if (!strcmp(service->name, name))
			return service;
	}
	return NULL;
}

void
fm_service_array_destroy_shallow(fm_config_service_array_t *array)
{
	if (array->entries)
		free(array->entries);
	memset(array, 0, sizeof(*array));
}

static void
fm_config_catalog_array_append(fm_config_catalog_array_t *array, fm_config_catalog_t *catalog)
{
	maybe_realloc_array(array->entries, array->count, 32);
	array->entries[array->count++] = catalog;
}

static fm_config_catalog_t *
fm_config_catalog_array_find(const fm_config_catalog_array_t *array, const char *name)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		fm_config_catalog_t *catalog = array->entries[i];

		if (!strcmp(catalog->name, name))
			return catalog;
	}
	return NULL;
}

static void
fm_config_preset_array_append(fm_config_preset_array_t *array, fm_config_preset_t *preset)
{
	maybe_realloc_array(array->entries, array->count, 32);
	array->entries[array->count++] = preset;
}

static fm_config_preset_t *
fm_config_preset_array_find(const fm_config_preset_array_t *array, const char *name)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		fm_config_preset_t *preset = array->entries[i];

		if (!strcmp(preset->name, name))
			return preset;
	}
	return NULL;
}

/*
 * create an empty scan module
 */
static fm_config_module_t *
fm_config_module_alloc(const char *name)
{
	fm_config_module_t *module;

	module = calloc(1, sizeof(*module));
	module->name = strdup(name);
	module->state = EMPTY;
	return module;
}

/*
 * Look up a routine gives its name
 */
static fm_config_routine_definition_t *
fm_config_module_find_routine_definition(const fm_config_module_t *module, int stage, const char *name)
{
	if (module->state != LOADED)
		return NULL;

	return fm_config_routine_definition_array_find(&module->routines, stage, name);
}

/*
 * Look up a service gives its name
 */
static fm_config_service_t *
fm_config_module_find_service(const fm_config_module_t *module, const char *name)
{
	if (module->state != LOADED)
		return NULL;

	return fm_config_service_array_find(&module->services, name);
}

/*
 * Look up a service catalog gives its name
 */
static fm_config_catalog_t *
fm_config_module_find_service_catalog(const fm_config_module_t *module, const char *name)
{
	if (module->state != LOADED)
		return NULL;

	return fm_config_catalog_array_find(&module->service_catalogs, name);
}

static bool
fm_config_library_get_module_path(fm_config_library_t *lib, const char *subdir, const char *module_name, char *path_buf, size_t size)
{
	unsigned int i;

	for (i = 0; i < lib->search_path.count; ++i) {
		const char *dir = lib->search_path.entries[i];

		if (subdir == NULL)
			snprintf(path_buf, size, "%s/%s.lib", dir, module_name);
		else
			snprintf(path_buf, size, "%s/%s/%s.lib", dir, subdir, module_name);
		if (access(path_buf, F_OK) >= 0)
			return true;
	}

	return false;
}

static fm_config_module_t *
fm_config_library_find_module_with_type(fm_config_library_t *lib, const char *subdir, const char *name, bool load_if_missing)
{
	fm_config_module_t *module;
	char path_buf[PATH_MAX];
	unsigned int i;

	for (i = 0; i < lib->modules.count; ++i) {
		module = lib->modules.entries[i];
		if (!strcmp(module->name, name))
			return module;
	}

	if (!load_if_missing)
		return NULL;

	module = fm_config_module_alloc(name);
	fm_config_module_array_append(&lib->modules, module);

	if (!fm_config_library_get_module_path(lib, subdir, name, path_buf, sizeof(path_buf))) {
		fm_log_error("Could not find module \"%s\" anywhere in my search path", name);
		return NULL;
	}

	if (fm_config_module_load(module, path_buf))
		module->state = LOADED;
	else
		module->state = FAILED;

	return module;
}

static fm_config_module_t *
fm_config_library_find_module(fm_config_library_t *lib, const char *name, bool load_if_missing)
{
	return fm_config_library_find_module_with_type(lib, NULL, name, load_if_missing);
}

/*
 * Handling of routine objects
 */
static fm_config_routine_t *
fm_config_routine_alloc(int stage, const char *name)
{
	fm_config_routine_t *routine;

	routine = calloc(1, sizeof(*routine));
	routine->stage = stage;
	if (name != NULL)
		routine->name = strdup(name);

	return routine;
}

static bool
fm_config_routine_resolve_probes(fm_config_routine_t *routine, int mode, const fm_string_array_t *names, const fm_config_module_t *context)
{
	fm_config_library_t *lib = fm_config_load_library();
	unsigned int i;

	for (i = 0; i < names->count; ++i) {
		const char *probe_name = names->entries[i];
		fm_config_probe_t *probe;

		probe = fm_config_library_resolve_probe(lib, mode, probe_name, context);
		if (probe == NULL)
			return false;

		fm_config_probe_array_append(&routine->probes, probe);
	}

	return true;
}

static fm_config_routine_definition_t *
fm_config_routine_definition_alloc(int stage, const char *name, fm_config_routine_definition_array_t *array)
{
	fm_config_routine_definition_t *routine_definition;

	routine_definition = calloc(1, sizeof(*routine_definition));
	routine_definition->stage = stage;
	if (name != NULL)
		routine_definition->name = strdup(name);

	if (array)
		fm_config_routine_definition_array_append(array, routine_definition);

	return routine_definition;
}


/*
 * Handling of preset objects
 */
static fm_config_preset_t *
fm_config_preset_alloc(const char *name, fm_config_preset_array_t *array)
{
	fm_config_preset_t *preset;

	preset = calloc(1, sizeof(*preset));
	preset->name = strdup(name);

	if (array)
		fm_config_preset_array_append(array, preset);

	return preset;
}

bool
fm_config_preset_resolve_stage(const fm_config_preset_t *preset, int stage, fm_config_routine_t **ret)
{
	fm_config_library_t *lib = fm_config_load_library();
	const char *reference = NULL;

	assert(preset->containing_module);

	*ret = NULL;

	switch (stage) {
	case FM_SCAN_STAGE_DISCOVERY:
		reference = preset->discovery_scan;
		break;
	case FM_SCAN_STAGE_TOPO:
		reference = preset->topology_scan;
		break;
	case FM_SCAN_STAGE_HOST:
		reference = preset->host_scan;
		break;
	case FM_SCAN_STAGE_PORT:
		reference = preset->port_scan;
		break;
	}

	if (reference == NULL)
		return true;
 
	*ret = fm_config_library_resolve_routine(lib, stage, reference, preset->containing_module);
	if (*ret == NULL) {
		fm_log_error("Preset %s.%s: could not resolve reference to stage%u scan routine \"%s\"",
				preset->containing_module->name, preset->name,
				stage, /* FIXME: we need a stage-to-string function */
				reference);
		return false;
	}

	return true;
}

/*
 * Create a library object
 */
fm_config_library_t *
fm_config_library_alloc(const char * const *search_paths)
{
	fm_config_library_t *lib;
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

/*
 * Parse a reference to a scan routine definition or similar, which is optionally prefixed
 * with a module name, separated by '.'
 * Returns the module name, if found, or NULL.
 * On return, *name_p will point to the routine name with any module prefix stripped
 * off.
 */
static char *
fm_config_library_parse_reference(const char **name_p)
{
	const char *name = *name_p, *s;
	unsigned int len;
	char *module_name;

	if ((s = strchr(name, '.')) == NULL)
		return NULL;

	len = s - name;

	/* routine name starts past the dot */
	*name_p = name + len + 1;

	/* now allocate the module name */
	module_name = malloc(len + 1);
	strncpy(module_name, name, len);
	module_name[len] = '\0';

	return module_name;
}

static const fm_config_module_t *
fm_config_library_resolve_reference_partial(fm_config_library_t *lib, const fm_config_module_t *context, const char **name_p)
{
	const fm_config_module_t *module;
	char *module_name;

	module_name = fm_config_library_parse_reference(name_p);
	if (module_name != NULL) {
		module = fm_config_library_find_module(lib, module_name, true);
		free(module_name);
	} else if (context != NULL) {
		module = context;
	} else {
		module = lib->standard;;
	}

	if (module == NULL || module->state != LOADED)
		return NULL;

	return module;
}

fm_config_probe_t *
fm_config_library_resolve_probe(fm_config_library_t *lib, int mode, const char *name, const fm_config_module_t *context)
{
	const fm_config_module_t *module;

	module = fm_config_library_resolve_reference_partial(lib, context, &name);
	if (module == NULL)
		return NULL;

	return fm_config_probe_array_find(&module->probes, mode, name);
}

fm_config_preset_t *
fm_config_library_resolve_preset(fm_config_library_t *lib, const char *name)
{
	const fm_config_module_t *module;

	module = fm_config_library_resolve_reference_partial(lib, NULL, &name);
	if (module == NULL)
		return NULL;

	return fm_config_preset_array_find(&module->presets, name);
}

fm_config_routine_t *
fm_config_library_resolve_routine(fm_config_library_t *lib, int stage, const char *name, const fm_config_module_t *context)
{
	fm_config_routine_definition_t *routine_definition = NULL;
	const fm_config_module_t *module;
	fm_config_routine_t *routine;

	module = fm_config_library_resolve_reference_partial(lib, context, &name);
	if (module == NULL)
		return NULL;

	routine_definition = fm_config_module_find_routine_definition(module, stage, name);
	if (routine_definition == NULL)
		return NULL;

	routine = fm_config_routine_alloc(routine_definition->stage, routine_definition->name);

	fm_config_routine_resolve_probes(routine, FM_PROBE_MODE_BCAST, &routine_definition->broadcast_probes, module);
	fm_config_routine_resolve_probes(routine, FM_PROBE_MODE_TOPO, &routine_definition->topology_probes, module);
	fm_config_routine_resolve_probes(routine, FM_PROBE_MODE_HOST, &routine_definition->host_probes, module);
	fm_config_routine_resolve_probes(routine, FM_PROBE_MODE_PORT, &routine_definition->port_probes, module);

	return routine;
}

/*
 * Resolve things such as service definitions, service catalogs etc.
 * A name can be qualified, as in module_name.resource_name
 *
 * We interpret unqualifieds name as the name of a module; the resource to look
 * for inside this module is called "default", so IOW the name "foobar"
 * is taken to refer to "foobar.default"
 */
static const fm_config_module_t *
fm_config_library_resolve_module(fm_config_library_t *lib, const char *subdir, const char **name_p, const fm_config_module_t *context)
{
	const fm_config_module_t *module;
	char *module_name;

	module_name = fm_config_library_parse_reference(name_p);
	if (module_name != NULL) {
		/* The name explicitly referenced a module. Easy. */
		module = fm_config_library_find_module_with_type(lib, subdir, module_name, true);
		free(module_name);
	} else {
		module = fm_config_library_find_module_with_type(lib, subdir, *name_p, true);
		*name_p = "default";
	}

	if (module == NULL || module->state != LOADED)
		return NULL;

	/* Let the caller take care of looking up the actual resource inside the module. */
	return module;
}

extern fm_config_service_t *
fm_config_library_resolve_service(fm_config_library_t *lib, const char *name, const fm_config_module_t *context)
{
	const fm_config_module_t *module;

	if ((module = fm_config_library_resolve_module(lib, "service", &name, context)) == NULL)
		return NULL;
	return fm_config_module_find_service(module, name);
}

extern fm_config_catalog_t *
fm_library_resolve_service_catalog(fm_config_library_t *lib, const char *name, const fm_config_module_t *context)
{
	const fm_config_module_t *module;

	if ((module = fm_config_library_resolve_module(lib, "service", &name, context)) == NULL)
		return NULL;
	return fm_config_module_find_service_catalog(module, name);
}

/*
 * Service probes
 * For now, a service probe defines one or more probe packets to send, and the
 * standard ports on which you would normally suspect this service.
 */
static fm_config_service_t *
fm_config_service_alloc(const char *name, fm_config_service_array_t *array)
{
	fm_config_service_t *service;

	service = calloc(1, sizeof(*service));
	service->name = strdup(name);

	if (array)
		fm_config_service_array_append(array, service);
	return service;
}

static void
fm_config_service_finalize(fm_config_service_t *service, fm_config_module_t *module)
{
	asprintf((char **) &service->fullname, "%s.%s", module->name, service->name);
	service->containing_module = module;
}

/*
 * Load a collection of routines into our library
 */
static bool
fm_config_module_load(fm_config_module_t *module, const char *path)
{
	curly_node_t *top;
	unsigned int i;
	bool rv;

	if (access(path, F_OK) < 0)
		return true;

	top = curly_node_read(path);
	if (top == NULL) {
		fm_log_error("Unable to parse config file %s", path);
		return false;
	}

	rv = fm_config_module_process(module, top);

	curly_node_free(top);

	/* Make the newly created service catalogs point back to the
	 * module that contains them */
	for (i = 0; i < module->service_catalogs.count; ++i)
		module->service_catalogs.entries[i]->containing_module = module;

	for (i = 0; i < module->presets.count; ++i)
		module->presets.entries[i]->containing_module = module;

	for (i = 0; i < module->routines.count; ++i)
		module->routines.entries[i]->containing_module = module;

	for (i = 0; i < module->services.count; ++i)
		fm_config_service_finalize(module->services.entries[i], module);

	return rv;
}

/*
 * Process a port or port range
 */
static bool
fm_config_routine_parse_port_list_entry(const char *arg, fm_uint_array_t *array)
{
	fm_port_range_t range;
	unsigned int low_port, high_port;

	/* TODO: if the argument is an alpha string, try getportbyname() */

	if (!fm_parse_port_range(arg, &range))
		return false;

	low_port = range.first;
	high_port = range.last;

	if (low_port == 0 || low_port > high_port || high_port > 65535)
		return false;

	while (low_port <= high_port)
		fm_uint_array_append(array, low_port++);

	return true;
}

/*
 * Process the list of ports or port ranges, convert to an int array of ports.
 */
static bool
fm_config_routine_parse_port_list(const fm_string_array_t *strings, const char *proto_name, fm_uint_array_t *values)
{
	unsigned int i;

	if (strings == NULL)
		return true;

	for (i = 0; i < strings->count; ++i) {
		const char *arg = strings->entries[i];

		if (!fm_config_routine_parse_port_list_entry(arg, values)) {
			fm_log_error("unable to parse %s port or port range \"%s\"", proto_name, arg);
			fm_uint_array_destroy(values);
			return false;
		}
	}

	return true;
}

/*
 * Finalize the probe definition just loaded.
 */
bool
fm_config_routine_bind_ports(fm_config_routine_t *routine, const char *proto_name, const fm_string_array_t *port_strings)
{
	fm_uint_array_t port_values = { 0 };
	unsigned int i;

	if (!fm_config_routine_parse_port_list(port_strings, proto_name, &port_values))
		return false;

	for (i = 0; i < routine->probes.count; ++i) {
		fm_config_probe_t *probe = routine->probes.entries[i];

		if (strcmp(probe->proto_name, proto_name))
			continue;

		if (port_values.count == 0) {
			fm_log_error("using port probe %s, but no %s ports defined by project", probe->name, proto_name);
			return false;
		}

		fm_uint_array_copy(&probe->ports, &port_values);
	}

	return true;
}

/*
 * Handle nodes like
 *   host-scan blah { ... }
 */
static void *
fm_config_module_create_routine_definition(curly_node_t *node, fm_config_routine_definition_array_t *array, int stage)
{
	const char *name = curly_node_name(node);

	return fm_config_routine_definition_alloc(stage, name, array);
}

static void *
fm_config_module_create_topo_routine(curly_node_t *node, void *data)
{
	return fm_config_module_create_routine_definition(node, data, FM_SCAN_STAGE_TOPO);
}

static void *
fm_config_module_create_host_routine(curly_node_t *node, void *data)
{
	return fm_config_module_create_routine_definition(node, data, FM_SCAN_STAGE_HOST);
}

static void *
fm_config_module_create_port_routine(curly_node_t *node, void *data)
{
	return fm_config_module_create_routine_definition(node, data, FM_SCAN_STAGE_PORT);
}

static void *
fm_config_module_create_discovery_routine(curly_node_t *node, void *data)
{
	return fm_config_module_create_routine_definition(node, data, FM_SCAN_STAGE_DISCOVERY);
}

/*
 * Handle presets blah { ... }
 */
static void *
fm_config_module_create_preset(curly_node_t *node, void *data)
{
	fm_config_preset_array_t *array = data;
	const char *name = curly_node_name(node);

	return fm_config_preset_alloc(name, array);
}

/*
 * Handle
 *  service-probe blah { .. }
 */
static void *
fm_config_module_create_service(curly_node_t *node, void *data)
{
	fm_config_service_array_t *array = data;
	const char *name = curly_node_name(node);

	return fm_config_service_alloc(name, array);
}

static void *
fm_config_module_create_service_catalog(curly_node_t *node, void *data)
{
	fm_config_catalog_array_t *array = data;
	const char *name = curly_node_name(node);

	return fm_config_catalog_alloc(name, NULL, array);
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
	else if (!strcmp(type, "broadcast-probe"))
		mode = FM_PROBE_MODE_BCAST;
	else
		fm_log_fatal("BUG: don't know about %s", type);

	parsed_probe = calloc(1, sizeof(*parsed_probe));
	parsed_probe->name = strdup(name);
	parsed_probe->mode = mode;
	fm_config_probe_array_append(array, parsed_probe);

	return parsed_probe;
}

/*
 * This is a bit messy because we throw all probes into one array, and
 * need to loop through them on a type basis when writing back to file.
 */
static void *
fm_config_probes_iterate(int mode, void *data, unsigned int index)
{
	fm_config_probe_array_t *array = (fm_config_probe_array_t *) data;
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		fm_config_probe_t *probe = array->entries[i];

		if (probe->mode == mode && index-- == 0)
			return probe;
	}
	return NULL;
}

static void *
fm_config_topo_probes_iterate(const fm_config_child_t *child_proc, void *data, unsigned int index)
{
	return fm_config_probes_iterate(FM_PROBE_MODE_TOPO, data, index);
}

static void *
fm_config_host_probes_iterate(const fm_config_child_t *child_proc, void *data, unsigned int index)
{
	return fm_config_probes_iterate(FM_PROBE_MODE_HOST, data, index);
}

static void *
fm_config_port_probes_iterate(const fm_config_child_t *child_proc, void *data, unsigned int index)
{
	return fm_config_probes_iterate(FM_PROBE_MODE_PORT, data, index);
}

static void *
fm_config_broadcast_probes_iterate(const fm_config_child_t *child_proc, void *data, unsigned int index)
{
	return fm_config_probes_iterate(FM_PROBE_MODE_BCAST, data, index);
}

/*
 * Marshal/unmarshal a routine pointer
 */
void *
fm_project_routine_ptr_alloc(curly_node_t *node, void *data)
{
	fm_config_routine_t **pointer_p = data;
	fm_config_routine_t *routine;

	routine = fm_config_routine_alloc(FM_SCAN_STAGE_PORT, NULL);
	*pointer_p = routine;
	return routine;
}

void *
fm_project_routine_ptr_iterate(const fm_config_child_t *child_proc, void *data, unsigned int index)
{
	fm_config_routine_t **pointer_p = data;

	if (index > 0 || *pointer_p == NULL)
		return NULL;

	return *pointer_p;
}

static void *
fm_config_packet_root_create(curly_node_t *node, void *data)
{
	fm_config_packet_array_t *array = (fm_config_packet_array_t *) data;
	const char *name = curly_node_name(node);
	fm_config_packet_t *parsed_packet;

	parsed_packet = calloc(1, sizeof(*parsed_packet));
	parsed_packet->name = strdup(name);
	fm_config_packet_array_append(array, parsed_packet);

	return parsed_packet;
}

/*
 * Parse a packet payload as a sequence of hex octets
 */
static bool
fm_config_packet_set_payload(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	fm_buffer_t **payload_p = attr_data, *bp;
	const char *attr_name = curly_attr_get_name(attr);
	unsigned int k, nattrs, pos, raw_len;

	nattrs = curly_attr_get_count(attr);
	for (k = 0, raw_len = 0; k < nattrs; ++k) {
		const char *octet = curly_attr_get_value(attr, k);

		if (!strncmp(octet, "str:", 4))
			raw_len += strlen(octet + 4);
		else
			raw_len += 1;
	}

	*payload_p = bp = fm_buffer_alloc(raw_len);

	for (k = 0, pos = 0; k < nattrs; ++k) {
		const char *octet = curly_attr_get_value(attr, k);
		const char *end;

		if (!strncmp(octet, "str:", 4)) {
			unsigned int nbytes = strlen(octet + 4);

			assert(pos + nbytes <= raw_len);
			memcpy(bp->data + pos, octet + 4, nbytes);
			pos += nbytes;
		} else {
			bp->data[pos++] = strtoul(octet, (char **) &end, 0);
			if (*end) {
				fm_config_complain(node, "attribute %s: cannot parse octet at index %u: \"%s\"", attr_name, k, octet);
				return false;
			}
		}
	}

	bp->wpos = pos;

	assert(fm_buffer_available(bp));
	return true;
}

static bool
fm_config_packet_get_payload(curly_node_t *node, void *attr_data, const char *attr_name)
{
	fm_buffer_t **bufp = attr_data;
	fm_buffer_t *bp;
	const unsigned char *data;
	unsigned int i, len;

	if ((bp = *bufp) == NULL)
		return true;

	len = fm_buffer_available(bp);
	if (len == 0)
		return true;

	data = fm_buffer_head(bp);
	for (i = 0; i < len; ++i) {
		char value[16];

		snprintf(value, sizeof(value), "0x%02x", data[i]);
		curly_node_add_attr_list(node, attr_name, value);
	}

	return true;
}

/*
 * curly file structure for library
 */
static fm_config_proc_t	fm_config_probe_root = {
	.name = ATTRIB_STRING(fm_config_probe_t, name),
	.attributes = {
		{ "info",	offsetof(fm_config_probe_t, info),			FM_CONFIG_ATTR_TYPE_STRING },
		{ "protocol",	offsetof(fm_config_probe_t, proto_name),		FM_CONFIG_ATTR_TYPE_STRING },
		{ "optional",	offsetof(fm_config_probe_t, optional),			FM_CONFIG_ATTR_TYPE_BOOL },
		{ "random",	offsetof(fm_config_probe_t, random),			FM_CONFIG_ATTR_TYPE_BOOL },
		{ "retries",	offsetof(fm_config_probe_t, retries),			FM_CONFIG_ATTR_TYPE_INT },
		{ "payload",	offsetof(fm_config_probe_t, payload),			FM_CONFIG_ATTR_TYPE_SPECIAL, .setfn = fm_config_packet_set_payload, .getfn = fm_config_packet_get_payload },

		{ "*",		offsetof(fm_config_probe_t, extra_args),		FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
	},
};

static fm_config_proc_t	fm_config_packet_root = {
	.name = ATTRIB_STRING(fm_config_packet_t, name),
	.attributes = {
		{ "payload",		offsetof(fm_config_packet_t, payload),		FM_CONFIG_ATTR_TYPE_SPECIAL, .setfn = fm_config_packet_set_payload }
	},
};

fm_config_proc_t	fm_config_routine_root = {
	.name = ATTRIB_STRING(fm_config_routine_t, name),
	.attributes = {
		ATTRIB_BOOL(fm_config_routine_t, optional),
		{ "topo-probe",		offsetof(fm_config_routine_t, topology_probes),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "host-probe",		offsetof(fm_config_routine_t, host_probes),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "port-probe",		offsetof(fm_config_routine_t, port_probes),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "broadcast-probe",	offsetof(fm_config_routine_t, broadcast_probes),FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
	},
	.children = {
		{ "topo-probe",		offsetof(fm_config_routine_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create, .iterate_children = fm_config_topo_probes_iterate, },
		{ "host-probe",		offsetof(fm_config_routine_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create, .iterate_children = fm_config_host_probes_iterate },
		{ "port-probe",		offsetof(fm_config_routine_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create, .iterate_children = fm_config_port_probes_iterate },
		{ "broadcast-probe",	offsetof(fm_config_routine_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create, .iterate_children = fm_config_broadcast_probes_iterate },
	},
};

static fm_config_proc_t	fm_config_routine_definition_root = {
	.name = ATTRIB_STRING(fm_config_routine_definition_t, name),
	.attributes = {
		{ "topo-probe",		offsetof(fm_config_routine_definition_t, topology_probes),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "host-probe",		offsetof(fm_config_routine_definition_t, host_probes),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "port-probe",		offsetof(fm_config_routine_definition_t, port_probes),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "broadcast-probe",	offsetof(fm_config_routine_definition_t, broadcast_probes),FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
	},
};

static fm_config_proc_t	fm_config_service_root = {
	.name = ATTRIB_STRING(fm_config_service_t, name),
	.attributes = {
		ATTRIB_INT_ARRAY(fm_config_service_t, tcp_ports),
		ATTRIB_INT_ARRAY(fm_config_service_t, udp_ports),
	},
	.children = {
		{ "packet",		offsetof(fm_config_service_t, packets),		&fm_config_packet_root, .alloc_child = fm_config_packet_root_create },
	},
};

static fm_config_proc_t	fm_config_catalog_root = {
	.name = ATTRIB_STRING(fm_config_catalog_t, name),
	.attributes = {
		{ "use",		offsetof(fm_config_catalog_t, names),		FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "extend",		offsetof(fm_config_catalog_t, extend),		FM_CONFIG_ATTR_TYPE_STRING },
	},
};

static fm_config_proc_t	fm_config_preset_root = {
	.name = ATTRIB_STRING(fm_config_preset_t, name),
	.attributes = {
		{ "info",		offsetof(fm_config_preset_t, info),		FM_CONFIG_ATTR_TYPE_STRING },
		{ "tcp-ports",		offsetof(fm_config_preset_t, tcp_ports),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "udp-ports",		offsetof(fm_config_preset_t, udp_ports),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY },
		{ "discovery-scan",	offsetof(fm_config_preset_t, discovery_scan),	FM_CONFIG_ATTR_TYPE_STRING },
		{ "topology-scan",	offsetof(fm_config_preset_t, topology_scan),	FM_CONFIG_ATTR_TYPE_STRING },
		{ "host-scan",		offsetof(fm_config_preset_t, host_scan),	FM_CONFIG_ATTR_TYPE_STRING },
		{ "port-scan",		offsetof(fm_config_preset_t, port_scan),	FM_CONFIG_ATTR_TYPE_STRING },
	},
};

static fm_config_proc_t	fm_config_module_root = {
	.children = {
		{ "topology-scan",	offsetof(fm_config_module_t, routines),	&fm_config_routine_definition_root, .alloc_child = fm_config_module_create_topo_routine },
		{ "host-scan",		offsetof(fm_config_module_t, routines),	&fm_config_routine_definition_root, .alloc_child = fm_config_module_create_host_routine },
		{ "port-scan",		offsetof(fm_config_module_t, routines),	&fm_config_routine_definition_root, .alloc_child = fm_config_module_create_port_routine },
		{ "discovery-scan",	offsetof(fm_config_module_t, routines),	&fm_config_routine_definition_root, .alloc_child = fm_config_module_create_discovery_routine },
		{ "service-probe",	offsetof(fm_config_module_t, services),	&fm_config_service_root, .alloc_child = fm_config_module_create_service },
		{ "service-catalog",	offsetof(fm_config_module_t, service_catalogs),
										&fm_config_catalog_root, .alloc_child = fm_config_module_create_service_catalog },
		{ "preset",		offsetof(fm_config_module_t, presets),	&fm_config_preset_root,  .alloc_child = fm_config_module_create_preset },
		{ "topo-probe",		offsetof(fm_config_module_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
		{ "host-probe",		offsetof(fm_config_module_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
		{ "port-probe",		offsetof(fm_config_module_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
		{ "broadcast-probe",	offsetof(fm_config_module_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
	},
};

static bool
fm_config_module_process(fm_config_module_t *module, curly_node_t *node)
{
	if (!fm_config_process_node(node, &fm_config_module_root, module)) {
		fm_config_complain(node, "unable to parse module definition");
		return false;
	}

	return true;
}

extern fm_config_catalog_t *
fm_config_library_resolve_service_catalog(fm_config_library_t *lib, const char *name, const fm_config_module_t *context)
{
	const fm_config_module_t *module;

	module = fm_config_library_resolve_reference_partial(lib, context, &name);
	if (module == NULL)
		return NULL;

	return fm_config_module_find_service_catalog(module, name);
}

/*
 * Service catalogs
 */
static fm_config_catalog_t *
fm_config_catalog_alloc(const char *name, const fm_config_module_t *module, fm_config_catalog_array_t *array)
{
	fm_config_catalog_t *catalog;

	catalog = calloc(1, sizeof(*catalog));
	catalog->name = strdup(name);
	catalog->containing_module = module;

	if (array)
		fm_config_catalog_array_append(array, catalog);
	return catalog;
}

static bool
fm_config_catalog_resolve_services(fm_config_catalog_t *catalog, fm_service_catalog_t *service_catalog)
{
	fm_config_library_t *lib = fm_config_load_library();
	const fm_config_module_t *context;
	unsigned int i;

	while (catalog != NULL) {
		context = catalog->containing_module;
		for (i = 0; i < catalog->names.count; ++i) {
			const char *name = catalog->names.entries[i];
			fm_config_service_t *service;

			service = fm_config_library_resolve_service(lib, name, context);
			if (service == NULL) {
				fm_log_error("service catalog %s.%s: could not find referenced service %s",
						context->name, catalog->name, name);
				return false;
			}

			fm_service_catalog_add_service(service_catalog, service);
		}

		if (catalog->extend == NULL) {
			break;
		} else {
			fm_config_catalog_t *next;

			next = fm_library_resolve_service_catalog(lib, catalog->extend, context);
			if (next == NULL) {
				fm_log_error("service catalog %s.%s: extends service catalog %s, but I could not find it",
						context->name, catalog->name, catalog->extend);
				return false;
			}

			/* FIXME: we do not protect against circular loops */
			catalog = next;
		}

	}

	return true;
}

/*
 * program objects
 */
fm_config_program_t *
fm_config_program_alloc(void)
{
	fm_config_program_t *program;

	program = calloc(1, sizeof(*program));
	program->service_catalog = fm_service_catalog_alloc();
	return program;
}

bool
fm_config_program_set_stage(fm_config_program_t *program, unsigned int index, const fm_config_routine_t *routine)
{
	if (index >= __FM_SCAN_STAGE_MAX)
		return false;

	program->stage[index] = routine;
	return true;
}

void
fm_config_program_free(fm_config_program_t *program)
{
	free(program);
}

void
fm_config_program_dump(const fm_config_program_t *program)
{
	/* this does not do anything right now */
}


/*
 * Attach service catalog
 */
bool
fm_config_program_set_service_catalog(fm_config_program_t *program, const char *name)
{
	fm_config_module_t *context = NULL;
	fm_config_catalog_t *catalog;
	fm_config_library_t *lib;

	lib = fm_config_load_library();

	if (!strchr(name, '.')) {
		context = fm_config_library_find_module(lib, "standard", true);
		assert(context != NULL);
	} else  {
		abort();
	}

	if (!(catalog = fm_config_load_service_catalog(name, context)))
		return false;

	if (!fm_config_catalog_resolve_services(catalog, program->service_catalog))
		return false;

	return true;
}

/*
 * Convert a program into a sequence of scan actions
 */
static bool
fm_config_routine_compile(const fm_config_routine_t *routine, fm_scanner_t *scanner)
{
	unsigned int i;
	bool ok = true;

	if (routine == NULL)
		return true;

	for (i = 0; ok && i < routine->probes.count; ++i) {
		fm_config_probe_t *probe = routine->probes.entries[i];

		ok = fm_scanner_add_probe(scanner, routine->stage, probe) && ok;
	}

	return ok;
}

bool
fm_config_program_compile(const fm_config_program_t *program, fm_scanner_t *scanner)
{
	unsigned int i;

	fm_scanner_set_service_catalog(scanner, program->service_catalog);

	for (i = 0; i < __FM_SCAN_STAGE_MAX; ++i) {
		if (!fm_config_routine_compile(program->stage[i], scanner))
			return false;
	}

	return true;
}
