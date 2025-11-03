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

typedef struct fm_config_probe_array {
	unsigned int		count;
	fm_config_probe_t **	entries;
} fm_config_probe_array_t;

typedef struct fm_config_catalog_array {
	unsigned int		count;
	fm_config_catalog_t **	entries;
} fm_config_catalog_array_t;

struct fm_config_module {
	const char *		name;
	int			state;
	fm_config_routine_array_t routines;
	fm_config_service_array_t services;
	fm_config_catalog_array_t	service_catalogs;
};

struct fm_config_routine {
	const char *		name;
	int			mode;
	bool			optional;
	fm_config_probe_array_t	probes;
};

struct fm_config_library {
	fm_string_array_t	search_path;
	fm_config_module_array_t	modules;
};


static fm_config_catalog_t *fm_config_catalog_alloc(const char *name, const fm_config_module_t *module, fm_config_catalog_array_t *array);
static bool		fm_config_module_process(fm_config_module_t *module, curly_node_t *node);
static fm_config_module_t *fm_config_library_find_module(fm_config_library_t *lib, const char *name, bool load_if_missing);
static bool		fm_config_module_load(fm_config_module_t *module, const char *path);


/*
 * These are global entry points for the application
 */
fm_config_library_t *
fm_config_load_library(void)
{
	static fm_config_library_t *the_library;

	if (the_library == NULL) {
		the_library = fm_config_library_alloc(NULL);

		if (!fm_config_library_find_module(the_library, "standard", true))
			the_library = NULL;
	}
	return the_library;
}

fm_config_routine_t *
fm_config_load_routine(int mode, const char *name)
{
	fm_config_library_t *lib;

	if (name == NULL)
		return NULL;

	if ((lib = fm_config_load_library()) == NULL)
		return NULL;

	return fm_config_library_resolve_routine(lib, mode, name);
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
void
fm_config_routine_array_append(fm_config_routine_array_t *array, fm_config_routine_t *routine)
{
	maybe_realloc_array(array->entries, array->count, 32);
	array->entries[array->count++] = routine;
}

static fm_config_routine_t *
fm_config_routine_array_find(const fm_config_routine_array_t *array, int mode, const char *name)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		fm_config_routine_t *routine = array->entries[i];
		if (routine->mode == mode && !strcmp(routine->name, name))
			return routine;
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
static fm_config_routine_t *
fm_config_module_find_routine(fm_config_module_t *module, int mode, const char *name)
{
	if (module->state != LOADED)
		return NULL;

	return fm_config_routine_array_find(&module->routines, mode, name);
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
fm_config_routine_alloc(int mode, const char *name, fm_config_routine_array_t *array)
{
	fm_config_routine_t *routine;

	routine = calloc(1, sizeof(*routine));
	routine->mode = mode;
	routine->name = strdup(name);

	if (array)
		fm_config_routine_array_append(array, routine);

	return routine;
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

static char *
fm_config_library_parse_routine_reference(const char **name_p)
{
	return fm_config_library_parse_reference(name_p);
}

static char *
fm_config_library_parse_catalog_reference(const char **name_p)
{
	return fm_config_library_parse_reference(name_p);
}

extern fm_config_routine_t *
fm_config_library_resolve_routine(fm_config_library_t *lib, int mode, const char *name)
{
	fm_config_routine_t *routine = NULL;
	char *module_name;
	fm_config_module_t *module;

	module_name = fm_config_library_parse_routine_reference(&name);
	if (module_name != NULL) {
		module = fm_config_library_find_module(lib, module_name, true);
		free(module_name);

		if (module == NULL || module->state != LOADED)
			return NULL;

		routine = fm_config_module_find_routine(module, mode, name);
	} else {
		unsigned int i;

		/* No module name provided; just loop over all modules and return
		 * whatever matches. */
		for (i = 0; i < lib->modules.count && routine == NULL; ++i) {
			fm_config_module_t *module = lib->modules.entries[i];

			routine = fm_config_module_find_routine(module, mode, name);
		}
	}

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
	for (i = 0; i < module->service_catalogs.count; ++i) {
		fm_config_catalog_t *catalog = module->service_catalogs.entries[i];
		catalog->containing_module = module;
	}

	for (i = 0; i < module->services.count; ++i)
		fm_config_service_finalize(module->services.entries[i], module);

	return rv;
}

static void
fm_config_probe_array_append(fm_config_probe_array_t *array, fm_config_probe_t *parsed_probe)
{
	maybe_realloc_array(array->entries, array->count, 4);
	array->entries[array->count++] = parsed_probe;
}

/*
 * Handle nodes like
 *   host-scan blah { ... }
 */
static void *
fm_config_module_create_routine(curly_node_t *node, fm_config_routine_array_t *array, int mode)
{
	const char *name = curly_node_name(node);

	return fm_config_routine_alloc(mode, name, array);
}

static void *
fm_config_module_create_topo_routine(curly_node_t *node, void *data)
{
	return fm_config_module_create_routine(node, data, FM_PROBE_MODE_TOPO);
}

static void *
fm_config_module_create_host_routine(curly_node_t *node, void *data)
{
	return fm_config_module_create_routine(node, data, FM_PROBE_MODE_HOST);
}

static void *
fm_config_module_create_port_routine(curly_node_t *node, void *data)
{
	return fm_config_module_create_routine(node, data, FM_PROBE_MODE_PORT);
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
	else
		fm_log_fatal("BUG: don't know about %s", type);

	parsed_probe = calloc(1, sizeof(*parsed_probe));
	parsed_probe->name = strdup(name);
	parsed_probe->mode = mode;
	fm_config_probe_array_append(array, parsed_probe);

	return parsed_probe;
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
 * Handle unknown attributes - convert them to foo=bar notation and store them as strings
 * probe->extra_args.
 * If the attribute contains more than one value, we concat them together as
 *   foo=bar,baz,bloopie
 */
static bool
fm_config_probe_set_extra(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	fm_string_array_t *extra_args = attr_data;
	const char *attr_name = curly_attr_get_name(attr);
	const char *attr_value;
	unsigned int k, count, size, pos;
	char *formatted;

	count = curly_attr_get_count(attr);

	size = strlen(attr_name) + 1;
	for(k = 0; k < count; ++k) {
		attr_value = curly_attr_get_value(attr, k);

		size += strlen(attr_value) + 1;
	}

	formatted = calloc(size, 1);
	strcpy(formatted, attr_name);

	for(k = 0, pos = 0; k < count; ++k) {
		pos += strlen(formatted + pos);

		if (k == 0)
			formatted[pos++] = '=';
		else
			formatted[pos++] = ',';

		strcpy(formatted + pos, curly_attr_get_value(attr, k));
	}

	assert(formatted[size - 1] == 0);

	fm_string_array_append(extra_args, formatted);
	free(formatted);

	return true;
}

/*
 * Parse a packet payload as a sequence of hex octets
 */
static bool
fm_config_packet_set_payload(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	fm_buffer_t **payload_p = attr_data, *bp;
	const char *attr_name = curly_attr_get_name(attr);
	unsigned int k, raw_len;

	raw_len = curly_attr_get_count(attr);
	*payload_p = bp = fm_buffer_alloc(raw_len);

	for (k = 0; k < raw_len; ++k) {
		const char *octet = curly_attr_get_value(attr, k);
		const char *end;

		bp->data[k] = strtoul(octet, (char **) &end, 0);
		if (*end) {
			fm_config_complain(node, "attribute %s: cannot parse octet at index %u: \"%s\"", attr_name, k, octet);
			return false;
		}
	}

	bp->wpos = k;

	assert(fm_buffer_available(bp));
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

static fm_config_proc_t	fm_config_packet_root = {
	.name = ATTRIB_STRING(fm_config_packet_t, name),
	.attributes = {
		{ "payload",		offsetof(fm_config_packet_t, payload),		FM_CONFIG_ATTR_TYPE_SPECIAL, .setfn = fm_config_packet_set_payload }
	},
};

static fm_config_proc_t	fm_config_routine_root = {
	.name = ATTRIB_STRING(fm_config_routine_t, name),
	.attributes = {
		ATTRIB_BOOL(fm_config_routine_t, optional),
	},
	.children = {
		{ "topo-probe",		offsetof(fm_config_routine_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
		{ "host-probe",		offsetof(fm_config_routine_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
		{ "port-probe",		offsetof(fm_config_routine_t, probes),	&fm_config_probe_root, .alloc_child = fm_config_probe_root_create },
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

static fm_config_proc_t	fm_config_module_root = {
	.children = {
		{ "topology-scan",	offsetof(fm_config_module_t, routines),	&fm_config_routine_root, .alloc_child = fm_config_module_create_topo_routine },
		{ "host-scan",		offsetof(fm_config_module_t, routines),	&fm_config_routine_root, .alloc_child = fm_config_module_create_host_routine },
		{ "port-scan",		offsetof(fm_config_module_t, routines),	&fm_config_routine_root, .alloc_child = fm_config_module_create_port_routine },
		{ "service-probe",	offsetof(fm_config_module_t, services),	&fm_config_service_root, .alloc_child = fm_config_module_create_service },
		{ "service-catalog",	offsetof(fm_config_module_t, service_catalogs),
										&fm_config_catalog_root, .alloc_child = fm_config_module_create_service_catalog },

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
fm_config_library_resolve_service_catalog(fm_config_library_t *lib, const char *name, fm_config_module_t *context)
{
	char *module_name;
	fm_config_module_t *module;

	module_name = fm_config_library_parse_catalog_reference(&name);
	if (module_name != NULL) {
		module = fm_config_library_find_module(lib, module_name, true);
		free(module_name);
	} else {
		module = context;
	}

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

fm_config_program_t *
fm_config_program_build(const char *name, const char *topology_scan, const char *host_scan, const char *port_scan)
{
	fm_config_program_t *program;

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

	program->service_catalog = fm_service_catalog_alloc();

	return program;

fail:
	fm_config_program_free(program);
	return NULL;
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

	for (i = 0; ok && i < routine->probes.count; ++i) {
		fm_config_probe_t *probe = routine->probes.entries[i];

		ok = fm_scanner_add_probe(scanner, probe) && ok;

		if (routine->mode == FM_PROBE_MODE_HOST) {
			fm_scanner_insert_barrier(scanner);
			fm_scanner_add_reachability_check(scanner);
		}
	}

	return ok;
}

bool
fm_config_program_compile(const fm_config_program_t *program, fm_scanner_t *scanner)
{
	fm_scanner_set_service_catalog(scanner, program->service_catalog);

	return fm_config_routine_compile(program->topo_scan, scanner)
	    && fm_config_routine_compile(program->host_scan, scanner)
	    && fm_config_routine_compile(program->port_scan, scanner);
}
