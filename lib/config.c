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
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <curlies.h>

#include "freemap.h"
#include "config.h"
#include "projects.h"
#include "filefmt.h"
#include "program.h"
#include "logging.h"

static fm_config_proc_t		fm_config_root;
static fm_config_proc_t		fm_project_root;

static bool		fm_config_render_node(curly_node_t *node, fm_config_proc_t *proc, void *data);
static bool		fm_config_apply_value(curly_node_t *node, void *data, const fm_config_attr_t *attr_def, const curly_attr_t *attr);
static void		fm_config_dump(curly_node_t *np, unsigned int indent);

fm_config_t *
fm_config_create(const fm_config_t *inherit)
{
	fm_config_t *conf;

	conf = calloc(1, sizeof(*conf));
	if (inherit)
		*conf = *inherit;

	return conf;
}

static bool
fm_config_load_work(const char *path, fm_config_proc_t *root_proc, void *data)
{
	curly_node_t *top;
	bool rv;

	if (access(path, F_OK) < 0)
		return true;

	top = curly_node_read(path);
	if (top == NULL) {
		fm_log_error("Unable to parse config file %s", path);
		return false;
	}

	/* fm_config_dump(top, 0); */

	rv = fm_config_process_node(top, root_proc, data);

	curly_node_free(top);
	return rv;
}

static bool
fm_config_save_work(const char *path, fm_config_proc_t *root_proc, const char *type, const char *name, void *data)
{
	curly_node_t *root;
	bool rv;

	root = curly_node_new();

	rv = fm_config_render_node(root, root_proc, data);

	if (rv) {
		char *temp_path = NULL;
		FILE *fp;

		if (false) {
			printf("Trying to save to %s\n", path);
			fm_config_dump(root, 0);
		}

		asprintf(&temp_path, "%s.tmp", path);
		if (!(fp = fopen(temp_path, "w"))) {
			fm_log_error("Unable to open %s for writing: %m", temp_path);
			rv = false;
		} else if (curly_node_write_fp(root, fp) < 0) {
			fm_log_error("failed to write configuration data to %s", temp_path);
			rv = false;
		}

		if (fp != NULL)
			fclose(fp);

		if (rv && rename(temp_path, path) < 0) {
			fm_log_error("failed to rename %s to %s: %m", temp_path, path);
			rv = false;
		}

		free(temp_path);
	}

	curly_node_free(root);
	return rv;
}

bool
fm_config_load(fm_config_t *conf, const char *path)
{
	return fm_config_load_work(path, &fm_config_root, conf);
}

bool
fm_config_load_project(fm_project_t *project, const char *path)
{
	if (!fm_config_load_work(path, &fm_project_root, project))
		return false;

	if (project->port_scan != NULL) {
		fm_config_routine_bind_ports(project->port_scan, "udp", &project->udp_ports);
		fm_config_routine_bind_ports(project->port_scan, "tcp", &project->tcp_ports);
	}

	return true;
}

bool
fm_config_save_project(fm_project_t *project, const char *path)
{
	return fm_config_save_work(path, &fm_project_root, "project", project->name, project);
}

/*
 * Error handling
 */
void
fm_config_complain(curly_node_t *node, const char *fmt, ...)
{
	const char *filename = curly_node_get_source_file(node);
	unsigned int line = curly_node_get_source_line(node);
	char msgbuf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	if (filename != NULL) {
		fm_log_error("%s, line %u: %s", filename, line, msgbuf);
	} else {
		fm_log_error("%s", msgbuf);
	}
	va_end(ap);
}

static inline void *
fm_config_addr_apply_offset(void *data, unsigned int offset)
{
	caddr_t child_data_addr = (caddr_t) data + offset;
	return (void *) child_data_addr;
}

static bool
set_address_family(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	const char *value = curly_attr_get_value(attr, 0);

	if (!strcasecmp(value, "ipv4"))
		*(int *) attr_data = AF_INET;
	else if (!strcasecmp(value, "ipv6"))
		*(int *) attr_data = AF_INET6;
	else if (!strcasecmp(value, "any"))
		*(int *) attr_data = AF_UNSPEC;
	else
		return false;
	return true;
}

/*
 * library
 */
static fm_config_proc_t		fm_config_library = {
	.attributes = {
		ATTRIB_STRING_ARRAY(struct fm_config_library_settings, search_path),
	},
};

/*
 * address_generation
 */
static fm_config_proc_t		fm_config_address_generation = {
	.attributes = {
		ATTRIB_SPECIAL(struct fm_config_address_generation, only_family, set_address_family),
		ATTRIB_BOOL(struct fm_config_address_generation, try_all),
		ATTRIB_BOOL(struct fm_config_address_generation, randomize),
	},
};

/*
 * target-pool
 */
static fm_config_proc_t		fm_config_target_pool = {
	.attributes = {
		ATTRIB_INT(struct fm_config_target_pool, initial_size),
		ATTRIB_INT(struct fm_config_target_pool, max_size),
		ATTRIB_INT(struct fm_config_target_pool, resize_interval),
	},
};

/*
 * scanner
 */
static fm_config_proc_t		fm_config_scanner = {
	.attributes = {
		ATTRIB_INT(struct fm_config_scanner, global_packet_rate),
		ATTRIB_INT(struct fm_config_scanner, target_packet_rate),
		ATTRIB_INT(struct fm_config_scanner, socket_send_buffer),
	},
};

/*
 * ipv4 node
 */
static fm_config_proc_t		fm_config_ipv4 = {
	.attributes = {
		ATTRIB_INT(struct fm_config_ipv4, ttl),
		ATTRIB_INT(struct fm_config_ipv4, tos),
	},
};

/*
 * ipv6 node
 */
static fm_config_proc_t		fm_config_ipv6 = {
	.attributes = {
		ATTRIB_INT(struct fm_config_ipv6, ttl),
		ATTRIB_INT(struct fm_config_ipv6, tos),
	},
};

/*
 * udp node
 */
static fm_config_proc_t		fm_config_udp = {
	.attributes = {
		ATTRIB_INT(struct fm_config_udp, application_delay),
		ATTRIB_INT(struct fm_config_udp, retries),
		ATTRIB_INT(struct fm_config_udp, packet_spacing),
		ATTRIB_INT(struct fm_config_udp, timeout),
	},
};

/*
 * tcp node
 */
static fm_config_proc_t		fm_config_tcp = {
	.attributes = {
		ATTRIB_INT(struct fm_config_tcp, application_delay),
		ATTRIB_INT(struct fm_config_tcp, retries),
		ATTRIB_INT(struct fm_config_tcp, packet_spacing),
		ATTRIB_INT(struct fm_config_tcp, timeout),
	},
};

/*
 * icmp node
 */
static fm_config_proc_t		fm_config_icmp = {
	.attributes = {
		ATTRIB_INT(struct fm_config_icmp, retries),
		ATTRIB_INT(struct fm_config_icmp, packet_spacing),
		ATTRIB_INT(struct fm_config_icmp, timeout),
	},
};

/*
 * arp node
 */
static fm_config_proc_t		fm_config_arp = {
	.attributes = {
		ATTRIB_INT(struct fm_config_arp, retries),
		ATTRIB_INT(struct fm_config_arp, packet_spacing),
		ATTRIB_INT(struct fm_config_arp, timeout),
	},
};

/*
 * config file root node
 */
static fm_config_proc_t		fm_config_root = {
	.children = {
		{ "library",	offsetof(fm_config_t, library),		&fm_config_library },
		{ "address-generation",
				offsetof(fm_config_t, address_generation), &fm_config_address_generation },
		{ "target-pool",offsetof(fm_config_t, target_pool),	&fm_config_target_pool },
		{ "scanner",	offsetof(fm_config_t, scanner),		&fm_config_scanner },
		{ "ipv4",	offsetof(fm_config_t, ipv4),		&fm_config_ipv4 },
		{ "ipv6",	offsetof(fm_config_t, ipv6),		&fm_config_ipv6 },
		{ "udp",	offsetof(fm_config_t, udp),		&fm_config_udp },
		{ "tcp",	offsetof(fm_config_t, tcp),		&fm_config_tcp },
		{ "icmp",	offsetof(fm_config_t, icmp),		&fm_config_icmp },
		{ "arp",	offsetof(fm_config_t, arp),		&fm_config_arp },
	},
};

/*
 * ===== project file nodes =====
 */
static fm_config_proc_t		fm_project_main = {
	.name = ATTRIB_STRING(fm_project_t, name),
	.attributes = {
		ATTRIB_STRING_ARRAY(fm_project_t, targets),
		ATTRIB_STRING(fm_project_t, preset),
		ATTRIB_STRING_ARRAY(fm_project_t, tcp_ports),
		ATTRIB_STRING_ARRAY(fm_project_t, udp_ports),
	},
	.children = {
		{ "discovery-scan",	offsetof(fm_project_t, discovery_scan),	&fm_config_routine_root, .alloc_child = fm_project_routine_ptr_alloc, .iterate_children = fm_project_routine_ptr_iterate },
		{ "topology-scan",	offsetof(fm_project_t, topology_scan),	&fm_config_routine_root, .alloc_child = fm_project_routine_ptr_alloc, .iterate_children = fm_project_routine_ptr_iterate },
		{ "host-scan",		offsetof(fm_project_t, host_scan),	&fm_config_routine_root, .alloc_child = fm_project_routine_ptr_alloc, .iterate_children = fm_project_routine_ptr_iterate },
		{ "port-scan",		offsetof(fm_project_t, port_scan),	&fm_config_routine_root, .alloc_child = fm_project_routine_ptr_alloc, .iterate_children = fm_project_routine_ptr_iterate },
	},
};

static fm_config_proc_t		fm_project_root = {
	.children = {
		{ "project",	0,					&fm_project_main }
	},
};

/*
 * Replace _ with - and vice versa
 */
static const char *
fm_attr_string_translate(const char *attr_name, char bad, char good)
{
	static char converted_name[128];
	char *s;

	if (strchr(attr_name, bad) == NULL)
		return attr_name;

	if (strlen(attr_name) >= sizeof(converted_name))
		return attr_name;

	strcpy(converted_name, attr_name);
	for (s = converted_name; *s; ++s) {
		if (*s == bad)
			*s = good;
	}

	return converted_name;
}

static bool
fm_config_apply_child(curly_node_t *parent, fm_config_proc_t *proc, void *data, curly_node_t *node)
{
	const char *type;
	unsigned int i;

	type = curly_node_type(node);

	for (i = 0; i < MAX_CHILDREN; ++i) {
		fm_config_child_t *child_proc = &proc->children[i];

		if (child_proc->name == NULL)
			break;

		if (!strcmp(child_proc->name, type)) {
			void *child_data = fm_config_addr_apply_offset(data, child_proc->offset);

			if (child_proc->alloc_child != NULL)
				child_data = child_proc->alloc_child(node, child_data);

			return fm_config_process_node(node, child_proc->proc, child_data);
		}
	}

	fm_config_complain(node, "unknown child \"%s\"", type);
	return false;
}

static bool
fm_config_attr_set_int(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	const char *value = curly_attr_get_value(attr, 0);
	char *end;

	*(int *) attr_data = strtol(value, &end, 0);
	return *end == '\0';

}

static bool
fm_config_attr_render_int(curly_node_t *node, void *attr_data, const char *name)
{
	int ivalue = *(int *) attr_data;
	char value[32];

	if (ivalue == 0)
		return true;

	snprintf(value, sizeof(value), "%d", ivalue);
	curly_node_set_attr(node, name, value);
	return true;
}

static bool
fm_config_attr_set_bool(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	const char *value = curly_attr_get_value(attr, 0);

	if (!strcasecmp(value, "true")
	 || !strcasecmp(value, "yes")
	 || !strcasecmp(value, "1"))
		*(bool *) attr_data = true;
	else
	if (!strcasecmp(value, "false")
	 || !strcasecmp(value, "no")
	 || !strcasecmp(value, "0"))
		*(bool *) attr_data = false;
	else
		return false;

	return true;
}

static bool
fm_config_attr_render_bool(curly_node_t *node, void *attr_data, const char *name)
{
	bool value = *(bool *) attr_data;

	if (!value)
		return true;

	curly_node_set_attr(node, name, value? "true" : "false");
	return true;
}

static bool
fm_config_attr_set_string_internal(curly_node_t *node, void *attr_data, const char *value)
{
	char **var = (char **) attr_data;

	drop_string(var);
	if (value != NULL)
		*var = strdup(value);
	return true;

}

static bool
fm_config_attr_set_string(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	const char *value = curly_attr_get_value(attr, 0);
	return fm_config_attr_set_string_internal(node, attr_data, value);
}

static bool
fm_config_attr_render_string(curly_node_t *node, void *attr_data, const char *name)
{
	char *value = *(char **) attr_data;

	if (value != NULL)
		curly_node_set_attr(node, name, value);
	return true;
}

static bool
fm_config_attr_set_string_array(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	fm_string_array_t *array = (fm_string_array_t *) attr_data;
	const char * const *values;

	if (!(values = curly_attr_get_values(attr)))
		return false;

	/* zap what was there */
	fm_string_array_destroy(array);

	while (*values)
		fm_string_array_append(array, *values++);

	return true;

}

static bool
fm_config_attr_render_string_array(curly_node_t *node, void *attr_data, const char *name)
{
	fm_string_array_t *array = (fm_string_array_t *) attr_data;
	unsigned int i;

	if (array->count == 0)
		return true;

	for (i = 0; i < array->count; ++i)
		curly_node_add_attr_list(node, name, array->entries[i]);

	return true;
}

static bool
fm_config_attr_set_int_array(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
{
	fm_uint_array_t *array = (fm_uint_array_t *) attr_data;
	const char * const *values;
	const char *item;

	if (!(values = curly_attr_get_values(attr)))
		return false;

	/* zap what was there */
	fm_uint_array_destroy(array);

	while ((item = *values++) != NULL) {
		unsigned int value;
		char *end;

		value = strtol(item, &end, 0);
		if (*end)
			return false;
		fm_uint_array_append(array, value);
	}

	return true;

}

static bool
fm_config_attr_render_int_array(curly_node_t *node, void *attr_data, const char *name)
{
	fm_uint_array_t *array = (fm_uint_array_t *) attr_data;
	unsigned int i;

	if (array->count == 0)
		return true;

	for (i = 0; i < array->count; ++i) {
		char numbuf[16];

		snprintf(numbuf, sizeof(numbuf), "%u", array->entries[i]);
		curly_node_add_attr_list(node, name, numbuf);
	}

	return true;
}

static bool
fm_config_apply_value(curly_node_t *node, void *data, const fm_config_attr_t *attr_def, const curly_attr_t *attr)
{
	void *attr_data = fm_config_addr_apply_offset(data, attr_def->offset);
	unsigned int count;
	const char *value;
	bool okay;

	if (attr_def->type == FM_CONFIG_ATTR_TYPE_INT
	 || attr_def->type == FM_CONFIG_ATTR_TYPE_BOOL
	 || attr_def->type == FM_CONFIG_ATTR_TYPE_STRING) {
		count = curly_attr_get_count(attr);
		if (count != 1) {
			fm_config_complain(node, "attribute %s expects exactly one value", attr_def->name);
			return false;
		}
	}

	value = curly_attr_get_value(attr, 0);

	switch (attr_def->type) {
	case FM_CONFIG_ATTR_TYPE_INT:
		okay = fm_config_attr_set_int(node, attr_data, attr);
		break;

	case FM_CONFIG_ATTR_TYPE_BOOL:
		okay = fm_config_attr_set_bool(node, attr_data, attr);
		break;

	case FM_CONFIG_ATTR_TYPE_STRING:
		okay = fm_config_attr_set_string(node, attr_data, attr);
		break;

	case FM_CONFIG_ATTR_TYPE_SPECIAL:
		if (attr_def->setfn == NULL) {
			fm_config_complain(node, "attribute %s has no set() function", attr_def->name);
			return false;
		}
		okay = attr_def->setfn(node, attr_data, attr);
		break;

	case FM_CONFIG_ATTR_TYPE_INT_ARRAY:
		okay = fm_config_attr_set_int_array(node, attr_data, attr);
		break;

	case FM_CONFIG_ATTR_TYPE_STRING_ARRAY:
		okay = fm_config_attr_set_string_array(node, attr_data, attr);
		break;

	default:
		fm_config_complain(node, "attribute %s has unsupported type", attr_def->name);
		return false;
	}

	if (!okay)
		fm_config_complain(node, "unable to parse attribute %s=\"%s\"",
				attr_def->name, value);

	return okay;
}

static bool
fm_config_render_value(curly_node_t *node, void *data, const fm_config_attr_t *attr_def)
{
	void *attr_data = fm_config_addr_apply_offset(data, attr_def->offset);
	const char *attr_name = attr_def->name;
	bool okay;

	attr_name = fm_attr_string_translate(attr_def->name, '_', '-');

	switch (attr_def->type) {
	case FM_CONFIG_ATTR_TYPE_INT:
		okay = fm_config_attr_render_int(node, attr_data, attr_name);
		break;

	case FM_CONFIG_ATTR_TYPE_BOOL:
		okay = fm_config_attr_render_bool(node, attr_data, attr_name);
		break;

	case FM_CONFIG_ATTR_TYPE_STRING:
		okay = fm_config_attr_render_string(node, attr_data, attr_name);
		break;

	case FM_CONFIG_ATTR_TYPE_SPECIAL:
		if (attr_def->getfn == NULL) {
			fm_config_complain(node, "attribute %s has no get() function", attr_name);
			return false;
		}
		okay = attr_def->getfn(node, attr_data);
		break;

	case FM_CONFIG_ATTR_TYPE_INT_ARRAY:
		okay = fm_config_attr_render_int_array(node, attr_data, attr_name);
		break;

	case FM_CONFIG_ATTR_TYPE_STRING_ARRAY:
		okay = fm_config_attr_render_string_array(node, attr_data, attr_name);
		break;

	default:
		fm_config_complain(node, "attribute %s has unsupported type", attr_name);
		return false;
	}

	if (!okay)
		fm_config_complain(node, "unable to render attribute %s", attr_name);

	return okay;
}

/*
 * Handle unknown attributes - convert them to foo=bar notation and store them as strings
 * probe->extra_args.
 * If the attribute contains more than one value, we concat them together as
 *   foo=bar,baz,bloopie
 */
static bool
fm_config_add_wildcard_item(curly_node_t *node, void *attr_data, const curly_attr_t *attr)
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


static bool
fm_config_apply_wildcard(curly_node_t *node, void *data, const fm_config_attr_t *attr_def, const curly_attr_t *attr)
{
	void *attr_data = fm_config_addr_apply_offset(data, attr_def->offset);

	if (attr_def->type != FM_CONFIG_ATTR_TYPE_STRING_ARRAY) {
		fm_config_complain(node, "wildcard attribute has incompatible type (must be string array)");
		return false;
	}

	return fm_config_add_wildcard_item(node, attr_data, attr);
}

static bool
fm_config_render_wildcard_item(curly_node_t *node, const char *item)
{
	char *copy = strdupa(item);
	char *attr_name, *s, *attr_value, *next;

	attr_name = copy;
	if ((s = strchr(copy, '=')) == NULL)
		return false;

	*s++ = '\0';

	for (attr_value = s; attr_value; attr_value = next) {
		if ((next = strchr(attr_value, ',')) != NULL)
			*next++ = '\0';
		curly_node_add_attr_list(node, attr_name, attr_value);
	}
	return true;
}

static bool
fm_config_render_wildcard(curly_node_t *node, void *data, const fm_config_attr_t *attr_def)
{
	void *attr_data = fm_config_addr_apply_offset(data, attr_def->offset);
	fm_string_array_t *extra_args;
	unsigned int i;

	if (attr_def->type != FM_CONFIG_ATTR_TYPE_STRING_ARRAY) {
		fm_log_error("%s: wildcard attribute has incompatible type (must be string array)", curly_node_type(node));
		return false;
	}

	extra_args = attr_data;
	for (i = 0; i < extra_args->count; ++i) {
		if (!fm_config_render_wildcard_item(node, extra_args->entries[i])) {
			fm_log_error("%s: cannot render wildcard attr %s", curly_node_type(node), extra_args->entries[i]);
			return false;
		}
	}
	return true;
}

static bool
fm_config_process_one_attr(curly_node_t *node, fm_config_proc_t *proc, void *data, curly_attr_t *attr)
{
	const char *attr_name = curly_attr_get_name(attr), *conv_name;
	unsigned int i;

	/* Owing to the way we build the processing information, the attr names in these
	 * tables use C member field names like bla_size, while we want the config file(s)
	 * to use "bla-size" instead.
	 */
	conv_name = fm_attr_string_translate(attr_name, '-', '_');

	for (i = 0; i < MAX_ATTRIBUTES; ++i) {
		fm_config_attr_t *adef = &proc->attributes[i];

		if (adef->name == NULL)
			break;

		if (!strcmp(adef->name, attr_name) || !strcmp(adef->name, conv_name))
			return fm_config_apply_value(node, data, adef, attr);

		if (!strcmp(adef->name, "*"))
			return fm_config_apply_wildcard(node, data, adef, attr);
	}

	/* FIXME: we may be nice and handle cases where users write short-hand node
	 * definitions, omitting the body if it's empty.
	 * Example:
	 *   hosts-probe icmp;
	 * We could catch this here and divert this "attribute" to fm_config_process_node()
	 */

	fm_config_complain(node, "unknown attribute \"%s\"", attr_name);
	return false;
}

bool
fm_config_process_node(curly_node_t *node, fm_config_proc_t *proc, void *data)
{
	const char *name;
	curly_iter_t *iter;
	curly_node_t *child;
	curly_attr_t *attr;
	bool rv = true;

	name = curly_node_name(node);
	if (proc->name.type != 0) {
		void *name_data = fm_config_addr_apply_offset(data, proc->name.offset);

		if (name == NULL) {
			fm_config_complain(node, "missing name argument");
			return false;
		}

		assert(proc->name.type == FM_CONFIG_ATTR_TYPE_STRING);
		fm_config_attr_set_string_internal(node, name_data, name);
	} else
	if (name != NULL) {
		fm_config_complain(node, "unexpected extra name argument");
		return false;
	}

	if ((iter = curly_node_iterate(node)) != NULL) {
		while ((attr = curly_iter_next_attr(iter)) != NULL) {
			if (!fm_config_process_one_attr(node, proc, data, attr))
				rv = false;
		}

		while ((child = curly_iter_next_node(iter)) != NULL) {
			if (!fm_config_apply_child(node, proc, data, child))
				rv = false;
		}

		curly_iter_free(iter);
	}

	return rv;
}

static bool
fm_config_render_child(curly_node_t *node, fm_config_child_t *child_proc, void *data)
{
	fm_config_attr_t *name_attr_def = &child_proc->proc->name;
	const char *name = NULL;
	curly_node_t *child;

	if (name_attr_def->type == FM_CONFIG_ATTR_TYPE_BAD) {
		/* unnamed child node
		 *   blah-type { ... }
		 */
	} else
	if (name_attr_def->type == FM_CONFIG_ATTR_TYPE_STRING) {
		void *attr_data = fm_config_addr_apply_offset(data, name_attr_def->offset);
		name = *(char **) attr_data;
	} else
	if (name_attr_def->type) {
		fm_config_complain(node, "support for %s child node with name not implemented", child_proc->name);
		return false;
	}

	child = curly_node_add_child(node, child_proc->name, name);

	return fm_config_render_node(child, child_proc->proc, data);
}

static bool
fm_config_render_node(curly_node_t *node, fm_config_proc_t *proc, void *data)
{
	unsigned int i;

	for (i = 0; i < MAX_ATTRIBUTES; ++i) {
		fm_config_attr_t *attr_def = &proc->attributes[i];

		if (attr_def->name == NULL)
			break;
		if (!strcmp(attr_def->name, "*")) {
			if (!fm_config_render_wildcard(node, data, attr_def))
				return false;
		} else
		if (!fm_config_render_value(node, data, attr_def))
			return false;
	}

	for (i = 0; i < MAX_CHILDREN; ++i) {
		fm_config_child_t *child_proc = &proc->children[i];
		void *child_data;

		if (child_proc->name == NULL)
			break;

		child_data = fm_config_addr_apply_offset(data, child_proc->offset);

		if (child_proc->iterate_children != NULL) {
			unsigned int index = 0;
			void *item_data;

			while ((item_data = child_proc->iterate_children(child_proc, child_data, index++)) != NULL) {
				if (!fm_config_render_child(node, child_proc, item_data))
					return false;
			}
			continue;
		}

		if (child_proc->alloc_child != NULL) {
			fm_log_error("cannot marshal %s.%s: node lacks iterate_children() method",
					curly_node_type(node), child_proc->name);
			return false;
		}

		if (!fm_config_render_child(node, child_proc, child_data))
			return false;
	}

	return true;
}

static void
fm_config_dump_attrs(curly_node_t *np, unsigned int indent)
{
	const char **attr_names;
	unsigned int n, k;

	attr_names = curly_node_get_attr_names(np);
	if (attr_names == NULL)
		return;

	for (n = 0; attr_names[n]; ++n) {
		const char *name = attr_names[n];
		const char * const *values;

		printf("%*.*s%s = ", indent, indent, "", name);

		values = curly_node_get_attr_list(np, name);
		for (k = 0; values[k]; ++k) {
			if (k)
				printf(", ");
			printf(" '%s'", values[k]);
		}
		printf(";\n");
	}

	free(attr_names);
}

static void
fm_config_dump_children(curly_node_t *np, unsigned int indent)
{
	curly_iter_t *iter;
	curly_node_t *child;

	if ((iter = curly_node_iterate(np)) == NULL)
		return;

	while ((child = curly_iter_next_node(iter)) != NULL)
		fm_config_dump(child, indent);

	curly_iter_free(iter);
}


void
fm_config_dump(curly_node_t *np, unsigned int indent)
{
	const char *s;

	printf("%*.*s", indent, indent, "");

	printf("%s", curly_node_type(np));

	if ((s = curly_node_name(np)) != NULL)
		printf(" %s", s);
	printf(" {\n");
	fm_config_dump_attrs(np, indent + 2);
	fm_config_dump_children(np, indent + 2);

	printf("%*.*s}\n", indent, indent, "");
}
