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
#include <curlies.h>

#include "freemap.h"
#include "config.h"

typedef struct fm_config_child	fm_config_child_t;
typedef struct fm_config_attr	fm_config_attr_t;
typedef struct fm_config_proc	fm_config_proc_t;

static fm_config_proc_t		fm_config_root;

static bool		fm_config_process_node(curly_node_t *node, fm_config_proc_t *proc, void *data);;
static bool		fm_config_apply_value(curly_node_t *node, void *data, const fm_config_attr_t *attr_def, const char *value);
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

bool
fm_config_load(fm_config_t *conf, const char *path)
{
	return fm_config_load_work(path, &fm_config_root, conf);
}

/*
 * Error handling
 */
static void
fm_config_complain(curly_node_t *node, const char *fmt, ...)
{
	char msgbuf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	fm_log_error("%s, line %u: %s",
			curly_node_get_source_file(node),
			curly_node_get_source_line(node),
			msgbuf);
	va_end(ap);
}

enum {
	FM_CONFIG_ATTR_TYPE_BAD = 0,
	FM_CONFIG_ATTR_TYPE_INT,
	FM_CONFIG_ATTR_TYPE_BOOL,
	FM_CONFIG_ATTR_TYPE_STRING,
	FM_CONFIG_ATTR_TYPE_SPECIAL,
};

struct fm_config_child {
	const char *		name;
	unsigned int		offset;
	fm_config_proc_t *	proc;
};

struct fm_config_attr {
	const char *		name;
	unsigned int		offset;
	int			type;

	bool			(*setfn)(curly_node_t *node, void *attr_data, const char *value);
};

#define MAX_CHILDREN		16
#define MAX_ATTRIBUTES		16

struct fm_config_proc {
	fm_config_attr_t	name;
	fm_config_child_t	children[MAX_CHILDREN];
	fm_config_attr_t	attributes[MAX_ATTRIBUTES];
};

#define offsetof(type, member) \
	((unsigned long) &(((type *) 0)->member))
#define ATTRIB_INT(container, member) \
		{ #member,	offsetof(container, member),	FM_CONFIG_ATTR_TYPE_INT }
#define ATTRIB_BOOL(container, member) \
		{ #member,	offsetof(container, member),	FM_CONFIG_ATTR_TYPE_BOOL }
#define ATTRIB_STRING(container, member) \
		{ #member,	offsetof(container, member),	FM_CONFIG_ATTR_TYPE_STRING }
#define ATTRIB_SPECIAL(container, member, __setfn) \
		{ #member,	offsetof(container, member),	FM_CONFIG_ATTR_TYPE_SPECIAL, .setfn = __setfn }

static inline void *
fm_config_addr_apply_offset(void *data, unsigned int offset)
{
	caddr_t child_data_addr = (caddr_t) data + offset;
	return (void *) child_data_addr;
}

static bool
set_address_family(curly_node_t *node, void *attr_data, const char *value)
{
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
 * address_generation
 */
static fm_config_proc_t		fm_config_address_generation = {
	.attributes = {
		ATTRIB_SPECIAL(struct fm_config_address_generation, only_family, set_address_family),
		ATTRIB_BOOL(struct fm_config_address_generation, try_all),
		ATTRIB_INT(struct fm_config_address_generation, randomize),
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
	},
};

/*
 * tcp node
 */
static fm_config_proc_t		fm_config_tcp = {
	.attributes = {
		ATTRIB_INT(struct fm_config_tcp, application_delay),
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

static bool
fm_config_apply_child(curly_node_t *parent, fm_config_proc_t *proc, void *data, curly_node_t *node)
{
	const char *type, *name;
	unsigned int i;

	type = curly_node_type(node);
	name = curly_node_name(node);
	if (proc->name.type != 0) {
		if (name == NULL) {
			fm_config_complain(parent, "missing name argument for child \"%s\"", type);
			return false;
		}

		if (!fm_config_apply_value(node, data, &proc->name, name))
			return false;
	} else
	if (name != NULL) {
		fm_config_complain(parent, "unexpected extra name argument for child \"%s\"", type);
		return false;
	}

	for (i = 0; i < MAX_CHILDREN; ++i) {
		fm_config_child_t *child_proc = &proc->children[i];

		if (child_proc->name == NULL)
			break;

		if (!strcmp(child_proc->name, type)) {
			return fm_config_process_node(node, child_proc->proc,
					fm_config_addr_apply_offset(data, child_proc->offset));
		}
	}

	fm_config_complain(parent, "unknown child \"%s\"", type);
	return false;
}

static bool
fm_config_attr_set_int(curly_node_t *node, void *attr_data, const char *value)
{
	char *end;

	*(int *) attr_data = strtol(value, &end, 0);
	return *end == '\0';

}

static bool
fm_config_attr_set_bool(curly_node_t *node, void *attr_data, const char *value)
{
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
fm_config_attr_set_string(curly_node_t *node, void *attr_data, const char *value)
{
	char **var = (char **) attr_data;

	drop_string(var);
	if (value != NULL)
		*var = strdup(value);
	return true;

}

static bool
fm_config_apply_value(curly_node_t *node, void *data, const fm_config_attr_t *attr_def, const char *value)
{
	void *attr_data = fm_config_addr_apply_offset(data, attr_def->offset);
	bool okay;

	switch (attr_def->type) {
	case FM_CONFIG_ATTR_TYPE_INT:
		okay = fm_config_attr_set_int(node, attr_data, value);
		break;

	case FM_CONFIG_ATTR_TYPE_BOOL:
		okay = fm_config_attr_set_bool(node, attr_data, value);
		break;

	case FM_CONFIG_ATTR_TYPE_STRING:
		okay = fm_config_attr_set_string(node, attr_data, value);
		break;

	case FM_CONFIG_ATTR_TYPE_SPECIAL:
		if (attr_def->setfn == NULL) {
			fm_config_complain(node, "attribute %s has not set() function", attr_def->name);
			return false;
		}
		okay = attr_def->setfn(node, attr_data, value);
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
fm_config_process_one_attr(curly_node_t *node, fm_config_proc_t *proc, void *data, curly_attr_t *attr)
{
	const char *attr_name = curly_attr_get_name(attr);
	char converted_attr_name[64];
	unsigned int count = curly_attr_get_count(attr);
	unsigned int i;

	/* Owing to the way we build the processing information, the attr names in these
	 * tables use C member field names like bla_size, while we want the config file(s)
	 * to use "bla-size" instead.
	 */
	if (strchr(attr_name, '-') && strlen(attr_name) < sizeof(converted_attr_name)) {
		char *s;

		strcpy(converted_attr_name, attr_name);
		while ((s = strchr(converted_attr_name, '-')) != NULL)
			*s = '_';
		attr_name = converted_attr_name;
	}

	for (i = 0; i < MAX_ATTRIBUTES; ++i) {
		fm_config_attr_t *adef = &proc->attributes[i];

		if (adef->name == NULL)
			break;

		if (!strcmp(adef->name, attr_name)) {
			const char *value;

			if (count != 1) {
				fm_config_complain(node, "attribute %s expects exactly one value", attr_name);
				return false;
			}

			value = curly_attr_get_value(attr, 0);
			if (!fm_config_apply_value(node, data, adef, value)) {
				fm_config_complain(node, "unable to parse attribute %s=\"%s\"",
						attr_name, value);
				return false;
			}

			return true;
		}
	}

	fm_config_complain(node, "unknown attribute \"%s\"", attr_name);
	return false;
}

static bool
fm_config_process_node(curly_node_t *node, fm_config_proc_t *proc, void *data)
{
	curly_iter_t *iter;
	curly_node_t *child;
	curly_attr_t *attr;
	bool rv = true;

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
