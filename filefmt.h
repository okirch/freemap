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

#ifndef FREEMAP_FILEFMT_H
#define FREEMAP_FILEFMT_H

#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>

#include <curlies.h>

#include "freemap.h"
#include "program.h"
#include "scanner.h"


typedef struct fm_config_child	fm_config_child_t;
typedef struct fm_config_attr	fm_config_attr_t;
typedef struct fm_config_proc	fm_config_proc_t;

enum {
	FM_CONFIG_ATTR_TYPE_BAD = 0,
	FM_CONFIG_ATTR_TYPE_INT,
	FM_CONFIG_ATTR_TYPE_BOOL,
	FM_CONFIG_ATTR_TYPE_STRING,
	FM_CONFIG_ATTR_TYPE_INT_ARRAY,
	FM_CONFIG_ATTR_TYPE_STRING_ARRAY,
	FM_CONFIG_ATTR_TYPE_SPECIAL,
};

struct fm_config_child {
	const char *		name;
	unsigned int		offset;
	fm_config_proc_t *	proc;

	void *			(*alloc_child)(curly_node_t *, void *data);
};

struct fm_config_attr {
	const char *		name;
	unsigned int		offset;
	int			type;

	bool			(*setfn)(curly_node_t *node, void *attr_data, const curly_attr_t *attr);
	bool			(*getfn)(curly_node_t *node, void *attr_data);
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
#define ATTRIB_INT_ARRAY(container, member) \
		{ #member,	offsetof(container, member),	FM_CONFIG_ATTR_TYPE_INT_ARRAY }
#define ATTRIB_STRING_ARRAY(container, member) \
		{ #member,	offsetof(container, member),	FM_CONFIG_ATTR_TYPE_STRING_ARRAY }


extern void			fm_config_complain(curly_node_t *node, const char *fmt, ...);
extern bool			fm_config_process_node(curly_node_t *node, fm_config_proc_t *prov, void *data);

#endif /* FREEMAP_FILEFMT_H */
