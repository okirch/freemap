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

#ifndef FREEMAP_UTILS_H
#define FREEMAP_UTILS_H

#include <stdlib.h>
#include "types.h"

static inline void
drop_string(char **var)
{
	char *s = *var;

	if (s != NULL) {
		free(s);
		*var = NULL;
	}
}

#define drop_pointer(pp) do { \
	void **__pp = (void **) pp; \
	if (*__pp) { \
		free(*__pp); *__pp = NULL; \
	} \
} while (0)

struct fm_string_array {
	unsigned int	count;
	char **		entries;
};

extern void		fm_string_array_append(fm_string_array_t *, const char *);
extern void		fm_string_array_destroy(fm_string_array_t *);
extern const char *	fm_string_array_get(fm_string_array_t *, unsigned int);

extern bool		fm_parse_port_range(const char *, fm_port_range_t *);
extern bool		fm_parse_numeric_argument(const char *arg, const char *option_name, unsigned int *value_p);
extern bool		fm_parse_string_argument(const char *arg, const char *option_name, const char **value_p);

extern void		fm_print_hexdump(const unsigned char *p, unsigned int len);

#endif /* FREEMAP_UTILS_H */
