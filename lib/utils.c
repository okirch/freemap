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

#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#include "utils.h"

/*
 * Arrays of (unsigned) integers
 */
void
fm_uint_array_append(fm_uint_array_t *array, unsigned int value)
{
	maybe_realloc_array(array->entries, array->count, 32);
	array->entries[array->count++] = value;
}

void
fm_uint_array_copy(fm_uint_array_t *dst, const fm_uint_array_t *src)
{
	fm_uint_array_destroy(dst);

	maybe_realloc_array(dst->entries, dst->count, src->count);
	memcpy(dst->entries, src->entries, src->count * sizeof(dst->entries[0]));
	dst->count = src->count;
}

void
fm_uint_array_destroy(fm_uint_array_t *array)
{
	if (array->entries) {
		free(array->entries);
		array->entries = NULL;
	}
}

int
fm_uint_array_get(const fm_uint_array_t *array, unsigned int index)
{
	if (index >= array->count)
		return -1;
	return array->entries[index];
}

void
fm_uint_array_randomize(fm_uint_array_t *array)
{
	unsigned int count;

	/* We randomize the array by a sequence of pair swaps.
	 * Algebra 101 - every permutation can be reduced to pair swaps.
	 *
	 * I don't really know what is random "enough" but let's try
	 * by doing 2 * arraysize swaps
	 */
	count = 2 * array->count;

	while (count--) {
		unsigned int i, k, value;

		do {
			i = random() % array->count;
			k = random() % array->count;
		} while (i == k);

		value = array->entries[i];
		array->entries[i] = array->entries[k];
		array->entries[k] = value;
	}
}

/*
 * Arrays of strings
 */
void
fm_string_array_append(fm_string_array_t *sarr, const char *s)
{
	static const unsigned int chunk = 16;

	if (s == NULL)
		return;

	if ((sarr->count % chunk) == 0)
		sarr->entries = realloc(sarr->entries, (sarr->count + chunk) * sizeof(sarr->entries[0]));
	sarr->entries[sarr->count++] = strdup(s);
}

void
fm_string_array_copy(fm_string_array_t *dst, const fm_string_array_t *src)
{
	unsigned int i;

	fm_string_array_destroy(dst);

	maybe_realloc_array(dst->entries, dst->count, src->count);

	for (i = 0; i < src->count; ++i)
		dst->entries[i] = strdup(src->entries[i]);

	dst->count = src->count;
}

void
fm_string_array_destroy(fm_string_array_t *sarr)
{
	unsigned int i;

	if (sarr->count) {
		for (i = 0; i < sarr->count; ++i)
			free(sarr->entries[i]);
		free(sarr->entries);
	}

	memset(sarr, 0, sizeof(*sarr));
}

const char *
fm_string_array_get(fm_string_array_t *sarr, unsigned int index)
{
	if (index >= sarr->count)
		return NULL;
	return sarr->entries[index];
}

bool
fm_string_array_contains(const fm_string_array_t *array, const char *s)
{
	unsigned int i;

	if (s == NULL)
		return false;

	for (i = 0; i < array->count; ++i) {
		if (!strcmp(array->entries[i], s))
			return true;
	}
	return false;
}

/*
 * Port range
 */
bool
fm_parse_port_range(const char *s, fm_port_range_t *range)
{
	const char *end;

	if (!strcmp(s, "unpriv")) {
		range->first = 1024;
		range->last = 65535;
		return true;
	}

	range->first = strtoul(s, (char **) &end, 0);
	range->last = range->first;

	if (*end == '-')
		range->last = strtoul(end + 1, (char **) &end, 0);

	if (*end != '\0')
		return false;

	if (range->last < range->first)
		return false;

	return true;
}

/*
 * Handle numeric options like "retries=4"
 */
bool
fm_parse_numeric_argument(const char *arg, const char *option_name, unsigned int *value_p)
{
	int optlen = strlen(option_name);
	const char *end;

	if (strncmp(arg, option_name, optlen) || arg[optlen] != '=')
		return false;

	*value_p = strtoul(arg + optlen + 1, (char **) &end, 0);
	if (*end != '\0')
		return false;

	return true;
}

bool
fm_parse_numeric_argument_symbolic(const char *arg, const char *option_name,
				int (*sym_to_string)(const char *), unsigned int *value_p)
{
	const char *string_value;
	const char *end;
	int r;

	if (!fm_parse_string_argument(arg, option_name, &string_value))
		return false;

	*value_p = strtoul(string_value, (char **) &end, 0);
	if (*end == '\0')
		return true;

	if (sym_to_string != NULL && (r = sym_to_string(string_value)) >= 0) {
		*value_p = r;
		return true;
	}

	return false;
}

/*
 * Handle string options like "type=echo"
 */
bool
fm_parse_string_argument(const char *arg, const char *option_name, const char **value_p)
{
	int optlen = strlen(option_name);

	*value_p = NULL;

	if (strncmp(arg, option_name, optlen) || arg[optlen] != '=')
		return false;

	*value_p = arg + optlen + 1;
	return true;
}

/*
 * Print buffer as hexdump
 */
void
fm_print_hexdump(const unsigned char *p, unsigned int len)
{
	unsigned int i;

	if (len == 0) {
		printf("0000: EMPTY buffer\n");
		return;
	}

	for (i = 0; i < len; i += 32) {
		unsigned int n, k;

		if ((n = len - i) > 32)
			n = 32;

		printf("%04x:", i);
		for (k = 0; k < 32; ++k) {
			if (k + i < len)
				printf(" %02x", p[k + i]);
			else
				printf("   ");
		}

		printf(" ");
		for (k = 0; k < n && i + k < len; ++k) {
			unsigned char cc = p[i + k];

			printf("%c", isalnum(cc)? cc : '.');
		}
		printf("\n");
	}
	fflush(stdout);
}

/*
 * Make sure a directory tree exists
 * path must be writable.
 */
bool
fm_makedirs(char *path)
{
	char *s;
	bool ok;

	if (mkdir(path, 0755) == 0 || errno == EEXIST)
		return true;

	if (errno != ENOENT)
		return false;

	if ((s = strrchr(path, '/')) == NULL)
		return false;

	*s = '\0';
	ok = fm_makedirs(path);
	*s = '/';

	if (ok && mkdir(path, 0755) < 0)
		ok = false;

	return ok;
}

