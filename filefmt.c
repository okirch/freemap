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


struct file_scanner {
	FILE *fp;
	const char *path;
	unsigned int line;

	bool have_line;
	bool end_of_entry;
	bool error;

	unsigned int rpos;
	char squirrel;
	char linebuf[1024];
};

struct file_scanner *
file_scanner_open(const char *path)
{
	struct file_scanner *fs;
	FILE *fp;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((fp = fopen(path, "r")) == NULL)
		return NULL;

	fs = calloc(1, sizeof(*fs));
	fs->path = path;
	fs->fp = fp;
	return fs;
}

void
file_scanner_close(struct file_scanner *fs)
{
	if (fs->fp != NULL) {
		fclose(fs->fp);
		fs->fp = NULL;
	}
}

void
file_scanner_free(struct file_scanner *fs)
{
	file_scanner_close(fs);
	free(fs);
}

bool
file_scanner_error(struct file_scanner *fs, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printf("%s:%u: ", fs->path, fs->line);
	vprintf(fmt, ap);
	va_end(ap);

	file_scanner_close(fs);
	fs->error = true;

	return false;
}

static inline char
file_scanner_getc(struct file_scanner *fs)
{
	char cc = 0;

	if (fs->have_line) {
		cc = fs->linebuf[fs->rpos];
		if (cc)
			fs->rpos += 1;
	}

	return cc;
}

static inline void
file_scanner_ungetc(struct file_scanner *fs, char cc)
{
	assert(fs->have_line);
	assert(fs->linebuf[fs->rpos - 1] == cc);
	fs->rpos -= 1;
}

static char *
__file_scanner_next_entry(struct file_scanner *fs, bool require_continuation)
{
	fs->end_of_entry = false;

	while (fs->fp != NULL) {
		char *w, cc;

		if (!fs->have_line) {
			if (fgets(fs->linebuf, sizeof(fs->linebuf), fs->fp) == NULL) {
				file_scanner_close(fs);
				continue;
			}

			fs->linebuf[strcspn(fs->linebuf, "\n")] = '\0';
			fs->line += 1;

			fs->have_line = true;

			if (require_continuation && !isspace(fs->linebuf[0]))
				return NULL;

			if (!require_continuation && isspace(fs->linebuf[0])) {
				file_scanner_error(fs, "continuation line before first entry\n");
				return NULL;
			}

			fs->squirrel = '\0';
			fs->rpos = 0;
		}

		if (fs->squirrel != '\0') {
			fs->linebuf[fs->rpos] = fs->squirrel;
			fs->squirrel = '\0';
		}

		do {
			cc = file_scanner_getc(fs);
		} while (isspace(cc));

		if (cc == '\0') {
			fs->have_line = false;
			continue; /* EOL */
		}

		w = &fs->linebuf[fs->rpos - 1];

		if (isalnum(cc)) {
			do {
				cc = file_scanner_getc(fs);
			} while (isalnum(cc) || cc == '=' || cc == '-' || cc == '_');
			file_scanner_ungetc(fs, cc);
		} else if (cc != '\0') {
			/* return a single char */
			cc = 0;
		}

		if (cc && !isspace(cc)) {
			fs->linebuf[fs->rpos] = '\0';
			fs->squirrel = cc;
		} else {
			fs->linebuf[fs->rpos++] = '\0';
		}

		// printf("TOKEN |%s|\n", w);
		return w;
	}

	return NULL;
}

char *
file_scanner_next_entry(struct file_scanner *fs)
{
	return __file_scanner_next_entry(fs, false);
}

char *
file_scanner_continue_entry(struct file_scanner *fs)
{
	return __file_scanner_next_entry(fs, true);
}

bool
file_scanner_has_error(const struct file_scanner *fs)
{
	return fs->error;
}
