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

#ifndef FREEMAP_SUBCOMMAND_H
#define FREEMAP_SUBCOMMAND_H

#include <getopt.h>

struct fm_cmdparser_option_handler {
	const char *		name;

	int			value;
	int			has_arg;
	bool			(*fn)(int opt, const char *arg_value);
};

typedef struct fm_cmdparser	fm_cmdparser_t;

struct fm_cmdparser {
	const char *		name;
	unsigned int		cmdid;

	fm_cmdparser_t *	parent;

	char *			short_options;

	unsigned int		num_long_options;
	struct option *		long_options;

	unsigned int		num_handlers;
	struct fm_cmdparser_option_handler *handlers;

	fm_cmdparser_t **	subcommands;
};

extern fm_cmdparser_t *	fm_cmdparser_main(const char *name, unsigned int cmdid,
				const char *short_options, const struct option *long_options,
				bool (*opt_fn)(int, const char *));
extern fm_cmdparser_t *	fm_cmdparser_add_subcommand(fm_cmdparser_t *parent, const char *name, unsigned int cmdid,
				const char *short_options, const struct option *long_options,
				bool (*opt_fn)(int, const char *));
extern int			fm_cmdparser_process_args(const fm_cmdparser_t *, int argc, char **argv);

#endif /* FREEMAP_SUBCOMMAND_H */

