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

#define FM_ARG_NONE		0
#define FM_ARG_REQUIRED		1
#define FM_ARG_OPTIONAL		2

typedef struct fm_long_option {
	const char *		name;
	int			has_arg;
	int			value;
} fm_long_option_t;

typedef bool			fm_cmdparser_option_handler_fn_t(int opt, const char *argument);

typedef struct fm_cmdparser	fm_cmdparser_t;

struct fm_cmdparser {
	const char *		name;
	unsigned int		cmdid;

	fm_cmdparser_option_handler_fn_t *process_option;

	fm_cmdparser_t *	parent;

	unsigned int		num_handlers;
	fm_long_option_t *	handlers;

	fm_cmdparser_t **	subcommands;
};

typedef struct fm_command	fm_command_t;
struct fm_command {
	/* This would be something like "freemap scan" */
	const char *		fullname;
	int			cmdid;

	unsigned int		nvalues;
	char **			values;
};

extern fm_cmdparser_t *	fm_cmdparser_main(const char *name, unsigned int cmdid,
				const char *short_options, const fm_long_option_t *long_options,
				fm_cmdparser_option_handler_fn_t *process_option);
extern fm_cmdparser_t *	fm_cmdparser_add_subcommand(fm_cmdparser_t *parent, const char *name, unsigned int cmdid,
				const char *short_options, const fm_long_option_t *long_options,
				fm_cmdparser_option_handler_fn_t *process_option);
extern fm_command_t *		fm_cmdparser_process_args(const fm_cmdparser_t *, int argc, char **argv);

#endif /* FREEMAP_SUBCOMMAND_H */

