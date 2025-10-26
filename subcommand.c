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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "freemap.h"
#include "subcommand.h"
#include "utils.h"

/*
 * Our own simple argv parser.
 */
typedef struct fm_arg_parser {
	int		argc;
	char **		argv;

	bool		eof;
	int		optind;

	struct {
		const char *	option;
		int		value;
		int		has_arg;
		const char *	argument;
		bool		(*setfn)(int, const char *);
	} found;
} fm_arg_parser_t;

#define FM_ARG_OK		0
#define FM_ARG_EOF		-1
#define FM_ARG_POSITIONALS	-2
#define FM_ARG_UNKNOWN_OPTION	-3
#define FM_ARG_MISSING_ARGUMENT	-4

static int
fm_short_options_iter(const char **pos, int *has_arg_p)
{
	const char *p = *pos;
	char optchar;

	if (p == NULL)
		return EOF;

	do {
		optchar = *p++;
	} while (optchar == ':' || optchar == '+');

	if (optchar == '\0') {
		*pos = p;
		return -1;
	}

	*has_arg_p = no_argument;
	if (p[0] == ':') {
		*has_arg_p = required_argument;
		if (p[1] == ':')
			*has_arg_p = optional_argument;
		while (*p == ':')
			++p;
	}

	*pos = p;
	return optchar;
}

static bool
fm_options_contain(const struct option *list, unsigned int list_count, const struct option *o)
{
	unsigned int i;

	for (i = 0; i < list_count; ++i) {
		if (!strcmp(o->name, list[i].name))
			return true;
	}
	return false;
}

static void
fm_cmdparser_add_handler(fm_cmdparser_t *parser, const char *name, int val, int has_arg, bool (*fn)(int, const char *))
{
	struct fm_cmdparser_option_handler *h;

	if ((parser->num_handlers % 16) == 0)
		parser->handlers = realloc(parser->handlers, (parser->num_handlers + 16) * sizeof(parser->handlers[0]));

	h = &parser->handlers[parser->num_handlers++];
	h->name = strdup(name);
	h->value = val;
	h->has_arg = has_arg;
	h->fn = fn;
}

static bool
fm_cmdparser_find_long_option_handler(const fm_cmdparser_t *parser, const char *name, fm_arg_parser_t *state)
{
	static char errname[64];
	unsigned int i;

	while (parser != NULL) {
		for (i = 0; i < parser->num_handlers; ++i) {
			const struct fm_cmdparser_option_handler *h = &parser->handlers[i];

			if (!strcmp(h->name, name)) {
				state->found.option = h->name;
				state->found.value = h->value;
				state->found.has_arg = h->has_arg;
				state->found.setfn = h->fn;
				return true;
			}
		}

		parser = parser->parent;
	}

	strncpy(errname, name, sizeof(errname) - 1);
	state->found.option = errname;

	return false;
}

static bool
fm_cmdparser_find_short_option_handler(const fm_cmdparser_t *parser, char cc, fm_arg_parser_t *state)
{
	char namebuf[8];

	snprintf(namebuf, sizeof(namebuf), "-%c", cc);
	return fm_cmdparser_find_long_option_handler(parser, namebuf, state);
}

static inline const struct fm_cmdparser_option_handler *
fm_cmdparser_find_handler(const fm_cmdparser_t *parser, int optchar)
{
	unsigned int i;

	for (i = 0; i < parser->num_handlers; ++i) {
		const struct fm_cmdparser_option_handler *h = &parser->handlers[i];

		if (h->value == optchar)
			return h;
	}
	return NULL;
}

static bool
fm_cmdparser_copy_handler(fm_cmdparser_t *parser, const fm_cmdparser_t *parent, int optchar)
{
	const struct fm_cmdparser_option_handler *h;

	h = fm_cmdparser_find_handler(parent, optchar);
	if (h != NULL) {
		fm_cmdparser_add_handler(parser, h->name, h->value, h->has_arg, h->fn);
		return true;
	}
	return false;
}

static void
fm_cmdparser_add_long_option(fm_cmdparser_t *parser, const struct option *o)
{
	maybe_realloc_array(parser->long_options, parser->num_long_options, 16);

	parser->long_options[parser->num_long_options++] = *o;
}

static void
fm_cmdparser_add_short_option(fm_cmdparser_t *parser, int val, int has_arg)
{
	char spec[8], *new_opts = NULL;
	int len = 0;

	spec[len++] = val;
	if (has_arg != no_argument) {
		spec[len++] = ':';
		if (has_arg == optional_argument)
			spec[len++] = ':';
	}
	spec[len] = '\0';

	if (parser->short_options == NULL) {
		asprintf(&new_opts, "+%s", spec);
	} else {
		asprintf(&new_opts, "%s%s", parser->short_options, spec);
	}

	drop_string(&parser->short_options);
	parser->short_options = new_opts;
}

fm_cmdparser_t *
fm_cmdparser_main(const char *name, unsigned int cmdid,
			const char *short_options, const struct option *long_options,
			bool (*opt_fn)(int, const char *))
{
	static const struct option empty_options[] = { { NULL, } };
	fm_cmdparser_t *parser;
	const struct option *o;
	const char *pos;
	int c, has_arg;

	if (cmdid == 0)
		fm_log_fatal("Cannot register command %s: invalid id %u", name, cmdid);

	if (short_options == NULL)
		short_options = "";

	if (long_options == NULL)
		long_options = empty_options;

	parser = calloc(1, sizeof(*parser));
	parser->name = strdup(name);
	parser->cmdid = cmdid;

	if (short_options[0] == '+') {
		parser->short_options = strdup(short_options);
	} else {
		char *new_short_options;

		new_short_options = malloc(strlen(short_options) + 2);
		new_short_options[0] = '+';
		strcpy(new_short_options + 1, short_options);
		parser->short_options = new_short_options;
	}

	for (o = long_options; o->name; ++o) {
		char *long_name = NULL;

		fm_cmdparser_add_long_option(parser, o);

		asprintf(&long_name, "--%s", o->name);
		fm_cmdparser_add_handler(parser, long_name, o->val, o->has_arg, opt_fn);
		free(long_name);
	}

	pos = short_options;
	while ((c = fm_short_options_iter(&pos, &has_arg)) >= 0) {
		char namebuf[8];

		snprintf(namebuf, sizeof(namebuf), "-%c" ,c);
		fm_cmdparser_add_handler(parser, namebuf, c, has_arg, opt_fn);
	}

	return parser;
}

static void
fm_cmdparser_install_subcommand(fm_cmdparser_t *parent, fm_cmdparser_t *parser)
{
	unsigned int count = 0;

	assert(parser->parent == NULL);

	if (parent->subcommands != NULL) {
		while (parent->subcommands[count])
			++count;
	}

	parent->subcommands = realloc(parent->subcommands, (count + 2) * sizeof(parent->subcommands[0]));

	parent->subcommands[count++] = parser;
	parser->parent = parent;
}

static fm_cmdparser_t *
fm_cmdparser_find_subcommand(const fm_cmdparser_t *parser, const char *cmdname)
{
	fm_cmdparser_t **list = parser->subcommands, *sub;

	if (list == NULL)
		return NULL;

	while ((sub = *list++) != NULL) {
		if (!strcmp(sub->name, cmdname))
			return sub;
	}

	return NULL;
}

fm_cmdparser_t *
fm_cmdparser_add_subcommand(fm_cmdparser_t *parent, const char *name, unsigned int cmdid,
				const char *short_options, const struct option *long_options,
				bool (*opt_fn)(int, const char *))
{
	fm_cmdparser_t *parser;
	const char *iter;
	int c, has_arg;
	unsigned int i;

	parser = fm_cmdparser_main(name, cmdid, short_options, long_options, opt_fn);

	fm_cmdparser_install_subcommand(parent, parser);

	for (i = 0; i < parent->num_long_options; ++i) {
		const struct option *o = &parent->long_options[i];

		if (fm_options_contain(parser->long_options, parser->num_long_options, o)) {
			fm_log_debug("subcommand %s: ignoring option --%s of parent argument parser",
					name, o->name);
			continue;
		}

		fm_cmdparser_add_long_option(parser, o);
		fm_cmdparser_copy_handler(parser, parent, o->val);
	}

	iter = parent->short_options;
	while ((c = fm_short_options_iter(&iter, &has_arg)) >= 0) {
		if (short_options && strchr(short_options, c) != NULL) {
			fm_log_debug("subcommand %s overrides option -%c from base command", name, c);
			continue;
		}

		fm_cmdparser_add_short_option(parser, c, has_arg);
		fm_cmdparser_copy_handler(parser, parent, c);
	}

	return parser;
}

static void
fm_cmdparser_usage(const fm_cmdparser_t *parser, int exval)
{
	fprintf(stderr, "Usage message goes here\n");
	exit(1);
}

/*
 * Our own simple argv parser.
 */
static void
fm_arg_parser_init(fm_arg_parser_t *ap, int argc, char **argv)
{
	memset(ap, 0, sizeof(*ap));

	ap->argc = argc;
	ap->argv = argv;
	ap->optind = 1;
}

static int
fm_arg_parser_next_option(fm_arg_parser_t *state, const fm_cmdparser_t *parser)
{
	char *next;

	memset(&state->found, 0, sizeof(state->found));

	if (state->eof)
		return FM_ARG_EOF;

	if (state->optind >= state->argc) {
		state->eof = true;
		return FM_ARG_EOF;
	}

	next = state->argv[state->optind];

	if (!strcmp(next, "--")) {
		state->eof = true;
		state->optind++;
		return FM_ARG_EOF;
	}

	if (next[0] != '-')
		return FM_ARG_POSITIONALS;

	if (next[1] == '\0')
		return FM_ARG_POSITIONALS;

	if (next[1] != '-') {
		char short_value = next[1];

		if (!fm_cmdparser_find_short_option_handler(parser, short_value, state))
			return FM_ARG_UNKNOWN_OPTION;

		if (state->found.has_arg == no_argument) {
			if (next[2] != '\0') {
				/* -abc, and -a is an option that doesn't want an arg */
				next[1] = '-';
				state->argv[state->optind] = next + 1;
			} else {
				state->optind += 1;
			}
			return 0;
		} else
		if (next[2] != '\0') {
			/* -abc, and -a wants an argument: optarg="bc" */
			state->found.argument = next + 2;
			state->optind++;
			return 0;
		}
	} else {
		/* --foobar */

		state->optind++;

		if (!fm_cmdparser_find_long_option_handler(parser, next, state))
			return FM_ARG_UNKNOWN_OPTION;

		if (state->found.has_arg == no_argument)
			return 0;
	}

	/* Regular argument parsing:
	 *  -c blah
	 *  --foobar blah
	 */
	if (state->optind >= state->argc) {
		if (state->found.has_arg == optional_argument)
			return 0;

		return FM_ARG_MISSING_ARGUMENT;
	}

	next = state->argv[state->optind];
	if (!strncmp(next, "--", 2)) {
		if (state->found.has_arg == optional_argument)
			return 0;

		fm_log_error("%s: option %s requires an argument but is followed by \"%s\"",
				parser->name, state->found.option, next);
		return FM_ARG_MISSING_ARGUMENT;
	}

	state->found.argument = next;
	state->optind++;

	return 0;
}

static const char *
fm_arg_parser_next_positional(fm_arg_parser_t *state)
{
	if (state->eof)
		return NULL;

	if (state->optind >= state->argc)
		return NULL;

	return state->argv[state->optind++];
}

int
fm_cmdparser_process_args(const fm_cmdparser_t *parser, int argc, char **argv)
{
	fm_arg_parser_t state;

	fm_arg_parser_init(&state, argc, argv);

	while (true) {
		const char *cmdname;
		int c;

		while (true) {
			c = fm_arg_parser_next_option(&state, parser);

			if (c == FM_ARG_EOF || c == FM_ARG_POSITIONALS)
				break;

			if (c < 0) {
				fm_log_error("error: %s", state.found.option);
				fm_cmdparser_usage(parser, 1);
			}

			if (!state.found.setfn(state.found.value, state.found.argument))
				fm_cmdparser_usage(parser, 1);
		}

		if (parser->subcommands == NULL)
			break;

		cmdname = fm_arg_parser_next_positional(&state);
		if (cmdname == NULL) {
			fm_log_error("%s: missing subcommand", parser->name);
			fm_cmdparser_usage(parser, 1);
		} else {
			fm_cmdparser_t *subparser;

			subparser = fm_cmdparser_find_subcommand(parser, cmdname);
			if (subparser == NULL) {
				fm_log_error("%s: unknown subcommand \"%s\"", parser->name, cmdname);
				fm_cmdparser_usage(parser, 1);
			}

			parser = subparser;
		}
	}

	optind = state.optind;

	return parser->cmdid;
}
