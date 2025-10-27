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
#include <stdarg.h>
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
		fm_cmdparser_option_handler_fn_t *setfn;
	} found;
} fm_arg_parser_t;

#define FM_ARG_OK		0
#define FM_ARG_EOF		-1
#define FM_ARG_POSITIONALS	-2
#define FM_ARG_ERROR		-3

/* Context for fm_cmdparser_usage() */
static const fm_cmdparser_t *	last_parser_used;

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

	*has_arg_p = FM_ARG_NONE;
	if (p[0] == ':') {
		*has_arg_p = FM_ARG_REQUIRED;
		if (p[1] == ':')
			*has_arg_p = FM_ARG_OPTIONAL;
		while (*p == ':')
			++p;
	}

	*pos = p;
	return optchar;
}

static void
fm_cmdparser_add_handler(fm_cmdparser_t *parser, const char *name, int val, int has_arg)
{
	fm_long_option_t *h;

	maybe_realloc_array(parser->options, parser->num_options, 16);

	h = &parser->options[parser->num_options++];
	h->name = strdup(name);
	h->value = val;
	h->has_arg = has_arg;
}

static bool
fm_cmdparser_find_long_option_handler(const fm_cmdparser_t *parser, const char *name, fm_arg_parser_t *state)
{
	static char errname[64];
	unsigned int i;

	while (parser != NULL) {
		for (i = 0; i < parser->num_options; ++i) {
			const fm_long_option_t *h = &parser->options[i];

			if (!strcmp(h->name, name)) {
				state->found.option = h->name;
				state->found.value = h->value;
				state->found.has_arg = h->has_arg;
				state->found.setfn = parser->process_option;
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

fm_cmdparser_t *
fm_cmdparser_main(const char *name, unsigned int cmdid,
			const char *short_options, const fm_long_option_t *long_options,
			bool (*opt_fn)(int, const char *))
{
	static const fm_long_option_t empty_options[] = { { NULL, } };
	fm_cmdparser_t *parser;
	const fm_long_option_t *o;
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
	parser->process_option = opt_fn;

	for (o = long_options; o->name; ++o) {
		char *long_name = NULL;

		asprintf(&long_name, "--%s", o->name);
		fm_cmdparser_add_handler(parser, long_name, o->value, o->has_arg);
		free(long_name);
	}

	pos = short_options;
	while ((c = fm_short_options_iter(&pos, &has_arg)) >= 0) {
		char namebuf[8];

		snprintf(namebuf, sizeof(namebuf), "-%c" ,c);
		fm_cmdparser_add_handler(parser, namebuf, c, has_arg);
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
	parent->subcommands[count] = NULL;
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
				const char *short_options, const fm_long_option_t *long_options,
				bool (*opt_fn)(int, const char *))
{
	fm_cmdparser_t *parser;

	parser = fm_cmdparser_main(name, cmdid, short_options, long_options, opt_fn);
	fm_cmdparser_install_subcommand(parent, parser);

	return parser;
}

static char *
fm_cmdparser_fullname(const fm_cmdparser_t *parser)
{
	const char *names[16];
	unsigned int count, size = 0, k, pos;
	char *result;

	for (count = 0; parser; parser = parser->parent) {
		size += strlen(parser->name) + 1;
		names[count++] = parser->name;
	}

	result = calloc(size, 1);
	for (k = count, pos = 0; k--; ) {
		if (pos)
			result[pos++] = ' ';
		strcpy(result + pos, names[k]);
		pos = strlen(result);
	}

	return result;
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

static void
fm_arg_parser_error(fm_arg_parser_t *state, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "bad command line option: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
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

		if (!fm_cmdparser_find_short_option_handler(parser, short_value, state)) {
			fm_arg_parser_error(state, "unknown option -%c\n", short_value);
			return FM_ARG_ERROR;
		}

		if (state->found.has_arg == FM_ARG_NONE) {
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

		if (!fm_cmdparser_find_long_option_handler(parser, next, state)) {
			fm_arg_parser_error(state, "unknown option %s\n", next);
			return FM_ARG_ERROR;
		}

		if (state->found.has_arg == FM_ARG_NONE)
			return 0;
	}

	/* Regular argument parsing:
	 *  -c blah
	 *  --foobar blah
	 */
	if (state->optind >= state->argc) {
		if (state->found.has_arg == FM_ARG_OPTIONAL)
			return 0;

		fm_arg_parser_error(state, "option %s requires an argument\n", state->found.option);
		return FM_ARG_ERROR;
	}

	next = state->argv[state->optind];
	if (!strncmp(next, "--", 2)) {
		if (state->found.has_arg == FM_ARG_OPTIONAL)
			return 0;

		fm_arg_parser_error(state, "option %s requires an argument but i followed by \"%s\"\n",
				state->found.option, next);
		return FM_ARG_ERROR;
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

fm_command_t *
fm_cmdparser_process_args(const fm_cmdparser_t *parser, int argc, char **argv)
{
	fm_arg_parser_t state;
	fm_command_t *result;

	fm_arg_parser_init(&state, argc, argv);

	while (true) {
		const char *cmdname;
		int c;

		last_parser_used = parser;

		while (true) {
			c = fm_arg_parser_next_option(&state, parser);

			if (c == FM_ARG_EOF || c == FM_ARG_POSITIONALS)
				break;

			if (c < 0)
				return NULL;

			if (!state.found.setfn(state.found.value, state.found.argument))
				return NULL;
		}

		if (parser->subcommands == NULL)
			break;

		cmdname = fm_arg_parser_next_positional(&state);
		if (cmdname == NULL) {
			fm_log_error("%s: missing subcommand", parser->name);
			return NULL;
		} else {
			fm_cmdparser_t *subparser;

			subparser = fm_cmdparser_find_subcommand(parser, cmdname);
			if (subparser == NULL) {
				fm_log_error("%s: unknown subcommand \"%s\"", parser->name, cmdname);
				return NULL;
			}

			parser = subparser;
		}
	}

	result = calloc(1, sizeof(*result));
	result->fullname = fm_cmdparser_fullname(parser);
	result->cmdid = parser->cmdid;
	result->nvalues = state.argc - state.optind;
	result->values = state.argv + state.optind;

	return result;
}

/*
 * Display command usage
 */
static void
fm_cmdparser_usage_work(FILE *fp, const fm_cmdparser_t *parser, bool last)
{
	char *fullname = fm_cmdparser_fullname(parser);
	unsigned int k;

	if (last) {
		fprintf(fp, "Usage: %s ...\n", fullname);

		if (parser->subcommands) {
			fm_cmdparser_t *sub;

			fprintf(fp, "\nAvailable subcommands:\n");
			for (k = 0; (sub = parser->subcommands[k]) != NULL; ++k) {
				fprintf(fp, "  %s (no help)\n", sub->name);
			}
		}

		if (parser->num_options)
			fprintf(fp, "\nOptions:\n");
	} else if (parser->num_options) {
		fprintf(fp, "\nAdditional %s options:\n", fullname);
	}

	free(fullname);

	for (k = 0; k < parser->num_options; ++k) {
		const fm_long_option_t *o = &parser->options[k];

		if (o->has_arg == FM_ARG_NONE) {
			fprintf(fp, "  %s", o->name);
		} else {
			const char *arg_name = "ARGUMENT";

			if (o->has_arg == FM_ARG_OPTIONAL)
				fprintf(fp, "  %s [%s]", o->name, arg_name);
			else
				fprintf(fp, "  %s %s", o->name, arg_name);
		}

		fprintf(fp, " (do something useful)\n");
	}

	if (parser->parent != NULL)
		fm_cmdparser_usage_work(fp, parser->parent, false);
}

void
fm_cmdparser_usage(FILE *fp)
{
	if (fp == NULL)
		fp = stderr;

	if (last_parser_used == NULL) {
		fprintf(fp, "%s() called before any args have been parsed\n", __func__);
		return;
	}

	fm_cmdparser_usage_work(fp, last_parser_used, true);
}
