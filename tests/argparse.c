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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "freemap.h"
#include "subcommand.h"

fm_long_option_t	global_long_options[] = {
	{ "foobar",	FM_ARG_REQUIRED,	'f'	},
	{ "debug",	FM_ARG_NONE,		'd'	},
	{ "brain",	FM_ARG_OPTIONAL,	'b'	},
	{ NULL }
};

struct global_opts {
	const char *	foobar;
	unsigned int	debug;
	const char *	brain;
} global_opts;

static bool
global_set_fn(int val, const char *argument)
{
	switch (val) {
	case 'f':
		global_opts.foobar = argument;
		break;

	case 'd':
		global_opts.debug++;
		break;

	case 'b':
		global_opts.brain = argument;
		break;

	default:
		return false;
	}

	return true;
}

static bool
strings_equal(const char *s1, const char *s2)
{
	if (s1 == NULL || s2 == NULL)
		return s1 == s2;

	return !strcmp(s1, s2);
}

static char **
clone_argv(int argc, char **argv)
{
	char **ret;
	int i;

	ret = calloc(argc + 1, sizeof(ret[0]));
	for (i = 0; i < argc; ++i)
		ret[i] = strdup(argv[i]);
	return ret;
}

bool
parse_one(fm_cmdparser_t *parser, char **argv, const struct global_opts *expect)
{
	int argc = 0;
	fm_command_t *cmd;

	while (argv[argc] != NULL)
		++argc;

	argv = clone_argv(argc, argv);

	memset(&global_opts, 0, sizeof(global_opts));

	cmd = fm_cmdparser_process_args(parser, argc, argv);
	if (cmd == NULL) {
		fprintf(stderr, "%s: fm_cmdparser_process_args() returns error", argv[0]);
		return false;
	}

	if (cmd->cmdid != 1) {
		fprintf(stderr, "%s: fm_cmdparser_process_args() returns commmand id %d", argv[0], cmd->cmdid);
		return false;
	}

	if (expect) {
		if (!strings_equal(global_opts.foobar, expect->foobar)) {
			fprintf(stderr, "%s: unexpected difference: expected foobar=\"%s\", found \"%s\"\n",
					argv[0], expect->foobar, global_opts.foobar);
			return false;
		}
		if (global_opts.debug != expect->debug) {
			fprintf(stderr, "%s: unexpected difference: expected debug=%d, found %d\n",
					argv[0], expect->debug, global_opts.debug);
			return false;
		}
		if (!strings_equal(global_opts.brain, expect->brain)) {
			fprintf(stderr, "%s: unexpected difference: expected brain=\"%s\", found \"%s\"\n",
					argv[0], expect->brain, global_opts.brain);
			return false;
		}
	}

	printf("%s: OK\n", argv[0]);
	return true;
}

void
test1(fm_cmdparser_t *parser)
{
	struct global_opts expect = { 0 };
	char *argv[] = {
		(char *) __func__,
		NULL
	};

	parse_one(parser, argv, &expect);
}

void
test2(fm_cmdparser_t *parser)
{
	struct global_opts expect = { .debug = 3 };
	char *argv[] = {
		(char *) __func__,
		"-ddd",
		NULL
	};

	parse_one(parser, argv, &expect);
}

void
test3(fm_cmdparser_t *parser)
{
	struct global_opts expect = { .foobar = "strange" };
	char *argv[] = {
		(char *) __func__,
		"--foobar",
		"strange",
		NULL
	};

	parse_one(parser, argv, &expect);
}

void
test4(fm_cmdparser_t *parser)
{
	struct global_opts expect = { .brain = NULL };
	char *argv[] = {
		(char *) __func__,
		"--brain",
		NULL
	};

	parse_one(parser, argv, &expect);
}

void
test5(fm_cmdparser_t *parser)
{
	struct global_opts expect = { .brain = "dead" };
	char *argv[] = {
		(char *) __func__,
		"--brain",
		"dead",
		NULL
	};

	parse_one(parser, argv, &expect);
}

void
test6(fm_cmdparser_t *parser)
{
	struct global_opts expect = { .foobar = "red", .debug = 1 };
	char *argv[] = {
		(char *) __func__,
		"-dfred",
		NULL
	};

	parse_one(parser, argv, &expect);
}

int
main(int argc, char **argv)
{
	fm_cmdparser_t *parser;

	parser = fm_cmdparser_main("test", 1, "df:b::", global_long_options, global_set_fn);

	test1(parser);
	test2(parser);
	test3(parser);
	test4(parser);
	test5(parser);
	test6(parser);
}

