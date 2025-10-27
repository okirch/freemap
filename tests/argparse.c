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

fm_long_option_t	frob_long_options[] = {
	{ "output",	FM_ARG_REQUIRED,	'o'	},
	{ NULL }
};

struct global_opts {
	const char *	foobar;
	unsigned int	debug;
	const char *	brain;

	const char *	output;

	char *		values[16];
} global_opts;

struct testcase {
	char *		argv[16];
	struct global_opts expect;
	unsigned int	expect_cmdid;
	const char *	expect_cmdname;
};

static unsigned int	test_index = 1;

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
frob_set_fn(int val, const char *argument)
{
	switch (val) {
	case 'o':
		global_opts.output = argument;
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
	char testname[32];
	char **ret;
	int i;

	snprintf(testname, sizeof(testname), "test%u", test_index++);
	argv[0] = testname;

	ret = calloc(argc + 1, sizeof(ret[0]));
	for (i = 0; i < argc; ++i)
		ret[i] = strdup(argv[i]);
	return ret;
}

bool
perform_test(fm_cmdparser_t *parser, char **argv, const struct global_opts *expect, int expected_subcommand, const char *expected_name)
{
	int argc = 0;
	fm_command_t *cmd;

	while (argv[argc] != NULL)
		++argc;

	argv = clone_argv(argc, argv);

	if (true) {
		int k;

		printf("%s:\n", argv[0]);
		printf("   cmd:");
		for (k = 0; k < argc; ++k)
			printf(" %s", argv[k]);
		printf("\n");

		printf("   expect result:\n    cmdid=%d", expected_subcommand);
		if (expected_name)
			printf(" cmdname=\"%s\"", expected_name);
		printf("\n");

		printf("    option foobar: %s\n", expect->foobar);
		printf("    option brain:  %s\n", expect->brain);
		printf("    option debug:  %d\n", expect->debug);

		if (expected_subcommand == 2)
			printf("    option output: %s\n", expect->output);

		if (expect->values[0]) {
			printf("    arguments:    ");
			for (k = 0; expect->values[k]; ++k)
				printf(" %s", expect->values[k]);
			printf("\n");
		}
	}

	memset(&global_opts, 0, sizeof(global_opts));

	cmd = fm_cmdparser_process_args(parser, argc, argv);
	if (cmd == NULL) {
		fprintf(stderr, "%s: fm_cmdparser_process_args() returns error", argv[0]);
		return false;
	}

	if (cmd->cmdid != expected_subcommand) {
		fprintf(stderr, "%s: fm_cmdparser_process_args() returns commmand id %d, expected %d", argv[0], cmd->cmdid, expected_subcommand);
		return false;
	}

	if (expected_name && !strings_equal(cmd->fullname, expected_name)) {
		fprintf(stderr, "%s: unexpected difference: expected command name \"%s\", found \"%s\"\n",
				argv[0], expected_name, cmd->fullname);
		return false;
	}

	if (expect) {
		unsigned int k, nexpected;

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
		if (!strings_equal(global_opts.output, expect->output)) {
			fprintf(stderr, "%s: unexpected difference: expected output=\"%s\", found \"%s\"\n",
					argv[0], expect->output, global_opts.output);
			return false;
		}

		for (nexpected = 0; expect->values[nexpected] != NULL; nexpected++)
			;

		if (cmd->nvalues != nexpected) {
			fprintf(stderr, "%s: unexpected difference: expected %u positional arguments, found %u\n",
					argv[0], nexpected, cmd->nvalues);
			return false;
		}

		for (k = 0; k < cmd->nvalues; ++k) {
			if (strcmp(expect->values[k], cmd->values[k])) {
				fprintf(stderr, "%s: unexpected difference: wrong positional arguments in value[%d]; expected \"%s\", got \"%s\"\n",
						argv[0], k, expect->values[k], cmd->values[k]);
				return false;
			}
		}
	}

	printf("%s: OK\n", argv[0]);
	return true;
}

void
run_test_set_simple(fm_cmdparser_t *parser, struct testcase *tc)
{
	while (tc->argv[0] != NULL) {
		if (tc->expect_cmdid == 0)
			tc->expect_cmdid = 1;
		if (tc->expect_cmdname == NULL)
			tc->expect_cmdname = "test";

		perform_test(parser, (char **) tc->argv, &tc->expect, tc->expect_cmdid, tc->expect_cmdname);
		tc++;
	}
}

static struct testcase	test_set0[] = {
	{
		.argv = {
			"test",
		},
	},
	{
		.argv = {
			"test", "-ddd"
		},
		.expect = { .debug = 3, }
	},
	{
		.argv = {
			"test", "--foobar", "strange"
		},
		.expect = { .foobar = "strange" }
	},
	{
		.argv = {
			"test", "--brain",
		},
		.expect = { .brain = NULL, },
	},
	{
		.argv = {
			"test", "--brain", "dead",
		},
		.expect = { .brain = "dead", },
	},
	{
		.argv = {
			"test", "-dfred",
		},
		.expect = { .foobar = "red", .debug = 1, },
	},
	{
		.argv = {
			"test", "--debug", "positional",
		},
		.expect = { .debug = 1, .values = { "positional", } },
	},
	{
		.argv = {
			"test", "--debug", "--", "-d",
		},
		.expect = { .debug = 1, .values = { "-d", } },
	},
	{
		.argv = {
			"test", "--", "-d",
		},
		.expect = { .values = { "-d", } },
	},

	{ .argv = { NULL }, }
};

static struct testcase	test_set1[] = {
	{
		.argv = {
			"test", "frobnicate", "-d", "bork",
		},
		.expect = { .debug = 1, .values = { "bork" } },
		.expect_cmdid = 2,
		.expect_cmdname = "test frobnicate",
	},

	{ .argv = { NULL }, }
};

int
main(int argc, char **argv)
{
	fm_cmdparser_t *parser;

	parser = fm_cmdparser_main("test", 1, "df:b::", global_long_options, global_set_fn);

	run_test_set_simple(parser, test_set0);

	fm_cmdparser_add_subcommand(parser, "frobnicate", 2, NULL, frob_long_options, frob_set_fn);

	test_index = 100;
	run_test_set_simple(parser, test_set1);
}

