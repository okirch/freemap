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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "freemap.h"
#include "target.h"

struct fm_scheduler {
	fm_scanner_t *		scanner;

	const struct fm_scheduler_ops {
		const char *	name;
		size_t		size;

		bool		(*attach)(fm_scheduler_t *, fm_target_t *);
		void		(*detach)(fm_scheduler_t *, fm_target_t *);
		fm_probe_t *	(*get_next_probe)(fm_scheduler_t *, fm_target_t *);
		void		(*destroy)(fm_scheduler_t *);
	} *ops;
};

struct fm_linear_scheduler {
	fm_scheduler_t		base;
};

struct fm_linear_sched_target_state {
	fm_scan_action_t *	action;
	unsigned int		action_index;
	unsigned int		probe_index;
};

fm_scheduler_t *
fm_scheduler_alloc(fm_scanner_t *scanner, const struct fm_scheduler_ops *ops)
{
	fm_scheduler_t *ret;

	assert(ops->size >= sizeof(*ret));
	ret = calloc(1, ops->size);
	ret->scanner = scanner;
	ret->ops = ops;
	return ret;
}

void
fm_scheduler_free(fm_scheduler_t *sched)
{
	if (sched->ops->destroy)
		sched->ops->destroy(sched);
	memset(sched, 0, sizeof(sched->ops->size));
	free(sched);
}

fm_probe_t *
fm_scheduler_get_next_probe(fm_scheduler_t *sched, fm_target_t *target)
{
	return sched->ops->get_next_probe(sched, target);
}

bool
fm_scheduler_attach_target(fm_scheduler_t *sched, fm_target_t *target)
{
	return sched->ops->attach(sched, target);
}

void
fm_scheduler_detach_target(fm_scheduler_t *sched, fm_target_t *target)
{
	sched->ops->detach(sched, target);
}

/*
 * Linear scheduler
 */
static bool
fm_linear_scheduler_attach(fm_scheduler_t *sched, fm_target_t *target)
{
	struct fm_linear_sched_target_state *state;

	assert(target->sched_state == NULL);

	state = calloc(1, sizeof(*state));
	target->sched_state = state;
	return true;
}

static void
fm_linear_scheduler_detach(fm_scheduler_t *sched, fm_target_t *target)
{
	assert(target->sched_state != NULL);
	free(target->sched_state);
	target->sched_state = NULL;
}

static fm_probe_t *
fm_linear_scheduler_get_next_probe(fm_scheduler_t *sched, fm_target_t *target)
{
	struct fm_linear_sched_target_state *state = target->sched_state;
	fm_scan_action_t *action;
	fm_probe_t *probe;

	assert(state != NULL);

	while (true) {
		action = state->action;
		if (action == NULL) {
			if (!(action = fm_scanner_get_action(sched->scanner, state->action_index)))
				return NULL;

			state->action = action;
			state->action_index += 1;
			state->probe_index = 0;
		}

		probe = fm_scan_action_get_next_probe(action, target, state->probe_index);
		if (probe != NULL) {
			state->probe_index += 1;
			break;
		}

		if (state->probe_index == 0)
			fm_log_warning("scan action %s does not generate any probe packets at all!\n", fm_scan_action_id(action));

		state->action = NULL;
		state->probe_index = 0;
	}

	return probe;
}

static struct fm_scheduler_ops		fm_linear_scheduler_ops = {
	.name		= "linear",
	.size		= sizeof(fm_scheduler_t),

	.attach		= fm_linear_scheduler_attach,
	.detach		= fm_linear_scheduler_detach,
	.get_next_probe	= fm_linear_scheduler_get_next_probe,
};

fm_scheduler_t *
fm_linear_scheduler_create(fm_scanner_t *scanner)
{
	return fm_scheduler_alloc(scanner, &fm_linear_scheduler_ops);
}
