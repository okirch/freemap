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

#ifndef FREEMAP_SCANNER_H
#define FREEMAP_SCANNER_H

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "freemap.h"
#include "lists.h"
#include "utils.h"

typedef struct fm_scan_dummy	fm_scan_state_t;

#define FM_SCAN_ACTION_FLAG_OPTIONAL	0x0001
#define FM_SCAN_ACTION_FLAG_LOCAL_ONLY	0x0100

struct fm_scan_action {
	struct fm_multiprobe *	multiprobe;
	fm_target_pool_t *	target_queue;
};

typedef struct fm_scan_action_array {
	unsigned int		count;
	fm_scan_action_t **	entries;
} fm_scan_action_array_t;

struct fm_scanner {
	fm_target_manager_t *	target_manager;
	fm_report_t *		report;

	struct timeval		scan_started;
	struct timeval		next_pool_resize;

	/* We put an overall limit on the number of packets we
	 * generate per second.
	 * In addition, we put a limit on the number of packets
	 * that we send to an individual host.
	 */
	fm_ratelimit_t		send_rate_limit;

	const fm_service_catalog_t *service_catalog;

	fm_address_enumerator_t *addr_discovery;

	struct {
		/* Index into scanner->stage_requests */
		unsigned int		index;
		unsigned int		next_pool_id;

		unsigned int		num_done;
		fm_scan_action_array_t *actions;
	}			current_stage;
	fm_scan_action_array_t	stage_requests[__FM_SCAN_STAGE_MAX];

	const fm_protocol_engine_t *proto;
};

struct fm_scan_action_ops;

extern fm_scan_action_t *	fm_scan_action_create(fm_multiprobe_t *multiprobe);
extern bool			fm_scanner_add_probe(fm_scanner_t *, int stage, const fm_config_probe_t *);
extern void			fm_scanner_set_service_catalog(fm_scanner_t *, const fm_service_catalog_t *);
extern bool			fm_scanner_initiate_discovery(fm_scanner_t *, const char *addrspec);

extern void			fm_scanner_add_global_job(fm_scanner_t *scanner, fm_job_t *job);

static inline fm_scan_action_array_t *
fm_scanner_get_stage(fm_scanner_t *scanner, unsigned int stage)
{
	assert(stage < __FM_SCAN_STAGE_MAX);
	return &scanner->stage_requests[stage];
}

static inline fm_scan_action_array_t *
fm_scanner_get_current_stage(fm_scanner_t *scanner)
{
	return scanner->current_stage.actions;
}

#endif /* FREEMAP_SCANNER_H */

