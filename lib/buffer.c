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
#include <stdlib.h>
#include <string.h>

#include "freemap.h"
#include "buffer.h"
#include "logging.h"

fm_buffer_t *
fm_buffer_alloc(size_t payload)
{
	fm_buffer_t *pkt;

	pkt = malloc(sizeof(*pkt) + payload);
	memset(pkt, 0, sizeof(*pkt));

	pkt->size = payload;
	return pkt;
}

void
fm_buffer_free(fm_buffer_t *pkt)
{
	free(pkt);
}

void
fm_buffer_compact(fm_buffer_t *pkt)
{
	if (pkt->wpos == 0)
		return;

	if (pkt->rpos == pkt->wpos) {
		pkt->rpos = pkt->wpos = 0;
		return;
	}

	assert(pkt->rpos < pkt->wpos);
	memmove(pkt->data, pkt->data + pkt->rpos, pkt->wpos - pkt->rpos);

	pkt->wpos -= pkt->rpos;
	pkt->rpos = 0;
}

fm_buffer_t *
fm_buffer_pull_packet(fm_buffer_t *pkt, unsigned int count)
{
	fm_buffer_t *ret;

	if (fm_buffer_available(pkt) < count)
		return NULL;

	ret = fm_buffer_alloc(count);
	memcpy(ret->data, pkt->data + pkt->rpos, count);
	pkt->rpos += count;
	ret->wpos = count;

	return ret;
}

void
fm_buffer_dump(const fm_buffer_t *bp, const char *msg)
{
	unsigned int len = fm_buffer_available(bp);

	if (msg)
		fm_log_notice("%s (%u bytes)", msg, len);
	fm_print_hexdump(fm_buffer_head(bp), len);
}
