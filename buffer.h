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

#ifndef FREEMAP_BUFFER_H
#define FREEMAP_BUFFER_H

#include "types.h"

extern fm_buffer_t *	fm_buffer_alloc(size_t payload);
extern void		fm_buffer_free(fm_buffer_t *pkt);
extern void		fm_buffer_compact(fm_buffer_t *pkt);
extern fm_buffer_t *	fm_buffer_pull_packet(fm_buffer_t *pkt, unsigned int count);

static inline unsigned int
fm_buffer_available(fm_buffer_t *pkt)
{
	return pkt->wpos - pkt->rpos;
}

static inline unsigned int
fm_buffer_tailroom(fm_buffer_t *pkt)
{
	return pkt->size - pkt->wpos;
}

static inline void *
fm_buffer_push(fm_buffer_t *pkt, size_t count)
{
	void *ret = pkt->data + pkt->wpos;

	assert(pkt->size - pkt->wpos >= count);
	pkt->wpos += count;
	return ret;
}

static inline void *
fm_buffer_peek(fm_buffer_t *pkt, size_t len)
{
	if (pkt->wpos - pkt->rpos < len)
		return NULL;
	return pkt->data + pkt->rpos;
}

static inline void *
fm_buffer_pull(fm_buffer_t *pkt, size_t len)
{
	void *ret = fm_buffer_peek(pkt, len);

	if (ret != NULL)
		pkt->rpos += len;
	return ret;
}

static inline unsigned int
fm_buffer_len(fm_buffer_t *pkt, void *base)
{
	size_t offset = (unsigned char *) base - pkt->data;

	assert(offset <= pkt->wpos);
	return pkt->wpos - offset;
}


#endif /* FREEMAP_BUFFER_H */

