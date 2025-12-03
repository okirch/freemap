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

#include <assert.h>
#include <string.h>
#include "types.h"

extern fm_buffer_t *	fm_buffer_alloc(size_t payload);
extern void		fm_buffer_free(fm_buffer_t *pkt);
extern void		fm_buffer_compact(fm_buffer_t *pkt);
extern fm_buffer_t *	fm_buffer_pull_packet(fm_buffer_t *pkt, unsigned int count);
extern void		fm_buffer_dump(const fm_buffer_t *, const char *);

static inline const void *
fm_buffer_head(const fm_buffer_t *pkt)
{
	return pkt->data + pkt->rpos;
}

static inline unsigned int
fm_buffer_available(const fm_buffer_t *pkt)
{
	return pkt->wpos - pkt->rpos;
}

static inline void *
fm_buffer_tail(fm_buffer_t *pkt)
{
	return pkt->data + pkt->wpos;
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

static inline bool
fm_buffer_append(fm_buffer_t *bp, const void *data, size_t len)
{
	void *tail = fm_buffer_push(bp, len);

	if (tail == NULL)
		return false;
	memcpy(tail, data, len);
	return true;
}

static inline bool
fm_buffer_put16(fm_buffer_t *bp, u_int16_t word)
{
	return fm_buffer_append(bp, &word, 2);
}

static inline bool
fm_buffer_put32(fm_buffer_t *bp, u_int32_t word)
{
	return fm_buffer_append(bp, &word, 4);
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

static inline bool
fm_buffer_get16(fm_buffer_t *pkt, uint16_t *ret)
{
	const uint16_t *data;

	if (!(data = fm_buffer_pull(pkt, sizeof(*data))))
		return false;
	*ret = *data;
	return true;
}

static inline bool
fm_buffer_get32(fm_buffer_t *pkt, uint32_t *ret)
{
	const uint32_t *data;

	if (!(data = fm_buffer_pull(pkt, sizeof(*data))))
		return false;
	*ret = *data;
	return true;
}

static inline unsigned int
fm_buffer_len(fm_buffer_t *pkt, const void *base)
{
	size_t offset = (unsigned char *) base - pkt->data;

	assert(offset <= pkt->wpos);
	return pkt->wpos - offset;
}

static inline bool
fm_buffer_truncate(fm_buffer_t *pkt, unsigned int len)
{
	unsigned int new_wpos = pkt->rpos + len;

	if (new_wpos < pkt->rpos)
		return false; /* int overflow */
	if (new_wpos > pkt->wpos)
		return false;

	pkt->wpos = new_wpos;
	return true;
}

#endif /* FREEMAP_BUFFER_H */

