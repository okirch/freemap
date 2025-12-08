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

#ifndef FREEMAP_PROTOCOLS_H
#define FREEMAP_PROTOCOLS_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "freemap.h"
#include "protocols.h"
#include "lists.h"

struct fm_protocol {
	size_t		obj_size;
	const char *	name;

	int		id; /* FM_PROTO_* */

	unsigned int	supported_parameters;

	void		(*destroy)(fm_protocol_t *);

	fm_socket_t *	(*create_socket)(fm_protocol_t *, int af, const fm_address_t *bind_addr);

	fm_extant_t *	(*locate_error)(fm_protocol_t *, fm_pkt_t *, hlist_iterator_t *);
	fm_extant_t *	(*locate_response)(fm_protocol_t *, fm_pkt_t *, hlist_iterator_t *);

	bool		(*handle_os_error)(fm_protocol_t *, fm_pkt_t *);
};

#define FM_PARAM_TYPE_RETRIES_MASK	(1 << FM_PARAM_TYPE_RETRIES)
#define FM_PARAM_TYPE_PORT_MASK		(1 << FM_PARAM_TYPE_PORT)
#define FM_PARAM_TYPE_TTL_MASK		(1 << FM_PARAM_TYPE_TTL)
#define FM_PARAM_TYPE_TOS_MASK		(1 << FM_PARAM_TYPE_TOS)

#define FM_FEATURE_SOCKET_SHARING_MASK	(1 << FM_FEATURE_SOCKET_SHARING)
#define FM_FEATURE_STATUS_CALLBACK_MASK	(1 << FM_FEATURE_STATUS_CALLBACK)
#define FM_FEATURE_SERVICE_PROBES_MASK	(1 << FM_FEATURE_SERVICE_PROBES)

extern void		fm_protocol_directory_add(struct fm_protocol *ops);
extern void		fm_protocol_directory_display(void);

extern fm_protocol_t *	fm_protocol_by_name(const char *);
extern fm_protocol_t *	fm_protocol_by_id(unsigned int);

extern fm_socket_t *	fm_protocol_create_socket(fm_protocol_t *, int af, const fm_address_t *bind_addr);

extern fm_extant_t *	fm_protocol_locate_error(fm_protocol_t *, fm_pkt_t *, hlist_iterator_t *);
extern fm_extant_t *	fm_protocol_locate_response(fm_protocol_t *, fm_pkt_t *, hlist_iterator_t *);

#define FM_PROTOCOL_REGISTER(ops) \
__attribute__((constructor)) \
static void \
fm_protocol_register_ ## ops(void) \
{ \
	fm_protocol_directory_add(&ops); \
}

static inline bool
fm_protocol_supports_param(fm_protocol_t *proto, fm_param_type_t type)
{
	return !!(proto->supported_parameters & (1 << type));
}

/*
 * Utility functions for packet assembly and parsing
 */
extern const void *	fm_pkt_pull(fm_pkt_t *pkt, unsigned int wanted);
extern const void *	fm_pkt_push(fm_pkt_t *pkt, unsigned int wanted);
extern fm_pkt_t *	fm_pkt_alloc(int family, unsigned int size);
extern void		fm_pkt_apply_probe_params(fm_pkt_t *, const fm_probe_params_t *, unsigned int mask);
extern bool		fm_pkt_apply_param(fm_pkt_t *pkt, int param_type, unsigned int param_value);
extern void		fm_pkt_free(fm_pkt_t *pkt);
extern void		fm_pkt_set_peer_address_raw(fm_pkt_t *pkt, const fm_address_t *dst_addr, int ipproto);


#endif /* FREEMAP_PROTOCOLS_H */

