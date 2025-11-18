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

#ifndef FREEMAP_ADDRESSES_H
#define FREEMAP_ADDRESSES_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "freemap.h"
#include "lists.h"

typedef struct fm_address_prefix fm_address_prefix_t;

struct fm_address_prefix {
	/* This is the address we can route to.
	 * For point-to-point devices like tunnels, this will be the host address
	 * of the remote end.
	 */
	fm_address_t		address;
	unsigned int		pfxlen;

	/* This is the address we use when talking to this device */
	fm_address_t		source_addr;

	unsigned char		raw_mask[16];

	/* for local addrs */
	int			ifindex;
	char *			ifname;
	const fm_interface_t *	device;
};

struct fm_address_prefix_array {
	unsigned int		count;
	fm_address_prefix_t *	elements;
};

struct fm_address_array {
	unsigned int		count;
	fm_address_t *		elements;
};

struct fm_address_enumerator {
	fm_gateway_t *		unknown_gateway;

	/* every enumerator has its unique id */
	unsigned int		id;

	const struct fm_address_enumerator_ops {
		size_t		obj_size;
		const char *	name;
		void		(*destroy)(fm_address_enumerator_t *);
		void		(*restart)(fm_address_enumerator_t *, int);
		fm_error_t	(*get_one_address)(fm_address_enumerator_t *, fm_address_t *);
		void		(*add_address)(fm_address_enumerator_t *, const fm_address_t *);
	} *ops;
};

typedef struct fm_address_enumerator_array {
	unsigned int		count;
	fm_address_enumerator_t **entries;
} fm_address_enumerator_array_t;

struct fm_address_enumerator_list {
	struct hlist_head	head;
};

extern fm_address_enumerator_t *fm_address_enumerator_alloc(const struct fm_address_enumerator_ops *);
extern fm_address_enumerator_t *fm_address_enumerator_new_discovery(void);
extern void			fm_address_enumerator_array_append(fm_address_enumerator_array_t *,
						fm_address_enumerator_t *);
extern void			fm_address_enumerator_array_remove_shallow(fm_address_enumerator_array_t *,
						unsigned int);
extern void			fm_address_enumerator_array_destroy_shallow(fm_address_enumerator_array_t *);
extern const unsigned char *	fm_address_get_raw_addr(const fm_address_t *, unsigned int *nbits);
extern bool			fm_address_set_raw_addr(fm_address_t *,int family,  const unsigned char *raw_data, size_t len);
extern bool			fm_address_generator_address_eligible(const fm_address_t *address);
extern bool			fm_address_generator_address_eligible_any_state(const fm_address_t *address);
extern void			fm_interface_add(const char *name, const struct sockaddr_ll *);
extern const fm_address_prefix_t *fm_local_prefix_for_address(const fm_address_t *addr);
extern bool			fm_address_mask_from_prefixlen(int af, unsigned int pfxlen, unsigned char *mask, unsigned int size);
extern void			fm_local_neighbor_cache_update(const fm_address_t *net_addr, const fm_address_t *lladdr);
extern void			fm_local_cache_arp_entry(u_int32_t ipaddr, const fm_address_t *lladdr);

extern bool			fm_create_simple_address_enumerator(const char *, fm_target_manager_t *);
extern bool			fm_create_cidr_address_enumerator(const char *, fm_target_manager_t *);
extern bool			fm_create_local_address_enumerator(const char *, fm_target_manager_t *);

extern bool			fm_address_array_append_unique(fm_address_array_t *array, const fm_address_t *addr);
extern void			fm_address_prefix_array_append(fm_address_prefix_array_t *array, const fm_address_prefix_t *pfx);

static inline unsigned int
fm_addrfamily_max_addrbits(int af)
{
	switch (af) {
	case AF_INET:
		return 32;
	case AF_INET6:
		return 128;
	}

	return 0;
}

/*
 * Various functions for casting fm_address_t to sockaddr_*
 */
#define fm_address_maybe_cast(__addr, __af, __dtype) do { \
	if (__addr->family != __af) \
		return NULL; \
	return (__dtype *) __addr; \
} while (0)

#define DECLARE_FM_ADDRESS_CAST_FUNCTIONS(__af, __name, __dtype) \
static inline __dtype *__name(fm_address_t *addr) { \
	fm_address_maybe_cast(addr, __af, __dtype); \
} \
static inline const __dtype *__name ## _const(const fm_address_t *addr) { \
	fm_address_maybe_cast(addr, __af, const __dtype); \
}

DECLARE_FM_ADDRESS_CAST_FUNCTIONS(AF_PACKET, fm_address_to_link, struct sockaddr_ll)
DECLARE_FM_ADDRESS_CAST_FUNCTIONS(AF_INET, fm_address_to_ipv4, struct sockaddr_in)
DECLARE_FM_ADDRESS_CAST_FUNCTIONS(AF_INET6, fm_address_to_ipv6, struct sockaddr_in6)


static inline void
fm_address_array_append(fm_address_array_t *array, const fm_address_t *addr)
{
	if ((array->count % 8) == 0)
		array->elements = realloc(array->elements, (array->count + 8) * sizeof(array->elements[0]));
	array->elements[array->count++] = *addr;
}

static inline void
fm_address_array_destroy(fm_address_array_t *array)
{
	if (array->elements)
		free(array->elements);
	memset(array, 0, sizeof(*array));
}

#endif /* FREEMAP_ADDRESSES_H */
