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

#include "services.h"
#include "program.h"
#include "protocols.h"

fm_service_catalog_t *
fm_service_catalog_alloc(void)
{
	fm_service_catalog_t *catalog;

	catalog = calloc(1, sizeof(*catalog));
	catalog->services = calloc(1, sizeof(*(catalog->services)));
	return catalog;
}

static fm_service_probe_t *
fm_service_probe_alloc(unsigned int proto_id, unsigned int port)
{
	fm_service_probe_t *probe;

	probe = calloc(1, sizeof(*probe));
	probe->proto_id = proto_id;
	probe->port = port;
	return probe;
}

/*
 * Add a packet to a service probe
 */
static inline void
fm_service_probe_add_packet(fm_service_probe_t *probe, fm_buffer_t *bp)
{
	maybe_realloc_array(probe->packets, probe->npackets, 1);
	probe->packets[probe->npackets++] = bp;
}

static inline void
fm_service_probe_add_packet_array(fm_service_probe_t *probe, const fm_config_packet_array_t *packets)
{
	unsigned int i;

	for (i = 0; i < packets->count; ++i) {
		const fm_config_packet_t *packet = packets->entries[i];
		fm_service_probe_add_packet(probe, packet->payload);
	}
}

bool
fm_service_catalog_add_service(fm_service_catalog_t *catalog, fm_config_service_t *service)
{
	unsigned int i;

	/* silently ignore duplicates */
	for (i = 0; i < catalog->services->count; ++i) {
		if (service == catalog->services->entries[i])
			return true;
	}

	fm_log_debug("Service %ss added to service catalog", service->fullname);
	fm_config_service_array_append(catalog->services, service);
	return true;
}

static inline bool
fm_config_service_match(const fm_config_service_t *service, unsigned int proto_id, unsigned int port)
{
	const fm_uint_array_t *ports;
	unsigned int k;

	if (proto_id == FM_PROTO_TCP)
		ports = &service->tcp_ports;
	else if (proto_id == FM_PROTO_UDP)
		ports = &service->udp_ports;
	else
		return false;

	for (k = 0; k < ports->count; ++k) {
		if (port == ports->entries[k])
			return true;
	}

	return false;
}

fm_service_probe_t *
fm_service_catalog_get_service_probe(const fm_service_catalog_t *catalog, unsigned int proto_id, unsigned int port)
{
	fm_service_probe_t *result = NULL;
	unsigned int i;

	if (proto_id != FM_PROTO_TCP && proto_id != FM_PROTO_UDP)
		return NULL;

	for (i = 0; i < catalog->services->count; ++i) {
		fm_config_service_t *service = catalog->services->entries[i];

		if (!fm_config_service_match(service, proto_id, port))
			continue;

		if (service->packets.count == 0)
			continue;

		if (result == NULL)
			result = fm_service_probe_alloc(proto_id, port);

		fm_service_probe_add_packet_array(result, &service->packets);

		fm_log_debug("port %s/%u - use service probe %s (%u packets)",
				fm_protocol_id_to_string(proto_id), port,
				service->name, service->packets.count);
	}

	return result;
}


