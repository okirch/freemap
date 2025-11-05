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

#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <assert.h>

#include "assets.h"
#include "addresses.h"

struct fm_asset_fileformat {
	unsigned int	size;

	unsigned int	main_offset;
	unsigned int	port_map_offset[__FM_PROTO_MAX];
};

struct fm_asset_path {
	char *		asset_dir;

	struct fm_asset_fileformat format;

	int		family;
	unsigned int	addr_size;
	unsigned int	dir_size;
	unsigned char	raw[16];
};

static char *		fm_assetio_base_dir;
static bool		fm_assetio_read_write;

static void
fm_asset_fileformat_init(struct fm_asset_fileformat *fmt)
{
	const fm_protocol_asset_t *proto;
	unsigned int section_size;
	unsigned int i;

	memset(fmt, 0, sizeof(*fmt));

	/* the main data */
	fmt->size = 4096;

	section_size = sizeof(fm_asset_port_bitmap_t);
	for (i = 0; i < __FM_PROTO_MAX; ++i) {
		fmt->port_map_offset[i] = fmt->size;
		fmt->size += section_size;
	}
}

/*
 * Initialize an asset path object.
 * An asset may have an address like ff8e::1, corresponding to the path
 * ./ipv6/ff80/0000/0000/0000/0000:0000:0000:0001
 * Or it may have an address like 1.2.3.4, corresponding to the path ./ipv4/1/2/3/4
 */
static bool
fm_asset_path_init(struct fm_asset_path *path, const char *project_dir, int family)
{
	memset(path, 0, sizeof(*path));
	path->family = family;

	path->addr_size = fm_addrfamily_max_addrbits(family) / 8;
	if (path->addr_size == 0)
		return false;

	if (family == AF_INET6)
		path->dir_size = 3;
	else if (family == AF_INET6)
		path->dir_size = 8;
	else
		path->dir_size = path->addr_size - 1;

	asprintf(&path->asset_dir, "%s/%s", project_dir, fm_addrfamily_name(family));
	fm_asset_fileformat_init(&path->format);
	return true;
}

static void
fm_asset_path_destroy(struct fm_asset_path *path)
{
	drop_string(&path->asset_dir);
}

static bool
fm_asset_path_init_address(struct fm_asset_path *path, const char *project_dir, const fm_address_t *addr)
{
	unsigned int nbits;
	const void *raw_addr;

	raw_addr = fm_address_get_raw_addr(addr, &nbits);
	if (raw_addr == NULL || nbits / 8 > sizeof(path->raw))
		return false;

	if (!fm_asset_path_init(path, project_dir, addr->ss_family))
		return false;

	memcpy(path->raw, raw_addr, nbits / 8);
	return true;
}

/*
 * Convert the internal representation of the path to something we
 * can print and/or pass to the kernel.
 * If create_dirs is true, we will ensure that the complete
 * path exists (except for the file).
 */
static const char *
fm_asset_path_get(const struct fm_asset_path *path, bool create_dirs)
{
	char dir_path[PATH_MAX];
	static char file_path[PATH_MAX];

	if (path->family == AF_INET) {
		snprintf(dir_path, sizeof(dir_path), "%s/%d/%d/%d",
				path->asset_dir,
				path->raw[0], path->raw[1], path->raw[2]);
		snprintf(file_path, sizeof(file_path), "%s/%d",
				dir_path, path->raw[3]);
	} else {
		uint16_t raw16[8], i;

		for (i = 0; i < 8; ++i)
			raw16[i] = ((uint16_t) path->raw[2 * i]) | path->raw[2 * i + 1];

		snprintf(dir_path, sizeof(dir_path), "%s/%04x/%04x/%04x/%04x",
				path->asset_dir,
				raw16[0], raw16[1], raw16[2], raw16[3]);
		snprintf(file_path, sizeof(file_path), "%s/%04x:%04x:%04x:%04x", dir_path,
				raw16[4], raw16[5], raw16[6], raw16[7]);
	}

	if (create_dirs && !fm_makedirs(dir_path)) {
		fm_log_error("%s: cannot create directory: %m", dir_path);
		return NULL;
	}
	return file_path;
}

/*
 * This is used when processing the tree for reading.
 */
static void
fm_asset_path_inspect_work(struct fm_asset_path *path, const char *name, unsigned int *depth_p, char **endp)
{
	unsigned int value, depth;

	depth = *depth_p;
	if (path->family == AF_INET) {
		path->raw[depth++] = strtoul(name, endp, 10);
	} else if (path->family == AF_INET6) {
		value = strtoul(name, endp, 16);
		path->raw[depth++] = value >> 8;
		path->raw[depth++] = value & 0xFF;
	}

	assert(depth <= path->addr_size);
	*depth_p = depth;
}

static bool
fm_asset_path_inspect(struct fm_asset_path *path, const char *name, unsigned int *depth_p)
{
	char *end;

	fm_asset_path_inspect_work(path, name, depth_p, &end);
	return *end == '\0';
}

static bool
fm_asset_path_inspect_file(struct fm_asset_path *path, const char *name, unsigned int depth)
{
	unsigned int i;
	char *end;

	if (depth != path->dir_size)
		return false;

	if (path->family == AF_INET) {
		assert(depth == 3);
		fm_asset_path_inspect_work(path, name, &depth, &end);
	} else if (path->family == AF_INET6) {
		assert(depth == 8);
		for (i = 0; i < 3; ++i) {
			fm_asset_path_inspect_work(path, name, &depth, &end);
			if (*end != ':')
				return false;
		}
		fm_asset_path_inspect_work(path, name, &depth, &end);
	}

	return *end == '\0';
}

/*
 * Helper code for mapping the file into memory
 */
static fm_assetio_mapped_t *
fm_assetio_map(struct fm_asset_path *path, struct fm_asset_fileformat *fmt, bool for_writing)
{
	fm_assetio_mapped_t *mapped = NULL;
	const char *file_path;
	caddr_t	addr = NULL;
	unsigned int i;
	int fd;

	if (!(file_path = fm_asset_path_get(path, for_writing)))
		return NULL;

	if (for_writing) {
		if (fm_debug_level > 3)
			fm_log_debug("creating asset file %s", file_path);

		fd = open(file_path, O_RDWR|O_CREAT, 0644);
		if (fd < 0) {
			fm_log_error("cannot create %s: %m", file_path);
			return NULL;
		}

		if (lseek(fd, fmt->size - 1, SEEK_SET) < 0
		 || write(fd, "", 1) < 0) {
			fm_log_error("unable to resize map file %s (size %u): %m", file_path,  fmt->size);
			close(fd);
			return NULL;
		}

		addr = mmap(NULL, fmt->size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	} else {
		fd = open(file_path, O_RDONLY);
		if (fd < 0) {
			fm_log_error("cannot open %s: %m", file_path);
			return NULL;
		}

		addr = mmap(NULL, fmt->size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	}
	close(fd);

	if (addr == NULL) {
		fm_log_error("failed to mmap %s: %m", file_path);
		return NULL;
	}

	mapped = calloc(1, sizeof(*mapped));
	mapped->addr = addr;
	mapped->size = fmt->size;

	return mapped;
}

static void
fm_assetio_unmap(fm_assetio_mapped_t *mapped)
{
	if (mapped->addr)
		munmap(mapped->addr, mapped->size);

	memset(mapped, 0, sizeof(*mapped));
	free(mapped);
}

static fm_assetio_mapped_t *
fm_assetio_map_read(struct fm_asset_path *path)
{
	return fm_assetio_map(path, &path->format, false);
}

static fm_assetio_mapped_t *
fm_assetio_map_write(struct fm_asset_path *path)
{
	return fm_assetio_map(path, &path->format, true);
}

/*
 * Read case: we've reached a file, look up (ie create) the in-memory asset entry
 * that goes with it.
 */
static fm_host_asset_t *
fm_assetio_lookup_host(struct fm_asset_path *path, fm_host_asset_table_t *table)
{
	fm_address_t host_address;

	if (!fm_address_set_raw_addr(&host_address, path->family, path->raw, path->addr_size))
		return NULL;

	return fm_host_asset_get(&host_address, true);
}

/*
 * Read case: we have a path, and we have the host asset.
 * map the file into memory and copy data from disk.
 */
static void
fm_assetio_read_host(struct fm_asset_path *path, fm_host_asset_t *host)
{
	fm_assetio_mapped_t *mapped;
	const fm_host_asset_ondisk_t *disk;
	unsigned int i;

	if (fm_debug_level > 3)
		fm_log_debug("loading assets for %s from %s\n",
				fm_address_format(&host->address),
				fm_asset_path_get(path, false));

	if (!(mapped = fm_assetio_map_read(path)))
		return;

#if 0
	disk = mapped->main;

	host->state = disk->state;

	for (i = 0; i < __FM_PROTO_MAX; ++i) {
		const fm_protocol_asset_ondisk_t *proto_on_disk = &disk->protocols[i];
		fm_protocol_asset_t *proto = &host->protocols[i];

		if (proto_on_disk->state == FM_ASSET_STATE_UNDEF)
			continue;

		proto->proto_id = i;
	}
#endif

	fm_assetio_unmap(mapped);
}

/*
 * Write case: We have a path, and we have the host asset.
 * Map the file into memory and copy data to disk.
 */
static void
fm_assetio_write_host(struct fm_asset_path *path, const fm_host_asset_t *host)
{
	fm_assetio_mapped_t *mapped;
	fm_host_asset_ondisk_t *disk;
	unsigned int i;

	if (!(mapped = fm_assetio_map_write(path)))
		return;

#if 0
	disk = mapped->main;
	disk->state = host->state;
	for (i = 0; i < __FM_PROTO_MAX; ++i) {
		fm_protocol_asset_ondisk_t *proto_on_disk = &disk->protocols[i];
		const fm_protocol_asset_t *proto = &host->protocols[i];

		if (proto == NULL)
			continue;

		proto_on_disk->state = fm_protocol_asset_get_state(proto);
		if (proto_on_disk->state == FM_ASSET_STATE_UNDEF) {
			proto_on_disk->max_port = 0;
			continue;
		}

		/* just copy the entire port state as-is.
		 * might be wasteful... */
		memcpy(proto_on_disk->bitmap, proto->ports, sizeof(proto->ports));
		proto_on_disk->max_port = 65536;
	}

	for (i = 0; i < __FM_PROTO_MAX; ++i) {
		fm_protocol_asset_ondisk_t *proto_on_disk = &disk->protocols[i];

		proto_on_disk->bitmap = NULL;
	}
#endif

	fm_assetio_unmap(mapped);
}

/*
 * Read case: traverse the on-disk tree and load assets into memory.
 */
void
fm_asset_dir_scan(struct fm_asset_path *path, int fd, unsigned int depth, fm_host_asset_table_t *table)
{
	struct dirent *de;
	DIR *dir = NULL;

	if (fd < 0) {
		dir = opendir(path->asset_dir);
		if (dir == NULL) {
			if (errno != ENOENT)
				fm_log_error("%s: %m", path->asset_dir);
			goto out;
		}
	} else {
		dir = fdopendir(fd);
		if (dir == NULL) {
			fm_log_error("random %s subdir: %m", path->asset_dir);
			goto out;
		}
	}

	if (depth < path->dir_size) {
		while ((de = readdir(dir)) != NULL) {
			unsigned int next_depth = depth;
			int subdir_fd;

			if (de->d_type != DT_DIR)
				continue;

			if (!fm_asset_path_inspect(path, de->d_name, &next_depth))
				continue;

			subdir_fd = openat(dirfd(dir), de->d_name, O_RDONLY);
			if (subdir_fd < 0)
				continue;

			fm_asset_dir_scan(path, subdir_fd, next_depth, table);
		}
	} else {
		while ((de = readdir(dir)) != NULL) {
			fm_host_asset_t *host_asset;

			if (de->d_type != DT_REG)
				continue;

			if (!fm_asset_path_inspect_file(path, de->d_name, depth))
				continue;

			host_asset = fm_assetio_lookup_host(path, table);
			if (host_asset == NULL)
				continue;

			fm_assetio_read_host(path, host_asset);
		}
	}

out:
	if (dir)
		closedir(dir);
	else if (fd >= 0)
		close(fd);
}

void
fm_assets_read_table(const char *project_dir, int family, fm_host_asset_table_t *table)
{
	struct fm_asset_path path;

	if (!fm_asset_path_init(&path, project_dir, family))
		return;

	/* Start searching */
	fm_asset_dir_scan(&path, -1, 0, table);
}

/*
 * Write case: traverse the in-memory assets and write them to disk.
 */
static void
fm_assetio_traverse(const fm_host_asset_table_t *table, struct fm_asset_path *path, unsigned int depth)
{
	unsigned int i;

	if (depth + 1 == path->addr_size) {
		for (i = 0; i < 256; ++i) {
			const fm_host_asset_t *host_asset = table->host[i];

			if (host_asset == NULL || host_asset->main->host_state == FM_ASSET_STATE_UNDEF)
				continue;

			path->raw[depth] = i;
			fm_assetio_write_host(path, host_asset);
		}
	} else {
		for (i = 0; i < 256; ++i) {
			const fm_host_asset_table_t *sub_table = table->table[i];

			if (sub_table == NULL)
				continue;

			path->raw[depth] = i;
			fm_assetio_traverse(sub_table, path, depth + 1);
		}
	}
}

void
fm_assets_write_table(const char *project_dir, int family, const fm_host_asset_table_t *table)
{
	struct fm_asset_path path;
	fm_protocol_asset_t *ppp;

	assert(sizeof(ppp->ports) == sizeof(fm_asset_port_bitmap_t));

	if (!fm_asset_path_init(&path, project_dir, family))
		return;

	fm_assetio_traverse(table, &path, 0);
	fm_asset_path_destroy(&path);
}

static void *
fm_assetio_map_range(fm_assetio_mapped_t *mapping, unsigned int offset, unsigned int len)
{
	if (offset >= mapping->size || mapping->size - offset < len)
		return NULL;
	return mapping->addr + offset;
}

static bool
fm_assetio_setup_mapping(fm_host_asset_t *host, const struct fm_asset_fileformat *fmt)
{
	unsigned int i;

	if (!host->mapping)
		return false;

	host->main = fm_assetio_map_range(host->mapping, fmt->main_offset, sizeof(*host->main));

	for (i = 0; i < __FM_PROTO_MAX; ++i) {
		fm_protocol_asset_t *proto = &host->protocols[i];

		proto->proto_id = i;
		proto->ondisk = &host->main->protocols[i];
		proto->ports = fm_assetio_map_range(host->mapping, fmt->port_map_offset[i], sizeof(fm_asset_port_bitmap_t));
	}

	return true;
}

bool
fm_assetio_map_host(fm_host_asset_t *host)
{
	struct fm_asset_path path;

	if (host->mapping != NULL)
		return true;

	if (!fm_asset_path_init_address(&path, fm_assetio_base_dir, &host->address))
		goto out;

	host->mapping = fm_assetio_map(&path, &path.format, fm_assetio_read_write);

	fm_assetio_setup_mapping(host, &path.format);

out:
	fm_asset_path_destroy(&path);
	return !!host->mapping;
}

void
fm_assetio_unmap_host(fm_host_asset_t *host)
{
	if (host->mapping == NULL)
		return;

	fm_assetio_unmap(host->mapping);
	host->mapping = NULL;
}

void
fm_assetio_set_mapping(const char *project_dir, bool rw)
{
	drop_string(&fm_assetio_base_dir);
	fm_assetio_base_dir = strdup(project_dir);

	fm_assetio_read_write = rw;
}
