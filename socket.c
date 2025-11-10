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

#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "socket.h"
#include "protocols.h"
#include "utils.h"
#include "rawpacket.h"
#include "extant.h"
#include "buffer.h"

static struct fm_socket_list	socket_list;

struct fm_msghdr {
	struct sockaddr_storage peer_addr;
	struct msghdr msg;
	struct iovec iov;
	char control[1024];

	struct cmsghdr *cmsg;
};

/*
 * Socket level representation of a packet
 */
fm_pkt_t *
fm_pkt_alloc(int family, unsigned int size)
{
	fm_pkt_t *pkt;

	pkt = calloc(1, sizeof(*pkt));
	pkt->family = family;

	if (size != 0)
		pkt->payload = fm_buffer_alloc(size);
	return pkt;
}

void
fm_pkt_free(fm_pkt_t *pkt)
{
	fm_buffer_free(pkt->payload);
	free(pkt);
}

void
fm_pkt_apply_probe_params(fm_pkt_t *pkt, const fm_probe_params_t *params, unsigned int mask)
{
	if (mask & FM_PARAM_TYPE_TTL_MASK)
		pkt->info.ttl = params->ttl;
	if (mask & FM_PARAM_TYPE_TOS_MASK)
		pkt->info.tos = params->tos;
}

const void *
fm_pkt_pull(fm_pkt_t *pkt, unsigned int wanted)
{
	if (pkt->payload == NULL)
		return NULL;
	return fm_buffer_pull(pkt->payload, wanted);
}

bool
fm_pkt_is_ttl_exceeded(const fm_pkt_t *pkt)
{
	const struct sock_extended_err *ee;
	if (pkt == NULL || (ee = pkt->info.ee) == NULL)
		return false;

	if (ee->ee_origin == SO_EE_ORIGIN_ICMP)
		return ee->ee_type == ICMP_TIME_EXCEEDED;

	if (ee->ee_origin == SO_EE_ORIGIN_ICMP6)
		return ee->ee_type == ICMP6_TIME_EXCEEDED;

	return false;
}

/*
 * Socket functions
 */
static fm_socket_t *
fm_socket_allocate(int fd, int family, int type, socklen_t len)
{
	fm_socket_t *sock;

	sock = calloc(1, sizeof(*sock));
	sock->fd = fd;
	sock->family = family;
	sock->type = type;
	sock->addrlen = len;

	fm_socket_list_insert(&socket_list, sock);
	return sock;
}

void
fm_socket_free(fm_socket_t *sock)
{
	fm_socket_list_remove(sock);
	fm_socket_close(sock);

	free(sock);
}

void
fm_socket_close(fm_socket_t *sock)
{
	if (sock->fd >= 0) {
		close(sock->fd);
		sock->fd = -1;
	}
}

fm_socket_t *
fm_socket_create(int family, int type, int protocol, fm_protocol_t *driver)
{
	fm_socket_t *sock;
	socklen_t len;
	int fd;

	if ((len = fm_addrfamily_sockaddr_size(family)) == 0)
		return NULL;

	if ((fd = socket(family, type, protocol)) < 0)
		return NULL;

	fcntl(fd, F_SETFL, O_NONBLOCK);

	sock = fm_socket_allocate(fd, family, type, len);

	if (type == SOCK_DGRAM || type == SOCK_RAW) {
		/* datagram sockets are ready to receive after
		 *  (a) we have connected, or
		 *  (b) we have sent a packet using sendto()
		 * Don't bother with this fine print and just pretend we can receive
		 * right from the start.
		 */
		sock->rpoll = POLLIN;
	} else
	if (type == SOCK_STREAM) {
		/* For stream sockets, we don't start polling until we have
		 * initiated a connection. */
		sock->rpoll = 0;
	}

	fm_socket_enable_timestamp(sock);
	sock->proto = driver;

	return sock;
}

static inline const char *
fm_socket_family_name(const fm_socket_t *sock)
{
	return fm_addrfamily_name(sock->family);
}

void
fm_socket_attach_protocol(fm_socket_t *sock, fm_protocol_t *proto)
{
	assert(proto);

	sock->proto = proto;

	/* datagram sockets are ready to receive after
	 *  (a) we have connected, or
	 *  (b) we have sent a packet using sendto()
	 * Don't bother with this fine print and just pretend we can receive
	 * as soon as we have attached a protocol handler.
	 *
	 * For stream sockets, we don't start polling until we have
	 * initiated a connection.
	 */
	if (sock->type == SOCK_DGRAM)
		sock->rpoll = POLLIN;
}

/*
 * Extant maps provide a generic way to locate the original request
 */
void
fm_socket_attach_extant_map(fm_socket_t *sock, fm_extant_map_t *map)
{
	assert(sock->extant_map == NULL);
	assert(sock->proto != NULL);
	assert(sock->proto->locate_error != NULL);
	assert(sock->proto->locate_response != NULL);
	sock->extant_map = map;
}

fm_extant_t *
fm_socket_add_extant(fm_socket_t *sock, fm_host_asset_t *host, int family, int ipproto, const void *data, size_t len)
{
	if (sock->extant_map == NULL)
		return NULL;

	return fm_extant_map_add(sock->extant_map, host, family, ipproto, data, len);
}

/*
 * Change a boolean setsockopt
 */
static bool
fm_socket_option_set(fm_socket_t *sock, const char *name, int level, int type, unsigned int value)
{
	int optval = value;

	if (sock->fd < 0)
		return false;

	if (setsockopt(sock->fd, level, type, &optval, sizeof(optval)) < 0) {
		fm_log_error("Cannot set %s socket's %s option: %m",
				fm_socket_family_name(sock), name);
		return false;
	}

	return true;
}

bool
fm_socket_enable_timestamp(fm_socket_t *sock)
{
	return fm_socket_option_set(sock, "SO_TIMESTAMP", SOL_SOCKET, SO_TIMESTAMP, true);
}

/*
 * Socket time stamping
 */
void
fm_socket_timestamp_update(fm_socket_timestamp_t *ts)
{
	gettimeofday(&ts->when, NULL);
}

double
fm_pkt_rtt(const fm_pkt_t *pkt, const fm_socket_timestamp_t *send_ts)
{
	const struct timeval *sent = &send_ts->when;
	const struct timeval *recv = NULL;
	struct timeval now, delta;

	if (!timerisset(sent))
		return -1;

	if (pkt != NULL)
		recv = &pkt->info.timestamp.when;

	if (!recv || !timerisset(recv)) {
		gettimeofday(&now, NULL);
		recv = &now;
	}

	timersub(recv, sent, &delta);
	return delta.tv_sec + 1e-6 * delta.tv_usec;
}

/*
 * Include IP headers in SOCK_RAW sockets
 */
bool
fm_socket_enable_hdrincl(fm_socket_t *sock)
{
	if (sock->family == AF_INET)
		return fm_socket_option_set(sock, "IP_HDRINCL", SOL_IP, IP_HDRINCL, true);
	if (sock->family == AF_INET6)
		return fm_socket_option_set(sock, "IPV6_HDRINCL", SOL_IPV6, IPV6_HDRINCL, true);
	fm_log_error("Cannot set HDRINCL socket option on %s sockets", fm_socket_family_name(sock));
	return true;
}

bool
fm_socket_enable_ttl(fm_socket_t *sock)
{
	if (sock->family == AF_INET)
		return fm_socket_option_set(sock, "IP_RECVTTL", SOL_IP, IP_RECVTTL, true);

	if (sock->family == AF_INET6)
		return fm_socket_option_set(sock, "IPV6_RECVHOPLIMIT", SOL_IPV6, IPV6_RECVHOPLIMIT, true);

	fm_log_error("Cannot set RECVTTL socket option on %s sockets", fm_socket_family_name(sock));
	return true;
}

bool
fm_socket_enable_tos(fm_socket_t *sock)
{
	if (sock->family == AF_INET)
		return fm_socket_option_set(sock, "IP_RECVTOS", SOL_IP, IP_RECVTOS, true);

	if (sock->family == AF_INET6)
		return fm_socket_option_set(sock, "IPV6_RECVTCLASS", SOL_IPV6, IPV6_RECVTCLASS, true);

	fm_log_error("Cannot set RECVTOS socket option on %s sockets", fm_socket_family_name(sock));
	return true;
}

bool
fm_socket_enable_pktinfo(fm_socket_t *sock)
{
	if (sock->family == AF_INET)
		return fm_socket_option_set(sock, "IP_PKTINFO", SOL_IP, IP_PKTINFO, true);

	if (sock->family == AF_INET6)
		return fm_socket_option_set(sock, "IPV6_RECVPKTINFO", SOL_IPV6, IPV6_RECVPKTINFO, true);

	fm_log_error("Cannot set RECVPKTINFO socket option on %s sockets", fm_socket_family_name(sock));
	return true;
}

bool
fm_socket_set_send_ttl(fm_socket_t *sock, unsigned int ttl)
{
	if (sock->family == AF_INET)
		return fm_socket_option_set(sock, "IP_TTL", SOL_IP, IP_TTL, ttl);
	if (sock->family == AF_INET6)
		return fm_socket_option_set(sock, "IPV6_HOPLIMIT", SOL_IP, IPV6_HOPLIMIT, ttl);

	fm_log_error("Cannot set TTL socket option on %s sockets", fm_socket_family_name(sock));
	return false;
}

bool
fm_socket_enable_broadcast(fm_socket_t *sock)
{
	return fm_socket_option_set(sock, "SO_BROADCAST", SOL_SOCKET, SO_BROADCAST, 1);
}

/*
 * Access to socket level errors
 */
bool
fm_socket_enable_recverr(fm_socket_t *sock)
{
	if (sock->family == AF_INET)
		return fm_socket_option_set(sock, "IP_RECVERR", SOL_IP, IP_RECVERR, true);

	if (sock->family == AF_INET6)
		return fm_socket_option_set(sock, "IPV6_RECVERR", SOL_IPV6, IPV6_RECVERR, true);

	fm_log_error("Cannot set RECVERR socket option on %s sockets", fm_socket_family_name(sock));
	return true;
}

bool
fm_socket_get_pending_error(fm_socket_t *sock, int *ret)
{
	socklen_t opt_size = sizeof(*ret);
	int saved_errno = errno;

	if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, ret, &opt_size) < 0) {
		errno = saved_errno;
		return false;
	}

	return true;
}

static fm_pkt_t *
fm_socket_build_dummy_packet(const fm_socket_t *sock)
{
	fm_pkt_t *pkt;

	pkt = fm_pkt_alloc(sock->family, 0);
	pkt->peer_addr = sock->peer_address;
	pkt->local_addr = sock->local_address;
	return pkt;
}

static fm_pkt_t *
fm_socket_build_error_packet(const fm_socket_t *sock, int err)
{
	fm_pkt_t *pkt;
	struct sock_extended_err *ee;

	pkt = fm_socket_build_dummy_packet(sock);

	ee = (struct sock_extended_err *) pkt->info.eebuf;
	ee->ee_errno = err;
	ee->ee_origin = SO_EE_ORIGIN_LOCAL;

	pkt->info.ee = ee;
	return pkt;
}

bool
fm_socket_bind(fm_socket_t *sock, const fm_address_t *address)
{
	if (sock->fd < 0)
		return false;

	if (bind(sock->fd, (struct sockaddr *) address, sock->addrlen) < 0)
		return false;

	fm_socket_get_local_address(sock, NULL);

	return true;
}

bool
fm_socket_connect(fm_socket_t *sock, const fm_address_t *address)
{
	if (sock->fd < 0)
		return false;

	if (connect(sock->fd, (struct sockaddr *) address, sock->addrlen) < 0
	 && errno != EINPROGRESS)
		return false;

	/* Note to self: do not assert POLLIN on stream sockets unless you really want to handle
	 * incoming data, or the remote end closing the connection, etc etc etc.
	 */
	if (sock->type == SOCK_STREAM) {
		fm_log_debug("Initiated connection to %s on sock %d\n", fm_address_format(address), sock->fd);
		sock->rpoll = POLLOUT|POLLERR;
	} else {
		sock->rpoll = POLLIN;
	}

	sock->peer_address = *address;
	return true;
}

bool
fm_socket_get_local_address(const fm_socket_t *sock, fm_address_t *addr)
{
	if (sock->fd < 0)
		return false;

	if (sock->local_address.ss_family == AF_UNSPEC) {
		socklen_t slen = sizeof(sock->local_address);
		if (getsockname(sock->fd, (struct sockaddr *) &sock->local_address, &slen) < 0) {
			fm_log_error("getsockname: %m");
			return false;
		}
	}

	if (addr != NULL)
		*addr = sock->local_address;

	return true;
}

int
fm_socket_get_family(const fm_socket_t *sock)
{
	return sock->family;
}

/*
 * sendmsg convenience functions
 */
static struct fm_msghdr *
fm_sendmsg_prepare(const fm_address_t *dest_addr, fm_buffer_t *payload, int flags)
{
	struct fm_msghdr *rd;

	rd = calloc(1, sizeof(*rd));
	if (dest_addr && dest_addr->ss_family != AF_UNSPEC) {
		rd->peer_addr = *dest_addr;
		rd->msg.msg_name = &rd->peer_addr;
		rd->msg.msg_namelen = sizeof(rd->peer_addr);
	}

	rd->iov.iov_base = (void *) fm_buffer_head(payload);
	rd->iov.iov_len = fm_buffer_available(payload);
	rd->msg.msg_iov = &rd->iov;
	rd->msg.msg_iovlen = 1;
	rd->msg.msg_flags = flags;

	return rd;
}

static bool
fm_sendmsg_add_cmsg(struct fm_msghdr *rd, int level, int type, const void *value, size_t count)
{
	unsigned int max_size = sizeof(rd->control);
	unsigned int left;
	struct cmsghdr *cmsg;

	/* fm_log_debug("%s: level=%d type=%d len=%d\n", __func__, level, type, count); */
	if (rd->msg.msg_control == NULL) {
		rd->msg.msg_control = rd->control;
		rd->cmsg = (struct cmsghdr *) rd->control;
	}

	left = max_size - rd->msg.msg_controllen;
	if (left < CMSG_SPACE(count)) {
		fm_log_error("%s: control buffer overflow", __func__);
		return false;
	}

	cmsg = (struct cmsghdr *) (rd->control + rd->msg.msg_controllen);
	memcpy(CMSG_DATA(cmsg), value, count);
	cmsg->cmsg_level = level;
	cmsg->cmsg_type = type;
	cmsg->cmsg_len = CMSG_LEN(count);

	rd->msg.msg_controllen += CMSG_SPACE(count);
	assert(rd->msg.msg_controllen <= max_size);

	return true;
}

static bool
fm_sendmsg_add_cmsg_int(struct fm_msghdr *rd, int level, int type, int value)
{
	return fm_sendmsg_add_cmsg(rd, level, type, &value, sizeof(value));
}


/*
 * Send data
 */
bool
fm_socket_send(fm_socket_t *sock, const fm_address_t *dstaddr, const void *pkt, size_t len)
{
	int r;

	if (sock->fd < 0)
		return false;

	if (dstaddr == NULL) {
		r = send(sock->fd, pkt, len, 0);
	} else {
		r = sendto(sock->fd, pkt, len, 0, (const struct sockaddr *) dstaddr, sock->addrlen);
	}

	if (r < 0) {
		/* have the caller receive the error */
		if (errno == EMSGSIZE || errno == EHOSTUNREACH || errno == ECONNREFUSED)
			return true;

		if (errno == ENOBUFS || errno == EAGAIN)
			return false;

		fm_log_error("failed to send: %m (errno %d)", errno);
		return false;
	}

	return true;
}

bool
fm_socket_send_buffer(fm_socket_t *sock, const fm_address_t *dstaddr, fm_buffer_t *data)
{
	return fm_socket_send(sock, dstaddr, fm_buffer_head(data), fm_buffer_available(data));
}

bool
fm_socket_send_pkt(fm_socket_t *sock, fm_pkt_t *pkt)
{
	struct fm_msghdr *rd;
	int r;

	if (sock->fd < 0)
		return false;

	if (sock->trace) {
		fm_log_debug("Sendig packet on fd=%d", sock->fd);
		fm_print_hexdump(fm_buffer_head(pkt->payload), fm_buffer_available(pkt->payload));
	}

	rd = fm_sendmsg_prepare(&pkt->peer_addr, pkt->payload, 0);
	if (sock->family == AF_INET) {
		if (pkt->info.ttl != 0)
			fm_sendmsg_add_cmsg_int(rd, SOL_IP, IP_TTL, pkt->info.ttl);
		if (pkt->info.tos != 0)
			fm_sendmsg_add_cmsg_int(rd, SOL_IP, IP_TOS, pkt->info.tos);
	} else
	if (sock->family == AF_INET6) {
		if (pkt->info.ttl != 0)
			fm_sendmsg_add_cmsg_int(rd, SOL_IPV6, IPV6_HOPLIMIT, pkt->info.ttl);
		if (pkt->info.tos != 0)
			fm_sendmsg_add_cmsg_int(rd, SOL_IPV6, IPV6_TCLASS, pkt->info.tos);
	}

	r = sendmsg(sock->fd, &rd->msg, rd->msg.msg_flags);
	if (r < 0) {
		/* have the caller receive the error */
		if (errno == EMSGSIZE || errno == EHOSTUNREACH || errno == ECONNREFUSED)
			return true;

		if (errno == ENOBUFS || errno == EAGAIN)
			return false;

		fm_log_error("failed to send: %m (errno %d)", errno);
		return false;
	}

	return true;
}

bool
fm_socket_send_pkt_and_burn(fm_socket_t *sock, fm_pkt_t *pkt)
{
	bool rv;

	rv = fm_socket_send_pkt(sock, pkt);
	fm_pkt_free(pkt);
	return rv;
}

/*
 * recvmsg/sendmsg convenience functions
 */
static struct fm_msghdr *
fm_recvmsg_prepare(void *buffer, size_t bufsize, int flags)
{
	struct fm_msghdr *rd;

	rd = calloc(1, sizeof(*rd));

	rd->msg.msg_name = &rd->peer_addr;
	rd->msg.msg_namelen = sizeof(rd->peer_addr);
	rd->msg.msg_control = rd->control;
	rd->msg.msg_controllen = sizeof (rd->control);
	rd->iov.iov_base = buffer;
	rd->iov.iov_len = bufsize;
	rd->msg.msg_iov = &rd->iov;
	rd->msg.msg_iovlen = 1;
	rd->msg.msg_flags = flags;

	return rd;
}

static bool
fm_process_cmsg(struct fm_msghdr *rd, fm_pkt_info_t *info, fm_address_t *local_addr)
{
	struct cmsghdr *cm;

	memset(info, 0, sizeof(*info));

	for (cm = CMSG_FIRSTHDR(&rd->msg); cm; cm = CMSG_NXTHDR(&rd->msg, cm)) {
		void *ptr = CMSG_DATA(cm);

		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMP) {
			info->timestamp.when = *(struct timeval *) ptr;
		} else
		if ((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_TTL)
		 || (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_HOPLIMIT)) {
			info->ttl = *((int *) ptr);
		} else
		if ((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_TOS)
		 || (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_TCLASS)) {
			info->tos = *((int *) ptr);
		} else
		if ((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_RECVERR)
		 || (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_RECVERR)) {
			unsigned int len = cm->cmsg_len;

			if (len > sizeof(info->eebuf)) {
				fm_log_warning("Truncating RECVERR (%u > %u)\n",
						len, sizeof(info->eebuf));
				len = sizeof(info->eebuf);
			}

			memcpy(info->eebuf, ptr, len);
			info->ee = (struct sock_extended_err *) info->eebuf;
			info->offender = (const struct sockaddr_storage *) SO_EE_OFFENDER(info->ee);
			info->error_class = fm_socket_error_class(info);
		} else
		if (cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_PKTINFO) {
			unsigned int len = cm->cmsg_len;
			struct in_pktinfo pktinfo;
			
			if (local_addr && len >= sizeof(pktinfo)) {
				memcpy(&pktinfo, ptr, sizeof(pktinfo));
				fm_address_set_ipv4(local_addr, pktinfo.ipi_addr.s_addr);
			}
		} else
		if (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_PKTINFO) {
		}
	}

	return true;
}

bool
fm_socket_recverr(fm_socket_t *sock, fm_pkt_info_t *info)
{
	struct fm_msghdr *rd;
	unsigned char dummy_buf[1];
	int n;

	if (sock->fd < 0)
		return -1;

	/* recvmsg will give us the packet that caused the error,
	 * along with an indication of who complained, and why. */
	rd = fm_recvmsg_prepare(dummy_buf, sizeof(dummy_buf), MSG_ERRQUEUE);

	n = recvmsg(sock->fd, &rd->msg, MSG_ERRQUEUE);
	if (n >= 0)
		fm_process_cmsg(rd, info, NULL);

	free(rd);
	return n >= 0;
}

static int
fm_socket_recv(fm_socket_t *sock,
		struct sockaddr_storage *local_addr, struct sockaddr_storage *peer_addr,
		void *buffer, size_t size, fm_pkt_info_t *info, int flags)
{
	struct fm_msghdr *rd;
	int n;

	if (sock->fd < 0)
		return -1;

	/* in the bound socket case, return our bound addr by default */
	if (local_addr)
		*local_addr = sock->local_address;

	rd = fm_recvmsg_prepare(buffer, size, flags);

	n = recvmsg(sock->fd, &rd->msg, flags);
	if (n >= 0) {
		if (info != NULL)
			fm_process_cmsg(rd, info, local_addr);
		if (peer_addr != NULL)
			*peer_addr = rd->peer_addr;
	}

	free(rd);
	return n;
}

static fm_pkt_t *
fm_socket_recv_packet(fm_socket_t *sock, int flags)
{
	const unsigned int MAX_PAYLOAD = 512;
	fm_packet_parser_t *parser;
	fm_pkt_t *pkt;
	fm_buffer_t *bp;
	int n;

	if (flags & MSG_ERRQUEUE)
		parser = sock->error_parser;
	else
		parser = sock->data_parser;

	pkt = fm_pkt_alloc(sock->family, MAX_PAYLOAD);
	bp = pkt->payload;

	n = fm_socket_recv(sock, &pkt->local_addr, &pkt->peer_addr,
				bp->data, bp->size,
				&pkt->info, flags);
	if (n < 0) {
		fm_pkt_free(pkt);
		return NULL;
	}

	bp->wpos = n;

	/* For some reason, I don't always see the proper remote port with
	 * connected TCP raw sockets. */
	if (sock->type == SOCK_RAW && sock->proto->id == FM_PROTO_TCP
	 && sock->peer_address.ss_family != AF_UNSPEC) {
		uint16_t port = fm_address_get_port(&pkt->peer_addr);

		if (port == 0)
			pkt->peer_addr = sock->peer_address;
	}

	if (parser && !fm_packet_parser_inspect(parser, pkt)) {
		fm_log_debug("unable to parse incoming %s packet from %s",
				fm_addrfamily_name(sock->family),
				fm_address_format(&pkt->peer_addr));
	}

	/* If there's an extent map attached to the socket,
	 * see if we can score a quick win and locate the
	 * original request directly. */
	if (sock->extant_map) {
		bool processed;

		if (flags & MSG_ERRQUEUE)
			processed = fm_extant_map_process_error(sock->extant_map, sock->proto, pkt);
		else
			processed = fm_extant_map_process_data(sock->extant_map, sock->proto, pkt);
		if (processed) {
			fm_pkt_free(pkt);
			errno = EAGAIN;
			return NULL;
		}
	}

	return pkt;
}

/*
 * Process received packets
 */
bool
fm_socket_install_data_parser(fm_socket_t *sock, int proto_id)
{
	if (sock->data_parser == NULL)
		sock->data_parser = fm_packet_parser_alloc();
	return fm_packet_parser_add_layer(sock->data_parser, proto_id);
}

bool
fm_socket_install_error_parser(fm_socket_t *sock, int proto_id)
{
	if (sock->error_parser == NULL)
		sock->error_parser = fm_packet_parser_alloc();
	return fm_packet_parser_add_layer(sock->error_parser, proto_id);
}

/*
 * Helper function for displaying the extended socket error
 */
static inline const char *
ee_icmp_str(const struct sock_extended_err *ee)
{
	static char xx[64];

	switch (ee->ee_type) {
	case ICMP_SOURCE_QUENCH:
		return "source quench";
	case ICMP_REDIRECT:
		return "source redirect";
	case ICMP_TIME_EXCEEDED:
		if (ee->ee_code == ICMP_EXC_TTL)
			return "ttl exceeded";
		break;
	case ICMP_DEST_UNREACH:
		switch (ee->ee_code) {
		case ICMP_UNREACH_NET:
		case ICMP_UNREACH_NET_UNKNOWN:
		case ICMP_UNREACH_ISOLATED:
		case ICMP_UNREACH_TOSNET:
			return "network unreachable";

		case ICMP_UNREACH_HOST:
		case ICMP_UNREACH_HOST_UNKNOWN:
		case ICMP_UNREACH_TOSHOST:
			return "host unreachable";

		case ICMP_UNREACH_NET_PROHIB:
		case ICMP_UNREACH_HOST_PROHIB:
		case ICMP_UNREACH_FILTER_PROHIB:
			return "host/network prohibited";

		case ICMP_UNREACH_PORT:
			return "port unreachable";

		case ICMP_UNREACH_PROTOCOL:
			return "protocol unreachable";

		case ICMP_UNREACH_NEEDFRAG:
			return "need fragmentation";
		}
		break;
	}

	snprintf(xx, sizeof(xx), "icmp%u/%u", ee->ee_type, ee->ee_code);
	return xx;
}

static inline const char *
ee_icmp6_str(const struct sock_extended_err *ee)
{
	static char xx[64];

	switch (ee->ee_type) {
	case ICMP6_TIME_EXCEEDED:
		if (ee->ee_code == ICMP6_TIME_EXCEED_TRANSIT)
			return "ttl exceeded";
		break;
	case ICMP6_DST_UNREACH:
		switch (ee->ee_code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			return "network unreachable";

		case ICMP6_DST_UNREACH_BEYONDSCOPE:
		case ICMP6_DST_UNREACH_ADDR:
			return "host unreachable";

		case ICMP6_DST_UNREACH_ADMIN:
			return "host/network prohibited";

		case ICMP6_DST_UNREACH_NOPORT:
			return "port unreachable";
		}
		break;
	}

	snprintf(xx, sizeof(xx), "icmp%u/%u", ee->ee_type, ee->ee_code);
	return xx;
}

static inline const char *
fm_error_class_str(int cls)
{
	switch (cls) {
	case FM_ERROR_CLASS_IGNORE:
		return "ignore";
	case FM_ERROR_CLASS_TRANSIENT:
		return "transient";
	case FM_ERROR_CLASS_TOO_MANY_HOPS:
		return "too_many_hops";
	case FM_ERROR_CLASS_NET_UNREACH:
		return "network unreachable";
	case FM_ERROR_CLASS_HOST_UNREACH:
		return "host unreachable";
	case FM_ERROR_CLASS_ADMIN_PROHIBITED:
		return "administratively prohibited";
	case FM_ERROR_CLASS_PORT_UNREACH:
		return "port unreachable";
	case FM_ERROR_CLASS_OTHER:
		return "other";
	}

	return "unknown";
};

const char *
fm_socket_render_error(const fm_pkt_info_t *info)
{
	static char buffer[256];
	const struct sock_extended_err *ee;
	const char *clsname;

	if ((ee = info->ee) == NULL)
		return NULL;

	clsname = fm_error_class_str(info->error_class);
	if (ee->ee_origin == SO_EE_ORIGIN_LOCAL) {
		snprintf(buffer, sizeof(buffer), "local error: class %s; errno=%u (%s)",
				clsname, ee->ee_errno,
				strerror(ee->ee_errno));
	} else if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
		snprintf(buffer, sizeof(buffer), "icmp error: %s (%s)",
				clsname,
				fm_address_format(info->offender));
	} else if (ee->ee_origin == SO_EE_ORIGIN_ICMP6) {
		snprintf(buffer, sizeof(buffer), "icmp6 error: %s (%s)",
				clsname,
				fm_address_format(info->offender));
	} else {
		snprintf(buffer, sizeof(buffer), "error of unknown origin %u: errno=%u",
				ee->ee_origin, ee->ee_errno);
	}

	return buffer;
}

/*
 * Assess the impact of a local or remote socket error.
 */
int
fm_socket_error_class(const fm_pkt_info_t *info)
{
	const struct sock_extended_err *ee;

	if ((ee = info->ee) == NULL)
		return 0;

	if (ee->ee_origin == SO_EE_ORIGIN_LOCAL) {
		switch (ee->ee_errno) {
		case ENOBUFS:
			return FM_ERROR_CLASS_TRANSIENT;

		default:
			return FM_ERROR_CLASS_OTHER;
		}
	} else if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
		switch (ee->ee_type) {
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
			return FM_ERROR_CLASS_IGNORE;
		case ICMP_TIME_EXCEEDED:
			return FM_ERROR_CLASS_TOO_MANY_HOPS;
		case ICMP_DEST_UNREACH:
			switch (ee->ee_code) {
			case ICMP_UNREACH_PROTOCOL:
			case ICMP_UNREACH_NEEDFRAG:
				return FM_ERROR_CLASS_HOST_UNREACH;

			case ICMP_UNREACH_NET:
			case ICMP_UNREACH_NET_UNKNOWN:
			case ICMP_UNREACH_ISOLATED:
			case ICMP_UNREACH_TOSNET:
				return FM_ERROR_CLASS_NET_UNREACH;

			case ICMP_UNREACH_HOST:
			case ICMP_UNREACH_HOST_UNKNOWN:
			case ICMP_UNREACH_TOSHOST:
				return FM_ERROR_CLASS_HOST_UNREACH;

			case ICMP_UNREACH_NET_PROHIB:
			case ICMP_UNREACH_HOST_PROHIB:
			case ICMP_UNREACH_FILTER_PROHIB:
				return FM_ERROR_CLASS_ADMIN_PROHIBITED;

			case ICMP_UNREACH_PORT:
				return FM_ERROR_CLASS_PORT_UNREACH;

			}
			break;
		}
	} else if (ee->ee_origin == SO_EE_ORIGIN_ICMP6) {
		switch (ee->ee_type) {
		case ICMP6_TIME_EXCEEDED:
			return FM_ERROR_CLASS_TOO_MANY_HOPS;
		case ICMP6_DST_UNREACH:
			switch (ee->ee_code) {
			case ICMP6_DST_UNREACH_NOROUTE:
				return FM_ERROR_CLASS_NET_UNREACH;

			case ICMP6_DST_UNREACH_BEYONDSCOPE:
			case ICMP6_DST_UNREACH_ADDR:
				return FM_ERROR_CLASS_HOST_UNREACH;

			case ICMP6_DST_UNREACH_ADMIN:
				return FM_ERROR_CLASS_ADMIN_PROHIBITED;

			case ICMP6_DST_UNREACH_NOPORT:
				return FM_ERROR_CLASS_PORT_UNREACH;
			}
			break;
		}
	}

	return FM_ERROR_CLASS_OTHER;
}

bool
fm_socket_error_dest_unreachable(const fm_pkt_info_t *info)
{
	switch (info->error_class) {
	case FM_ERROR_CLASS_NET_UNREACH:
	case FM_ERROR_CLASS_HOST_UNREACH:
	case FM_ERROR_CLASS_ADMIN_PROHIBITED:
	case FM_ERROR_CLASS_PORT_UNREACH:
	case FM_ERROR_CLASS_OTHER:
		return true;
	}

	return false;
}

/*
 * Packet delivery and tracing
 */
static inline void
fm_socket_log_packet(fm_socket_t *sock, const char *verb, fm_pkt_t *pkt)
{
	fm_buffer_t *payload = pkt->payload;

	if (payload != NULL) {
		printf("sock %d %s packet from %s, payload:\n", sock->fd, verb, fm_address_format(&sock->peer_address));
		fm_print_hexdump(fm_buffer_head(payload), fm_buffer_available(payload));
	} else {
		printf("sock %d %s packet from %s (no payload)\n", sock->fd, verb, fm_address_format(&sock->peer_address));
	}
}

static void
fm_socket_process_os_error(fm_socket_t *sock, int _errno)
{
	fm_protocol_t *proto = sock->proto;
	fm_pkt_t *pkt;

	if (proto->handle_os_error == NULL)
		return;

	pkt = fm_socket_build_error_packet(sock, errno);
	proto->handle_os_error(proto, pkt);
	fm_pkt_free(pkt);
}

/*
 * Invoke the socket's poll callback
 */
static void
fm_socket_handle_poll_event(fm_socket_t *sock, int bits)
{
	fm_protocol_t *proto;
	fm_pkt_t *pkt;
	int err;

	if ((proto = sock->proto) == NULL)
		goto bad_setup;

	/* When we receive a TCP RST, the kernel asserts POLLERR|POLLIN
	 * but will not propagate the error via its ERRQUEUE.
	 * Instead we get an EAGAIN here, and the recvmsg for the regular
	 * POLLIN below will see ECONNREFUSED.
	 */
	if (bits & POLLERR) {
		pkt = fm_socket_recv_packet(sock, MSG_ERRQUEUE);
		if (pkt != NULL) {
			fm_pkt_free(pkt);
		} else if (errno != EAGAIN) {
			fm_log_error("socket %d: POLLERR set but recvmsg failed: %m", sock->fd);
		} else if (fm_socket_get_pending_error(sock, &err)) {
			fm_socket_process_os_error(sock, err);
		}

		bits &= ~POLLERR;
	}

	if (bits & POLLIN) {
		pkt = fm_socket_recv_packet(sock, 0);

		if (pkt != NULL) {
			fm_pkt_free(pkt);
		} else if (errno != EAGAIN) {
			fm_socket_process_os_error(sock, errno);
		}

		bits &= ~POLLIN;
	}

	if (bits & POLLOUT) {
		/* POLLOUT being asserted does not mean the remote port is there;
		 * it just means the kernel can tell us whether the connection attempt
		 * succeeded. So go and reap the status */
		if (connect(sock->fd, (struct sockaddr *) &sock->peer_address, sock->addrlen) < 0) {
			fm_socket_process_os_error(sock, err);
		} else {
			pkt = fm_socket_build_dummy_packet(sock);
			proto->connection_established(proto, pkt);
			fm_pkt_free(pkt);
		}

		bits &= ~POLLOUT;
	}

	/* clear the bits we couldn't handle above */
	if (sock->rpoll & bits) {
bad_setup:
		fm_log_error("socket %d (af=%d type=%d) invalid poll setup",
				sock->fd, sock->family, sock->type);
		if (bits & POLLIN)
			fm_log_error("   POLLIN not handled by protocol");
		if (bits & POLLOUT)
			fm_log_error("   POLLOUT not handled by protocol");
		if (bits & POLLERR)
			fm_log_error("   POLLERR not handled by protocol");
		sock->rpoll &= ~bits;
	}
}

bool
fm_socket_purge(void)
{
	fm_socket_t *sock, *next;

	for (sock = (fm_socket_t *) (socket_list.hlist.first); sock != NULL; sock = next) {
		next = (fm_socket_t *) sock->link.next;

		/* Do not remove the socket; it's probably still owned by a probe or
		 * something else.
		 * Remove it from the socket list, though. */
		if (sock->fd < 0)
			fm_socket_list_remove(sock);
	}

	return socket_list.hlist.first != NULL;
}

bool
fm_socket_poll_all(fm_time_t timeout)
{
	unsigned int max_fds = 0, nfds = 0;
	fm_socket_t *sock;
	struct pollfd *pfd;
	fm_socket_t **socks;
	long timeout_ms;
	int rv;

	timeout_ms = 100;
	if (timeout > 0) {
		timeout_ms = 1000 * (timeout - fm_time_now()) + .5;
		assert(timeout_ms >= 0);

		if (timeout_ms > 2000) {
			fm_log_warning("%s: excessively large timeout %f sec", timeout - fm_time_now());
			timeout_ms = 2000;
		}
	}

	fm_socket_foreach(&socket_list, sock) {
		max_fds++;
	}

	if (max_fds == 0) {
		poll(NULL, 0, timeout_ms);
		return false;
	}

	pfd = calloc(max_fds, sizeof(pfd[0]));
	socks = calloc(max_fds, sizeof(socks[0]));

	fm_socket_foreach(&socket_list, sock) {
		/* fm_log_debug("sock %d poll %d\n", sock->fd, sock->rpoll); */
		if (sock->fd >= 0 && sock->rpoll != 0) {
			pfd[nfds].fd = sock->fd;
			pfd[nfds].events = sock->rpoll;
			socks[nfds] = sock;
			nfds++;
		}
	}

	rv = poll(pfd, nfds, timeout_ms);
	if (rv >= 0) {
		while (nfds--) {
			struct pollfd *rp = &pfd[nfds];

			if (rp->revents != 0) {
				/* fm_log_debug("poll event %d on sock %d\n", rp->revents, rp->fd); */
				sock = socks[nfds];

				fm_socket_handle_poll_event(sock, rp->revents);
			}
		}
	}

	free(pfd);
	free(socks);

	return fm_socket_purge();
}
