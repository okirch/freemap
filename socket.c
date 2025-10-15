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

static struct fm_socket_list	socket_list;

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
fm_socket_create(int family, int type, int protocol)
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

	if (type == SOCK_DGRAM) {
		/* datagram sockets are ready to receive after
		 *  (a) we have connected, or
		 *  (b) we have sent a packet using sendto()
		 * Don't bother with this fine print and just pretend we can receive
		 * right from the start.
		 */
		sock->rpoll = POLLIN;
	} else {
		/* For stream sockets, we don't start polling until we have
		 * initiated a connection. */
		sock->rpoll = 0;
	}

	fm_socket_enable_timestamp(sock);

	return sock;
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
 * Socket time stamping
 */
bool
fm_socket_enable_timestamp(fm_socket_t *sock)
{
	int optval = 1;

	if (sock->fd < 0)
		return false;

	if (setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMP, &optval, sizeof(optval)) < 0) {
		fm_log_error("Cannot set socket's SO_TIMESTAMP option: %m");
		return false;
	}

	return true;
}

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
		recv = &pkt->info.recv_time.when;

	if (!recv || !timerisset(recv)) {
		gettimeofday(&now, NULL);
		recv = &now;
	}

	timersub(recv, sent, &delta);
	return delta.tv_sec + 1e-6 * delta.tv_usec;
}

/*
 * Access to socket level errors
 */
bool
fm_socket_enable_recverr(fm_socket_t *sock)
{
	int optval = 1;

	if (sock->fd < 0)
		return false;

	switch (sock->family) {
	case AF_INET:
		if (setsockopt(sock->fd, SOL_IP, IP_RECVERR, &optval, sizeof (optval)) < 0) {
			fm_log_error("Cannot set IPv4 socket's IP_RECVERR option: %m");
			return false;
		}
		break;

	case AF_INET6:
		if (setsockopt(sock->fd, SOL_IPV6, IPV6_RECVERR, &optval, sizeof (optval)) < 0) {
			fm_log_error("Cannot set IPv6 socket's IPV6_RECVERR option: %m");
			return false;
		}
		break;
        }

	return false;
}

bool
fm_socket_get_pending_error(fm_socket_t *sock, int *ret)
{
	socklen_t opt_size = sizeof(*ret);
	int saved_errno = errno;

	if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, ret, &opt_size) < 0) {
		printf("getsockopt(SO_ERROR): %m\n");
		errno = saved_errno;
		return false;
	}

	return true;
}

static fm_pkt_t *
fm_socket_build_error_packet(const fm_address_t *addr, int err)
{
	fm_pkt_t *pkt;
	struct sock_extended_err *ee;

	pkt = calloc(1, sizeof(*pkt));
	pkt->recv_addr = *addr;

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

	if (sock->type == SOCK_STREAM) {
		fm_log_debug("Initiated connection to %s on sock %d\n", fm_address_format(address), sock->fd);
		sock->rpoll = POLLIN|POLLOUT;
	} else {
		sock->rpoll = POLLIN;
	}

	sock->peer_address = *address;
	return true;
}

bool
fm_socket_get_local_address(const fm_socket_t *sock, fm_address_t *addr)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);

	if (sock->fd < 0)
		return false;

	memset(&ss, 0, sizeof(ss));
	if (getsockname(sock->fd, (struct sockaddr *) &ss, &slen) < 0) {
		fm_log_error("getsockname: %m");
		return false;
	}

	*addr = ss;
	return true;
}

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

/*
 * recvmsg convenience functions
 */
struct fm_recv_data {
	struct sockaddr_storage peer_addr;
	struct msghdr msg;
	struct iovec iov;
	char control[1024];
};

static struct fm_recv_data *
fm_recvmsg_prepare(void *buffer, size_t bufsize, int flags)
{
	struct fm_recv_data *rd;

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
fm_process_cmsg(struct fm_recv_data *rd, fm_pkt_info_t *info)
{
	struct cmsghdr *cm;

	memset(info, 0, sizeof(*info));

	for (cm = CMSG_FIRSTHDR(&rd->msg); cm; cm = CMSG_NXTHDR(&rd->msg, cm)) {
		void *ptr = CMSG_DATA(cm);

		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMP) {
			info->recv_time.when = *(struct timeval *) ptr;
		} else
		if ((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_TTL)
		 || (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_HOPLIMIT)) {
			info->recv_ttl = *((int *) ptr);
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
		}
	}

	return true;
}

bool
fm_socket_recverr(fm_socket_t *sock, fm_pkt_info_t *info)
{
	struct fm_recv_data *rd;
	unsigned char dummy_buf[1];
	int n;

	if (sock->fd < 0)
		return -1;

	/* recvmsg will give us the packet that caused the error,
	 * along with an indication of who complained, and why. */
	rd = fm_recvmsg_prepare(dummy_buf, sizeof(dummy_buf), MSG_ERRQUEUE);

	n = recvmsg(sock->fd, &rd->msg, MSG_ERRQUEUE);
	if (n >= 0)
		fm_process_cmsg(rd, info);

	free(rd);
	return n >= 0;
}

static int
fm_socket_recv(fm_socket_t *sock, struct sockaddr_storage *peer_addr, void *buffer, size_t size, fm_pkt_info_t *info, int flags)
{
	struct fm_recv_data *rd;
	int n;

	if (sock->fd < 0)
		return -1;

	rd = fm_recvmsg_prepare(buffer, size, flags);

	n = recvmsg(sock->fd, &rd->msg, flags);
	if (n >= 0) {
		if (info != NULL)
			fm_process_cmsg(rd, info);
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
	fm_pkt_t *pkt;
	int n;

	pkt = calloc(1, sizeof(*pkt) + MAX_PAYLOAD);
	pkt->family = sock->family;

	n = fm_socket_recv(sock, &pkt->recv_addr, pkt->data, MAX_PAYLOAD, &pkt->info, flags);
	if (n < 0) {
		free(pkt);
		return NULL;
	}

	pkt->len = n;

	return pkt;
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
 * Invoke the socket's poll callback
 */
static void
fm_socket_handle_poll_event(fm_socket_t *sock, int bits)
{
	fm_protocol_t *proto;
	fm_pkt_t *pkt;

	if ((proto = sock->proto) == NULL)
		goto bad_setup;

	/* When we receive a TCP RST, the kernel asserts POLLERR|POLLIN
	 * but will not propagate the error via its ERRQUEUE.
	 * Instead we get an EAGAIN here, and the recvmsg for the regular
	 * POLLIN below will see ECONNREFUSED.
	 */
	if ((bits & POLLERR) && proto->ops->process_error != NULL) {
		pkt = fm_socket_recv_packet(sock, MSG_ERRQUEUE);
		if (pkt != NULL) {
			proto->ops->process_error(proto, pkt);
			free(pkt);
		} else if (errno != EAGAIN) {
			fm_log_error("socket %d: POLLERR set but recvmsg failed: %m", sock->fd);
		}

		bits &= ~POLLERR;
	}

	if ((bits & POLLIN) && proto->ops->process_packet != NULL) {
		pkt = fm_socket_recv_packet(sock, 0);

		if (pkt == NULL && errno == ECONNREFUSED
		 && fm_socket_is_connected(sock)
		 && proto->ops->process_error != NULL) {
			pkt = fm_socket_build_error_packet(&sock->peer_address, errno);
			proto->ops->process_error(proto, pkt);
			free(pkt);
		} else
		if (pkt != NULL) {
			proto->ops->process_packet(proto, pkt);
			free(pkt);
		} else if (errno != EAGAIN) {
			fm_log_error("socket %d: POLLIN set but recvmsg failed: %m", sock->fd);
		}

		bits &= ~POLLIN;
	}

	if ((bits & POLLOUT) && proto->ops->connection_established != NULL) {
		proto->ops->connection_established(proto, &sock->peer_address);
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
fm_socket_poll_all(void)
{
	unsigned int max_fds = 0, nfds = 0;
	fm_socket_t *sock;
	struct pollfd *pfd;
	fm_socket_t **socks;
	int rv;

	fm_socket_foreach(&socket_list, sock) {
		max_fds++;
	}

	if (max_fds == 0)
		return false;

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

	rv = poll(pfd, nfds, 10);
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
