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
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "socket.h"

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

	/* we don't start polling on a socket until we either have
	 * a callback set up or we have initiated a connection. */
	sock->rpoll = 0;

	return sock;
}

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

void
fm_socket_set_callback(fm_socket_t *sock,
			void (*callback)(fm_socket_t *, int, void *user_data),
			void *user_data)
{
	sock->callback = callback;
	sock->user_data = user_data;

	if (sock->rpoll == 0)
		sock->rpoll = POLLIN;
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
		printf("Initiated connection to %s on sock %d\n", fm_address_format(address), sock->fd);
		sock->rpoll = POLLIN|POLLOUT;
	} else {
		sock->rpoll = POLLIN;
	}

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

static void
fm_socket_handle_poll_event(fm_socket_t *sock, int bits)
{
	if (sock->callback == NULL) {
		sock->rpoll = 0;
		return;
	}

	sock->callback(sock, bits, sock->user_data);
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
		/* printf("sock %d poll %d\n", sock->fd, sock->rpoll); */
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
				/* printf("poll event %d on sock %d\n", rp->revents, rp->fd); */
				sock = socks[nfds];

				fm_socket_handle_poll_event(sock, rp->revents);
			}
		}
	}

	free(pfd);
	free(socks);

	return fm_socket_purge();
}
