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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>

#include "freemap.h"
#include "addresses.h"
#include "routing.h"
#include "utils.h"

#if 0
# define nl_debug	printf
#else
# define nl_debug(fmt ...) \
	do { } while (0)
#endif

typedef struct nlpkt {
	unsigned int	rpos, wpos, size;
	unsigned char	data[0];
} nlpkt_t;

static unsigned int	netlink_seq = 0;

static void		fm_route_show(fm_route_t *r);

fm_route_t *
fm_route_alloc(int af, int type)
{
	fm_route_t *route;

	route = calloc(1, sizeof(*route));
	route->family = af;
	route->type = type;
	return route;
}

void
fm_route_free(fm_route_t *route)
{
	free(route);
}

fm_routing_cache_t *
fm_routing_cache_alloc(int af)
{
	fm_routing_cache_t *cache;

	cache = calloc(1, sizeof(*cache));
	cache->family = af;
	return cache;
}

void
fm_routing_cache_free(fm_routing_cache_t *cache)
{
	if (cache->entries) {
		unsigned int i;

		for (i = 0; i < cache->nroutes; ++i)
			fm_route_free(cache->entries[i]);

		free(cache->entries);
	}

	memset(cache, 9, sizeof(*cache));
	free(cache);
}

void
fm_routing_cache_add(fm_routing_cache_t *cache, fm_route_t *route)
{
	assert(route->family == cache->family);

	maybe_realloc_array(cache->entries, cache->nroutes, 16);
	cache->entries[cache->nroutes++] = route;
}

/*
 * Sort the rtcache from most specific to least
 */
static inline int
rt_type_to_prio(int type)
{
	/* put unicast and local routes first */
	if (type == RTN_UNICAST || type == RTN_LOCAL)
		return 0;
	return 1;
}

static int
rtcache_entry_cmp(const void *a, const void *b)
{
	fm_route_t *rta = *(fm_route_t **) a;
	fm_route_t *rtb = *(fm_route_t **) b;
	int diff;

	/* put unicast and local routes before mcast, anycast etc */
	diff = rt_type_to_prio(rta->type) - rt_type_to_prio(rtb->type);

	/* put longer prefix before shorter */
	if (diff == 0)
		diff = -(rta->dst.prefix_len - rtb->dst.prefix_len);

	/* put higher priority before shorter */
	if (diff == 0)
		diff = -(rta->priority - rtb->priority);

	return diff;
}

void
fm_routing_cache_sort(fm_routing_cache_t *cache)
{
	qsort(cache->entries, cache->nroutes, sizeof(cache->entries[0]), rtcache_entry_cmp);
}

void
fm_routing_cache_dump(fm_routing_cache_t *cache)
{
	printf("Routing cache for af %d\n", cache->family);
	for (unsigned int i = 0; i < cache->nroutes; ++i) {
		fm_route_show(cache->entries[i]);
	}
	printf("\n");
}

nlpkt_t *
nlpkt_alloc(size_t payload)
{
	nlpkt_t *pkt;

	pkt = malloc(sizeof(*pkt) + payload);
	memset(pkt, 0, sizeof(*pkt));

	pkt->size = payload;
	return pkt;
}

void
nlpkt_free(nlpkt_t *pkt)
{
	free(pkt);
}

void
nlpkt_compact(nlpkt_t *pkt)
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

static inline unsigned int
nlpkt_available(nlpkt_t *pkt)
{
	return pkt->wpos - pkt->rpos;
}

static inline unsigned int
nlpkt_tailroom(nlpkt_t *pkt)
{
	return pkt->size - pkt->wpos;
}

void *
nlpkt_push(nlpkt_t *pkt, size_t count)
{
	void *ret = pkt->data + pkt->wpos;

	assert(pkt->size - pkt->wpos >= count);
	pkt->wpos += count;
	return ret;
}

void *
nlpkt_peek(nlpkt_t *pkt, size_t len)
{
	if (pkt->wpos - pkt->rpos < len)
		return NULL;
	return pkt->data + pkt->rpos;
}

void *
nlpkt_pull(nlpkt_t *pkt, size_t len)
{
	void *ret = nlpkt_peek(pkt, len);

	if (ret != NULL)
		pkt->rpos += len;
	return ret;
}

static nlpkt_t *
nlpkt_pull_packet(nlpkt_t *pkt, unsigned int count)
{
	nlpkt_t *ret;

	if (nlpkt_available(pkt) < count)
		return NULL;

	ret = nlpkt_alloc(count);
	memcpy(ret->data, pkt->data + pkt->rpos, count);
	pkt->rpos += count;
	ret->wpos = count;

	return ret;
}

static unsigned int
nlpkt_len(nlpkt_t *pkt, void *base)
{
	size_t offset = (unsigned char *) base - pkt->data;

	assert(offset <= pkt->wpos);
	return pkt->wpos - offset;
}

int
netlink_open(void)
{
	struct sockaddr_nl snl;
	socklen_t slen;
	int fd, value;

	fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd < 0) {
		perror("could not create netlink routing socket");
		return -1;
	}

	value = 32768;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, 4) < 0) {
		perror("setsockopt(SO_SNDBUF)");
		goto failed;
	}

	value = 1048576;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, 4) < 0) {
		perror("setsockopt(SO_RCVBUF)");
		goto failed;
	}

	value = 1;
	if (setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &value, 4) < 0) {
		perror("setsockopt(NETLINK_EXT_ACK)");
		goto failed;
	}

#if 0
	/* If we set this option, rtnetlink will send us only unicast routes */
	value = 1;
	if (setsockopt(fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &value, 4) < 0) {
		perror("setsockopt(NETLINK_GET_STRICT_CHK)");
		goto failed;
	}
#endif

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *) &snl, sizeof(snl)) < 0) {
		perror("netlink bind");
		goto failed;
	}

	slen = sizeof(snl);
	if (getsockname(fd, (struct sockaddr *) &snl, &slen) < 0) {
		perror("netlink getsockname");
		goto failed;
	}

	while (netlink_seq == 0)
		netlink_seq = random();

	return fd;

failed:
	if (fd >= 0)
		close(fd);
	return -1;
}

bool
netlink_send(int fd, void *data, size_t len)
{
	if (sendto(fd, data, len, 0, NULL, 0) < 0) {
		perror("netlink sendto failed");
		return false;
	}
	return true;
}

bool
netlink_recv(int fd, nlpkt_t *pkt)
{
	struct sockaddr_nl snl;
	socklen_t slen = sizeof(snl);
	unsigned int tailroom;
	int n;

	/* In case we have some data left from the previous receive */
	nlpkt_compact(pkt);

	if ((tailroom = nlpkt_tailroom(pkt)) == 0) {
		fprintf(stderr, "Not enough room in receive packet\n");
		return false;
	}

	n = recvfrom(fd, pkt->data + pkt->wpos, tailroom, 0, (struct sockaddr *) &snl, &slen);
	if (n < 0) {
		perror("recvmsg");
		return false;
	}

	pkt->wpos += n;

	assert(pkt->rpos == 0);
	assert(pkt->wpos == n);
	return true;
}

struct nlmsghdr *
nlmsg_begin(nlpkt_t *pkt, int type, int flags)
{
	struct nlmsghdr *nh;

	nh = nlpkt_push(pkt, sizeof(*nh));
	nh->nlmsg_type = type;
	nh->nlmsg_flags = flags;
	nh->nlmsg_seq = netlink_seq++;

	return nh;
}

void
nlattr_add_int(nlpkt_t *pkt, int type, int value)
{
	struct nlattr *nla = nlpkt_push(pkt, sizeof(*nla) + 4);

	nla->nla_len = sizeof(*nla) + 4;
	nla->nla_type = type;
	*(int *) (nla + 1) = value;
}

bool
nlattr_get_int(struct nlattr *nla, unsigned int *ret)
{
	if (nla->nla_len != 8)
		return false;
	*ret = *(int *) (nla + 1);
	return true;
}

bool
nlattr_get_ipv4(struct nlattr *nla, struct in_addr *ret)
{
	if (nla->nla_len != 8)
		return false;
	ret->s_addr = *(uint32_t *) (nla + 1);
	return true;
}

bool
nlattr_get_ipv6(struct nlattr *nla, struct in6_addr *ret)
{
	if (nla->nla_len != 20)
		return false;
	memcpy(ret, nla + 1, 16);
	return true;
}

bool
nlattr_get_address(struct nlattr *nla, int af, struct sockaddr_storage *ret)
{
	memset(ret, 0, sizeof(*ret));
	if (af == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *) ret;

		sin->sin_family = AF_INET;
		return nlattr_get_ipv4(nla, &sin->sin_addr);
	}

	if (af == AF_INET6) {
		struct sockaddr_in6 *six = (struct sockaddr_in6 *) ret;

		six->sin6_family = AF_INET6;
		return nlattr_get_ipv6(nla, &six->sin6_addr);
	}

	return false;
}

bool
rtnetlink_process_newroute(int af, nlpkt_t *pkt, fm_route_t **ret_p)
{
	fm_route_t *route;
	struct nlmsghdr *nh;
	struct rtmsg *rt;

	*ret_p = NULL;

	nh = nlpkt_pull(pkt, sizeof(*nh));
	if (nh == NULL)
		return false;

	if (nh->nlmsg_type != RTM_NEWROUTE)
		return false;

	rt = nlpkt_pull(pkt, sizeof(*rt));
#if 0
	printf("af %u type %d dlen %u slen %d flags 0x%x payload %u\n",
			rt->rtm_family,
			rt->rtm_type,
			rt->rtm_dst_len,
			rt->rtm_src_len,
			rt->rtm_flags,
			nlpkt_available(pkt));
#endif

	route = fm_route_alloc(af, rt->rtm_type);
	route->src.prefix_len = rt->rtm_src_len;
	route->dst.prefix_len = rt->rtm_dst_len;

	if (!fm_address_mask_from_prefixlen(af, route->src.prefix_len, route->src.raw_mask, sizeof(route->src.raw_mask))) {
		fprintf(stderr, "invalid prefix len");
		goto failed;
	}

	if (!fm_address_mask_from_prefixlen(af, route->dst.prefix_len, route->dst.raw_mask, sizeof(route->dst.raw_mask))) {
		fprintf(stderr, "invalid prefix len");
		goto failed;
	}

	while (nlpkt_available(pkt)) {
		struct nlattr *nla;
		bool ok = true;

		if (!(nla = nlpkt_peek(pkt, sizeof(*nla)))
		 || nlpkt_available(pkt) < nla->nla_len) {
			fprintf(stderr, "truncated rtnetlink attribute\n");
			goto failed;
		}

		switch (nla->nla_type) {
		case RTA_TABLE:
		case RTA_CACHEINFO:
		case RTA_PREF:
			nl_debug("   ignore attr %u len %u\n", nla->nla_type, nla->nla_len);
			break;

		case RTA_PRIORITY:
			ok = nlattr_get_int(nla, &route->priority);
			break;

		case RTA_SRC:
			ok = nlattr_get_address(nla, af, &route->src.addr);
			break;

		case RTA_DST:
			ok = nlattr_get_address(nla, af, &route->dst.addr);
			break;

		case RTA_OIF:
			ok = nlattr_get_int(nla, &route->oif);
			break;

		case RTA_GATEWAY:
			ok = nlattr_get_address(nla, af, &route->gateway);
			break;

		case RTA_PREFSRC:
			ok = nlattr_get_address(nla, af, &route->pref_src_addr);
			break;

		default:
			nl_debug("   unexpected attr %u len %u\n", nla->nla_type, nla->nla_len);
			break;
		}

		if (!ok) {
			fprintf(stderr, "failed to parse netlink attribute %u len %u\n",
					nla->nla_type, nla->nla_len);
			goto failed;
		}

		nlpkt_pull(pkt, (nla->nla_len + 3) & ~3);
	}

	*ret_p = route;
	return true;

failed:
	if (route != NULL)
		fm_route_free(route);
	return false;
}

static const char *
address_format(const struct sockaddr_storage *ap)
{
	static char extra[128];
	if (ap->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *) ap;

		return inet_ntoa(sin->sin_addr);
	} else
	if (ap->ss_family == AF_INET6) {
		const struct sockaddr_in6 *six = (const struct sockaddr_in6 *) ap;

		return inet_ntop(AF_INET6, &six->sin6_addr, extra, sizeof(extra));
	}

	return "BAD";
}

static const char *
route_prefix_format(struct sockaddr_storage *addr, unsigned int pfxlen)
{
	static char abuf[128];

	if (pfxlen == 0)
		return "default";

	snprintf(abuf, sizeof(abuf), "%s/%u", address_format(addr), pfxlen);
	return abuf;
}

static const char *
route_type_name(int type)
{
	static char buffer[16];

	switch (type) {
	case RTN_UNICAST:
		return "unicast";
	case RTN_LOCAL:
		return "local";
	case RTN_BROADCAST:
		return "bcast";
	case RTN_ANYCAST:
		return "anycast";
	case RTN_MULTICAST:
		return "mcast";
	}

	snprintf(buffer, sizeof(buffer), "rt%u", type);
	return buffer;
}

void
fm_route_show(fm_route_t *r)
{
	printf("%-10s ", route_type_name(r->type));
	printf("%-25s", route_prefix_format(&r->dst.addr, r->dst.prefix_len));
	if (r->gateway.ss_family != AF_UNSPEC)
		printf(" via %s", address_format(&r->gateway));
	if (r->priority)
		printf(" priority %u", r->priority);
	if (r->oif)
		printf(" oif %u", r->oif);
	if (r->pref_src_addr.ss_family != AF_UNSPEC)
		printf(" prefsrc %s", address_format(&r->pref_src_addr));
	printf("\n");
}

static bool
netlink_process_response(fm_routing_cache_t *rtcache, nlpkt_t *pkt, unsigned int expect_seq, bool *done_p)
{
	nl_debug("processing netlink response (%u bytes)\n", nlpkt_available(pkt));
	while (!*done_p) {
		struct nlmsghdr *nh;
		nlpkt_t *msg;

		nh = nlpkt_peek(pkt, sizeof(*nh));
		if (nh == NULL || nh->nlmsg_len > nlpkt_available(pkt))
			break;

		/* any other rtnetlink message - how come? */
		if (nh->nlmsg_seq != expect_seq) {
			printf("unexpected sequence %u != %u\n", nh->nlmsg_seq, expect_seq);
			nlpkt_pull(pkt, nh->nlmsg_len);
			continue;
		}

		nl_debug("nlmsg type=%d len=%u flags=%x\n", nh->nlmsg_type, nh->nlmsg_len, nh->nlmsg_flags);

		/* Create a copy of this nlmsg */
		msg = nlpkt_pull_packet(pkt, nh->nlmsg_len);

		if (nh->nlmsg_type == RTM_NEWROUTE) {
			fm_route_t *route;

			if (!rtnetlink_process_newroute(rtcache->family, msg, &route)) {
				nlpkt_free(msg);
				return false;
			}

			if (route != NULL)
				fm_routing_cache_add(rtcache, route);
		} else
		if (nh->nlmsg_type == NLMSG_DONE) {
			nl_debug("found DONE; done with this request\n");
			*done_p = true;
		}

		if (!(nh->nlmsg_flags & NLM_F_MULTI)) {
			nl_debug("one-shot reply; done with this request\n");
			*done_p = true;
		}

		nlpkt_free(msg);
	}

	return true;
}

static unsigned int
netlink_send_dump_request(int fd, int af, int type)
{
	nlpkt_t *pkt;
	struct nlmsghdr *nh;
	struct rtmsg *rt;
	bool ok;

	pkt = nlpkt_alloc(256);
	memset(pkt->data, 0, pkt->size);

	nh = nlmsg_begin(pkt, type, NLM_F_REQUEST|NLM_F_DUMP);
	rt = nlpkt_push(pkt, sizeof(*rt));
	rt->rtm_family = af;

	nlattr_add_int(pkt, RTA_TABLE, RT_TABLE_MAIN);
	nh->nlmsg_len = nlpkt_len(pkt, nh);

	/* End with a NUL packet */
	nlmsg_begin(pkt, 0, 0);

	ok = netlink_send(fd, pkt->data, pkt->wpos);
	nlpkt_free(pkt);

	if (!ok)
		return 0;

	return nh->nlmsg_seq;
}

bool
netlink_dump_rt(int fd, fm_routing_cache_t *rtcache)
{
	nlpkt_t *pkt;
	bool done = false;
	unsigned int expect_seq;

	nl_debug("About to dump routes for af=%d\n", rtcache->family);

	expect_seq = netlink_send_dump_request(fd, rtcache->family, RTM_GETROUTE);
	if (expect_seq == 0)
		return false;

	pkt = nlpkt_alloc(65536);
	do {
		if (!netlink_recv(fd, pkt))
			break;
		if (!netlink_process_response(rtcache, pkt, expect_seq, &done))
			break;
	} while (!done);

	nlpkt_free(pkt);
	return done;
}

static fm_routing_cache_t *
netlink_build_routing_cache(int af)
{
	fm_routing_cache_t *rtcache;
	bool okay;
	int fd;

	if ((fd = netlink_open()) < 0)
		return false;

	rtcache = fm_routing_cache_alloc(af);

	okay = netlink_dump_rt(fd, rtcache);
	close(fd);

	if (!okay) {
		fm_routing_cache_free(rtcache);
		return NULL;
	}

	fm_routing_cache_sort(rtcache);

	return rtcache;
}

static fm_routing_cache_t *
fm_routing_cache_for_family(int af)
{
	static fm_routing_cache_t *ipv4 = NULL;
	static fm_routing_cache_t *ipv6 = NULL;
	fm_routing_cache_t **cache_p;

	if (af == AF_INET)
		cache_p = &ipv4;
	else if (af == AF_INET6)
		cache_p = &ipv6;
	else
		return NULL;

	if (*cache_p == NULL) {
		*cache_p = netlink_build_routing_cache(af);
		if (*cache_p == NULL)
			fprintf(stderr, "Error while trying to discover routing table for af %d\n", af);
	}
	return *cache_p;
}

static inline bool
fm_address_prefix_match(const fm_address_t *a, const fm_address_t *b, unsigned int pfxlen)
{
	return false;
}

fm_route_t *
fm_routing_for_address(const fm_address_t *addr)
{
	fm_routing_cache_t *rtcache;

	if ((rtcache = fm_routing_cache_for_family(addr->ss_family)) == NULL)
		return NULL;

	return NULL;
}

#if 0
int main(void)
{
	fm_routing_cache_t *rtcache;

	if ((rtcache = fm_routing_cache_for_family(AF_INET)) != NULL)
		fm_routing_cache_dump(rtcache);

	if ((rtcache = fm_routing_cache_for_family(AF_INET6)) != NULL)
		fm_routing_cache_dump(rtcache);

	return 0;
}
#endif
