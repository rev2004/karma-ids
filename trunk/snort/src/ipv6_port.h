#ifndef IPV6_PORT_H
#define IPV6_PORT_H

///////////////////
/* IPv6 and IPv4 */
#ifdef SUP_IP6

#include "sf_ip.h"

typedef sfip_t ip_t;
typedef sfip_t *ip_p;

#define IpAddrNode sfip_node_t
#define IpAddrSet sfip_var_t
#define IpAddrSetContains(x,y) sfvar_ip_in(x, y)
#define IpAddrSetPrint sfvar_print

#define inet_ntoa sfip_ntoa

#define GET_SRC_IP(p) (p->iph_api.iph_ret_src(p))
#define GET_DST_IP(p) (p->iph_api.iph_ret_dst(p))

#define GET_ORIG_SRC(p) (p->iph_api.orig_iph_ret_src(p))
#define GET_ORIG_DST(p) (p->iph_api.orig_iph_ret_dst(p))

/* These are here for backwards compatibility */
#define GET_SRC_ADDR(x) GET_SRC_IP(x)
#define GET_DST_ADDR(x) GET_DST_IP(x)

#define IP_EQUALITY(x,y) (sfip_cmp(x,y) == SFIP_EQUAL)
#define IP_LESSER(x,y)   (sfip_cmp(x,y) == SFIP_LESSER)
#define IP_GREATER(x,y)  (sfip_cmp(x,y) == SFIP_GREATER)

#define GET_IPH_TOS(p)   p->iph_api.iph_ret_tos(p)
#define GET_IPH_LEN(p)   p->iph_api.iph_ret_len(p)
#define GET_IPH_TTL(p)   p->iph_api.iph_ret_ttl(p)
#define GET_IPH_ID(p)    p->iph_api.iph_ret_id(p)
#define GET_IPH_OFF(p)   p->iph_api.iph_ret_off(p)
#define GET_IPH_VER(p)   p->iph_api.iph_ret_ver(p)
#define GET_IPH_PROTO(p) p->iph_api.iph_ret_proto(p)

#define GET_ORIG_IPH_PROTO(p)   p->iph_api.orig_iph_ret_proto(p)
#define GET_ORIG_IPH_VER(p)     p->iph_api.orig_iph_ret_ver(p)
#define GET_ORIG_IPH_LEN(p)     p->iph_api.orig_iph_ret_len(p)
#define GET_ORIG_IPH_OFF(p)     p->iph_api.orig_iph_ret_off(p)
#define GET_ORIG_IPH_PROTO(p)   p->iph_api.orig_iph_ret_proto(p)

#define IS_IP4(x) (x->family == AF_INET)
#define IS_IP6(x) (x->family == AF_INET6)
/* XXX make sure these aren't getting confused with sfip_is_valid within the code */
#define IPH_IS_VALID(p) iph_is_valid(p)

#define IP_CLEAR(x) x.bits = x.family = x.ip32[0] = x.ip32[1] = x.ip32[2] = x.ip32[3] = 0;

#define IS_SET(x) sfip_is_set(&x)

#define IP_COPY_VALUE(x,y) (x = *y)

#define GET_IPH_HLEN(p) (p->iph_api.iph_ret_hlen(p))
#define SET_IPH_HLEN(p, val)


#else
///////////////
/* IPv4 only */
#include <sys/types.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

typedef u_int32_t ip_t; /* 32 bits only -- don't use unsigned long */
typedef u_int32_t ip_p; /* 32 bits only -- don't use unsigned long */

#define IP_SRC_EQUALITY(x,y) (x->ip_addr == (y->iph->ip_src.s_addr & x->netmask))
#define IP_DST_EQUALITY(x,y) (x->ip_addr == (y->iph->ip_dst.s_addr & x->netmask))

#define GET_SRC_IP(x) x->iph->ip_src.s_addr
#define GET_DST_IP(x) x->iph->ip_dst.s_addr

#define GET_ORIG_SRC(p) (p->orig_iph->ip_src.s_addr)
#define GET_ORIG_DST(p) (p->orig_iph->ip_dst.s_addr)

#define GET_SRC_ADDR(x) x->iph->ip_src
#define GET_DST_ADDR(x) x->iph->ip_dst

#define IP_CLEAR_SRC(x) x->iph->ip_src.s_addr = 0
#define IP_CLAR_DST(x) x->iph->ip_dst.s_addr = 0

#define IP_EQUALITY(x,y) (x == y)
#define IP_LESSER(x,y) (x < y)
#define IP_GREATER(x,y) (x > y)

#define GET_IPH_PROTO(p) p->iph->ip_proto
#define GET_IPH_TOS(p) p->iph->ip_tos
#define GET_IPH_LEN(p) p->iph->ip_len
#define GET_IPH_TTL(p) p->iph->ip_ttl
#define GET_IPH_VER(p) ((p->iph->ip_verhl & 0xf0) >> 4)
#define GET_IPH_ID(p) p->iph->ip_id
#define GET_IPH_OFF(p) p->iph->ip_off

#define GET_ORIG_IPH_VER(p) IP_VER(p->orig_iph)
#define GET_ORIG_IPH_LEN(p) p->orig_iph->ip_len
#define GET_ORIG_IPH_OFF(p) p->orig_iph->ip_off
#define GET_ORIG_IPH_PROTO(p) p->orig_iph->ip_proto

#define IS_IP4(x) 1
#define IS_IP6(x) 0
#define IPH_IS_VALID(p) p->iph

#define IP_CLEAR(x) x = 0;
#define IS_SET(x) x

#define IP_COPY_VALUE(x,y) (x = y)

#define GET_IPH_HLEN(p) ((p)->iph->ip_verhl & 0x0f)
#define SET_IPH_HLEN(p, val) (((IPHdr *)(p)->iph)->ip_verhl = (unsigned char)(((p)->iph->ip_verhl & 0xf0) | ((val) & 0x0f)))

#endif /* SUP_IP6 */

#if !defined(IPPROTO_IPIP) && defined(WIN32)  /* Needed for some Win32 */
#define IPPROTO_IPIP 4
#endif

#endif /* IPV6_PORT_H */
