/****************************************************************************
 *
 * Copyright (C) 2005-2007 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/
 
#include "debug.h"
#include "decode.h"
#include "mstring.h"
#include "sfxhash.h"
#include "util.h"
#include "stream5_common.h"
#include "snort_stream5_session.h"

#include "snort_stream5_tcp.h"
#include "snort_stream5_udp.h"
#include "snort_stream5_icmp.h"

#include "parser.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats s5IcmpPerfStats;
#endif

/* client/server ip/port dereference */
#define icmp_sender_ip lwSsn->client_ip
#define icmp_responder_ip lwSsn->server_ip

/*  D A T A  S T R U C T U R E S  ***********************************/
typedef struct _IcmpSession
{
    Stream5LWSession *lwSsn;

    u_int32_t   echo_count;

    struct timeval ssn_time;

} IcmpSession;

typedef struct _Stream5IcmpPolicy
{
    u_int32_t   session_timeout;
    //u_int16_t   flags;
} Stream5IcmpPolicy;

/*  G L O B A L S  **************************************************/
static Stream5SessionCache *icmp_lws_cache;
static MemPool icmp_session_mempool;
static Stream5IcmpPolicy icmp_policy;
static u_int8_t numIcmpPolicies = 0;

/*  P R O T O T Y P E S  ********************************************/
static void Stream5ParseIcmpArgs(char *, Stream5IcmpPolicy *);
static void Stream5PrintIcmpConfig(Stream5IcmpPolicy *);
static int ProcessIcmpUnreach(Packet *p);
static int ProcessIcmpEcho(Packet *p);

void Stream5InitIcmp(void)
{
    /* Finally ICMP */ 
    if((icmp_lws_cache == NULL) && s5_global_config.track_icmp_sessions)
    {
        icmp_lws_cache = InitLWSessionCache(s5_global_config.max_icmp_sessions,
                30, 5, 0, NULL);

        if(!icmp_lws_cache)
        {
            FatalError("Unable to init stream5 ICMP session cache, no ICMP "
                       "stream inspection!\n");
        }

        mempool_init(&icmp_session_mempool, s5_global_config.max_icmp_sessions, sizeof(IcmpSession));
    }
}

void Stream5IcmpPolicyInit(char *args)
{
    numIcmpPolicies++;

    Stream5ParseIcmpArgs(args, &icmp_policy);

    Stream5PrintIcmpConfig(&icmp_policy);

    return;
}

static void Stream5ParseIcmpArgs(char *args, Stream5IcmpPolicy *s5IcmpPolicy)
{
    char **toks;
    int num_toks;
    int i;
    char *index;
    char **stoks = NULL;
    int s_toks;
    char *endPtr = NULL;

    s5IcmpPolicy->session_timeout = S5_DEFAULT_SSN_TIMEOUT;
    //s5IcmpPolicy->flags = 0;

    if(args != NULL && strlen(args) != 0)
    {
        toks = mSplit(args, ",", 6, &num_toks, 0);

        i=0;

        while(i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 2, &s_toks, 0);

            if (s_toks == 0)
            {
                FatalError("%s(%d) => Missing parameter in Stream5 ICMP config.\n",
                    file_name, file_line);
            }

            if(!strcasecmp(stoks[0], "timeout"))
            {
                if(stoks[1])
                {
                    s5IcmpPolicy->session_timeout = strtoul(stoks[1], &endPtr, 10);
                }
                
                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid timeout in config file.  Integer parameter required.\n",
                            file_name, file_line);
                }

                if ((s5IcmpPolicy->session_timeout > S5_MAX_SSN_TIMEOUT) ||
                    (s5IcmpPolicy->session_timeout < S5_MIN_SSN_TIMEOUT))
                {
                    FatalError("%s(%d) => Invalid timeout in config file.  "
                        "Must be between %d and %d\n",
                        file_name, file_line,
                        S5_MIN_SSN_TIMEOUT, S5_MAX_SSN_TIMEOUT);
                }
                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream5 ICMP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => Invalid Stream5 ICMP policy option\n", 
                            file_name, file_line);
            }

            mSplitFree(&stoks, s_toks);
            i++;
        }

        mSplitFree(&toks, num_toks);
    }

    return;
}

static void Stream5PrintIcmpConfig(Stream5IcmpPolicy *s5IcmpPolicy)
{
    LogMessage("Stream5 ICMP Policy config:\n");
    LogMessage("    Timeout: %d seconds\n", s5IcmpPolicy->session_timeout);
    //LogMessage("    Flags: 0x%X\n", s5UdpPolicy->flags);
    //IpAddrSetPrint("    Bound Addresses:", s5UdpPolicy->bound_addrs);

}

void IcmpSessionCleanup(Stream5LWSession *ssn)
{
    IcmpSession *icmpssn = NULL;
    
    if (ssn->proto_specific_data)
        icmpssn = ssn->proto_specific_data->data;

    if (!icmpssn)
    {
        /* Huh? */
        return;
    }

    /* Cleanup the proto specific data */
    mempool_free(&icmp_session_mempool, ssn->proto_specific_data);
    ssn->proto_specific_data = NULL;

    s5stats.icmp_sessions_released++;
}

void Stream5CleanIcmp()
{
    /* Clean up hash table -- delete all sessions */
    PurgeLWSessionCache(icmp_lws_cache);
    icmp_lws_cache = NULL;

    mempool_destroy(&icmp_session_mempool);
}

int Stream5VerifyIcmpConfig()
{
    if (!icmp_lws_cache)
        return -1;

    if (numIcmpPolicies < 1)
        return -1;
    return 0;
}

int Stream5ProcessIcmp(Packet *p)
{
    switch (p->icmph->type)
    {
    case ICMP_DEST_UNREACH:
        return ProcessIcmpUnreach(p);
        break;
    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
        return ProcessIcmpEcho(p);
        break;
    default:
        /* We only handle the above ICMP messages with stream5 */
        break;
    }
    
    return 0;
}

static int ProcessIcmpUnreach(Packet *p)
{
    /* Handle ICMP unreachable */
    SessionKey skey;
    Stream5LWSession *ssn = NULL;
    u_int16_t sport;
    u_int16_t dport;
#ifdef SUP_IP6
    sfip_t *src;
    sfip_t *dst;
#endif

    /* No "orig" IP Header */
    if (!p->orig_iph)
        return 0;

    /* Get TCP/UDP/ICMP session from original protocol/port info
     * embedded in the ICMP Unreach message.  This is already decoded
     * in p->orig_foo.  TCP/UDP ports are decoded as p->orig_sp/dp.
     */
    skey.protocol = GET_ORIG_IPH_PROTO(p);
    sport = p->orig_sp;
    dport = p->orig_dp;

#ifdef SUP_IP6
    src = GET_ORIG_SRC(p);
    dst = GET_ORIG_DST(p);

    if (sfip_fast_lt6(src, dst))
    {
        COPY4(skey.ip_l, src->ip32);
        skey.port_l = sport;
        COPY4(skey.ip_h, dst->ip32);
        skey.port_h = dport;
    }
    else if (IP_EQUALITY(GET_ORIG_SRC(p), GET_ORIG_DST(p)))
    {
        COPY4(skey.ip_l, src->ip32);
        COPY4(skey.ip_h, skey.ip_l);
        if (sport < dport)
        {
            skey.port_l = sport;
            skey.port_h = dport;
        }
        else
        {
            skey.port_l = dport;
            skey.port_h = sport;
        }
    }
#else
    if (p->orig_iph->ip_src.s_addr < p->orig_iph->ip_dst.s_addr)
    {
        skey.ip_l = p->orig_iph->ip_src.s_addr;
        skey.port_l = sport;
        skey.ip_h = p->orig_iph->ip_dst.s_addr;
        skey.port_h = dport;
    }
    else if (p->orig_iph->ip_dst.s_addr == p->orig_iph->ip_src.s_addr)
    {
        skey.ip_l = p->orig_iph->ip_src.s_addr;
        skey.ip_h = skey.ip_l;
        if (sport < dport)
        {
            skey.port_l = sport;
            skey.port_h = dport;
        }
        else
        {
            skey.port_l = dport;
            skey.port_h = sport;
        }
    }
#endif
    else
    {
#ifdef SUP_IP6
        COPY4(skey.ip_l, dst->ip32);
        COPY4(skey.ip_h, src->ip32);
#else
        skey.ip_l = p->orig_iph->ip_dst.s_addr;
        skey.ip_h = p->orig_iph->ip_src.s_addr;
#endif
        skey.port_l = dport;
        skey.port_h = sport;
    }

    if (p->vh)
        skey.vlan_tag = (u_int16_t)VTH_VLAN(p->vh);
    else
        skey.vlan_tag = 0;

    switch (skey.protocol)
    {
    case IPPROTO_TCP:
        /* Lookup a TCP session */
        ssn = GetLWTcpSession(&skey);
        break;
    case IPPROTO_UDP:
        /* Lookup a UDP session */
        ssn = GetLWUdpSession(&skey);
        break;
    case IPPROTO_ICMP:
        /* Lookup a ICMP session */
        ssn = GetLWSessionFromKey(icmp_lws_cache, &skey);
        break;
    }

    if (ssn)
    {
        /* Mark this session as dead. */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Marking session as dead, per ICMP Unreachable!\n"););
        ssn->session_flags |= SSNFLAG_DROP_CLIENT;
        ssn->session_flags |= SSNFLAG_DROP_SERVER;
        ssn->session_state |= STREAM5_STATE_UNREACH;
    }

    return 0;
}

static int ProcessIcmpEcho(Packet *p)
{
    //SessionKey skey;
    //Stream5LWSession *ssn = NULL;

    return 0;
}

void IcmpUpdateDirection(Stream5LWSession *ssn, char dir,
                        ip_p ip, u_int16_t port)
{
    IcmpSession *icmpssn = ssn->proto_specific_data->data;
    ip_t tmpIp;

    if (!icmpssn)
    {
        /* Huh? */
        return;
    }

#ifdef SUP_IP6
    if (IP_EQUALITY(&icmpssn->icmp_sender_ip, ip))
    {
        if ((dir == SSN_DIR_SENDER) && (ssn->direction == SSN_DIR_SENDER))
        {
            /* Direction already set as SENDER */
            return;
        }
    }
    else if (IP_EQUALITY(&icmpssn->icmp_responder_ip, ip))
    {
        if ((dir == SSN_DIR_RESPONDER) && (ssn->direction == SSN_DIR_RESPONDER))
        {
            /* Direction already set as RESPONDER */
            return;
        }
    }
#else
    if (IP_EQUALITY(icmpssn->icmp_sender_ip, ip))
    {
        if ((dir == SSN_DIR_SENDER) && (ssn->direction == SSN_DIR_SENDER))
        {
            /* Direction already set as SENDER */
            return;
        }
    }
    else if (IP_EQUALITY(icmpssn->icmp_responder_ip, ip))
    {
        if ((dir == SSN_DIR_RESPONDER) && (ssn->direction == SSN_DIR_RESPONDER))
        {
            /* Direction already set as RESPONDER */
            return;
        }
    }
#endif

    /* Swap them -- leave ssn->direction the same */
    tmpIp = icmpssn->icmp_sender_ip;
    icmpssn->icmp_sender_ip = icmpssn->icmp_responder_ip;
    icmpssn->icmp_responder_ip = tmpIp;
}

