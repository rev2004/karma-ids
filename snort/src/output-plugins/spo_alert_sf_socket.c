/*
** Copyright (C) 2003 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id$ */

/* We use some Linux only socket capabilities */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LINUX

#include "spo_plugbase.h"
#include "plugbase.h"

#include "event.h"
#include "rules.h"
#include "debug.h"
#include "util.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdlib.h>
#include "generators.h"

/* error result codes */
#define SNORT_SUCCESS 0
#define SNORT_EINVAL 1
#define SNORT_ENOENT 2
#define SNORT_ENOMEM 3

static int configured = 0;
static int connected = 0;
static int sock = -1;
static struct sockaddr_un sockAddr;

extern RuleListNode *RuleLists;

typedef struct _SnortActionRequest
{
    u_int32_t event_id;
    u_int32_t tv_sec;
    u_int32_t generator;
    u_int32_t sid;
    ip_t      src_ip;
    ip_t      dest_ip;
    u_int16_t sport;
    u_int16_t dport;
    u_int8_t  protocol;
} SnortActionRequest;

/* For the list of GID/SIDs that are used by the
 * Finalize routine.
 */
typedef struct _AlertSFSocketGidSid
{
    u_int32_t sidValue;
    u_int32_t gidValue;
    struct _AlertSFSocketGidSid *next;
} AlertSFSocketGidSid;
static AlertSFSocketGidSid *sid_list = NULL;

static void AlertSFSocket_Init(char *args);
static void AlertSFSocketSid_Init(char *args);
void AlertSFSocketSid_InitFinalize(int unused, void *also_unused);
void AlertSFSocket(Packet *packet, char *msg, void *arg, Event *event);

static int AlertSFSocket_Connect(void);
static OptTreeNode *OptTreeNode_Search(u_int32_t gid, u_int32_t sid);
static int SignatureAddOutputFunc(u_int32_t gid, u_int32_t sid, 
        void (*outputFunc)(Packet *, char *, void *, Event *),
        void *args);
int String2ULong(char *string, unsigned long *result);

void AlertSFSocket_Setup(void)
{
    RegisterOutputPlugin("alert_sf_socket", NT_OUTPUT_ALERT, 
            AlertSFSocket_Init);
    RegisterOutputPlugin("alert_sf_socket_sid", NT_OUTPUT_ALERT,
            AlertSFSocketSid_Init);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: AlertSFSocket "
                "registered\n"););
}

/* this is defined in linux/un.h (see aldo sys/un.h) */
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

static void AlertSFSocket_Init(char *args)
{
    /* process argument */
    char *sockname;

    if(!args)
        FatalError("ERROR: AlertSFSocket: must specify a socket name\n");

    sockname = (char*)args;

    if(strlen(sockname) == 0)
        FatalError("ERROR: AlertSFSocket: must specify a socket name\n");
    
    if(strlen(sockname) > UNIX_PATH_MAX - 1)
        FatalError("ERROR: AlertSFSocket: socket name must be less than %i "
                "characters\n", UNIX_PATH_MAX - 1);
    
    /* create socket */
    if((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
    {
        FatalError("ERROR: Unable to create socket: %s\n", strerror(errno));
    }

    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.sun_family = AF_UNIX;
    memcpy(sockAddr.sun_path + 1, sockname, strlen(sockname));
    
    if(AlertSFSocket_Connect() == 0)
        connected = 1;

    configured = 1;

    return;
}

/*
 * Parse 'sidValue' or 'gidValue:sidValue'
 */
int GidSid2UInt(char * args, u_int32_t * sidValue, u_int32_t * gidValue)
{
    char gbuff[80];
    char sbuff[80];
    int  i;
    unsigned long glong,slong;

    *gidValue=GENERATOR_SNORT_ENGINE;
    *sidValue=0;
    
    i=0;
    while( args && *args && (i < 20) )
    {
        sbuff[i]=*args;
        if( sbuff[i]==':' ) break;
        args++;
        i++;
    }
    sbuff[i]=0;
    
    if( i >= 20 )
    {
       return SNORT_EINVAL;
    }

    if( *args == ':' ) 
    {
        memcpy(gbuff,sbuff,i);
        gbuff[i]=0;
        
        if(String2ULong(gbuff,&glong))
        {
            return SNORT_EINVAL;
        }
        *gidValue = (u_int32_t)glong;

        args++;
        i=0;
        while( args && *args && i < 20 )
        {
          sbuff[i]=*args;
          args++;
          i++;
        }
        sbuff[i]=0;

        if( i >= 20 )
        {
          return SNORT_EINVAL;
        }

        if(String2ULong(sbuff,&slong))
        {
            return SNORT_EINVAL;
        }
        *sidValue = (u_int32_t)slong;
    }
    else
    {
        if(String2ULong(sbuff,&slong))
        {
            return SNORT_EINVAL;
        }
        *sidValue=(u_int32_t)slong;
    }
    
    return SNORT_SUCCESS;
}

static void AlertSFSocketSid_Init(char *args)
{
    u_int32_t sidValue;
    u_int32_t gidValue;
    AlertSFSocketGidSid *new_sid = NULL;
    
    /* check configured value */
    if(!configured)
        FatalError("AlertSFSocket must be configured before attaching it to a "
                "sid");
    
    if (GidSid2UInt((char*)args, &sidValue, &gidValue) )
        FatalError("Invalid argument '%s' to alert_sf_socket_sid\n", args);

    new_sid = (AlertSFSocketGidSid *)SnortAlloc(sizeof(AlertSFSocketGidSid));

    new_sid->sidValue = sidValue;
    new_sid->gidValue = gidValue;

    if (sid_list)
    {
        /* Add this one to the front. */
        new_sid->next = sid_list;
    }
    else
    {
        AddFuncToPostConfigList(AlertSFSocketSid_InitFinalize, NULL);
    }
    sid_list = new_sid;
}

void AlertSFSocketSid_InitFinalize(int unused, void *also_unused)
{
    AlertSFSocketGidSid *new_sid = sid_list;
    AlertSFSocketGidSid *next_sid;
    u_int32_t sidValue;
    u_int32_t gidValue;
    int rval = 0;

    while (new_sid)
    {
        sidValue = new_sid->sidValue;
        gidValue = new_sid->gidValue;

        rval = SignatureAddOutputFunc( (u_int32_t)gidValue, (u_int32_t)sidValue, AlertSFSocket, NULL );

        switch(rval)
        {
            case SNORT_SUCCESS:
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "SFSocket output enabled for "
                            "sid %u.\n", sidValue););
                break;
            case SNORT_EINVAL:
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Invalid argument "
                            "attempting to attach output for sid %u.\n", 
                            sidValue););
                break;
            case SNORT_ENOENT:
                LogMessage("No entry found.  SFSocket output not enabled for "
                        "sid %lu.\n", sidValue);
                break;
            case SNORT_ENOMEM:
                FatalError("Out of memory");
                break;
        }

        /* Save ptr to next one in the list */
        next_sid = new_sid->next;
        /* Free the current one, not needed any more */
        free(new_sid);
        /* Reset the list */
        sid_list = new_sid = next_sid;
    }
}

static int AlertSFSocket_Connect(void)
{
    /* check sock value */
    if(sock == -1)
        FatalError("ERROR: AlertSFSocket: Invalid socket\n");

    if(connect(sock, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) == -1)
    {
        if(errno == ECONNREFUSED || errno == ENOENT)
        {
            LogMessage("WARNING: AlertSFSocket: Unable to connect to socket: "
                    "%s\n", strerror(errno));
            return 1;
        }
        else
        {
            FatalError("ERROR: AlertSFSocket: Unable to connect to socket "
                    "(%i): %s\n", errno, strerror(errno));
        }
    }
    return 0;
}
        
                   
static SnortActionRequest sar;

void AlertSFSocket(Packet *packet, char *msg, void *arg, Event *event)
{
    int tries = 0;

    if(!event || !packet || !IPH_IS_VALID(packet))
        return;

    /* construct the action request */
    sar.event_id = event->event_id;
    sar.tv_sec = packet->pkth->ts.tv_sec;
    sar.generator = event->sig_generator;
    sar.sid = event->sig_id;
#ifdef SUP_IP6
    sar.src_ip =  *GET_SRC_IP(packet);
    sar.dest_ip = *GET_DST_IP(packet);
#else
    sar.src_ip = ntohl(packet->iph->ip_src.s_addr);
    sar.dest_ip = ntohl(packet->iph->ip_dst.s_addr);
#endif
    sar.protocol = GET_IPH_PROTO(packet);

    if(sar.protocol == IPPROTO_UDP || sar.protocol == IPPROTO_TCP)
    {
        sar.sport = packet->sp;
        sar.dport = packet->dp;
    }
    else
    {
        sar.sport = 0;
        sar.dport = 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"AlertSFSocket fired for sid %u\n",
                            event->sig_id););

    do
    {
        tries++;
        /* connect as needed */
        if(!connected)
        {
            if(AlertSFSocket_Connect() != 0)
                break;
            connected = 1;
        }

        /* send request */
        if(send(sock, &sar, sizeof(sar), 0) == sizeof(sar))
        {
            /* success */
            return;
        }
        /* send failed */
        if(errno == ENOBUFS)
        {
            LogMessage("ERROR: AlertSFSocket: out of buffer space\n");
            break;
        }
        else if(errno == ECONNRESET)
        {
            connected = 0;
            LogMessage("WARNING: AlertSFSocket: connection reset, will attempt "
                    "to reconnect\n");
        }
        else if(errno == ECONNREFUSED)
        {
            LogMessage("WARNING: AlertSFSocket: connection refused, "
                    "will attempt to reconnect\n");
            connected = 0;
        }
        else if(errno == ENOTCONN)
        {
            LogMessage("WARNING: AlertSFSocket: not connected, "
                    "will attempt to reconnect\n");
            connected = 0;
        }
        else
        {
            LogMessage("ERROR: AlertSFSocket: unhandled error '%i' in send(): "
                    "%s\n", errno, strerror(errno));
            connected = 0;
        }
    } while(tries <= 1);
    LogMessage("ERROR: AlertSFSocket: Alert not sent\n");
    return;
}

static int SignatureAddOutputFunc( u_int32_t gid, u_int32_t sid, 
        void (*outputFunc)(Packet *, char *, void *, Event *),
        void *args)
{
    OptTreeNode *optTreeNode = NULL;
    OutputFuncNode *outputFuncs = NULL;
    
    if(!outputFunc)
        return SNORT_EINVAL;  /* Invalid argument */
                       
    if(!(optTreeNode = OptTreeNode_Search(gid,sid)))
    {
        LogMessage("Unable to find OptTreeNode for SID %u\n", sid);
        return SNORT_ENOENT;
    }

    if(!(outputFuncs = (OutputFuncNode *)calloc(1, sizeof(OutputFuncNode))))
    {
        LogMessage("Out of memory adding output function to SID %u\n", sid);
        return SNORT_ENOMEM;
    }

    outputFuncs->func = outputFunc;
    outputFuncs->arg = args;
    
    outputFuncs->next = optTreeNode->outputFuncs;

    optTreeNode->outputFuncs = outputFuncs;
    
    return SNORT_SUCCESS;
}


/* search for an OptTreeNode by sid */
static OptTreeNode *OptTreeNode_Search(u_int32_t gid, u_int32_t sid)
{
    RuleListNode *ruleListNode = RuleLists;
    
    if(sid == 0)
        return NULL;
    
    while(ruleListNode)
    {
        RuleTreeNode *ruleTreeNode;
        ListHead *listHead = ruleListNode->RuleList;
        
        ruleTreeNode = listHead->IpList;
        while(ruleTreeNode)
        {
            OptTreeNode *optTreeNode;

            optTreeNode = ruleTreeNode->down;
            while(optTreeNode)
            {
                if(optTreeNode->sigInfo.generator == gid && 
                   optTreeNode->sigInfo.id == sid)
                    return optTreeNode;
                    
                optTreeNode = optTreeNode->next;
            }   
            ruleTreeNode = ruleTreeNode->right;
        }
    
        ruleTreeNode = listHead->TcpList;
        while(ruleTreeNode)
        {
            OptTreeNode *optTreeNode;

            optTreeNode = ruleTreeNode->down;
            while(optTreeNode)
            {
                if(optTreeNode->sigInfo.id == sid)
                    return optTreeNode;
                    
                optTreeNode = optTreeNode->next;
            }   
            ruleTreeNode = ruleTreeNode->right;
        }
       
        ruleTreeNode = listHead->UdpList;
        while(ruleTreeNode)
        {
            OptTreeNode *optTreeNode;

            optTreeNode = ruleTreeNode->down;
            while(optTreeNode)
            {
                if(optTreeNode->sigInfo.id == sid)
                    return optTreeNode;
                    
                optTreeNode = optTreeNode->next;
            }   
            ruleTreeNode = ruleTreeNode->right;
        }

        ruleTreeNode = listHead->IcmpList;
        while(ruleTreeNode)
        {
            OptTreeNode *optTreeNode;

            optTreeNode = ruleTreeNode->down;
            while(optTreeNode)
            {
                if(optTreeNode->sigInfo.id == sid)
                    return optTreeNode;
                    
                optTreeNode = optTreeNode->next;
            }   
            ruleTreeNode = ruleTreeNode->right;
        }
        
        ruleListNode = ruleListNode->next;
    }

    return NULL;
}

int String2ULong(char *string, unsigned long *result)
{
    unsigned long value;
    char *endptr;
    if(!string)
        return -1;

    value = strtoul(string, &endptr, 10);
    if(*endptr != '\0')
        return -1;

    *result = value;

    return 0;
}


#endif   /* LINUX */

