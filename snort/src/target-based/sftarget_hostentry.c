/*
** Copyright (C) 2006-2007 Sourcefire, Inc.
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

/*
 * Author: Steven Sturges
 * sftarget_hostentry.c
 */

#include "sftarget_hostentry.h"

int hasService(HostAttributeEntry *host_entry,
               int ipprotocol,
               int protocol,
               int application)
{
    ApplicationEntry *service;

    if (!host_entry)
        return SFTARGET_NOMATCH;

    for (service = host_entry->services; service; service = service->next)
    {
        if (ipprotocol && (service->ipproto.attributeOrdinal == ipprotocol))
        {
            if (protocol && (service->protocol.attributeOrdinal == protocol))
            {
                if (application && (service->application.attributeOrdinal == application))
                {
                    /* match of ipproto, proto, & application */
                    return SFTARGET_MATCH;
                }
                else if (!application)
                {
                    /* match of ipproto, proto.
                     * application not speicifed */
                    return SFTARGET_MATCH;
                }
            }
            else if (!protocol)
            {
                /* match of ipproto.
                 * protocol not speicifed */
                return SFTARGET_MATCH;
            }
        }
        /* No ipprotocol specified, huh? */
    }

    return SFTARGET_NOMATCH;
}

int hasClient(HostAttributeEntry *host_entry,
               int ipprotocol,
               int protocol,
               int application)
{
    ApplicationEntry *client;

    if (!host_entry)
        return SFTARGET_NOMATCH;

    for (client = host_entry->clients; client; client = client->next)
    {
        if (ipprotocol && (client->ipproto.attributeOrdinal == ipprotocol))
        {
            if (protocol && (client->protocol.attributeOrdinal == protocol))
            {
                if (application && (client->application.attributeOrdinal == application))
                {
                    /* match of ipproto, proto, & application */
                    return SFTARGET_MATCH;
                }
                else if (!application)
                {
                    /* match of ipproto, proto.
                     * application not speicifed */
                    return SFTARGET_MATCH;
                }
            }
            else if (!protocol)
            {
                /* match of ipproto.
                 * protocol not speicifed */
                return SFTARGET_MATCH;
            }
        }
        /* No ipprotocol specified, huh? */
    }

    return SFTARGET_NOMATCH;
}

int hasProtocol(HostAttributeEntry *host_entry,
               int ipprotocol,
               int protocol,
               int application)
{
    int ret = SFTARGET_NOMATCH;

    ret = hasService(host_entry, ipprotocol, protocol, application);
    if (ret == SFTARGET_MATCH)
        return ret;

    ret = hasClient(host_entry, ipprotocol, protocol, application);
    if (ret == SFTARGET_MATCH)
        return ret;

    return ret;
}

char isFragPolicySet(HostAttributeEntry *host_entry)
{
    if (host_entry && host_entry->hostInfo.fragPolicySet)
    {
        return POLICY_SET;
    }
    return POLICY_NOT_SET;
}

char isStreamPolicySet(HostAttributeEntry *host_entry)
{
    if (host_entry && host_entry->hostInfo.streamPolicySet)
    {
        return POLICY_SET;
    }
    return POLICY_NOT_SET;
}

u_int16_t getFragPolicy(HostAttributeEntry *host_entry)
{
    if (!host_entry)
        return SFAT_UNKNOWN_FRAG_POLICY;

    if (!host_entry->hostInfo.fragPolicySet)
        return SFAT_UNKNOWN_FRAG_POLICY;

    return host_entry->hostInfo.fragPolicy;
}

u_int16_t getStreamPolicy(HostAttributeEntry *host_entry)
{
    if (!host_entry)
        return SFAT_UNKNOWN_STREAM_POLICY;

    if (!host_entry->hostInfo.streamPolicySet)
        return SFAT_UNKNOWN_STREAM_POLICY;

    return host_entry->hostInfo.streamPolicy;
}

int getApplicationProtocolId(HostAttributeEntry *host_entry,
               int ipprotocol,
               u_int16_t port,
               char direction)
{
    ApplicationEntry *application;

    if (!host_entry)
        return 0;

    if (direction == SFAT_SERVICE)
    {
        for (application = host_entry->services; application; application = application->next)
        {
            if (application->ipproto.attributeOrdinal == ipprotocol)
            {
                if ((u_int16_t)application->port.value.l_value == port)
                {
                    return application->protocol.attributeOrdinal;
                }
            }
        }
    }

    /* TODO: client? doesn't make much sense in terms of specific port */

    return 0;
}

