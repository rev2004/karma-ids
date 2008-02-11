/****************************************************************************
 *
 * Copyright (C) 2003-2007 Sourcefire, Inc.
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
 
/**
**  @file       hi_client_norm.c
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  
**  @brief      HTTP client normalization routines
**  
**  We deal with the normalization of HTTP client requests headers and 
**  URI.
**  
**  In this file, we handle all the different HTTP request URI evasions.  The
**  list is:
**      - ASCII decoding
**      - UTF-8 decoding
**      - IIS Unicode decoding
**      - Directory traversals (self-referential and traversal)
**      - Multiple Slashes
**      - Double decoding
**      - %U decoding
**      - Bare Byte Unicode decoding
**      - Base36 decoding
**  
**  NOTES:
**      - Initial development.  DJR
*/
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>

#include "hi_norm.h"
#include "hi_return_codes.h"

#define MAX_URI 4096

int hi_client_norm(HI_SESSION *Session)
{
    static u_char UriBuf[MAX_URI];
    static u_char PostBuf[MAX_URI];
    HI_CLIENT_REQ    *ClientReq;
    int iRet;
    int iUriBufSize = MAX_URI;
    int iPostBufSize = MAX_URI;

    if(!Session || !Session->server_conf)
    {
        return HI_INVALID_ARG;
    }

    ClientReq = &Session->client.request;

    /* Handle URI normalization */
    if(ClientReq->uri_norm)
    {
        Session->norm_flags &= ~HI_BODY;
        iRet = hi_norm_uri(Session, UriBuf, &iUriBufSize, 
                           ClientReq->uri, ClientReq->uri_size);
        if (iRet == HI_NONFATAL_ERR)
        {
            /* There was a non-fatal problem normalizing */
            ClientReq->uri_norm = NULL;
            ClientReq->uri_norm_size = 0;
        }
        else 
        {
            /* Client code is expecting these to be set to non-NULL if 
             * normalization occurred. */
            ClientReq->uri_norm      = UriBuf;
            ClientReq->uri_norm_size = iUriBufSize;
        }
    }

    /* Handle normalization of post methods. 
     * Note: posts go into a different buffer. */
    if(ClientReq->post_norm)
    {
        Session->norm_flags |= HI_BODY;
        iRet = hi_norm_uri(Session, PostBuf, &iPostBufSize, 
                           ClientReq->post_raw, ClientReq->post_raw_size);
        if (iRet == HI_NONFATAL_ERR)
        {
            ClientReq->post_norm = NULL;
            ClientReq->post_norm_size = 0;
        }
        else 
        {
            ClientReq->post_norm      = PostBuf;
            ClientReq->post_norm_size = iPostBufSize;
        }
    }

    /*
    printf("** uri_norm = |");
    for(iCtr = 0; iCtr < ClientReq->uri_norm_size; iCtr++)
    {
        if(!isprint((int)ClientReq->uri_norm[iCtr]))
        {
            printf(".[%.2x]", ClientReq->uri_norm[iCtr]);
            continue;
        }
        printf("%c", ClientReq->uri_norm[iCtr]);
    }
    printf("| size = %u\n", ClientReq->uri_norm_size);
    */

    return HI_SUCCESS;
}
