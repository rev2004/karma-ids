/* $Id$ */
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

#ifndef __HI_CLIENT_H__
#define __HI_CLIENT_H__


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#include "hi_include.h"
#include "hi_eo.h"
#include "hi_eo_events.h"

typedef struct s_HI_CLIENT_REQ
{
    /*
    u_char *method;
    int  method_size;
    */

    const u_char *uri;
    const u_char *uri_norm;
    const u_char *post_raw;
    const u_char *post_norm;
    u_int  uri_size;
    u_int uri_norm_size;
    u_int post_raw_size;
    u_int post_norm_size;

    /*
    u_char *param;
    u_int  param_size;
    u_int  param_norm;
    */

    /*
    u_char *ver;
    u_int  ver_size;

    u_char *hdr;
    u_int  hdr_size;

    u_char *payload;
    u_int  payload_size;
    */

    const u_char *pipeline_req;
    u_char method;

}  HI_CLIENT_REQ;

typedef struct s_HI_CLIENT
{
    HI_CLIENT_REQ request;
    int (*state)(void *, unsigned char, int);
    HI_CLIENT_EVENTS event_list;

}  HI_CLIENT;

int hi_client_inspection(void *Session, const unsigned char *data, int dsize);
int hi_client_init(HTTPINSPECT_GLOBAL_CONF *GlobalConf);

#endif 
