/* $Id$ */
/*
** Copyright (C) 2002 Sourcefire, Inc.
** Author(s):   Andrew R. Baker <andrewb@sourcefire.com>
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
#ifndef __SIGNATURE_H__
#define __SIGNATURE_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef OSF1
#include <sys/bitypes.h>
#endif

#include <sys/types.h>
#include <stdio.h>

/* Enable Port Lists */
#define PORTLISTS

struct _OptTreeNode;

/* this contains a list of the URLs for various reference systems */
typedef struct _ReferenceSystemNode
{
    char *name;
    char *url;
    struct _ReferenceSystemNode *next;
} ReferenceSystemNode;

extern ReferenceSystemNode *referenceSytems;
ReferenceSystemNode *ReferenceSystemAdd(char *name, char *id);
ReferenceSystemNode *ReferenceSystemLookup(char *name);
void ParseReferenceSystemConfig(char *args);
    


/* XXX: update to point to the ReferenceURLNode in the referenceURL list */
typedef struct _ReferenceNode
{
    char *id;
    ReferenceSystemNode *system;
    struct _ReferenceNode *next;
} ReferenceNode;

ReferenceNode *AddReference(ReferenceNode *, char *system, char *id);
void FPrintReference(FILE *, ReferenceNode *);
void ParseReference(char *args, struct _OptTreeNode *otn);

/* struct for rule classification */
typedef struct _ClassType
{
    char *type;      /* classification type */
    int id;          /* classification id */
    char *name;      /* "pretty" classification name */
    int priority;    /* priority */
    struct _ClassType *next;
} ClassType;

void ParseClassificationConfig(char *args);
void ParsePriority(char *priority, struct _OptTreeNode *otn);
void ParseClassType(char *classtype, struct _OptTreeNode *otn);
ClassType *ClassTypeLookupByType(char *type);
ClassType *ClassTypeLookupById(int id);

void ParseSID(char *sid, struct _OptTreeNode *otn);
void ParseRev(char *sid, struct _OptTreeNode *otn);


/*
 *  sid-gid -> otn mapping
 */
typedef struct {
   u_int32_t generator;
   u_int32_t id;
}sg_otn_key_t;

#define SI_RULE_FLUSHING_OFF 0
#define SI_RULE_FLUSHING_ON  1

#define SI_RULE_TYPE_DETECT  0
#define SI_RULE_TYPE_DECODE  1
#define SI_RULE_TYPE_PREPROC 2

typedef struct _SigInfo
{
    u_int32_t generator;
    u_int32_t id;
    u_int32_t rev;
    u_int32_t class_id;
    ClassType *classType;
    u_int32_t priority;
    char      *message;
    ReferenceNode *refs;
    int           shared; /* shared object rule */
    int           rule_type; /* 0-std rule, 1-decoder, rule, 3 preprocessor rule */
    int           rule_flushing; /* 0-disabled, 1-enabled */
    sg_otn_key_t otnKey;
#ifdef TARGET_BASED
#ifdef PORTLISTS 
   char          *service;
   int16_t       service_ordinal;
   char          *os;
#endif
#endif
} SigInfo;

int    soid_otn_lookup_init();
void   soid_otn_lookup_add( struct _OptTreeNode * );
void   otn_remove( struct _OptTreeNode *);
struct _OptTreeNode * soid_sg_otn_lookup( u_int32_t gid, u_int32_t sid );
struct _OptTreeNode * soid_sg_otn_lookup_next( u_int32_t gid, u_int32_t sid );

int    otn_lookup_init();
void   otn_lookup_add( struct _OptTreeNode * );
struct _OptTreeNode * otn_lookup( u_int32_t gid, u_int32_t sid );

#endif /* SIGNATURE */
