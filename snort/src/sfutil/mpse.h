/*
** $Id$
**
**  mpse.h       
**
** Copyright (C) 2002 Sourcefire,Inc
** Marc Norton <mnorton@sourcefire.com>
**
** Multi-Pattern Search Engine
**
**  Supports:
**
**    Modified Wu-Manber mwm.c/.h
**    Aho-Corasick - Deterministic Finite Automatum   
**    Keyword Trie with Boyer Moore Bad Character Shifts
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
** GNU Gener*
**
**
** Updates:
**
** man - 7/25/2002 - modified #defines for WIN32, and added uint64
**
*/

#ifndef _MPSE_H
#define _MPSE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "bitop.h"

/*
*   Move these defines to a generic Win32/Unix compatability file, 
*   there must be one somewhere...
*/
#ifndef CDECL 
#define CDECL 
#endif


/*
*  Pattern Matching Methods 
*/
//#define MPSE_MWM      1
#define MPSE_AC       2
//#define MPSE_KTBM     3
#define MPSE_LOWMEM   4    
//#define MPSE_AUTO     5
#define MPSE_ACF      6 
#define MPSE_ACS      7 
#define MPSE_ACB      8 
#define MPSE_ACSB     9 
#define MPSE_AC_BNFA   10 

#define MPSE_INCREMENT_GLOBAL_CNT 1
#define MPSE_DONT_INCREMENT_GLOBAL_COUNT 0

/*
** PROTOTYPES
*/
void * mpseNew( int method, int use_global_counter_flag );
void   mpseFree( void * pv );

int  mpseAddPattern  ( void * pv, void * P, int m, 
     unsigned noCase,unsigned offset, unsigned depth,  void* ID, int IID );

void mpseLargeShifts   ( void * pvoid, int flag );

int  mpsePrepPatterns  ( void * pv );

void mpseSetRuleMask   ( void *pv, BITOP * rm );

int  mpseSearch( void *pv, const unsigned char * T, int n, 
     int ( *action )(void* id, int index, void *data), 
     void * data, int* current_state ); 

UINT64 mpseGetPatByteCount(void);
void   mpseResetByteCount(void);

int mpsePrintInfo( void * obj );
int mpsePrintSummary(void );
  
void   mpseVerbose( void * pvoid );

#endif

