/*
** Copyright (C) 1998-2005 Martin Roesch <roesch@sourcefire.com>
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
/* Snort Preprocessor Plugin Source File Bo */

/* spp_bo 
 * 
 * Purpose: Detects Back Orifice traffic by brute forcing the weak encryption
 *          of the program's network protocol and detects the magic cookie
 *          that it's servers and clients require to communicate with each 
 *          other.
 *
 * Arguments: none
 *   
 * Effect: Analyzes UDP traffic for the BO magic cookie, reports if it finds
 *         traffic matching the profile.
 *
 * Comments:
 *
 */

/*
 * The following text describes a couple of ways in which the Back Orifice
 * signature is calculated.  The snort runtime generated an array of 65K
 * possible signatures, of which two are described here.  Refer back to
 * this simplified algorithm when evaluating the snort code below.
 *
 * Back Orifice magic cookie is "*!*QWTY?", which is located in the first
 * eight bytes of the packet.  But it is encrypted using an XOR.  Here we'll
 * generate a sequence of eight bytes which will decrypt (XOR) into the
 * magic cookie.  This test uses the NON-DEFAULT KEY to initialize (seed) the
 * "random" number generator.  The default seed results in the following
 * sequence of bytes:  E4 42 FB 83 41 B3 4A F0.  When XOR'd against the
 * magic cookie, we have our packet data which looks like a Back Orifice
 * signature:
 *
 *   Cookie:  2A 21 2A 51 57 54 59 3F
 *   Random:  E4 42 FB 83 41 B3 4A F0
 *   -------  -- -- -- -- -- -- -- --
 *   Result:  CE 63 D1 D2 16 E7 13 CF  (XOR'd result)
 * 
 * For demonstration purposes:
 *
 *   static long holdrand = 1L;
 *   static int LocalBoRand()
 *   {
 *       return(((holdrand = holdrand * 214013L + 2531011L) >> 16) & 0x7fff);
 *   }
 *   ...
 *
 *   int BoRandValues_NonDefaultKey[8];
 *   holdrand = BACKORIFICE_DEFAULT_KEY;    (seed value)
 *   BoRandValues_NonDefaultKey[0] = LocalBoRand() % 256;  --> 228 (0xe4)
 *   BoRandValues_NonDefaultKey[1] = LocalBoRand() % 256;  -->  66 (0x42)
 *   BoRandValues_NonDefaultKey[2] = LocalBoRand() % 256;  --> 251 (0xfb)
 *   BoRandValues_NonDefaultKey[3] = LocalBoRand() % 256;  --> 131 (0x83)
 *   BoRandValues_NonDefaultKey[4] = LocalBoRand() % 256;  -->  65 (0x41)
 *   BoRandValues_NonDefaultKey[5] = LocalBoRand() % 256;  --> 179 (0xb3)
 *   BoRandValues_NonDefaultKey[6] = LocalBoRand() % 256;  -->  74 (0x4a)
 *   BoRandValues_NonDefaultKey[7] = LocalBoRand() % 256;  --> 240 (0xf0)
 *
 *
 * The following test uses the DEFAULT KEY to initialize (seed) the
 * "random" number generator.  The default seed results in the following
 * sequence of bytes:  26 27 F6 85 97 15 AD 1D.  When XOR'd against the
 * magic cookie, we have our packet data which looks like a Back Orifice
 * signature:
 *
 *   Cookie:  2A 21 2A 51 57 54 59 3F
 *   Random:  26 27 F6 85 97 15 AD 1D
 *   -------  -- -- -- -- -- -- -- --
 *   Result:  0C 06 DC D4 C0 41 F4 22  (XOR'd result)
 * 
 * For demonstration purposes:
 *
 *   int BoRandValues_DefaultKey[8];
 *   holdrand = 0;    (seed value)
 *   BoRandValues_DefaultKey[0] = LocalBoRand() % 256;  -->  38 (0x26)
 *   BoRandValues_DefaultKey[1] = LocalBoRand() % 256;  -->  39 (0x27)
 *   BoRandValues_DefaultKey[2] = LocalBoRand() % 256;  --> 246 (0xf6)
 *   BoRandValues_DefaultKey[3] = LocalBoRand() % 256;  --> 133 (0x85)
 *   BoRandValues_DefaultKey[4] = LocalBoRand() % 256;  --> 151 (0x97)
 *   BoRandValues_DefaultKey[5] = LocalBoRand() % 256;  -->  21 (0x15)
 *   BoRandValues_DefaultKey[6] = LocalBoRand() % 256;  --> 173 (0xad)
 *   BoRandValues_DefaultKey[7] = LocalBoRand() % 256;  -->  29 (0x1d)
 * 
 * Notes:
 * 
 *   10/13/2005 marc norton - This has a lot of changes  to the runtime 
 *   decoding and testing.  The '% 256' op was removed, 
 *   the xor op is bit wise so modulo is not needed, 
 *   the char casting truncates to one byte,
 *   and len testing has been modified as was the xor decode copy and 
 *   final PONG test.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "generators.h"
#include "log.h"
#include "detect.h"
#include "decode.h"
#include "event.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "mstring.h"
#include "util.h"
#include "event_queue.h"
/* In case we need to drop this packet */
#include "inline.h"

#include "snort.h"

#include "profiler.h"

#define BACKORIFICE_DEFAULT_KEY   31337
#define BACKORIFICE_MAGIC_SIZE    8
#define BACKORIFICE_MIN_SIZE      18
#define BACKORIFICE_DEFAULT_PORT  31337
#define BO_TYPE_PING              1
#define BO_FROM_UNKNOWN           0
#define BO_FROM_CLIENT            1
#define BO_FROM_SERVER            2

#define BO_BUF_SIZE         8
#define BO_BUF_ATTACK_SIZE  1024

/* Configuration defines */
#define START_LIST      "{"
#define END_LIST        "}"
#define CONF_SEPARATORS         " \t\n\r"
#define BO_ALERT_GENERAL        0x0001
#define BO_ALERT_CLIENT         0x0002
#define BO_ALERT_SERVER         0x0004
#define BO_ALERT_SNORT_ATTACK   0x0008


/* list of function prototypes for this preprocessor */
void BoInit(char *);
void BoProcess(Packet *);
void BoFind(Packet *, void *);

/* list of private functions */
static int  BoGetDirection(Packet *p, char *pkt_data);
static void PrecalcPrefix();
static char BoRand();
static void ProcessArgs(char *args);
static int  ProcessOptionList(void);
static void PrintConfig(void);

#define MODNAME "spp_bo"


/* global keyvalue for the BoRand() function */
static long holdrand = 1L;

/* brute forcing is on by default */
int brute_force_enable = 1;
int default_key;

static u_int16_t noalert_flags = 0;
static u_int16_t drop_flags = 0;


u_int16_t lookup1[65536][3];
u_int16_t lookup2[65536];

#ifdef PERF_PROFILING
PreprocStats boPerfStats;
#endif

/*
 * Function: SetupBo()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupBo()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterPreprocessor("bo", BoInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                "Preprocessor: Back Orifice is setup...\n"););
}


/*
 * Function: BoInit(char *)
 *
 * Purpose: Link the BO preprocessor to the preperocessor call chain.
 *
 * Arguments: args => ptr to argument string (spp_bo takes no args)
 *
 * Returns: void function
 *
 */
void BoInit(char *args)
{
    static int bIsInitialized = 0;

    /* BoInit is re-entrant */
    if ( !bIsInitialized )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: Bo Initialized\n"););

        /* we no longer need to take args */
        PrecalcPrefix();

        /* Set the preprocessor function into the function list */
        AddFuncToPreprocList(BoFind, PRIORITY_LAST, PP_BO);

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("backorifice", &boPerfStats, 0, &totalPerfStats);
#endif

        bIsInitialized = 1;
    }

    /* Process argument list */
    ProcessArgs(args);
}


/*
 * Function: ProcessArgs(char *)
 *
 * Purpose: Parse additional config items.
 *
 * Arguments: args => ptr to argument string
 *   syntax:
 *     preprocessor bo: noalert { client | server | general | snort_attack } \
 *                      drop    { client | server | general | snort_attack }
 *
 *   example:
 *     preprocessor bo: noalert { general server } drop { snort_attack }
 *
 * Returns: void function
 *
 */
static void ProcessArgs(char *args)
{
    char *arg;
   
    if ( args == NULL )
        return;

    arg = strtok(args, CONF_SEPARATORS);
    
    while ( arg != NULL )
    {
        if ( !strcasecmp("noalert", arg) )
        {
            noalert_flags = (u_int16_t)ProcessOptionList();
        }
        else if ( !strcasecmp("drop", arg) )
        {
            drop_flags = (u_int16_t)ProcessOptionList();
        }
        else
        {
            FatalError("%s(%d) => Unknown bo option %s.\n", 
                        file_name, file_line, arg);
        }

        arg = strtok(NULL, CONF_SEPARATORS);
    }

    PrintConfig();

    return;
}


/*
 * Function: ProcessOptionList(u_char *)
 *
 * Purpose: Parse config list, either "noalert" or "drop".
 *
 * Arguments: none, use string from strtok in ProcessArgs
 *
 * Returns: AND'ed list of flags based on option list
 *
 */
static int ProcessOptionList(void)
{
    char *arg;
    int   retFlags = 0;
    int   endList = 0;

    arg = strtok(NULL, CONF_SEPARATORS);

    if ( arg == NULL || strcmp(START_LIST, arg) )
    {
        FatalError("%s(%d) => Invalid bo option.\n", file_name, file_line);        
        //return 0;
    }
    
    while ((arg = strtok(NULL, CONF_SEPARATORS)) != NULL)
    {
        if ( !strcmp(END_LIST, arg) )
        {
            endList = 1;
            break;
        }

        if ( !strcasecmp("general", arg) )
        {
            retFlags |= BO_ALERT_GENERAL;
        }
        else if ( !strcasecmp("client", arg) )
        {
            retFlags |= BO_ALERT_CLIENT;
        }
        else if ( !strcasecmp("server", arg) )
        {
            retFlags |= BO_ALERT_SERVER;
        }
        else if ( !strcasecmp("snort_attack", arg) )
        {
            retFlags |= BO_ALERT_SNORT_ATTACK;
        }
        else
        {
            FatalError("%s(%d) => Invalid bo option argument %s.\n", 
                        file_name, file_line, arg);        
        }
    }

    if ( !endList )
    {
        FatalError("%s(%d) => Must end configuration list with %s.\n", 
                   file_name, file_line, END_LIST);      
        //return 0;
    }

    return retFlags;
}

/*
 * Function: PrintConfig(u_char *)
 *
 * Purpose: Print configuration
 *
 * Arguments: none
 *
 * Returns: none
 *
 */
static void PrintConfig(void)
{
    if ( noalert_flags != 0 || drop_flags != 0 )
        LogMessage("Back Orifice Config:\n");
    
    if ( noalert_flags != 0 )
    {
        LogMessage("    Disable alerts:");
        if ( noalert_flags & BO_ALERT_CLIENT )
            LogMessage(" client");
        if ( noalert_flags & BO_ALERT_SERVER )
            LogMessage(" server");
        if ( noalert_flags & BO_ALERT_GENERAL )
            LogMessage(" general");
        if ( noalert_flags & BO_ALERT_SNORT_ATTACK )
            LogMessage(" snort_attack");
        LogMessage("\n");
    }
    if ( drop_flags != 0 )
    {
        LogMessage("    Drop packets (inline only) on alerts:");
        if ( drop_flags & BO_ALERT_CLIENT )
            LogMessage(" client");
        if ( drop_flags & BO_ALERT_SERVER )
            LogMessage(" server");
        if ( drop_flags & BO_ALERT_GENERAL )
            LogMessage(" general");
        if ( drop_flags & BO_ALERT_SNORT_ATTACK )
            LogMessage(" snort_attack");
        LogMessage("\n");
    }
}

/*
 * Function: BoRand()
 *
 * Purpose: Back Orifice "encryption" algorithm
 *
 * Arguments: None.
 *
 * Returns: key to XOR with current char to be "encrypted"
 */
static char BoRand()
{
    holdrand = holdrand * 214013L + 2531011L;
    return (char) (((holdrand  >> 16) & 0x7fff) & 0xFF);
}


/*
 * Precalculate the known cyphertext into a prefix and suffix lookup table 
 * to recover the key.  Using this in the BoFind() function below is much
 * faster than the old brute force method
 */
static void PrecalcPrefix()
{
    u_int8_t cookie_cyphertext[BACKORIFICE_MAGIC_SIZE];
    char *cookie_plaintext = "*!*QWTY?";
    int key;
    int cookie_index;
    char *cp_ptr;       /* cookie plaintext indexing pointer */
    u_int16_t cyphertext_referent;

    memset(&lookup1[0], 0, sizeof(lookup1));
    memset(&lookup2[0], 0, sizeof(lookup2));
    
    for(key=0;key<65536;key++)
    {
        /* setup to generate cyphertext for this key */
        holdrand = key;
        cp_ptr = cookie_plaintext;

        /* convert the plaintext cookie to cyphertext for this key */
        for(cookie_index=0;cookie_index<BACKORIFICE_MAGIC_SIZE;cookie_index++)
        {
            cookie_cyphertext[cookie_index] =(u_int8_t)(*cp_ptr^(BoRand()));
            cp_ptr++;
        }

        /* 
         * generate the key lookup mechanism from the first 2 characters of
         * the cyphertext
         */
        cyphertext_referent = (u_int16_t) (cookie_cyphertext[0] << 8) & 0xFF00;
        cyphertext_referent |= (u_int16_t) (cookie_cyphertext[1]) & 0x00FF;

        /* if there are any keyspace collisions that's going to suck */
        if(lookup1[cyphertext_referent][0] != 0)
        {
            if(lookup1[cyphertext_referent][1] != 0)
            {
                lookup1[cyphertext_referent][2] = (u_int16_t)key;
            }
            else
            {
                lookup1[cyphertext_referent][1] = (u_int16_t)key;
            }
        }
        else
        {
            lookup1[cyphertext_referent][0] = (u_int16_t)key;
        }

        /* 
         * generate the second lookup from the last two characters of 
         * the cyphertext
         */
        cyphertext_referent = (u_int16_t) (cookie_cyphertext[6] << 8) & 0xFF00;
        cyphertext_referent |= (u_int16_t) (cookie_cyphertext[7]) & 0x00FF;

        /*
         * set the second lookup with the current key
         */
        lookup2[key] = cyphertext_referent;
    }
}


/*
 * Function: BoFind(Packet *)
 *
 * Purpose: Look for the magic cookie, squawk if you find it.
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 *
 */
void BoFind(Packet *p, void *context)
{
    u_int16_t cyphertext_referent;
    u_int16_t cyphertext_suffix;
    u_int16_t key;
    char *magic_cookie = "*!*QWTY?";
    char *pkt_data;
    char *magic_data;
    char *end;
    char plaintext;
    int i;
    int bo_direction = 0;
    PROFILE_VARS;

    /* make sure it's UDP and that it's at least 19 bytes long */
    if(!PacketIsUDP(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                    "   -> spp_bo: Not UDP\n"););
        return;
    }

    if(p->dsize < BACKORIFICE_MIN_SIZE)
    {
        return;
    }

    PREPROC_PROFILE_START(boPerfStats);

    /*
     * take the first two characters of the packet and generate the 
     * first reference that gives us a reference key
     */
    cyphertext_referent = (u_int16_t) (p->data[0] << 8) & 0xFF00;
    cyphertext_referent |= (u_int16_t) (p->data[1]) & 0x00FF;

    /* 
     * generate the second referent from the last two characters
     * of the cyphertext
     */
    cyphertext_suffix = (u_int16_t) (p->data[6] << 8) & 0xFF00;
    cyphertext_suffix |= (u_int16_t) (p->data[7]) & 0x00FF;

    for(i=0;i<3;i++)
    {
        /* get the key from the cyphertext */
        key = lookup1[cyphertext_referent][i];

        /* 
         * if the lookup from the proposed key matches the cyphertext reference
         * then we've probably go the right key and can proceed to full 
         * decryption using the key
         *
         * moral of the story: don't use a lame keyspace 
         */
        if(lookup2[key] == cyphertext_suffix)
        {
            holdrand = key;
            pkt_data = (char*)p->data;
            end = (char*)p->data + BACKORIFICE_MAGIC_SIZE;
            magic_data = magic_cookie;

            while(pkt_data<end)
            {
                plaintext = (char) (*pkt_data ^ BoRand());

                if(*magic_data != plaintext)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                            "Failed check one on 0x%X : 0x%X\n", 
                            *magic_data, plaintext););
                    PREPROC_PROFILE_END(boPerfStats);
                    return;
                }

                magic_data++;
                pkt_data++;
            }
            
            /* if we fall thru there's a detect */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                        "Detected Back Orifice Data!\n");
            DebugMessage(DEBUG_PLUGIN, "hash value: %d\n", key););

            bo_direction = BoGetDirection(p, pkt_data);

            if ( bo_direction == BO_FROM_CLIENT )
            {
                if ( !(noalert_flags & BO_ALERT_CLIENT) )
                {
                    SnortEventqAdd(GENERATOR_SPP_BO, BO_CLIENT_TRAFFIC_DETECT, 1, 0, 0,
                                            BO_CLIENT_TRAFFIC_DETECT_STR, 0);
                }
                if ( (drop_flags & BO_ALERT_CLIENT) && InlineMode() )
                {
                    InlineDrop(p);
                }
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Client packet\n"););
            }
            else if ( bo_direction == BO_FROM_SERVER )
            {
                if ( !(noalert_flags & BO_ALERT_SERVER) )
                {
                    SnortEventqAdd(GENERATOR_SPP_BO, BO_SERVER_TRAFFIC_DETECT, 1, 0, 0,
                                            BO_SERVER_TRAFFIC_DETECT_STR, 0);
                }
                if ( (drop_flags & BO_ALERT_SERVER) && InlineMode() )
                {
                    InlineDrop(p);
                }
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Server packet\n"););
            }
            else
            {
                if ( !(noalert_flags & BO_ALERT_GENERAL) )
                {
                    SnortEventqAdd(GENERATOR_SPP_BO, BO_TRAFFIC_DETECT, 1, 0, 0,
                                            BO_TRAFFIC_DETECT_STR, 0);
                }
                if ( (drop_flags & BO_ALERT_GENERAL) && InlineMode() )
                {
                    InlineDrop(p);
                }
            }           
        }
    }

    PREPROC_PROFILE_END(boPerfStats);

    return;
}


/*
 * Function: BoGetDirection(Packet *)
 *
 * Purpose: Attempt to guess the direction this packet is going in.
 *
 * Arguments: p        => pointer to the current packet data struct
 *            pkt_data => pointer to data after magic cookie
 *
 * Returns: BO_FROM_UNKNOWN  if direction unknown
 *          BO_FROM_CLIENT   if direction from client to server
 *          BO_FROM_SERVER   if direction from server to client
 *
 * Reference: http://www.magnux.org/~flaviovs/boproto.html
 *    BO header structure:
 *      Mnemonic    Size in bytes
 *      -------------------------
 *      MAGIC       8
 *      LEN         4
 *      ID          4
 *      T           1
 *      DATA        variable
 *      CRC         1
 *
 */
static int BoGetDirection(Packet *p, char *pkt_data)
{
    u_int32_t len = 0;
    u_int32_t id = 0;
    u_int32_t l, i;
    char type;
    static char buf1[BO_BUF_SIZE];
    char plaintext;

    /* Check for the default port on either side */
    if ( p->dp == BACKORIFICE_DEFAULT_PORT )
    {
        return BO_FROM_CLIENT;
    }
    else if ( p->sp == BACKORIFICE_DEFAULT_PORT )
    {
        return BO_FROM_SERVER;
    }
    
    /* Didn't find default port, so look for ping packet */  
    
    /* Get length from BO header - 32 bit int */
    for ( i = 0; i < 4; i++ )
    {
        plaintext = (char) (*pkt_data ^ BoRand());
        l = (u_int32_t) plaintext;
        len += l << (8*i);
        pkt_data++;
    }

    /* Get ID from BO header - 32 bit int */
    for ( i = 0; i < 4; i++ )
    {
        plaintext = (char) (*pkt_data ^ BoRand() );
        l = ((u_int32_t) plaintext) & 0x000000FF;
        id += l << (8*i);
        pkt_data++;
    }
    
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Data length = %lu\n", len););
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "ID = %lu\n", id););

    /* Do more len checking */
    
    if ( len >= BO_BUF_ATTACK_SIZE )
    {
        if ( !(noalert_flags & BO_ALERT_SNORT_ATTACK) )
        {
            SnortEventqAdd(GENERATOR_SPP_BO, BO_SNORT_BUFFER_ATTACK, 1, 0, 0,
                                            BO_SNORT_BUFFER_ATTACK_STR, 0);
        }
        if ( (drop_flags & BO_ALERT_SNORT_ATTACK) && InlineMode() )
        {
            InlineDrop(p);
        }

        return BO_FROM_UNKNOWN;
    }

    /* Adjust for BO packet header length */
    if (len <= BACKORIFICE_MIN_SIZE)
    {
        /* Need some data, or we can't figure out client or server */
        return BO_FROM_UNKNOWN; 
    }
    else
    {
        len -= BACKORIFICE_MIN_SIZE;
    }

    if( len > 7 )
    {
        len = 7; /* we need no more than  7 variable chars */
    }

    /* Continue parsing BO header */
    type = (char) (*pkt_data ^ BoRand());
    pkt_data++;

    /* check to make sure we don't run off end of packet */
    if ((u_int32_t)(p->dsize - ((u_int8_t *)pkt_data - p->data)) < len)
    {
        /* We don't have enough data to inspect */
        return BO_FROM_UNKNOWN;
    }
    
    if ( type & 0x80 )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Partial packet\n"););
    }
    if ( type & 0x40 )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Continued packet\n"););
    }

    /* Extract type of BO packet */
    type = type & 0x3F;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Type = 0x%x\n", type););

    /* Only examine data if this is a ping request or response */
    if ( type == BO_TYPE_PING )
    {
        if ( len < 7 )
        {
            return BO_FROM_CLIENT;
        }

        for(i=0;i<len;i++ ) /* start at 0 to advance the BoRand() function properly */
        {
            buf1[i] = (char) (pkt_data[i] ^ BoRand());
            if ( buf1[i] == 0 )
            {
                return BO_FROM_UNKNOWN; 
            }
        }

        if( ( buf1[3] == 'P' || buf1[3] == 'p' ) &&
            ( buf1[4] == 'O' || buf1[4] == 'o' ) && 
            ( buf1[5] == 'N' || buf1[5] == 'n' ) && 
            ( buf1[6] == 'G' || buf1[6] == 'g' ) )
        {
            return BO_FROM_SERVER;
        }
        else
        {
            return BO_FROM_CLIENT;
        }
    } 
   
    return BO_FROM_UNKNOWN;
}
