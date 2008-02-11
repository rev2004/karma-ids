/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

/* spo_alert_full
 * 
 * Purpose:  output plugin for full alerting
 *
 * Arguments:  alert file (eventually)
 *   
 * Effect:
 *
 * Alerts are written to a file in the snort full alert format
 *
 * Comments:   Allows use of full alerts with other output plugin types
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event.h"
#include "decode.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "debug.h"
#include "parser.h"
#include "util.h"
#include "log.h"
#include "mstring.h"

#include "ipc_c.h"

#include "snort.h"

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <stdio.h>
#include <stdlib.h>

typedef struct _SpoAlertShmemData
{
    CInterprocessCommunication *ipc;

} SpoAlertShmemData;

void AlertShmemInit(char *);
SpoAlertShmemData *ParseAlertShmemArgs(char *);
void AlertShmem(Packet *, char *, void *, Event *);
void AlertShmemCleanExit(int, void *);
void AlertShmemRestart(int, void *);


/*
 * Function: SetupAlertShmem()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void AlertShmemSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_shmem", NT_OUTPUT_ALERT, AlertShmemInit);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: AlertShmem is setup...\n"););
}


/*
 * Function: AlertShmemInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertShmemInit(char *args)
{
    SpoAlertShmemData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: AlertShmem Initialized\n"););
    
    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    data = ParseAlertShmemArgs(args);
    
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking AlertShmem functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertShmem, NT_OUTPUT_ALERT, data);
    AddFuncToCleanExitList(AlertShmemCleanExit, data);
    AddFuncToRestartList(AlertShmemRestart, data);
}

void AlertShmem(Packet *p, char *msg, void *arg, Event *event)
{
    printf("Alert: %s\n", msg);
    char timestamp[TIMEBUF_SIZE];
    SpoAlertShmemData *data = (SpoAlertShmemData *)arg;
    char evnt[512];
    bzero((char *) evnt, 512);
    char interface[512];
    bzero((char *) interface, 512);
    char temp[1024];
    bzero((char *) temp, 1024);
    if(msg == NULL)
        msg = "[ SNORT ALERT ]";

    bzero((char *) timestamp, TIMEBUF_SIZE);
    ts_print(p == NULL ? NULL : (struct timeval *) & p->pkth->ts, timestamp);

    FILE* tmp = tmpfile();
    if(p && IPH_IS_VALID(p))
    {
        if(pv.show2hdr_flag)
        {
            Print2ndHeader(tmp, p);
        }

        PrintIPHeader(tmp, p);

        /* if this isn't a fragment, print the other header info */
        if(!p->frag_flag)
        {
            switch(GET_IPH_PROTO(p))
            {
                case IPPROTO_TCP:
                    PrintTCPHeader(tmp, p);
                    break;

                case IPPROTO_UDP:
                    PrintUDPHeader(tmp, p);
                    break;

                case IPPROTO_ICMP:
                    PrintICMPHeader(tmp, p);
                    break;

                default:
                    break;
            }

            PrintXrefs(tmp, 1);
        }

    } /* End of if(p) */
    char buffer[1024];
    char dmesg[1024];
    *dmesg = 0;
    fseek (tmp , 0 , SEEK_END);
    long lSize = ftell (tmp);
    rewind (tmp);
    while (fgets(buffer, lSize, tmp)){
      char * end_string = strpbrk(buffer, "\r\n");
      *end_string = 0;
      sprintf(dmesg, "%s %s", dmesg, buffer); 
    } 
    fclose (tmp); 
    sprintf(temp, "SNORT [%s] [%s] %s", timestamp, msg, dmesg);

    InterprocessCommunicationWrite(data->ipc, temp);
    return;
}


/*
 * Function: ParseAlertShmemArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
SpoAlertShmemData *ParseAlertShmemArgs(char *args)
{
    SpoAlertShmemData *data;

    data = (SpoAlertShmemData *)SnortAlloc(sizeof(SpoAlertShmemData));
    FILE* p_key = fopen("key.id","r");
    char buf[1024];
    int count = fread(buf,1,1024,p_key);
    fclose(p_key);
    buf[count]=0;
    int key=atoi(buf); 
    data->ipc = new_ipc(1719,0,0);
    InterprocessCommunicationWrite(data->ipc, "# SNORT CONNECTED");
    return data;
}

void AlertShmemCleanExit(int signal, void *arg)
{
    SpoAlertShmemData *data = (SpoAlertShmemData *)arg;
    InterprocessCommunicationWrite(data->ipc, "# SNORT DISCONNECTED");
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertShmemCleanExit\n"););
    /* free memory from SpoAlertShmemData */
    free(data);
}

void AlertShmemRestart(int signal, void *arg)
{
    SpoAlertShmemData *data = (SpoAlertShmemData *)arg;
    /* free memory from SpoAlertShmemData */
    free(data);
}

