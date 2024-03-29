/*
**  $Id$
**
**  perf.c
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker <droelker@sourcefire.com>
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
**
**
**  DESCRIPTION
**    These are the basic functions that are needed to call performance
**    functions.
**
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#ifndef WIN32
#include <time.h>
#include <unistd.h>
#endif /* WIN32 */

#include "util.h"
#include "perf.h"

int InitPerfStats(SFPERF *sfPerf);
int UpdatePerfStats(SFPERF *sfPerf, const unsigned char *pucPacket, int len,
        int iRebuiltPkt);
int ProcessPerfStats(SFPERF *sfPerf);


int sfInitPerformanceStatistics(SFPERF *sfPerf)
{
    memset(sfPerf, 0x00, sizeof(SFPERF));
    sfSetPerformanceSampleTime(sfPerf, 0);
    sfSetPerformanceStatistics(sfPerf, 0);

    return 0;
}

int sfSetPerformanceSampleTime(SFPERF *sfPerf, int iSeconds)
{
    sfPerf->sample_time = 0;
    
    if(iSeconds < 0)
    {
        iSeconds = 0;
    }

    sfPerf->sample_interval = iSeconds;

    return 0;
}


int sfSetPerformanceAccounting(SFPERF *sfPerf, int iReset)
{
    sfPerf->sfBase.iReset = iReset;
    
    return 0;
}


int sfSetPerformanceStatistics(SFPERF *sfPerf, int iFlag)
{
    if(iFlag & SFPERF_BASE)
    {
        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_BASE;
    }

#ifndef LINUX_SMP

    if(iFlag & SFPERF_BASE_MAX)
    {
        sfPerf->sfBase.iFlags |= MAX_PERF_STATS;
    }

#endif

    if(iFlag & SFPERF_FLOW)
    {
        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_FLOW;
    }
    if(iFlag & SFPERF_EVENT)
    {
        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_EVENT;
    }
    if(iFlag & SFPERF_CONSOLE)
    {
        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_CONSOLE;
    }
    
    return 0;
}

int sfSetPerformanceStatisticsEx(SFPERF *sfPerf, int iFlag, void * p)
{
#ifndef WIN32    
    mode_t old_umask;
#endif 
    
    if(iFlag & SFPERF_FILE)
    {
        static char start_up = 1;

        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_FILE;
        
        SnortStrncpy(sfPerf->file, (char *)p, sizeof(sfPerf->file));

        /* this file needs to be readable by everyone */
#ifndef WIN32
        old_umask = umask(022);
#endif         

        /* append to existing perfmon file if just starting up */
        if (start_up)
        {
            sfPerf->fh = fopen(sfPerf->file, "a");
            start_up = 0;
        }
        /* otherwise we've rotated - start a new one */
        else
        {
            sfPerf->fh = fopen(sfPerf->file, "w");
        }

#ifndef WIN32
        umask(old_umask);
#endif
        
        if( !sfPerf->fh )
            return -1;
    }
    else if(iFlag & SFPERF_FILECLOSE)
    {
        if (sfPerf->fh)
        {
            fclose(sfPerf->fh);
            sfPerf->fh = NULL;
        }
    }
    else if(iFlag & SFPERF_PKTCNT)
    {
        sfPerf->iPktCnt = *(int*)p;
    }
    else if (iFlag & SFPERF_SUMMARY)
    {
        sfPerf->iPerfFlags |= SFPERF_SUMMARY;
    }
    return 0;
}


#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#ifndef FILE_MAX
#define FILE_MAX  (PATH_MAX + 256)
#endif

int sfRotatePerformanceStatisticsFile(SFPERF *sfPerf)
{
    int        ret;
    time_t     t;
    struct tm *tm;
    char       newfile[FILE_MAX];
    char      *ptr;
    int        prefix_len = 0;
#ifdef WIN32
    struct _stat stat_buf;
#else
    struct stat stat_buf;
#endif

    /* Close current stats file - if it is open already */
    if(!sfPerf->fh)
    {
        LogMessage("Performance log file '%s' not open",
                        sfPerf->file);

        return(1);
    }
    
    ret = fclose(sfPerf->fh);
    
    if ( ret != 0 )
    {
        FatalError("Cannot close performance log file '%s': %s\n",
                                    sfPerf->file, strerror(errno));
    }
    
    /* Rename current stats file with yesterday's date */
#ifndef WIN32
    ptr = strrchr(sfPerf->file, '/');
#else
    ptr = strrchr(sfPerf->file, '\\');
#endif

    if (ptr != NULL)
    {
        /* take length of string up to path separator and add 
         * one to include path separator */
        prefix_len = (ptr - &sfPerf->file[0]) + 1;
    }

    /* Get current time, then subtract one day to get yesterday */
    t = time(&t);
    t -= (24*60*60);
    tm = localtime(&t);
    SnortSnprintf(newfile, FILE_MAX, "%.*s%d-%02d-%02d",
                  prefix_len, sfPerf->file, tm->tm_year + 1900,
                  tm->tm_mon + 1, tm->tm_mday);

    /* Checking return code from rename */
#ifdef WIN32
    if (_stat(newfile, &stat_buf) == -1)
#else
    if (stat(newfile, &stat_buf) == -1)
#endif
    {
        /* newfile doesn't exist - just rename sfPerf->file to newfile */
        if(rename(sfPerf->file, newfile) != 0)
        {
            LogMessage("Cannot move performance log file '%s' to '%s': %s\n",
                       sfPerf->file, newfile,strerror(errno));
        }
    }
    else
    {
        /* append to current archive file */
        FILE *newfh, *curfh;
        char read_buf[1024];
        size_t num_read, num_wrote;

        do
        {
            newfh = fopen(newfile, "a");
            if (newfh == NULL)
            {
                LogMessage("Cannot open performance log archive file "
                           "'%s' for writing: %s\n",
                           newfile, strerror(errno));
                break;
            }

            curfh = fopen(sfPerf->file, "r");
            if (curfh == NULL)
            {
                LogMessage("Cannot open performance log file '%s' for reading: %s\n",
                           sfPerf->file, strerror(errno));
                fclose(newfh);
                break;
            }

            while (!feof(curfh))
            {
                num_read = fread(read_buf, sizeof(char), sizeof(read_buf), curfh);
                if (num_read < sizeof(read_buf))
                {
                    if (ferror(curfh))
                    {
                        /* a read error occurred */
                        LogMessage("Error reading performance log file '%s': %s\n",
                                   sfPerf->file, strerror(errno));
                        break;
                    }
                }

                if (num_read > 0)
                {
                    num_wrote = fwrite((const char *)read_buf, sizeof(char), num_read, newfh);
                    if (num_wrote != num_read)
                    {
                        if (ferror(newfh))
                        {
                            /* a bad write occurred */
                            LogMessage("Error writing to performance log "
                                       "archive file '%s': %s\n",
                                       newfile, strerror(errno));
                            break;
                        }
                    }
                }
            }

            fclose(newfh);
            fclose(curfh);

        } while (0);
    }

    ret = sfSetPerformanceStatisticsEx(sfPerf, SFPERF_FILE, sfPerf->file);

    if( ret != 0 )
    {
        FatalError("Cannot open performance log file '%s': %s\n",
                                    sfPerf->file, strerror(errno));
    }

    return 0;
}

int sfPerformanceStats(SFPERF *sfPerf, const unsigned char *pucPacket, int len,
                       int iRebuiltPkt)
{
    static unsigned int cnt=0;

    if (( cnt==0 || cnt >= sfPerf->iPktCnt ) &&
        !(sfPerf->iPerfFlags & SFPERF_SUMMARY))
    {
       cnt=1;
       CheckSampleInterval(time(NULL), sfPerf);
    }

    cnt++;

    UpdatePerfStats(sfPerf, pucPacket, len, iRebuiltPkt);

    return 0;
}

int CheckSampleInterval(time_t curr_time, SFPERF *sfPerf)
{
    time_t prev_time = sfPerf->sample_time;

    /*
    *  This is for when sfBasePerformance is
    *  starting up.
    */
    if(prev_time == 0)
    {
        InitPerfStats(sfPerf);
    }
    else if((curr_time - prev_time) >= sfPerf->sample_interval)
    {
        ProcessPerfStats(sfPerf);
        InitPerfStats(sfPerf);
    }

    return 0;
}

int InitPerfStats(SFPERF *sfPerf)
{
    static int first = 1;
    /*
    *  Reset sample time for next sampling
    */
    sfPerf->sample_time = time(NULL);

    if(sfPerf->iPerfFlags & SFPERF_BASE)
    {  
        if(InitBaseStats(&(sfPerf->sfBase)))
            return -1;
    }
    if(sfPerf->iPerfFlags & SFPERF_FLOW)
    {  
        if(first) InitFlowStats(&(sfPerf->sfFlow));
        first = 0;
    }
    if(sfPerf->iPerfFlags & SFPERF_EVENT)
    {  
        InitEventStats(&(sfPerf->sfEvent));
    }

    return 0;
}

int UpdatePerfStats(SFPERF *sfPerf, const unsigned char *pucPacket, int len,
                    int iRebuiltPkt)
{
    if(sfPerf->iPerfFlags & SFPERF_BASE)
    {
        UpdateBaseStats(&(sfPerf->sfBase), len, iRebuiltPkt);
    }
    if(sfPerf->iPerfFlags & SFPERF_FLOW)
    {
        UpdateFlowStats(&(sfPerf->sfFlow), pucPacket, len, iRebuiltPkt);
    }

    return 0;
}

int sfProcessPerfStats(SFPERF *sfPerf)
{
    return ProcessPerfStats(sfPerf);
}

int ProcessPerfStats(SFPERF *sfPerf)
{
    if(sfPerf->iPerfFlags & SFPERF_BASE)
    {
        /* Allow this to go out to console and/or a file */
        ProcessBaseStats(&(sfPerf->sfBase),
                sfPerf->iPerfFlags & SFPERF_CONSOLE,
                sfPerf->iPerfFlags & SFPERF_FILE,
                sfPerf->fh );
    }
    
    /* Always goes to the console */
    if(sfPerf->iPerfFlags & SFPERF_FLOW)
    {
        if( sfPerf->iPerfFlags & SFPERF_CONSOLE )
            ProcessFlowStats(&(sfPerf->sfFlow));
    }
   
    if(sfPerf->iPerfFlags & SFPERF_EVENT)
    {
        if( sfPerf->iPerfFlags & SFPERF_CONSOLE )
            ProcessEventStats(&(sfPerf->sfEvent));
    }

    return 0;
}
    
