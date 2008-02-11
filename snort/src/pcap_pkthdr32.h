#ifndef __PCAP_PKTHDR32_H__
#define __PCAP_PKTHDR32_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/time.h>
#endif

#include <stdlib.h>
#include <time.h>
#include <sys/types.h>


/* we must use fixed size of 32 bits, because on-disk
 * format of savefiles uses 32-bit tv_sec (and tv_usec)
 */
struct timeval32
{
    u_int32_t tv_sec;      /* seconds */
    u_int32_t tv_usec;     /* microseconds */
};

/* this is equivalent to the pcap pkthdr struct, but we need
 * a 32 bit one for unified output
 */
struct pcap_pkthdr32
{
    struct timeval32 ts;   /* packet timestamp */
    u_int32_t caplen;      /* packet capture length */
    u_int32_t pktlen;      /* packet "real" length */
};


#endif // __PCAP_PKTHDR32_H__

