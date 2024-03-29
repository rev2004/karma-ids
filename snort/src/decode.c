/* $Id$ */

/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "decode.h"
#include "snort.h"
#include "debug.h"
#include "util.h"
#include "detect.h"
#include "checksum.h"
#include "log.h"
#include "generators.h"
#include "event_queue.h"
#include "inline.h"
#include "sfxhash.h"
#include "bounds.h"
#include "strlcpyu.h"
#include "sf_iph.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats decodePerfStats;
#endif

/* No great place to put this right now */
HttpUri UriBufs[URI_COUNT];
u_int8_t DecodeBuffer[DECODE_BLEN];
Packet *BsdPseudoPacket;

#ifdef SUP_IP6
IPH_API ip4 = 
    {
       ip4_ret_src,
       ip4_ret_dst,
       ip4_ret_tos,
       ip4_ret_ttl,
       ip4_ret_len,
       ip4_ret_id,
       ip4_ret_proto,
       ip4_ret_off,
       ip4_ret_ver,
       ip4_ret_hlen,

       orig_ip4_ret_src,
       orig_ip4_ret_dst,
       orig_ip4_ret_tos,
       orig_ip4_ret_ttl,
       orig_ip4_ret_len,
       orig_ip4_ret_id,
       orig_ip4_ret_proto,
       orig_ip4_ret_off,
       orig_ip4_ret_ver,
       orig_ip4_ret_hlen,
    };

IPH_API ip6 =
    {
       ip6_ret_src,
       ip6_ret_dst,
       ip6_ret_toc,
       ip6_ret_hops,
       ip6_ret_len,
       ip6_ret_id,
       ip6_ret_next,
       ip6_ret_off,
       ip6_ret_ver,
       ip6_ret_hlen,

       orig_ip6_ret_src,
       orig_ip6_ret_dst,
       orig_ip6_ret_toc,
       orig_ip6_ret_hops,
       orig_ip6_ret_len,
       orig_ip6_ret_id,
       orig_ip6_ret_next,
       orig_ip6_ret_off,
       orig_ip6_ret_ver,
       orig_ip6_ret_hlen,
    };
#endif

/* For the BSD fragmentation vulnerability */
SFXHASH *ipv6_frag_hash;


/*
 * Function: DecodeEthPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeEthPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */
    PROFILE_VARS;
        
    PREPROC_PROFILE_START(decodePerfStats);
    pc.eth++;
    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(pv.readmode_flag && (pkt_len < cap_len))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet capture length is "
            "greater than the packet's total length.  Broken PCAP?\n");); 
        p->iph = NULL;
        pc.discards++;
        pc.ethdisc++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }
    
    if(snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len);
            );

    /* do a little validation */
    if(cap_len < ETHERNET_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Captured data length < Ethernet header length!"
                         " (%d bytes)\n", p->pkth->caplen);
        }
        
        p->iph = NULL;
        pc.discards++;
        pc.ethdisc++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the ethernet structure over the packet data */
    p->eh = (EtherHdr *) pkt;

    DEBUG_WRAP(
            DebugMessage(DEBUG_DECODE, "%X   %X\n", 
                *p->eh->ether_src, *p->eh->ether_dst);
            );

    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_PPPoE_DISC:
        case ETHERNET_TYPE_PPPoE_SESS:
            DecodePPPoEPkt(p, pkthdr, pkt);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, 
                        "IP datagram size calculated to be %lu bytes\n",
                        (unsigned long)(cap_len - ETHERNET_HEADER_LEN));
                    );

            DecodeIP(p->pkt + ETHERNET_HEADER_LEN, 
                    cap_len - ETHERNET_HEADER_LEN, p);

            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(p->pkt + ETHERNET_HEADER_LEN, 
                    cap_len - ETHERNET_HEADER_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(p->pkt + ETHERNET_HEADER_LEN, 
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_IPX:
            DecodeIPX(p->pkt + ETHERNET_HEADER_LEN, 
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(p->pkt + ETHERNET_HEADER_LEN, 
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return; 

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + ETHERNET_HEADER_LEN, 
                    cap_len - ETHERNET_HEADER_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return; 

        default:
            pc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}


/*
 * Function: DecodeIEEE80211Pkt(Packet *, char *, struct pcap_pkthdr*, 
 *                               u_int8_t*)
 *
 * Purpose: Decode those fun loving wireless LAN packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeIEEE80211Pkt(Packet * p, const struct pcap_pkthdr * pkthdr, 
                        const u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */
    PROFILE_VARS;
        
    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(p->pkth->caplen < MINIMAL_IEEE80211_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Captured data length < IEEE 802.11 header length! (%d bytes)\n", p->pkth->caplen);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }
    /* lay the wireless structure over the packet data */
    p->wifih = (WifiHdr *) pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%X   %X\n", *p->wifih->addr1, 
                *p->wifih->addr2););

    /* determine frame type */
    switch(p->wifih->frame_control & 0x00ff)
    {
        /* management frames */
        case WLAN_TYPE_MGMT_ASREQ:
        case WLAN_TYPE_MGMT_ASRES:
        case WLAN_TYPE_MGMT_REREQ:
        case WLAN_TYPE_MGMT_RERES:
        case WLAN_TYPE_MGMT_PRREQ:
        case WLAN_TYPE_MGMT_PRRES:
        case WLAN_TYPE_MGMT_BEACON:
        case WLAN_TYPE_MGMT_ATIM:
        case WLAN_TYPE_MGMT_DIS:
        case WLAN_TYPE_MGMT_AUTH:
        case WLAN_TYPE_MGMT_DEAUTH:
            pc.wifi_mgmt++;
            break;

            /* Control frames */
        case WLAN_TYPE_CONT_PS:
        case WLAN_TYPE_CONT_RTS:
        case WLAN_TYPE_CONT_CTS:
        case WLAN_TYPE_CONT_ACK:
        case WLAN_TYPE_CONT_CFE:
        case WLAN_TYPE_CONT_CFACK:
            pc.wifi_control++;
            break;
            /* Data packets without data */
        case WLAN_TYPE_DATA_NULL:
        case WLAN_TYPE_DATA_CFACK:
        case WLAN_TYPE_DATA_CFPL:
        case WLAN_TYPE_DATA_ACKPL:

            pc.wifi_data++;
            break;
        case WLAN_TYPE_DATA_DTCFACK:
        case WLAN_TYPE_DATA_DTCFPL:
        case WLAN_TYPE_DATA_DTACKPL:
        case WLAN_TYPE_DATA_DATA:
            pc.wifi_data++;

            if(cap_len < IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc))
            {
                if(pv.verbose_flag)
                {
                    ErrorMessage("Not enough data for EthLlc header\n");
                }
                
                if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
                {
                    SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                            DECODE_BAD_80211_ETHLLC, 1, DECODE_CLASS, 3, 
                            DECODE_BAD_80211_ETHLLC_STR, 0);

                    if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                    {
                       DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                       InlineDrop(p);
                    }
                }
                
                PREPROC_PROFILE_END(decodePerfStats);
                return;
            }

            p->ehllc = (EthLlc *) (pkt + IEEE802_11_DATA_HDR_LEN);

#ifdef DEBUG
            PrintNetData(stdout,(u_int8_t *)  p->ehllc, sizeof(EthLlc));
            //ClearDumpBuf();

            printf("LLC Header:\n");
            printf("   DSAP: 0x%X\n", p->ehllc->dsap);
            printf("   SSAP: 0x%X\n", p->ehllc->ssap);
#endif

            if(p->ehllc->dsap == ETH_DSAP_IP && p->ehllc->ssap == ETH_SSAP_IP)
            {
                if(cap_len < IEEE802_11_DATA_HDR_LEN +
                   sizeof(EthLlc) + sizeof(EthLlcOther))
                {
                    if(pv.verbose_flag)
                    {
                        ErrorMessage("Not enough data for EthLlcOther header\n");
                    }

                    if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
                    {
                        SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                                DECODE_BAD_80211_ETHLLC, 1, DECODE_CLASS, 3, 
                                DECODE_BAD_80211_ETHLLC_STR, 0);
                        if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                        {
                           DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n");); 
                           InlineDrop(p);
                        }
                    }
                    
                    PREPROC_PROFILE_END(decodePerfStats);
                    return;
                }

                p->ehllcother = (EthLlcOther *) (pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc));
#ifdef DEBUG
                PrintNetData(stdout,(u_int8_t *) p->ehllcother, sizeof(EthLlcOther));
                //ClearDumpBuf();
                printf("LLC Other Header:\n");
                printf("   CTRL: 0x%X\n", p->ehllcother->ctrl);
                printf("   ORG: 0x%02X%02X%02X\n", p->ehllcother->org_code[0], 
                        p->ehllcother->org_code[1], p->ehllcother->org_code[2]);
                printf("   PROTO: 0x%04X\n", ntohs(p->ehllcother->proto_id));
#endif

                switch(ntohs(p->ehllcother->proto_id))
                {
                    case ETHERNET_TYPE_IP:
                        DecodeIP(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                                sizeof(EthLlcOther), 
                                pkt_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) - 
                                sizeof(EthLlcOther), p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;

                    case ETHERNET_TYPE_ARP:
                    case ETHERNET_TYPE_REVARP:
                        DecodeARP(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                                sizeof(EthLlcOther), 
                                pkt_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                                sizeof(EthLlcOther), p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;
                    case ETHERNET_TYPE_EAPOL:
                        DecodeEapol(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                                sizeof(EthLlcOther),
                                pkt_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                                sizeof(EthLlcOther), p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;
                    case ETHERNET_TYPE_8021Q:
                        DecodeVlan(p->pkt + IEEE802_11_DATA_HDR_LEN , 
                                   cap_len - IEEE802_11_DATA_HDR_LEN , p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return; 
                        
                    case ETHERNET_TYPE_IPV6:
                        DecodeIPV6(p->pkt + IEEE802_11_DATA_HDR_LEN, 
                                cap_len - IEEE802_11_DATA_HDR_LEN, p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;

                    default:
                        pc.other++;
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;
                }
            }
            break;
        default:
            pc.other++;
            break;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}


void DecodeVlan(const u_int8_t * pkt, const u_int32_t len, Packet * p)
{

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_vlan++;
    else
        pc.vlan++;
#else
    pc.vlan++;
#endif

    if(len < sizeof(VlanTagHdr))
    {
        if(pv.verbose_flag)
            ErrorMessage("Not enough data to process a vlan header\n");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_BAD_VLAN, 1, 
                    DECODE_CLASS, 3, DECODE_BAD_VLAN_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n");); 
               InlineDrop(p);
            }
 
        }
        
        pc.discards++;
        p->iph = NULL;
        return;
    }

    p->vh = (VlanTagHdr *) pkt;
    
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Vlan traffic:\n");
               DebugMessage(DEBUG_DECODE, "   Priority: %d(0x%X)\n", 
                            VTH_PRIORITY(p->vh), VTH_PRIORITY(p->vh));
               DebugMessage(DEBUG_DECODE, "   CFI: %d\n", VTH_CFI(p->vh));
               DebugMessage(DEBUG_DECODE, "   Vlan ID: %d(0x%04X)\n", 
                            VTH_VLAN(p->vh), VTH_VLAN(p->vh));
               DebugMessage(DEBUG_DECODE, "   Vlan Proto: 0x%04X\n", 
                            ntohs(p->vh->vth_proto));
               );

    /* check to see if we've got an encapsulated LLC layer
     * http://www.geocities.com/billalexander/ethernet.html
     */
    if(ntohs(p->vh->vth_proto) <= ETHERNET_MAX_LEN_ENCAP)
    {
        if(len < sizeof(VlanTagHdr) + sizeof(EthLlc))
        {
            if(pv.verbose_flag)
            {
                ErrorMessage("Not enough data for EthLlc header");
            }

            if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
            {
                SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_BAD_VLAN_ETHLLC,
                      1, DECODE_CLASS, 3, DECODE_BAD_VLAN_ETHLLC_STR, 0);
                 if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                 {
                    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                    InlineDrop(p);
                 }
            }

            pc.discards++;
            p->iph = NULL;
            return;            
        }
        
        p->ehllc = (EthLlc *) (pkt + sizeof(VlanTagHdr));

        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, "LLC Header:\n");
                DebugMessage(DEBUG_DECODE, "   DSAP: 0x%X\n", p->ehllc->dsap);
                DebugMessage(DEBUG_DECODE, "   SSAP: 0x%X\n", p->ehllc->ssap);
                );

        if(p->ehllc->dsap == ETH_DSAP_IP && p->ehllc->ssap == ETH_SSAP_IP)
        {
            if(len < sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther))
            {
                if(pv.verbose_flag)
                {
                    ErrorMessage("Not enough data for VLAN header");
                }

                if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
                {
                    SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                            DECODE_BAD_VLAN_OTHER, 1, DECODE_CLASS, 3, 
                            DECODE_BAD_VLAN_OTHER_STR, 0);
                    if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                    {
                      DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                      InlineDrop(p);
                    }

                }
                
                pc.discards++;
                p->iph = NULL;
                return;            
            }

            p->ehllcother = (EthLlcOther *) (pkt + sizeof(VlanTagHdr) + sizeof(EthLlc));

            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, "LLC Other Header:\n");
                    DebugMessage(DEBUG_DECODE, "   CTRL: 0x%X\n", 
                        p->ehllcother->ctrl);
                    DebugMessage(DEBUG_DECODE, "   ORG: 0x%02X%02X%02X\n", 
                        p->ehllcother->org_code[0], p->ehllcother->org_code[1], 
                        p->ehllcother->org_code[2]);
                    DebugMessage(DEBUG_DECODE, "   PROTO: 0x%04X\n", 
                        ntohs(p->ehllcother->proto_id));
                    );

            switch(ntohs(p->ehllcother->proto_id))
            {
                case ETHERNET_TYPE_IP:
                    DecodeIP(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther),
                        len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther), p);
                    return;

                case ETHERNET_TYPE_ARP:
                case ETHERNET_TYPE_REVARP:
                    DecodeARP(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther),
                        len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther), p);
                    return;

                case ETHERNET_TYPE_IPV6:
                    DecodeIPV6(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + 
                            sizeof(EthLlcOther), 
                            len - sizeof(VlanTagHdr) - sizeof(EthLlc) - 
                            sizeof(EthLlcOther), p);
                    return;

                default:
                    pc.other++;
                    return;
            }
        }
    }
    else
    {
        switch(ntohs(p->vh->vth_proto))
        {
            case ETHERNET_TYPE_IP:
                DecodeIP(pkt + sizeof(VlanTagHdr), 
                        len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_ARP:
            case ETHERNET_TYPE_REVARP:
                DecodeARP(pkt + sizeof(VlanTagHdr), 
                        len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_IPV6:
                DecodeIPV6(pkt +sizeof(VlanTagHdr), 
                        len - sizeof(VlanTagHdr), p);
                return;

            default:
                pc.other++;
                return;
        }
    }

    pc.other++;
    return;
}

#ifdef GIDS
#ifndef IPFW
/*
 * Function: DecodeIptablesPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decoding iptables.
 * 
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 * 
 */
void DecodeIptablesPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t len;
    u_int32_t cap_len;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.iptables++;
    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));
    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    DecodeIP(p->pkt, cap_len, p);

    PREPROC_PROFILE_END(decodePerfStats);
}
#else
/*
 * Function: DecodeIpfwPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decoding ipfw divert socket
 * 
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 * 
 */
void DecodeIpfwPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t len;
    u_int32_t cap_len;
    PROFILE_VARS;
        
    PREPROC_PROFILE_START(decodePerfStats);

    pc.ipfw++;
    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));
    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    DecodeIP(p->pkt, cap_len, p);

    PREPROC_PROFILE_END(decodePerfStats);
}
#endif
#endif /* GIDS */


/*
 * Function: DecodeNullPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decoding on loopback devices.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeNullPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t len;
    u_int32_t cap_len;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"); );

    /* do a little validation */
    if(cap_len < NULL_HDRLEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("NULL header length < captured len! (%d bytes)\n",
                    cap_len);
        }

        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    DecodeIP(p->pkt + NULL_HDRLEN, cap_len - NULL_HDRLEN, p);
    PREPROC_PROFILE_END(decodePerfStats);
}

/*
 * Function: DecodeTRPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode Token Ring packets!
 *
 * Arguments: p=> pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeTRPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */
    u_int32_t dataoff;      /* data offset is variable here */
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;


    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len,(unsigned long) pkt_len);
            );

    if(cap_len < sizeof(Trh_hdr))
    {
        if(pv.verbose_flag)
            ErrorMessage("Captured data length < Token Ring header length! "
                         "(%d < %d bytes)\n", p->pkth->caplen, TR_HLEN);

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_BAD_TRH, 1, 
                    DECODE_CLASS, 3, DECODE_BAD_TRH_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
               InlineDrop(p);
            }

        }

        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the tokenring header structure over the packet data */
    p->trh = (Trh_hdr *) pkt;

    /*
     * according to rfc 1042:
     *
     *   The presence of a Routing Information Field is indicated by the Most
     *   Significant Bit (MSB) of the source address, called the Routing
     *   Information Indicator (RII).  If the RII equals zero, a RIF is
     *   not present.  If the RII equals 1, the RIF is present.
     *   ..
     *   However the MSB is already zeroed by this moment, so there's no
     *   real way to figure out whether RIF is presented in packet, so we are
     *   doing some tricks to find IPARP signature..
     */

    /*
     * first I assume that we have single-ring network with no RIF
     * information presented in frame
     */
    if(cap_len < (sizeof(Trh_hdr) + sizeof(Trh_llc)))
    {
        if(pv.verbose_flag)
            ErrorMessage("Captured data length < Token Ring header length! "
                         "(%d < %d bytes)\n", cap_len,
                         (sizeof(Trh_hdr) + sizeof(Trh_llc)));
        
        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_BAD_TR_ETHLLC, 1, 
                    DECODE_CLASS, 3, DECODE_BAD_TR_ETHLLC_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
              DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
              InlineDrop(p);
            }

        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    
    p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr));

    if(p->trhllc->dsap != IPARP_SAP && p->trhllc->ssap != IPARP_SAP)
    {
        /*
         * DSAP != SSAP != 0xAA .. either we are having frame which doesn't
         * carry IP datagrams or has RIF information present. We assume
         * lattest ...
         */

        if(cap_len < (sizeof(Trh_hdr) + sizeof(Trh_llc) + sizeof(Trh_mr)))
        {
            if(pv.verbose_flag)
                ErrorMessage("Captured data length < Token Ring header length! "
                             "(%d < %d bytes)\n", cap_len,
                             (sizeof(Trh_hdr) + sizeof(Trh_llc) + sizeof(Trh_mr)));
            
            if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
            {
                SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_BAD_TRHMR, 1, 
                        DECODE_CLASS, 3, DECODE_BAD_TRHMR_STR, 0);
                if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                {
                   DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                   InlineDrop(p);
                }

            }
            
            PREPROC_PROFILE_END(decodePerfStats);
            return;
        }
        
        p->trhmr = (Trh_mr *) (pkt + sizeof(Trh_hdr));

        
        if(cap_len < (sizeof(Trh_hdr) + sizeof(Trh_llc) +
                      sizeof(Trh_mr) + TRH_MR_LEN(p->trhmr)))
        {
            if(pv.verbose_flag)
                ErrorMessage("Captured data length < Token Ring header length! "
                             "(%d < %d bytes)\n", cap_len,
                             (sizeof(Trh_hdr) + sizeof(Trh_llc) + sizeof(Trh_mr)));

            
            if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
            {
                SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_BAD_TR_MR_LEN, 1, 
                        DECODE_CLASS, 3, DECODE_BAD_TR_MR_LEN_STR, 0);
                if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                {
                   DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                   InlineDrop(p);
                }
 
            }
            
            PREPROC_PROFILE_END(decodePerfStats);
            return;
        }
        
        p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr) + TRH_MR_LEN(p->trhmr));
        dataoff   = sizeof(Trh_hdr) + TRH_MR_LEN(p->trhmr) + sizeof(Trh_llc);

    }
    else
    {
        p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr));
        dataoff = sizeof(Trh_hdr) + sizeof(Trh_llc);
    }

    /*
     * ideally we would need to check both SSAP, DSAP, and protoid fields: IP
     * datagrams and ARP requests and replies are transmitted in standard
     * 802.2 LLC Type 1 Unnumbered Information format, control code 3, with
     * the DSAP and the SSAP fields of the 802.2 header set to 170, the
     * assigned global SAP value for SNAP [6].  The 24-bit Organization Code
     * in the SNAP is zero, and the remaining 16 bits are the EtherType from
     * Assigned Numbers [7] (IP = 2048, ARP = 2054). .. but we would check
     * SSAP and DSAP and assume this would be enough to trust.
     */
    if(p->trhllc->dsap != IPARP_SAP && p->trhllc->ssap != IPARP_SAP)
    {
        DEBUG_WRAP(
                   DebugMessage(DEBUG_DECODE, "DSAP and SSAP arent set to SNAP\n");
                );
        p->trhllc = NULL;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    switch(htons(p->trhllc->ethertype))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding IP\n"););
            DecodeIP(p->pkt + dataoff, cap_len - dataoff, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, "Decoding ARP\n");
                    );
            pc.arp++;

            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + dataoff, cap_len - dataoff, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return; 

        default:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown network protocol: %d\n", 
                        htons(p->trhllc->ethertype)));
            pc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}


/*
 * Function: DecodeFDDIPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Mainly taken from CyberPsycotic's Token Ring Code -worm5er
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeFDDIPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* length of the packet */
    u_int32_t cap_len;      /* capture length variable */
    u_int32_t dataoff = sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps);
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    pkt_len = pkthdr->len;
    cap_len = pkthdr->caplen;

    if(snaplen < pkt_len)
    {
        pkt_len = cap_len;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long) cap_len,(unsigned long) pkt_len);
            );

    /* Bounds checking (might not be right yet -worm5er) */
    if(p->pkth->caplen < dataoff)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Captured data length < FDDI header length! "
                         "(%d %d bytes)\n", p->pkth->caplen, dataoff);
            PREPROC_PROFILE_END(decodePerfStats);
            return;
        }
    }
    /* let's put this in as the fddi header structure */
    p->fddihdr = (Fddi_hdr *) pkt;

    p->fddisaps = (Fddi_llc_saps *) (pkt + sizeof(Fddi_hdr));

    /* First we'll check and see if it's an IP/ARP Packet... */
    /* Then we check to see if it's a SNA packet */
    /*
     * Lastly we'll declare it none of the above and just slap something
     * generic on it to discard it with (I know that sucks, but heck we're
     * only looking for IP/ARP type packets currently...  -worm5er
     */
    if((p->fddisaps->dsap == FDDI_DSAP_IP) && (p->fddisaps->ssap == FDDI_SSAP_IP))
    {
        dataoff += sizeof(Fddi_llc_iparp);
        
        if(p->pkth->caplen < dataoff)
        {
            if(pv.verbose_flag)
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", p->pkth->caplen, dataoff);
                PREPROC_PROFILE_END(decodePerfStats);
                return;
            }
        }
            
        p->fddiiparp = (Fddi_llc_iparp *) (pkt + sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps));
    }
    else if((p->fddisaps->dsap == FDDI_DSAP_SNA) &&
            (p->fddisaps->ssap == FDDI_SSAP_SNA))
    {
        dataoff += sizeof(Fddi_llc_sna);

        if(p->pkth->caplen < dataoff)
        {
            if(pv.verbose_flag)
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", p->pkth->caplen, dataoff);
                PREPROC_PROFILE_END(decodePerfStats);
                return;
            }
        }
        
        p->fddisna = (Fddi_llc_sna *) (pkt + sizeof(Fddi_hdr) +
                                       sizeof(Fddi_llc_saps));
    }
    else
    {
        dataoff += sizeof(Fddi_llc_other);
        p->fddiother = (Fddi_llc_other *) (pkt + sizeof(Fddi_hdr) +
                sizeof(Fddi_llc_other));

        if(p->pkth->caplen < dataoff)
        {
            if(pv.verbose_flag)
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", p->pkth->caplen, dataoff);
                PREPROC_PROFILE_END(decodePerfStats);
                return;
            }
        }
    }

    /*
     * Now let's see if we actually care about the packet... If we don't,
     * throw it out!!!
     */
    if((p->fddisaps->dsap != FDDI_DSAP_IP) && 
            (p->fddisaps->ssap != FDDI_SSAP_IP))
    {
        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, 
                    "This FDDI Packet isn't an IP/ARP packet...\n");
                );
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    pkt_len -= dataoff;
    cap_len -= dataoff;

    switch(htons(p->fddiiparp->ethertype))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding IP\n"););
            DecodeIP(p->pkt + dataoff, cap_len, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding ARP\n"););
            pc.arp++;

            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + dataoff, cap_len, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return; 


        default:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown network protocol: %d\n",
                        htons(p->fddiiparp->ethertype));
                    );
            pc.other++;

            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Function: DecodeLinuxSLLPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode those fun loving LinuxSLL (linux cooked sockets) 
 *          packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
 
#ifdef DLT_LINUX_SLL 

void DecodeLinuxSLLPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* the length of the packet */
    u_int32_t cap_len;      /* caplen value */
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(p->pkth->caplen < SLL_HDR_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Captured data length < SLL header length (your "
                         "libpcap is broken?)! (%d bytes)\n", p->pkth->caplen);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }
    /* lay the ethernet structure over the packet data */
    p->sllh = (SLLHdr *) pkt;

    /* grab out the network type */
    switch(ntohs(p->sllh->sll_protocol))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                        "IP datagram size calculated to be %lu bytes\n",
                        (unsigned long)(cap_len - SLL_HDR_LEN)););

            DecodeIP(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(p->pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_IPX:
            DecodeIPX(p->pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case LINUX_SLL_P_802_3:
            DEBUG_WRAP(DebugMessage(DEBUG_DATALINK,
                        "Linux SLL P 802.3 is not supported.\n"););
            pc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case LINUX_SLL_P_802_2:
            DEBUG_WRAP(DebugMessage(DEBUG_DATALINK,
                        "Linux SLL P 802.2 is not supported.\n"););
            pc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return; 

        default:
            /* shouldn't go here unless pcap library changes again */
            /* should be a DECODE generated alert */
            DEBUG_WRAP(DebugMessage(DEBUG_DATALINK,"(Unknown) %X is not supported. "
                        "(need tcpdump snapshots to test. Please contact us)\n",
                        p->sllh->sll_protocol););
            pc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

#endif /* DLT_LINUX_SLL */

/*
 * Function: DecodeOldPflog(Packet *, struct pcap_pkthdr *, u_int8_t *)
 *
 * Purpose: Pass old pflog format device packets off to IP or IP6 -fleck
 *
 * Arguments: p => pointer to the decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodeOldPflog(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(p->pkth->caplen < OLDPFLOG_HDRLEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Captured data length < Pflog header length! "
                    "(%d bytes)\n", p->pkth->caplen);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the pf header structure over the packet data */
    p->opfh = (OldPflogHdr *) pkt;

    /*  get the network type - should only be AF_INET or AF_INET6 */
    switch(ntohl(p->opfh->af))
    {
        case AF_INET:   /* IPv4 */
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP datagram size calculated to be %lu "
                        "bytes\n", (unsigned long)(cap_len - OLDPFLOG_HDRLEN)););

            DecodeIP(p->pkt + OLDPFLOG_HDRLEN, cap_len - OLDPFLOG_HDRLEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

#if defined(AF_INET) || defined(SUP_IP6)
        case AF_INET6:  /* IPv6 */
            DecodeIPV6(p->pkt + OLDPFLOG_HDRLEN, (cap_len - OLDPFLOG_HDRLEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;
#endif

        default:
            /* To my knowledge, pflog devices can only 
             * pass IP and IP6 packets. -fleck 
             */
            pc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Function: DecodePflog(Packet *, struct pcap_pkthdr *, u_int8_t *)
 *
 * Purpose: Pass pflog device packets off to IP or IP6 -fleck
 *
 * Arguments: p => pointer to the decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodePflog(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(p->pkth->caplen < PFLOG_HDRLEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Captured data length < Pflog header length! "
                    "(%d bytes)\n", p->pkth->caplen);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the pf header structure over the packet data */
    p->pfh = (PflogHdr *) pkt;

    /*  get the network type - should only be AF_INET or AF_INET6 */
    /* p->pfh->af is sa_family_t which is a u_int8_t */
    switch(p->pfh->af)
    {
        case AF_INET:   /* IPv4 */
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP datagram size calculated to be %lu "
                        "bytes\n", (unsigned long)(cap_len - PFLOG_HDRLEN)););

            DecodeIP(p->pkt + PFLOG_HDRLEN, cap_len - PFLOG_HDRLEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

#if defined(AF_INET6) || defined(SUP_IP6)
        case AF_INET6:  /* IPv6 */
            DecodeIPV6(p->pkt + PFLOG_HDRLEN, (cap_len - PFLOG_HDRLEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;
#endif

        default:
            /* To my knowledge, pflog devices can only 
             * pass IP and IP6 packets. -fleck 
             */
            pc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}


/*
 * Function: DecodePPPoEPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 * see http://www.faqs.org/rfcs/rfc2516.html
 *
 */
void DecodePPPoEPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */
    const PPPoEHdr *ppppoep=NULL;
    //PPPoE_Tag *ppppoe_tag=0;
    //PPPoE_Tag tag;  /* needed to avoid alignment problems */

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(cap_len < PPPOE_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Captured data length < Ethernet header length! "
                         "(%d bytes)\n", p->pkth->caplen);
        }
        
        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_BAD_PPPOE, 1, 
                    DECODE_CLASS, 3, DECODE_BAD_PPPOE_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
              DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
              InlineDrop(p);
            }

        }
        
        return;
    }

    /* XXX - MFR
     * This code breaks the decode model that Snort uses, we should 
     * reimplement it properly ASAP
     */
    /*
     * Not sure how long ago the above comment was added, but
     * it is now fixed.  It may or may not fall under the 'ASAP'
     * category.
     */

    /* lay the ethernet structure over the packet data */
    /* Don't need to do this.  It is already done in the decoding
     * of the ethernet header, which then calls this function for
     * PPP over Ethernet.
    p->eh = (EtherHdr *) pkt;
     */

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%X   %X\n", 
                *p->eh->ether_src, *p->eh->ether_dst););

    /* lay the PPP over ethernet structure over the packet data */
    ppppoep = p->pppoeh = (PPPoEHdr *)pkt;

    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_PPPoE_DISC:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Discovery) "););
            break;

        case ETHERNET_TYPE_PPPoE_SESS:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Session) "););
            break;

        default:
            return;
    }

#ifdef DEBUG
    switch(ppppoep->code)
    {
        case PPPoE_CODE_PADI:
            /* The Host sends the PADI packet with the DESTINATION_ADDR set 
             * to the broadcast address.  The CODE field is set to 0x09 and
             * the SESSION_ID MUST be set to 0x0000.
             *
             * The PADI packet MUST contain exactly one TAG of TAG_TYPE 
             * Service-Name, indicating the service the Host is requesting, 
             * and any number of other TAG types.  An entire PADI packet 
             * (including the PPPoE header) MUST NOT exceed 1484 octets so 
             * as to leave sufficient room for a relay agent to add a 
             * Relay-Session-Id TAG.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery Initiation (PADI)\n");
            break;

        case PPPoE_CODE_PADO:
            /* When the Access Concentrator receives a PADI that it can 
             * serve, it replies by sending a PADO packet.  The 
             * DESTINATION_ADDR is the unicast address of the Host that 
             * sent the PADI.  The CODE field is set to 0x07 and the 
             * SESSION_ID MUST be set to 0x0000.  
             * 
             * The PADO packet MUST contain one AC-Name TAG containing the 
             * Access Concentrator's name, a Service-Name TAG identical to 
             * the one in the PADI, and any number of other Service-Name 
             * TAGs indicating other services that the Access Concentrator 
             * offers.  If the Access Concentrator can not serve the PADI 
             * it MUST NOT respond with a PADO.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery Offer (PADO)\n");
            break;

        case PPPoE_CODE_PADR:
            /* Since the PADI was broadcast, the Host may receive more than 
             * one PADO.  The Host looks through the PADO packets it receives 
             * and chooses one.  The choice can be based on the AC-Name or 
             * the Services offered.  The Host then sends one PADR packet 
             * to the Access Concentrator that it has chosen.  The 
             * DESTINATION_ADDR field is set to the unicast Ethernet address 
             * of the Access Concentrator that sent the PADO.  The CODE 
             * field is set to 0x19 and the SESSION_ID MUST be set to 0x0000.
             *
             * The PADR packet MUST contain exactly one TAG of TAG_TYPE 
             * Service-Name, indicating the service the Host is requesting, 
             * and any number of other TAG types.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery Request (PADR)\n");
            break;

        case PPPoE_CODE_PADS:
            /* When the Access Concentrator receives a PADR packet, it 
             * prepares to begin a PPP session.  It generates a unique 
             * SESSION_ID for the PPPoE session and replies to the Host with 
             * a PADS packet.  The DESTINATION_ADDR field is the unicast 
             * Ethernet address of the Host that sent the PADR.  The CODE 
             * field is set to 0x65 and the SESSION_ID MUST be set to the 
             * unique value generated for this PPPoE session.
             *
             * The PADS packet contains exactly one TAG of TAG_TYPE 
             * Service-Name, indicating the service under which Access 
             * Concentrator has accepted the PPPoE session, and any number 
             * of other TAG types.
             *
             * If the Access Concentrator does not like the Service-Name in 
             * the PADR, then it MUST reply with a PADS containing a TAG of 
             * TAG_TYPE Service-Name-Error (and any number of other TAG 
             * types).  In this case the SESSION_ID MUST be set to 0x0000.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery "
                         "Session-confirmation (PADS)\n");
            break;

        case PPPoE_CODE_PADT:
            /* This packet may be sent anytime after a session is established 
             * to indicate that a PPPoE session has been terminated.  It may 
             * be sent by either the Host or the Access Concentrator.  The 
             * DESTINATION_ADDR field is a unicast Ethernet address, the 
             * CODE field is set to 0xa7 and the SESSION_ID MUST be set to 
             * indicate which session is to be terminated.  No TAGs are 
             * required.  
             *
             * When a PADT is received, no further PPP traffic is allowed to 
             * be sent using that session.  Even normal PPP termination 
             * packets MUST NOT be sent after sending or receiving a PADT.  
             * A PPP peer SHOULD use the PPP protocol itself to bring down a 
             * PPPoE session, but the PADT MAY be used when PPP can not be 
             * used.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery Terminate (PADT)\n");
            break;

        case PPPoE_CODE_SESS: 
            DebugMessage(DEBUG_DECODE, "Session Packet (SESS)\n");
            break;

        default:
            DebugMessage(DEBUG_DECODE, "(Unknown)\n");
            break;
    }
#endif

    if (ntohs(p->eh->ether_type) != ETHERNET_TYPE_PPPoE_DISC)
    {
        DecodePppPktEncapsulated(p, cap_len - PPPOE_HEADER_LEN, pkt + PPPOE_HEADER_LEN);
        return;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Returning early on PPPOE discovery packet\n"););
        return;
    }

#if 0 
    ppppoe_tag = (PPPoE_Tag *)(pkt + sizeof(PPPoEHdr));

    while (ppppoe_tag < (PPPoE_Tag *)(pkt + pkthdr->caplen))
    {
        if (((char*)(ppppoe_tag)+(sizeof(PPPoE_Tag)-1)) > (char*)(pkt + pkthdr->caplen))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Not enough data in packet for PPPOE Tag\n"););
            break;
        }

        /* no guarantee in PPPoE spec that ppppoe_tag is aligned at all... */
        memcpy(&tag, ppppoe_tag, sizeof(tag));

        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, "\tPPPoE tag:\ntype: %04x length: %04x ", 
                    ntohs(tag.type), ntohs(tag.length)););

#ifdef DEBUG
        switch(ntohs(tag.type))
        {
            case PPPoE_TAG_END_OF_LIST:
                DebugMessage(DEBUG_DECODE, "(End of list)\n\t");
                break;
            case PPPoE_TAG_SERVICE_NAME:
                DebugMessage(DEBUG_DECODE, "(Service name)\n\t");
                break;
            case PPPoE_TAG_AC_NAME:
                DebugMessage(DEBUG_DECODE, "(AC Name)\n\t");
                break;
            case PPPoE_TAG_HOST_UNIQ:
                DebugMessage(DEBUG_DECODE, "(Host Uniq)\n\t");
                break;
            case PPPoE_TAG_AC_COOKIE:
                DebugMessage(DEBUG_DECODE, "(AC Cookie)\n\t");
                break;
            case PPPoE_TAG_VENDOR_SPECIFIC:
                DebugMessage(DEBUG_DECODE, "(Vendor Specific)\n\t");
                break;
            case PPPoE_TAG_RELAY_SESSION_ID:
                DebugMessage(DEBUG_DECODE, "(Relay Session ID)\n\t");
                break;
            case PPPoE_TAG_SERVICE_NAME_ERROR:
                DebugMessage(DEBUG_DECODE, "(Service Name Error)\n\t");
                break;
            case PPPoE_TAG_AC_SYSTEM_ERROR:
                DebugMessage(DEBUG_DECODE, "(AC System Error)\n\t");
                break;
            case PPPoE_TAG_GENERIC_ERROR:
                DebugMessage(DEBUG_DECODE, "(Generic Error)\n\t");
                break;
            default:
                DebugMessage(DEBUG_DECODE, "(Unknown)\n\t");
                break;
        }
#endif

        if (ntohs(tag.length) > 0)
        {
#ifdef DEBUG
            char *buf;
            int i;

            switch (ntohs(tag.type))
            {
                case PPPoE_TAG_SERVICE_NAME:
                case PPPoE_TAG_AC_NAME:
                case PPPoE_TAG_SERVICE_NAME_ERROR:
                case PPPoE_TAG_AC_SYSTEM_ERROR:
                case PPPoE_TAG_GENERIC_ERROR: * ascii data *
                    buf = (char *)SnortAlloc(ntohs(tag.length) + 1);
                    strlcpy(buf, (char *)(ppppoe_tag+1), ntohs(tag.length));
                    DebugMessage(DEBUG_DECODE, "data (UTF-8): %s\n", buf);
                    free(buf);
                    break;

                case PPPoE_TAG_HOST_UNIQ:
                case PPPoE_TAG_AC_COOKIE:
                case PPPoE_TAG_RELAY_SESSION_ID:
                    DebugMessage(DEBUG_DECODE, "data (bin): ");
                    for (i = 0; i < ntohs(tag.length); i++)
                        DebugMessage(DEBUG_DECODE,
                                "%02x", *(((unsigned char *)ppppoe_tag) + 
                                    sizeof(PPPoE_Tag) + i));
                    DebugMessage(DEBUG_DECODE, "\n");
                    break;

                default:
                    DebugMessage(DEBUG_DECODE, "unrecognized data\n");
                    break;
            }
#endif
        }

        ppppoe_tag = (PPPoE_Tag *)((char *)(ppppoe_tag+1)+ntohs(tag.length));
    }

#endif   /* #if 0 */

    return;
}


/*
 * Function: DecodePppPktEncapsulated(Packet *, const u_int32_t len, u_int8_t*)
 *
 * Purpose: Decode PPP traffic (RFC1661 framing).
 *
 * Arguments: p => pointer to decoded packet struct 
 *            len => length of data to process
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppPktEncapsulated(Packet * p, const u_int32_t len, const u_int8_t * pkt)
{
    static int had_vj = 0;
    u_int16_t protocol;
    u_int32_t hlen = 1; /* HEADER - try 1 then 2 */    
    
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    /* do a little validation:
     * 
     */
    if(len < 2)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Length not big enough for even a single "
                         "header or a one byte payload\n");
        }
        return;
    }

    
    if(pkt[0] & 0x01)
    {
        /* Check for protocol compression rfc1661 section 5
         *
         */
        hlen = 1;
        protocol = pkt[0];
    }
    else
    {
        protocol = ntohs(*((u_int16_t *)pkt));
        hlen = 2;
    }
    
    /* 
     * We only handle uncompressed packets. Handling VJ compression would mean
     * to implement a PPP state machine.
     */
    switch (protocol) 
    {
        case PPP_VJ_COMP:
            if (!had_vj)
                ErrorMessage("PPP link seems to use VJ compression, "
                        "cannot handle compressed packets!\n");
            had_vj = 1;
            break;
        case PPP_VJ_UCOMP:
            /* VJ compression modifies the protocol field. It must be set
             * to tcp (only TCP packets can be VJ compressed) */
            if(len < (hlen + IP_HEADER_LEN))
            {
                if(pv.verbose_flag)
                    ErrorMessage("PPP VJ min packet length > captured len! "
                                 "(%d bytes)\n", len);
                return;
            }

            ((IPHdr *)(pkt + hlen))->ip_proto = IPPROTO_TCP;
            /* fall through */

        case PPP_IP:
            DecodeIP(pkt + hlen, len - hlen, p);
            break;

        case PPP_IPX:
            DecodeIPX(pkt + hlen, len - hlen, p);
            break;
    }
}


/*
 * Function: DecodePppPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode PPP traffic (either RFC1661 or RFC1662 framing).
 *          This really is intended to handle IPCP
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    int hlen = 0;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if(p->pkth->caplen < 2)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Length not big enough for even a single "
                         "header or a one byte payload\n");
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    if(pkt[0] == CHDLC_ADDR_BROADCAST && pkt[1] == CHDLC_CTRL_UNNUMBERED)
    {
        /*
         * Check for full HDLC header (rfc1662 section 3.2)
         */
        hlen = 2;
    }

    DecodePppPktEncapsulated(p, p->pkth->caplen - hlen, p->pkt + hlen);

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}


/*
 * Function: DecodePppSerialPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode Mixed PPP/CHDLC traffic. The PPP frames will always have the
 *          full HDLC header.
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppSerialPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if(p->pkth->caplen < PPP_HDRLEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Captured data length < PPP header length"
                         " (%d bytes)\n", p->pkth->caplen);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    if(pkt[0] == CHDLC_ADDR_BROADCAST && pkt[1] == CHDLC_CTRL_UNNUMBERED)
    {
        DecodePppPktEncapsulated(p, p->pkth->caplen - 2, p->pkt + 2);
    } else {
        DecodeChdlcPkt(p, pkthdr, pkt);
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}


/*
 * Function: DecodeSlipPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode SLIP traffic
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeSlipPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    u_int32_t len;
    u_int32_t cap_len;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    /* do a little validation */
    if(cap_len < SLIP_HEADER_LEN)
    {
        ErrorMessage("SLIP header length < captured len! (%d bytes)\n",
                     cap_len);
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    DecodeIP(p->pkt + SLIP_HEADER_LEN, cap_len - SLIP_HEADER_LEN, p);
    PREPROC_PROFILE_END(decodePerfStats);
}



/*
 * Function: DecodeRawPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeRawPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    DecodeIP(pkt, p->pkth->caplen, p);

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}



/*
 * Function: DecodeI4LRawIPPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeI4LRawIPPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const u_int8_t * pkt)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    if(p->pkth->len < 2)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "What the hell is this?\n"););
        pc.other++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););
    DecodeIP(pkt + 2, p->pkth->len - 2, p);

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}



/*
 * Function: DecodeI4LCiscoIPPkt(Packet *, char *, 
 *                               struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeI4LCiscoIPPkt(Packet *p, const struct pcap_pkthdr *pkthdr, const u_int8_t *pkt)
{
    PROFILE_VARS;
        
    PREPROC_PROFILE_START(decodePerfStats);
    
    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    if(p->pkth->len < 4)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "What the hell is this?\n"););
        pc.other++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }


    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    DecodeIP(pkt + 4, p->pkth->caplen - 4, p);

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Function: DecodeChdlcPkt(Packet *, char *, 
 *                               struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decodes Cisco HDLC encapsulated packets, f.ex. from SONET.
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeChdlcPkt(Packet *p, const struct pcap_pkthdr *pkthdr, const u_int8_t *pkt)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *) p, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    if(p->pkth->caplen < CHDLC_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Captured data length < CHDLC header length"
                         " (%d bytes)\n", p->pkth->caplen);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if ((pkt[0] == CHDLC_ADDR_UNICAST || pkt[0] == CHDLC_ADDR_MULTICAST) &&
           ntohs((u_int16_t)(pkt[2] | pkt[3] << 8)) == ETHERNET_TYPE_IP)
    {
        DecodeIP(p->pkt + CHDLC_HEADER_LEN,
                 p->pkth->caplen - CHDLC_HEADER_LEN, p);
    } else {
        pc.other++;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Some IP Header tests
 * Land Attack(same src/dst ip)
 * Loopback (src or dst in 127/8 block)
 * Modified: 2/22/05-man for High Endian Architecture.
 */
void IPHdrTestsv4( Packet * p )
{
#if 0
#ifdef WORDS_BIGENDIAN
    unsigned int ip4_ip = 0x7f000000;
#else
    unsigned int ip4_ip = 0x7f;
#endif 
#endif  /* #if 0 */

    if( p->iph->ip_src.s_addr == p->iph->ip_dst.s_addr )
    {
        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                    DECODE_BAD_TRAFFIC_SAME_SRCDST, 1, DECODE_CLASS, 3, 
                    DECODE_BAD_TRAFFIC_SAME_SRCDST_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet"
                           "-- same IP\n"););
               InlineDrop(p);
            }
        }
    }

    /* Loopback traffic  - don't use htonl for speed reasons - 
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    if( (p->iph->ip_src.s_addr & 0xff000000) == 0x7f000000  || 
        (p->iph->ip_dst.s_addr & 0xff000000 ) == 0x7f000000 ) /* BE */
#else
    if( (p->iph->ip_src.s_addr & 0xff) == 0x7f || 
        (p->iph->ip_dst.s_addr & 0xff ) == 0x7f ) /* LE */
#endif
    {
        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                    DECODE_BAD_TRAFFIC_LOOPBACK, 1, DECODE_CLASS, 3, 
                    DECODE_BAD_TRAFFIC_LOOPBACK_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet"
                           "-- loopback\n"););
               InlineDrop(p);
            }
        }
    }
}

#ifdef DLT_ENC
/* see http://sourceforge.net/mailarchive/message.php?msg_id=1000380 */
/*
 * Function: DecodeEncPkt(Packet *, struct pcap_pkthdr *, u_int8_t *)
 *
 * Purpose: Decapsulate packets of type DLT_ENC.
 *          XXX Are these always going to be IP in IP?
 *
 * Arguments: p => pointer to decoded packet struct
 *            pkthdr => pointer to the packet header
 *            pkt => pointer to the real live packet data
 */
void DecodeEncPkt(Packet *p, const struct pcap_pkthdr *pkthdr, const u_int8_t *pkt)
{
    struct enc_header *enc_h;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    pc.total_processed++;

    bzero((char *)p, sizeof(Packet));
    p->pkth = pkthdr;
    p->pkt = pkt;

    if (p->pkth->caplen < ENC_HEADER_LEN)
    {
        if (pv.verbose_flag)
        {
            ErrorMessage("Captured data length < Encap header length!  (%d bytes)\n", p->pkth->caplen);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    enc_h = (struct enc_header *)p->pkt;
    if (enc_h->af == AF_INET)
    {
        DecodeIP(p->pkt + ENC_HEADER_LEN + IP_HEADER_LEN,
                 pkthdr->caplen - ENC_HEADER_LEN - IP_HEADER_LEN, p);
    }
    else
    {
        ErrorMessage("[!] WARNING: Unknown address family! (af: 0x%x)\n",
                enc_h->af);
    }
    PREPROC_PROFILE_END(decodePerfStats);
    return;
}
#endif /* DLT_ENC */

/*
 * Function: DecodeIP(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the packet decode struct
 *
 * Returns: void function
 */
void DecodeIP(const u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    u_int32_t ip_len; /* length from the start of the ip hdr to the pkt end */
    u_int32_t hlen;   /* ip header length */
    u_int16_t csum;   /* checksum */

    /* lay the IP struct over the raw data */
    p->iph = (IPHdr *) pkt;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ip++;
    else
        pc.ip++;
#else
    pc.ip++;
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    /* do a little validation */
    if(len < IP_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("IP header truncated! (%d bytes)\n", len);
        }
        p->iph = NULL;
        pc.discards++;
        pc.ipdisc++;

#ifdef SUP_IP6
        p->family = NO_IP;
#endif
        return;
    }

#ifdef GRE
    if (p->greh != NULL && GET_IPH_PROTO(p) == IPPROTO_GRE)
    {
        /* discard packet - multiple GRE encapsulation
         * only allowing one level of encapsulation */
        if(pv.verbose_flag)
            ErrorMessage("Multiple GRE encapsulations in packet");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        { 
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_GRE_MULTIPLE_ENCAPSULATION, 
                           1, DECODE_CLASS, 3, DECODE_GRE_MULTIPLE_ENCAPSULATION_STR, 0);

            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

        p->greh = NULL;
        p->iph = NULL;
        pc.discards++;

        return;
    }
#endif

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if(IP_VER(p->iph) != 4)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Not IPv4 datagram! "
                    "([ver: 0x%x][len: 0x%x])\n", 
                    IP_VER(p->iph), p->iph->ip_len);
        }
        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_NOT_IPV4_DGRAM, 1,
                    DECODE_CLASS, 3, DECODE_NOT_IPV4_DGRAM_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }
        p->iph = NULL;
        pc.discards++;
        pc.ipdisc++;

#ifdef SUP_IP6
        p->family = NO_IP;
#endif
        return;
    }

#ifdef SUP_IP6
    sfiph_build(p, p->iph, AF_INET);
#endif

//    p->ip_payload_len = p->iph->ip_len;
//    p->ip_payload_off = p->ip_payload_len + (int)pkt;

    /* set the IP datagram length */
    ip_len = ntohs(p->iph->ip_len);

    /* set the IP header length */
    hlen = IP_HLEN(p->iph) << 2;


    /* header length sanity check */
    if(hlen < IP_HEADER_LEN)
    {
#ifdef DEBUG
        if(pv.verbose_flag)
            ErrorMessage("Bogus IP header length of %i bytes\n", 
                    hlen);
#endif
        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts) 
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                    DECODE_IPV4_INVALID_HEADER_LEN, 1, DECODE_CLASS, 3, 
                    DECODE_IPV4_INVALID_HEADER_LEN_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }

        }


        p->iph = NULL;
        pc.discards++;
        pc.ipdisc++;
#ifdef SUP_IP6
        p->family = NO_IP;
#endif
        return;
    }

    if (ip_len != len)
    {
        if (ip_len > len) 
        {
#ifdef DEBUG
            if (pv.verbose_flag)
                ErrorMessage("IP Len field is %d bytes bigger"
                        " than captured length.\n"
                        "    (ip.len: %lu, cap.len: %lu)\n",
                        ip_len - len, ip_len, len);
#endif
            if((runMode == MODE_IDS) && pv.decoder_flags.oversized_alert) 
            {
                SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_IPV4_DGRAM_GT_IPHDR, 
                        1, DECODE_CLASS, 3, DECODE_IPV4_DGRAM_GT_IPHDR_STR, 0);
                if ((InlineMode()) && pv.decoder_flags.oversized_drop)
                { 
                    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                    InlineDrop(p);
                }
    
            }

            p->iph = NULL;
            pc.discards++;
            pc.ipdisc++;
#ifdef SUP_IP6
            p->family = NO_IP;
#endif
            return;
        }
        else
        {
#ifdef DEBUG
            if (pv.verbose_flag)
                ErrorMessage("IP Len field is %d bytes "
                        "smaller than captured length.\n"
                        "    (ip.len: %lu, cap.len: %lu)\n",
                        len - ip_len, ip_len, len);
#endif

        }
    }

    if(ip_len < hlen)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("IP dgm len (%d bytes) < IP hdr "
                    "len (%d bytes), packet discarded\n", ip_len, hlen);
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts) 
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_IPV4_DGRAM_LT_IPHDR, 
                    1, DECODE_CLASS, 3, DECODE_IPV4_DGRAM_LT_IPHDR_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            { 
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }

        }

        p->iph = NULL;
        pc.discards++;
        pc.ipdisc++;
#ifdef SUP_IP6
        p->family = NO_IP;
#endif        
        return;
    }

    /* 
     * IP Header tests: Land attack, and Loop back test 
     */
    if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts) 
    {
        IPHdrTestsv4(p);
    }


    if(pv.checksums_mode & DO_IP_CHECKSUMS)
    {
        /* routers drop packets with bad IP checksums, we don't really 
         * need to check them (should make this a command line/config
         * option
         */
        csum = in_chksum_ip((u_short *)p->iph, hlen);

        if(csum)
        {
            p->csum_flags |= CSE_IP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad IP checksum\n"););

            if(InlineMode() && (pv.checksums_drop & DO_IP_CHECKSUMS))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, 
                            "Dropping packet with Bad IP checksum\n"););
                InlineDrop(p);
            }
        }
#ifdef DEBUG
        else
        {
            DebugMessage(DEBUG_DECODE, "IP Checksum: OK\n");
        }
#endif /* DEBUG */
    }

    /* test for IP options */
    p->ip_options_len = hlen - IP_HEADER_LEN;

    if(p->ip_options_len > 0)
    {
        p->ip_options_data = pkt + IP_HEADER_LEN;
        DecodeIPOptions((pkt + IP_HEADER_LEN), p->ip_options_len, p);
    }
    else
    {
#ifdef GRE
        /* If delivery header for GRE encapsulated packet is IP and it 
         * had options, the packet's ip options will be refering to this
         * outer IP's options
         * Zero these options so they aren't associated with this inner IP
         * since p->iph will be pointing to this inner IP
         */
        if (p->greh != NULL)
        {
            p->ip_options_data = NULL;
            p->ip_options_len = 0;
            memset(&(p->ip_options[0]), 0, sizeof(p->ip_options));
            p->ip_lastopt_bad = 0;
        }
#endif
        p->ip_option_count = 0;
    }

    /* set the real IP length for logging */
    p->actual_ip_len = (u_int16_t) ip_len;

    /* set the remaining packet length */
    ip_len -= hlen;

    /* check for fragmented packets */
    p->frag_offset = ntohs(p->iph->ip_off);

    /* 
     * get the values of the reserved, more 
     * fragments and don't fragment flags 
     */
    p->rf = (u_int8_t)((p->frag_offset & 0x8000) >> 15);
    p->df = (u_int8_t)((p->frag_offset & 0x4000) >> 14);
    p->mf = (u_int8_t)((p->frag_offset & 0x2000) >> 13);

    /* mask off the high bits in the fragment offset field */
    p->frag_offset &= 0x1FFF;

    if(p->frag_offset || p->mf)
    {
        /* set the packet fragment flag */
        p->frag_flag = 1;
        pc.frags++;
    } 
    else 
    {
        p->frag_flag = 0;
    }

    /* if this packet isn't a fragment
     * or if it is, its a UDP packet and offset isn't 0 */
    if(!(p->frag_flag) || 
            (p->frag_flag && (p->frag_offset == 0) && 
            (p->iph->ip_proto == IPPROTO_UDP)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP header length: %lu\n", 
                    (unsigned long)hlen););

        switch(p->iph->ip_proto)
        {
            case IPPROTO_TCP:
                pc.tcp++;
                DecodeTCP(pkt + hlen, ip_len, p);
                //ClearDumpBuf();
                return;

            case IPPROTO_UDP:
                pc.udp++;
                DecodeUDP(pkt + hlen, ip_len, p);
                //ClearDumpBuf();
                return;

            case IPPROTO_ICMP:
                pc.icmp++;
                DecodeICMP(pkt + hlen, ip_len, p);
                //ClearDumpBuf();
                return;
            
//            case IPPROTO_IPV6:
// XXX-IPv6 decrement IPv4 count?
                DecodeIPV6(pkt + hlen, ip_len, p);
                return;

#ifdef GRE
            case IPPROTO_GRE:
                pc.gre++;
                DecodeGRE(pkt + hlen, ip_len, p);
                //ClearDumpBuf();
                return;
#endif

            default:
                pc.other++;
                p->data = pkt + hlen;
                p->dsize = (u_short) ip_len;
                //ClearDumpBuf();
                return;
        }
    }
    else
    {
        /* set the payload pointer and payload size */
        p->data = pkt + hlen;
        p->dsize = (u_short) ip_len;
    }

    pc.other++;
    p->data = pkt + hlen;
    p->dsize = (u_short) ip_len;
}

/*
 * Function: DecodeTCP(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => Pointer to packet decode struct
 *
 * Returns: void function
 */
void DecodeTCP(const u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    struct pseudoheader6       /* pseudo header for TCP checksum calculations */
    {
        u_int32_t sip[4], dip[4];   /* IP addr */
        u_int8_t  zero;       /* checksum placeholder */
        u_int8_t  protocol;   /* protocol number */
        u_int16_t tcplen;     /* tcp packet length */
    };

    struct pseudoheader       /* pseudo header for TCP checksum calculations */
    {
        u_int32_t sip, dip;   /* IP addr */
        u_int8_t  zero;       /* checksum placeholder */
        u_int8_t  protocol;   /* protocol number */
        u_int16_t tcplen;     /* tcp packet length */
    };
    u_int32_t hlen;            /* TCP header length */
    u_short csum;              /* checksum */
    struct pseudoheader ph;    /* pseudo header declaration */
#ifdef SUP_IP6
    struct pseudoheader6 ph6;    /* pseudo header declaration */
#endif

    if(len < 20)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("TCP packet (len = %d) cannot contain "
                         "20 byte header\n", len);
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts) 
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_TCP_DGRAM_LT_TCPHDR, 
                    1, DECODE_CLASS, 3, DECODE_TCP_DGRAM_LT_TCPHDR_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {  
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
               InlineDrop(p);
            }
 
        }

        p->tcph = NULL;
        pc.discards++;
        pc.tdisc++;

        return;
    }

    /* lay TCP on top of the data cause there is enough of it! */
    p->tcph = (TCPHdr *) pkt;

    /* multiply the payload offset value by 4 */
    hlen = TCP_OFFSET(p->tcph) << 2;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "TCP th_off is %d, passed len is %lu\n", 
                TCP_OFFSET(p->tcph), (unsigned long)len););

    if(hlen < 20)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("TCP Data Offset (%d) < hlen (%d) \n",
                         TCP_OFFSET(p->tcph), hlen);
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_TCP_INVALID_OFFSET, 
                    1, DECODE_CLASS, 3, DECODE_TCP_INVALID_OFFSET_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {  
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
               InlineDrop(p);
            }

        }

        p->tcph = NULL;
        pc.discards++;
        pc.tdisc++;

        return;
    }

    if(hlen > len)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("TCP Data Offset(%d) < longer than payload(%d)!\n",
                         TCP_OFFSET(p->tcph) << 2, len);
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.oversized_alert)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_TCP_LARGE_OFFSET, 1, 
                    DECODE_CLASS, 3, DECODE_TCP_LARGE_OFFSET_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.oversized_drop)
            {  
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n");); 
               InlineDrop(p);
            }
 
        }

        p->tcph = NULL;
        pc.discards++;
        pc.tdisc++;

        return;
    }

    /* stuff more data into the printout data struct */
    p->sp = ntohs(p->tcph->th_sport);
    p->dp = ntohs(p->tcph->th_dport);

    if(pv.checksums_mode & DO_TCP_CHECKSUMS)
    {
#ifdef SUP_IP6
        if(IS_IP4(p)) 
        {
            ph.sip = *p->ip4h.ip_src.ip32;
            ph.dip = *p->ip4h.ip_dst.ip32;
#else
            ph.sip = (u_int32_t)(p->iph->ip_src.s_addr);
            ph.dip = (u_int32_t)(p->iph->ip_dst.s_addr);
#endif
            /* setup the pseudo header for checksum calculation */
            ph.zero = 0;
            ph.protocol = GET_IPH_PROTO(p);
            ph.tcplen = htons((u_short)len);
    
            /* if we're being "stateless" we probably don't care about the TCP 
             * checksum, but it's not bad to keep around for shits and giggles */
            /* calculate the checksum */
            csum = in_chksum_tcp((u_int16_t *)&ph, (u_int16_t *)(p->tcph), len);
#ifdef SUP_IP6
        } 
        /* IPv6 traffic */
        else
        {   
            COPY4(ph6.sip, p->ip6h.ip_src.ip32);
            COPY4(ph6.dip, p->ip6h.ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.tcplen = htons((u_short)len);

            csum = in_chksum_tcp6((u_int16_t *)&ph6, (u_int16_t *)(p->tcph), len);
        }   
#endif
        
        if(csum)
        {
            p->csum_flags |= CSE_TCP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad TCP checksum\n",
                                    "0x%x versus 0x%x\n", csum,
                                    ntohs(p->tcph->th_sum)););
            if(InlineMode() && (pv.checksums_drop & DO_TCP_CHECKSUMS))
            {     
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, 
                            "Dropping packet with Bad TCP checksum\n"););
                InlineDrop(p);
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"TCP Checksum: OK\n"););
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "tcp header starts at: %p\n", p->tcph););


    /* if options are present, decode them */
    p->tcp_options_len = hlen - 20;
    
    if(p->tcp_options_len > 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%lu bytes of tcp options....\n", 
                    (unsigned long)(p->tcp_options_len)););

        p->tcp_options_data = pkt + 20;
        DecodeTCPOptions((u_int8_t *) (pkt + 20), p->tcp_options_len, p);
    }
    else
    {
        p->tcp_option_count = 0;
    }

    /* set the data pointer and size */
    p->data = (u_int8_t *) (pkt + hlen);

    if(hlen < len)
    {
        p->dsize = (u_short)(len - hlen);
    }
    else
    {
        p->dsize = 0;
    }

    /*  Drop packet if we ignore this port  */
    if ((pv.ignore_ports[p->sp] == IPPROTO_TCP) || (pv.ignore_ports[p->dp] == IPPROTO_TCP) )
    {
        /*  Ignore all preprocessors for this packet */
        p->packet_flags |= PKT_IGNORE_PORT;
    }
}


/*
 * Function: DecodeUDP(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct  
 *
 * Returns: void function
 */
void DecodeUDP(const u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    struct pseudoheader6
    {
        u_int32_t sip[4], dip[4];
        u_int8_t  zero;
        u_int8_t  protocol;
        u_int16_t udplen;
    };

    struct pseudoheader 
    {
        u_int32_t sip, dip;
        u_int8_t  zero;
        u_int8_t  protocol;
        u_int16_t udplen;
    };
    u_short csum;
    u_int16_t uhlen;
    struct pseudoheader ph;
#ifdef SUP_IP6
    struct pseudoheader6 ph6;
#endif
    u_char fragmented_udp_flag = 0;

    if(len < sizeof(UDPHdr))
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Truncated UDP header (%d bytes)\n", len);
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts) 
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_UDP_DGRAM_LT_UDPHDR, 
                    1, DECODE_CLASS, 3, DECODE_UDP_DGRAM_LT_UDPHDR_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
               InlineDrop(p);
            }
 
        }

        p->udph = NULL;
        pc.discards++;
        pc.udisc++;

        return;
    }

    /* set the ptr to the start of the UDP header */
    p->udph = (UDPHdr *) pkt;

    if (!p->frag_flag)
    {
        uhlen = ntohs(p->udph->uh_len);
    }
    else
    {
        u_int16_t ip_len = ntohs(GET_IPH_LEN(p));
        /* Don't forget, IP_HLEN is a word - multiply x 4 */
// XXX-IPv6 double check IP_HLEN -> GET_IPH_HLEN ?
        uhlen = ip_len - (GET_IPH_HLEN(p) * 4 );
        fragmented_udp_flag = 1;
    }
    
    /* verify that the header len is a valid value */
    if(uhlen < UDP_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Invalid UDP Packet, length field < 8\n");
        }
        
        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                    DECODE_UDP_DGRAM_INVALID_LENGTH, 1, DECODE_CLASS, 3, 
                    DECODE_UDP_DGRAM_INVALID_LENGTH_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
               InlineDrop(p);
            }

        }
        p->udph = NULL;
        pc.udisc++;
        pc.discards++;

        return;
    }

    /* make sure there are enough bytes as designated by length field */
    if(len < uhlen)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Short UDP packet, length field > payload length\n");
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts) 
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                    DECODE_UDP_DGRAM_SHORT_PACKET, 1, DECODE_CLASS, 3, 
                    DECODE_UDP_DGRAM_SHORT_PACKET_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {  
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n");); 
               InlineDrop(p);
            }
 
        }

        p->udph = NULL;
        pc.discards++;
        pc.udisc++;

        return;
    } 
    else if(len > uhlen)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Long UDP packet, length field < payload length\n");
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.oversized_alert) 
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                    DECODE_UDP_DGRAM_LONG_PACKET, 1, DECODE_CLASS, 3, 
                    DECODE_UDP_DGRAM_LONG_PACKET_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.oversized_drop)
            {  
               DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n");); 
               InlineDrop(p);
            }
 
        }

        p->udph = NULL;
        pc.discards++;
        pc.udisc++;

        return;
    }

    /* fill in the printout data structs */
    p->sp = ntohs(p->udph->uh_sport);
    p->dp = ntohs(p->udph->uh_dport);

    if(pv.checksums_mode & DO_UDP_CHECKSUMS)
    {
        /* look at the UDP checksum to make sure we've got a good packet */
#ifdef SUP_IP6
        if(IS_IP4(p)) 
        {
            ph.sip = *p->ip4h.ip_src.ip32;
            ph.dip = *p->ip4h.ip_dst.ip32;
#else
            ph.sip = (u_int32_t)(p->iph->ip_src.s_addr);
            ph.dip = (u_int32_t)(p->iph->ip_dst.s_addr);
#endif
            ph.zero = 0;
            ph.protocol = GET_IPH_PROTO(p);
            ph.udplen = p->udph->uh_len; 
            /* Don't do checksum calculation if
             * 1) Framented, OR
             * 2) UDP header chksum value is 0.
             */
            if( !fragmented_udp_flag && p->udph->uh_chk )
            {
                csum = in_chksum_udp((u_int16_t *)&ph, 
                        (u_int16_t *)(p->udph), uhlen); 
            }
            else
            {
                csum = 0;
            }
#ifdef SUP_IP6
        }
        else 
        {
            COPY4(ph6.sip, p->ip6h.ip_src.ip32);
            COPY4(ph6.dip, p->ip6h.ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.udplen = htons((u_short)len);
            /* Don't do checksum calculation if
             * 1) Framented, OR
             * 2) UDP header chksum value is 0.
             */
            if( !fragmented_udp_flag && p->udph->uh_chk )
            {
                csum = in_chksum_udp6((u_int16_t *)&ph6, 
                        (u_int16_t *)(p->udph), uhlen); 
            }
            else
            {
                csum = 0;
            }
        }
#endif
        if(csum)
        {
            p->csum_flags |= CSE_UDP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad UDP Checksum\n"););

            if(InlineMode() && (pv.checksums_drop & DO_UDP_CHECKSUMS))
            {     
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, 
                            "Dropping packet with Bad UDP checksum\n"););
                InlineDrop(p);
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "UDP Checksum: OK\n"););
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "UDP header starts at: %p\n", p->udph););

    p->data = (u_int8_t *) (pkt + UDP_HEADER_LEN);
    
    /* length was validated up above */
    p->dsize = uhlen - UDP_HEADER_LEN; 

    /*  Drop packet if we ignore this port  */
    if ( (pv.ignore_ports[p->sp] == IPPROTO_UDP) || (pv.ignore_ports[p->dp] == IPPROTO_UDP) )
    {
        /*  Ignore all preprocessors for this packet */
        p->packet_flags |= PKT_IGNORE_PORT;
    }

    return;
}



/*
 * Function: DecodeICMP(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the decoded packet struct
 *
 * Returns: void function
 */
void DecodeICMP(const u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    u_int16_t csum;

    if(len < ICMP_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("WARNING: Truncated ICMP header "
                         "(%d bytes)\n", len);
        }
        
        p->icmph = NULL;
        pc.discards++;
        pc.icmpdisc++;

        return;
    }

    /* set the header ptr first */
    p->icmph = (ICMPHdr *) pkt;

    switch (p->icmph->type)
    {
        case ICMP_DEST_UNREACH:
        case ICMP_SOURCE_QUENCH:
        case ICMP_REDIRECT:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETERPROB:
        case ICMP_ECHOREPLY:
        case ICMP_ECHO:
        case ICMP_ROUTER_ADVERTISE:
        case ICMP_ROUTER_SOLICIT:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
            if (len < 8)
            {
                if(pv.verbose_flag)
                {
                    ErrorMessage("Truncated ICMP header(%d bytes)\n", len);
                }

                if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
                {
                    SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                            DECODE_ICMP_DGRAM_LT_ICMPHDR, 1, DECODE_CLASS, 3, 
                            DECODE_ICMP_DGRAM_LT_ICMPHDR_STR, 0);
                    if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                    { 
                      DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                      InlineDrop(p);
                    }
 
                }

                p->icmph = NULL;
                pc.discards++;
                pc.icmpdisc++;
        
                return;
            }

            break;

        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
            if (len < 20)
            {
                if(pv.verbose_flag)
                {
                    ErrorMessage("Truncated ICMP header(%d bytes)\n", len);
                }

                if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
                {
                    SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                            DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR, 1, DECODE_CLASS,
                            3, DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR_STR, 0);
                    if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                    { 
                      DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                      InlineDrop(p);
                    }

                }

                p->icmph = NULL;
                pc.discards++;
                pc.icmpdisc++;

                return;
            }

            break;

        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
            if (len < 12)
            {
                if(pv.verbose_flag)
                {
                    ErrorMessage("Truncated ICMP header(%d bytes)\n", len);
                }


                if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
                {
                    SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                            DECODE_ICMP_DGRAM_LT_ADDRHDR, 1, DECODE_CLASS, 3, 
                            DECODE_ICMP_DGRAM_LT_ADDRHDR_STR, 0);
                    if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                    {
                      DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                      InlineDrop(p);
                    }
 
                }

                p->icmph = NULL;
                pc.discards++;
                pc.icmpdisc++;

                return;
            }

            break;
    }


    if(pv.checksums_mode & DO_ICMP_CHECKSUMS)
    {
        csum = in_chksum_icmp((u_int16_t *)p->icmph, len);

        if(csum)
        {
            p->csum_flags |= CSE_ICMP;

            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad ICMP Checksum\n"););
 
            if(InlineMode() && (pv.checksums_drop & DO_ICMP_CHECKSUMS))
            {     
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, 
                            "Dropping packet with Bad ICMP checksum\n"););
                InlineDrop(p);
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: OK\n"););
        }
    }

    p->dsize = (u_short)(len - ICMP_HEADER_LEN);
    p->data = pkt + ICMP_HEADER_LEN;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP type: %d   code: %d\n", 
                p->icmph->code, p->icmph->type););

    switch(p->icmph->type)
    {
        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            /* setup the pkt id and seq numbers */
            p->dsize -= sizeof(struct idseq);   /* add the size of the 
                                                 * echo ext to the data
                                                 * ptr and subtract it 
                                                 * from the data size */
            p->data += sizeof(struct idseq);
            break;

        case ICMP_DEST_UNREACH:
        case ICMP_REDIRECT:
        case ICMP_SOURCE_QUENCH:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETERPROB:
            /* account for extra 4 bytes in header */
            p->dsize -= 4; 
            p->data += 4;

            DecodeICMPEmbeddedIP(p->data, p->dsize, p);

            break;
    }

    return;
}

/*
 * Function: DecodeICMPEmbeddedIP(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the ICMP embedded IP header + 64 bits payload
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
void DecodeICMPEmbeddedIP(const u_int8_t *pkt, const u_int32_t len, Packet *p)
{
    u_int32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */
    u_int32_t hlen;             /* ip header length */
    u_int16_t orig_frag_offset;

    /* do a little validation */
    if(len < IP_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("ICMP: IP short header (%d bytes)\n", len);
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                           DECODE_ICMP_ORIG_IP_TRUNCATED, 1, DECODE_CLASS, 3, 
                           DECODE_ICMP_ORIG_IP_TRUNCATED_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            { 
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

#ifdef SUP_IP6
        p->orig_family = NO_IP;
#endif
        p->orig_iph = NULL;
        return;
    }

    /* lay the IP struct over the raw data */
#ifdef SUP_IP6
    sfiph_orig_build(p, pkt, AF_INET);
#endif
    p->orig_iph = (IPHdr *) pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeICMPEmbeddedIP: ip header"
                    " starts at: %p, length is %lu\n", p->orig_iph, 
                    (unsigned long) len););
    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if(GET_ORIG_IPH_VER(p) != 4 && !IS_IP6(p))
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("ICMP: not IPv4 datagram "
                         "([ver: 0x%x][len: 0x%x])\n", 
                         GET_ORIG_IPH_VER(p), GET_ORIG_IPH_LEN(p));

        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                           DECODE_ICMP_ORIG_IP_NOT_IPV4, 1, DECODE_CLASS, 3, 
                           DECODE_ICMP_ORIG_IP_NOT_IPV4_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            { 
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

#ifdef SUP_IP6
        p->orig_family = NO_IP;
#endif
        p->orig_iph = NULL;
        return;
    }

    /* set the IP datagram length */
    ip_len = ntohs(GET_ORIG_IPH_LEN(p));

    /* set the IP header length */
#ifdef SUP_IP6
    hlen = (p->orig_ip4h.ip_verhl & 0x0f) << 2;
#else
    hlen = IP_HLEN(p->orig_iph) << 2;
#endif

    if(len < hlen)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("ICMP: IP len (%d bytes) < "
                         "IP hdr len (%d bytes), packet discarded\n", ip_len, hlen);
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                           DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP, 1, DECODE_CLASS, 3, 
                           DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            { 
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }
        
#ifdef SUP_IP6
        p->orig_family = NO_IP;
#endif
        p->orig_iph = NULL;
        return;
    }

    /* set the remaining packet length */
    ip_len = len - hlen;

    orig_frag_offset = ntohs(GET_ORIG_IPH_OFF(p));
    orig_frag_offset &= 0x1FFF;

#ifdef SUP_IP6
    p->orig_family = AF_INET6;
#endif

    if (orig_frag_offset == 0) 
    {
        /* Original IP payload should be 64 bits */
        if (ip_len < 8)
        {
            if (pv.verbose_flag)
            {
                ErrorMessage("ICMP: IP payload length < 64 bits\n");
            }

            if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
            {
                SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                               DECODE_ICMP_ORIG_PAYLOAD_LT_64, 1, DECODE_CLASS, 3, 
                               DECODE_ICMP_ORIG_PAYLOAD_LT_64_STR, 0);
                if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                { 
                    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                    InlineDrop(p);
                }
            }

            return;
        }
        /* ICMP error packets could contain as much of original payload
         * as possible, but not exceed 576 bytes
         */
        else if (ntohs(GET_IPH_LEN(p)) > 576)
        {
            if (pv.verbose_flag)
            {
                ErrorMessage("ICMP: ICMP error packet length > 576 bytes\n");
            }

            if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
            {
                SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                               DECODE_ICMP_ORIG_PAYLOAD_GT_576, 1, DECODE_CLASS, 3, 
                               DECODE_ICMP_ORIG_PAYLOAD_GT_576_STR, 0);
                if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                { 
                    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                    InlineDrop(p);
                }
            }
        }
    }
    else
    {
        /* RFC states that only first frag will get an ICMP response */
        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                           DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET, 1, DECODE_CLASS, 3, 
                           DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            { 
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP Unreachable IP header length: "
                            "%lu\n", (unsigned long)hlen););

    switch(GET_ORIG_IPH_PROTO(p))
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
            p->orig_tcph = (TCPHdr *)(pkt + hlen);

            /* stuff more data into the printout data struct */
            p->orig_sp = ntohs(p->orig_tcph->th_sport);
            p->orig_dp = ntohs(p->orig_tcph->th_dport);

            break;

        case IPPROTO_UDP:
            p->orig_udph = (UDPHdr *)(pkt + hlen);

            /* fill in the printout data structs */
            p->orig_sp = ntohs(p->orig_udph->uh_sport);
            p->orig_dp = ntohs(p->orig_udph->uh_dport);

            break;

        case IPPROTO_ICMP:
            p->orig_icmph = (ICMPHdr *)(pkt + hlen);
            break;
    }

    return;
}

/*
 * Function: DecodeARP(u_int8_t *, u_int32_t, Packet *)
 *
 * Purpose: Decode ARP stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeARP(const u_int8_t * pkt, u_int32_t len, Packet * p)
{

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_arp++;
    else
        pc.arp++;
#else
    pc.arp++;
#endif

    p->ah = (EtherARP *) pkt;

    if(len < sizeof(EtherARP))
    {
        if(pv.verbose_flag)
            ErrorMessage("Truncated packet\n");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_ARP_TRUNCATED, 1, 
                    DECODE_CLASS, 3, DECODE_ARP_TRUNCATED_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
              DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n");); 
              InlineDrop(p);
            }
        }

        pc.discards++;
        return;
    }

    return;
}

/*
 * Function: DecodeEapol(u_int8_t *, u_int32_t, Packet *)
 *
 * Purpose: Decode 802.1x eapol stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEapol(const u_int8_t * pkt, u_int32_t len, Packet * p)
{
    p->eplh = (EtherEapol *) pkt;
    pc.eapol++;
    if(len < sizeof(EtherEapol))
    {
        if(pv.verbose_flag)
            ErrorMessage("Truncated packet\n");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_EAPOL_TRUNCATED, 1, 
                    DECODE_CLASS, 3, DECODE_EAPOL_TRUNCATED_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
              DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
              InlineDrop(p);
            } 

        }

        pc.discards++;
        return;
    }
    if (p->eplh->eaptype == EAPOL_TYPE_EAP) {
        DecodeEAP(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p);
    }    
    else if(p->eplh->eaptype == EAPOL_TYPE_KEY) {
        DecodeEapolKey(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p);
    }
    return;
}

/*
 * Function: DecodeEapolKey(u_int8_t *, u_int32_t, Packet *)
 *
 * Purpose: Decode 1x key setup
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEapolKey(const u_int8_t * pkt, u_int32_t len, Packet * p)
{
    p->eapolk = (EapolKey *) pkt;
    if(len < sizeof(EapolKey))
    {
        if(pv.verbose_flag)
            printf("Truncated packet\n");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_EAPKEY_TRUNCATED, 1, 
                    DECODE_CLASS, 3, DECODE_EAPKEY_TRUNCATED_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
              DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
              InlineDrop(p);
            } 

        }

        pc.discards++;
        return;
    }

    return;  
}

/*
 * Function: DecodeEAP(u_int8_t *, u_int32_t, Packet *)
 *
 * Purpose: Decode Extensible Authentication Protocol
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEAP(const u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    p->eaph = (EAPHdr *) pkt;
    if(len < sizeof(EAPHdr))
    {
        if(pv.verbose_flag)
            printf("Truncated packet\n");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_EAP_TRUNCATED, 1, 
                    DECODE_CLASS, 3, DECODE_EAP_TRUNCATED_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
              DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
              InlineDrop(p);
            } 

        }

        pc.discards++;
        return;
    }
    if (p->eaph->code == EAP_CODE_REQUEST ||
            p->eaph->code == EAP_CODE_RESPONSE) {
        p->eaptype = pkt + sizeof(EAPHdr);
    }
    return;
}

static INLINE void FragEvent(
    Packet *p, int gid, char *str, int event_flag, int drop_flag) 
{
    if((runMode == MODE_IDS) && event_flag) 
    {
        SnortEventqAdd(GENERATOR_SPP_FRAG3, gid, 1, 
                       DECODE_CLASS, 3, str, 0);
        if ((InlineMode()) && drop_flag)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
            InlineDrop(p);
        }
    }
}

static INLINE void DecoderEvent(
    Packet *p, int gid, char *str, int event_flag, int drop_flag) 
{
    if((runMode == MODE_IDS) && event_flag) 
    {
        SnortEventqAdd(GENERATOR_SNORT_DECODE, gid, 1, 
                       DECODE_CLASS, 3, str, 0);
        if ((InlineMode()) && drop_flag)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
            InlineDrop(p);
        }
    }
}

void BsdFragHashCleanup()
{
    if (ipv6_frag_hash)
    {
        sfxhash_delete(ipv6_frag_hash);
        ipv6_frag_hash = NULL;
    }
}

void BsdFragHashInit(int max)
{
    int rows = sfxhash_calcrows((int) (max * 1.4));

    ipv6_frag_hash = sfxhash_new( 
            /* one row per element in table, when possible */
            rows,
            36,      /* key size :  padded with zeros */
            4,       /* data size:  padded with zeros */
            /* Set max to the sizeof a hash node, plus the size of 
             * the stored data, plus the size of the key (32), plus
             * this size of a node pointer plus max rows plus 1. */
            max * (36 + sizeof(SFXHASH_NODE) + sizeof(u_int32_t) + sizeof(SFXHASH_NODE*)) 
                + (rows+1) * sizeof(SFXHASH_NODE*),   
            1,       /* enable AutoNodeRecovery */
            NULL, /* provide a function to let user know we want to kill a node */
            NULL, /* provide a function to release user memory */
            1);      /* Recycle nodes */

    if (!ipv6_frag_hash) {
        FatalError("could not allocate ipv6_frag_hash");
    }
}

static INLINE void BsdFragVulnCheck(Packet *p, const u_int8_t *data, u_int32_t size) 
{
    IP6Frag  *frag;
    unsigned short frag_data;
    char key[36]; /* Two 16 bit IP addresses and one fragmentation ID */
    SFXHASH_NODE *hash_node;

    if(sizeof(IP6Frag) > size) 
    {
        DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT, 
                     DECODE_IPV6_TRUNCATED_EXT_STR,
                     pv.decoder_flags.decode_alerts,
                     pv.decoder_flags.drop_alerts);
        return;
    }

    frag = (IP6Frag *)data; 
    frag_data = frag->ip6f_offlg;

    /* Source and dest IPs */
    memcpy(key, (u_char*)p->iph + 8, 32);
    *(u_int32_t*)(key+32) = frag->ip6f_ident;

    hash_node = sfxhash_find_node(ipv6_frag_hash, key);

    /* Check if the frag offset mask is set. 
     * If it is, we're not looking at the exploit in question */
    if(frag_data & IP6F_OFF_MASK)
    {
        /* If this arrives before the two 0 offset frags, we will
         * still add them as though they were the first, and false
         * positive */
        if(hash_node) 
            sfxhash_free_node(ipv6_frag_hash, hash_node);

        return;
    }

    /* Check if there are no more frags */
    if(!(frag_data & IP6F_MORE_FRAG))
    {
        /* At this point, we've seen a frag header with no offset 
         * that doesn't have the more flags set.  Need to see if 
         * this follows a packet that did have the more flag set. */
        if(hash_node)
        {
            /* Check if the first packet timed out */
            if( (p->pkth->ts.tv_sec - *(u_int32_t*)hash_node->data)
                 > pv.ipv6_frag_timeout ) 
            {
                sfxhash_free_node(ipv6_frag_hash, hash_node);

                FragEvent(p, FRAG3_IPV6_BAD_FRAG_PKT, 
                        FRAG3_IPV6_BAD_FRAG_PKT_STR , 
                        pv.decoder_flags.ipv6_bad_frag_pkt,
                        pv.decoder_flags.drop_bad_ipv6_frag);
                return;
            }

            if(size > 100)
            {
                FragEvent(p, FRAG3_IPV6_BSD_ICMP_FRAG, 
                        FRAG3_IPV6_BSD_ICMP_FRAG_STR, 
                        pv.decoder_flags.ipv6_bad_frag_pkt,
                        pv.decoder_flags.drop_bad_ipv6_frag);
                return;
            }

            sfxhash_free_node(ipv6_frag_hash, hash_node);
             
            FragEvent(p, FRAG3_IPV6_BAD_FRAG_PKT, 
                    FRAG3_IPV6_BAD_FRAG_PKT_STR , 
                    pv.decoder_flags.ipv6_bad_frag_pkt,
                    pv.decoder_flags.drop_bad_ipv6_frag);
            return;
        }
    
        /* We never saw the first packet, but this one is still bogus */
        FragEvent(p, FRAG3_IPV6_BAD_FRAG_PKT, 
                FRAG3_IPV6_BAD_FRAG_PKT_STR , 
                pv.decoder_flags.ipv6_bad_frag_pkt,
                pv.decoder_flags.drop_bad_ipv6_frag);
        return;
    }
    
    /* At this point, we've seen a header with no offset and a 
     * more flag */
    if(!hash_node) 
    {
        /* There are more frags remaining, add current to hash */
        if(sfxhash_add(ipv6_frag_hash, key, (void *)&p->pkth->ts.tv_sec) 
            == SFXHASH_NOMEM)
        {
            return;
        }
    }
    else
    {
        /* Update this node's timestamp */
        *(u_int32_t*)hash_node->data = p->pkth->ts.tv_sec;
    }
}


#ifdef SUP_IP6
/*
 * Function: DecodeICMPEmbeddedIP6(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the ICMP embedded IP6 header + payload
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
void DecodeICMPEmbeddedIP6(const u_int8_t *pkt, const u_int32_t len, Packet *p)
{
    u_int32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */
    u_int32_t hlen;             /* ip header length */
    u_int16_t orig_frag_offset;
    

    /* lay the IP struct over the raw data */
    IP6Hdr *ip6h = (IP6Hdr *) pkt;
    pc.embdip++;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeICMPEmbeddedIP6: ip header"
                    " starts at: %p, length is %lu\n", ip6h, 
                    (unsigned long) len););

    /* do a little validation */
    if(len < IP6_HDR_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("ICMP6: IP short header (%d bytes)\n", len);
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                           DECODE_ICMP_ORIG_IP_TRUNCATED, 1, DECODE_CLASS, 3, 
                           DECODE_ICMP_ORIG_IP_TRUNCATED_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            { 
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

        pc.discards++;
        return;
    }

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
// XXX-IPv6 double check this - checking version in IPv6 header
    if((ip6h->vcl & 0xf0) != 0x60)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("ICMP: not IPv6 datagram "
                         "([ver: 0x%x][len: 0x%x])\n", 
                        // XXX-IPv6 shouldn't the length be ntohs'ed?
                         (ip6h->vcl & 0x0f)>>4, ip6h->len);

        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                           DECODE_ICMP_ORIG_IP_NOT_IPV4, 1, DECODE_CLASS, 3, 
                           DECODE_ICMP_ORIG_IP_NOT_IPV4_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            { 
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }
        pc.discards++;
        return;
    }

    /* set the IP datagram length */
    ip_len = ntohs(ip6h->len);

    /* set the IP header length */
    hlen = (ip6h->vcl & 0x0f ) << 2;

    if(len < hlen)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("ICMP6: IP6 len (%d bytes) < "
                         "IP6 hdr len (%d bytes), packet discarded\n", ip_len, hlen);
        }

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                           DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP, 1, DECODE_CLASS, 3, 
                           DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            { 
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

        pc.discards++;
        return;
    }
#ifdef SUP_IP6
    sfiph_orig_build(p, pkt, AF_INET6);
#endif

    /* set the remaining packet length */
    ip_len = len - hlen;

    orig_frag_offset = ntohs(GET_ORIG_IPH_OFF(p));
    orig_frag_offset &= 0x1FFF;

// XXX NOT YET IMPLEMENTED - fragments inside ICMP payload
#if 0
    if (orig_frag_offset == 0) 
    {
        /* Original IP payload should be 64 bits */
        if (ip_len < 8)
        {
            if (pv.verbose_flag)
            {
                ErrorMessage("ICMP6: IP6 payload length < 64 bits\n");
            }

            if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
            {
                SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                               DECODE_ICMP_ORIG_PAYLOAD_LT_64, 1, DECODE_CLASS, 3, 
                               DECODE_ICMP_ORIG_PAYLOAD_LT_64_STR, 0);
                if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                { 
                    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                    InlineDrop(p);
                }
            }

            return;
        }
        /* ICMP6 error packets could contain as much of original payload
         * as possible, but not exceed the MTU
         */
#warning "MTU?"
        else if (ntohs(p->iph->ip_len) > 576)
        {
            if (pv.verbose_flag)
            {
                ErrorMessage("ICMP: ICMP error packet length > 576 bytes\n");
            }

            if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
            {
                SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                               DECODE_ICMP_ORIG_PAYLOAD_GT_576, 1, DECODE_CLASS, 3, 
                               DECODE_ICMP_ORIG_PAYLOAD_GT_576_STR, 0);
                if ((InlineMode()) && pv.decoder_flags.drop_alerts)
                { 
                    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                    InlineDrop(p);
                }
            }
        }
    }
    else
    {
        /* RFC states that only first frag will get an ICMP response */
        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        {
            SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                           DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET, 1, DECODE_CLASS, 3, 
                           DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            { 
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

        return;
    }
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP6 Unreachable IP6 header length: "
                            "%lu\n", (unsigned long)hlen););

    switch(GET_ORIG_IPH_PROTO(p))
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
            p->orig_tcph = (TCPHdr *)(pkt + hlen);

            /* stuff more data into the printout data struct */
            p->orig_sp = ntohs(p->orig_tcph->th_sport);
            p->orig_dp = ntohs(p->orig_tcph->th_dport);

            break;

        case IPPROTO_UDP:
            p->orig_udph = (UDPHdr *)(pkt + hlen);

            /* fill in the printout data structs */
            p->orig_sp = ntohs(p->orig_udph->uh_sport);
            p->orig_dp = ntohs(p->orig_udph->uh_dport);

            break;

        case IPPROTO_ICMP:
            p->orig_icmph = (ICMPHdr *)(pkt + hlen);
            break;
    }

    return;
}

void DecodeICMP6(const u_int8_t *pkt, u_int32_t len, Packet *p)
{
    if(len < ICMP6_MIN_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("WARNING: Truncated ICMP header "
                         "(%d bytes)\n", len);
        }
        
        pc.discards++;
        return;
    }
        
    p->icmph = (ICMPHdr*)pkt;
//    p->icmp6h = pkt;
//    p->icmph = (ICMPHdr*)p->icmp6h;
//    memcpy(&p->icmp6h, pkt, ICMP6_MIN_HEADER_LEN);
//    p->icmp6h.body = pkt + ICMP6_MIN_HEADER_LEN;  

    /* Do checksums */
    if((pv.checksums_mode & DO_ICMP_CHECKSUMS) &&
        in_chksum_icmp6((u_int16_t*)p->icmph, len))
    {
        p->csum_flags |= CSE_ICMP;

        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad ICMP Checksum\n"););
 
        if(InlineMode() && (pv.checksums_drop & DO_ICMP_CHECKSUMS))
        {     
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, 
                        "Dropping packet with Bad ICMP checksum\n"););
            InlineDrop(p);
        }
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: OK\n"););
    }

    
    p->dsize = (u_short)(len - ICMP6_MIN_HEADER_LEN); 
    p->data = pkt + ICMP6_MIN_HEADER_LEN;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP type: %d   code: %d\n", 
                p->icmph->code, p->icmph->type););

    switch(p->icmph->type)
    {
        case ICMP6_ECHO:
        case ICMP6_REPLY:
            p->dsize -= 2; 
            p->data += 2;
            break;

        case ICMP6_TIME:
        case ICMP6_PARAMS:
        case ICMP6_BIG:
        case ICMP6_UNREACH:
            DecodeICMPEmbeddedIP6(p->data, p->dsize, p);
            break;
    }

    return;
}

void DecodeIPV6Extensions(u_int8_t next, const u_int8_t *pkt, u_int32_t len, Packet *p);

void DecodeIPV6Options(int type, const u_int8_t *pkt, u_int32_t len, Packet *p)
{
    int hdrlen;

    /* This should only be called by DecodeIPV6 or DecodeIPV6Extensions
     * so no validation performed.  Otherwise, uncomment the following: */
    /* if(IPH_IS_VALID(p)) return */

    pc.ipv6opts++;

    /* Need two bytes, one for hdrlen, one for 
     *     p->ip_options[p->ip_option_count].data */
    if(len < 3)
    {
        DecoderEvent(p, DECODE_IPV6_TRUNCATED, DECODE_IPV6_TRUNCATED_STR,
                     pv.decoder_flags.decode_alerts, pv.decoder_flags.drop_alerts);
        return;
    }

    hdrlen = (*(pkt+1) + 1) << 3;

    if(p->ip_option_count < IP_OPTMAX)
    {
        p->ip_options[p->ip_option_count].code = type;
        p->ip_options[p->ip_option_count].len = hdrlen;
        p->ip_options[p->ip_option_count].data = pkt+2;
        p->ip_option_count++;
    }

    if(hdrlen > len) 
    {
        DecoderEvent(p, DECODE_IPV6_TRUNCATED, DECODE_IPV6_TRUNCATED_STR,
                     pv.decoder_flags.decode_alerts, pv.decoder_flags.drop_alerts);
        return;
    }

    DecodeIPV6Extensions(*pkt, pkt + hdrlen, len - hdrlen, p);
}

void DecodeIPV6Extensions(u_int8_t next, const u_int8_t *pkt, u_int32_t len, Packet *p)
{
    /* XXX might this introduce an issue if the "next" field is invalid? */
    p->ip6h.next = next;
    pc.ip6ext++;
    
    switch(next) {
        case IPPROTO_TCP:
            pc.tcp6++;
            DecodeTCP(pkt, len, p);
            return;
        case IPPROTO_UDP:
            pc.udp6++;
            DecodeUDP(pkt, len, p);
            return;
        case IPPROTO_ICMP:
            pc.icmp++;
            DecodeICMP(pkt, len, p);
            return;
        case IPPROTO_ICMPV6:
            pc.icmp6++;
            DecodeICMP6(pkt , len, p);
            return;
        case IPPROTO_FRAGMENT:
            /* This should later be moved into frag3 */
            BsdFragVulnCheck(p, pkt, len);

            // XXX
            // Fragmentation not yet supported
            // DecodeIPv6FragHdr(p, pkt);
            // XXX 
             
            p->frag_flag = 1;
            pc.frag6++;
            p->dsize = 0;
            return;
        case IPPROTO_IPIP:
            DecodeIP(pkt, len, p);
            return;
        case IPPROTO_IPV6:
            DecodeIPV6(pkt, len, p);
            return;
        case IPPROTO_NONE:
            p->dsize = 0;
            return;
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING:
            DecodeIPV6Options(next, pkt, len, p); 
            // Anything special to do here?  just return?
            return;
        default: 
            // There may be valid headers after this unsupported one,
            // need to decode this header, set "next" and continue 
            // looping.
            pc.other++;
            p->data = pkt;
            p->dsize = len;
            break;
    };
}
#endif /* SUP_IP6 */


#ifndef SUP_IP6

/* This is the Snort-IPv4 version of the IPv6 BSD frag checking code */

#define IPV6_FRAG_STR_ALERTED 1
#define IPV6_FRAG_NO_ALERT 0
#define IPV6_FRAG_ALERT 1
#define IPV6_FRAG_BAD_PKT 2
#define IPV6_MIN_TTL_EXCEEDED 3
#define IPV6_IS_NOT 4
#define IPV6_TRUNCATED_EXT 5
#define IPV6_TRUNCATED_FRAG 6
#define IPV6_TRUNCATED 7

int CheckIPV6Frag (char *data, u_int32_t size, Packet *p)
{
    typedef struct _IP6HdrChain
    {
        u_int8_t        next_header;
        u_int8_t        length;
    } IP6HdrChain;

    IP6RawHdr *hdr;
    IP6Frag  *frag;
    IP6HdrChain *chain;
    u_int8_t next_header;
    u_int32_t offset;
    unsigned int header_length;
    unsigned short frag_data;
    char key[36]; /* Two 16 bit IP addresses and one fragmentation ID */
    SFXHASH_NODE *hash_node;

    if (sizeof(IP6RawHdr) > size)
        return IPV6_TRUNCATED;

    hdr = (IP6RawHdr *) data;

    if (sizeof(IP6RawHdr) + ntohs(hdr->ip6plen) > size)
        return IPV6_TRUNCATED;

    if(((hdr->ip6vfc & 0xf0) >> 4) != 6) 
    {
        return IPV6_IS_NOT;
    }

    /* Check TTL */
    if(hdr->ip6hops < pv.min_ttl) 
    {
        return IPV6_MIN_TTL_EXCEEDED;
    }

    next_header = hdr->ip6nxt;
    offset = sizeof(IP6RawHdr);

    while (offset < size)
    {
        switch (next_header) {
            case IP_PROTO_IPV6:
                return CheckIPV6Frag(data + offset, size - offset, p);
            case IP_PROTO_HOPOPTS:
            case IP_PROTO_ROUTING:
            case IP_PROTO_AH:
            case IP_PROTO_DSTOPTS:
                if (sizeof(IP6HdrChain) + offset > size)
                    return IPV6_TRUNCATED_EXT;

                chain = (IP6HdrChain* ) (data + offset);

                next_header     = chain->next_header;
                header_length   = 8 + (8 * chain->length);

                if (offset + header_length > size)
                    return IPV6_TRUNCATED_EXT;

                offset += header_length;
                break;

            case IP_PROTO_FRAGMENT:
                if (offset + sizeof(IP6Frag) > size)
                    return IPV6_TRUNCATED_EXT;

                frag = (IP6Frag *) (data + offset); 
                frag_data = frag->ip6f_offlg;

                /* srcip / dstip */
                memcpy(key, (data + 8), 32);
                *(u_int32_t*)(key+32) = frag->ip6f_ident;

                hash_node = sfxhash_find_node(ipv6_frag_hash, key);

                /* Check if the frag offset mask is set. 
                 * If it is, we're not looking at the exploit in question */
                if(frag_data & IP6F_OFF_MASK)
                {
                    /* If this arrives before the two 0 offset frags, we will
                     * still add them as though they were the first, and false
                     * positive */
                    if(hash_node) sfxhash_free_node(ipv6_frag_hash, hash_node);
                    return IPV6_FRAG_NO_ALERT;
                }

                /* Check if there are no more frags */
                if(!(frag_data & IP6F_MORE_FRAG))
                {
                    /* At this point, we've seen a frag header with no offset 
                     * that doesn't have the more flags set.  Need to see if 
                     * this follows a packet that did have the more flag set. */
                    if(hash_node)
                    {
                        /* Check if the first packet timed out */
                        if( (p->pkth->ts.tv_sec - *(u_int32_t*)hash_node->data)
                             > pv.ipv6_frag_timeout ) 
                        {
                            sfxhash_free_node(ipv6_frag_hash, hash_node);
                            return IPV6_FRAG_BAD_PKT;
                        }

                        if(size - offset > 100)
                        {
                            return IPV6_FRAG_ALERT;
                        }

                        sfxhash_free_node(ipv6_frag_hash, hash_node);
                         
                        return IPV6_FRAG_BAD_PKT;
                    }
                
                    /* We never saw the first packet, but this one is still bogus */
                    return IPV6_FRAG_BAD_PKT;
                }
                
                /* At this point, we've seen a header with no offset and a 
                 * more flag */
                if(!hash_node) 
                {
                    /* There are more frags remaining, add current to hash */
                    if(sfxhash_add(ipv6_frag_hash, key, (void *)&p->pkth->ts.tv_sec) 
                        == SFXHASH_NOMEM)
                    {
                        return -1;
                    }
                }
                else
                {
                    /* Update this node's timestamp */
                    *(u_int32_t*)hash_node->data = p->pkth->ts.tv_sec;
                }

            default:
                return IPV6_FRAG_NO_ALERT;
        }
    }

    return IPV6_FRAG_NO_ALERT;
}

#endif

/*
 * Function: DecodeIPV6(u_int8_t *, u_int32_t)
 *
 * Purpose: Decoding IPv6 headers
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeIPV6(const u_int8_t *pkt, u_int32_t len, Packet *p)
{
#ifndef SUP_IP6
    static u_int8_t pseudopacket_buf[ETHERNET_HEADER_LEN + IP_MAXPACKET];
    static Packet pseudopacket;
    static struct pcap_pkthdr pseudopcap_header;
    IP6RawHdr *ip6h;
    int alert_status;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ipv6++;
    else
        pc.ipv6++;
#else
    pc.ipv6++;
#endif

    alert_status = CheckIPV6Frag((char *) pkt, len, p);

    if(alert_status == IPV6_FRAG_NO_ALERT)
    {
        return;
    }

    p->packet_flags |= PKT_NO_DETECT;

    /* Need to set up a fake IP header for logging purposes.  First make sure
     * there is room */
    if(sizeof(IP6RawHdr) <= len) 
    {
        pseudopcap_header.ts.tv_sec = p->pkth->ts.tv_sec;
        pseudopcap_header.ts.tv_usec = p->pkth->ts.tv_usec;

        BsdPseudoPacket = &pseudopacket;
        pseudopacket.pkt = pseudopacket_buf;
        pseudopacket.pkth = &pseudopcap_header;

        if(p->eh)
        {
            SafeMemcpy(pseudopacket_buf, p->eh, 
                    ETHERNET_HEADER_LEN,
                    pseudopacket_buf, 
                    pseudopacket_buf + ETHERNET_HEADER_LEN + IP_MAXPACKET);

            pseudopcap_header.len = IP_HEADER_LEN + ETHERNET_HEADER_LEN;

            pseudopacket.iph = (IPHdr*)(pseudopacket_buf + ETHERNET_HEADER_LEN);
            pseudopacket.eh = (EtherHdr*)pseudopacket_buf;
            ((EtherHdr*)pseudopacket.eh)->ether_type = htons(ETHERNET_TYPE_IP);
        }
        else
        {
            SafeMemcpy(pseudopacket_buf, p->pkt, 
                    (pkt - p->pkt),
                    pseudopacket_buf, 
                    pseudopacket_buf + ETHERNET_HEADER_LEN + IP_MAXPACKET);

            pseudopcap_header.len = IP_HEADER_LEN + (pkt - p->pkt);

            pseudopacket.iph = (IPHdr*)(pseudopacket_buf + (pkt - p->pkt));
            pseudopacket.eh = NULL;
        }

        pseudopcap_header.caplen = pseudopcap_header.len;

        /* Need IP addresses for packet logging -- for now, just using the 
         * lowest 4 bytes of the IPv6 addresses */
        memset((IPHdr *)pseudopacket.iph, 0, sizeof(IPHdr));

        ((IPHdr *)pseudopacket.iph)->ip_len = htons(IP_HEADER_LEN);
        SET_IP_VER((IPHdr *)pseudopacket.iph, 0x4);
        SET_IP_HLEN((IPHdr *)pseudopacket.iph, 0x5);

        ip6h = (IP6RawHdr*)pkt;
   
#ifdef WORDS_BIGENDIAN
        ((IPHdr *)pseudopacket.iph)->ip_src.s_addr = ((u_int32_t)ip6h->ip6_src.s6_addr) & 0x00ffffff;
        ((IPHdr *)pseudopacket.iph)->ip_dst.s_addr = ((u_int32_t)ip6h->ip6_dst.s6_addr) & 0x00ffffff;
#else
        ((IPHdr *)pseudopacket.iph)->ip_src.s_addr = ((u_int32_t*)(&ip6h->ip6_src))[3] & 0xffffff00;
        ((IPHdr *)pseudopacket.iph)->ip_dst.s_addr = ((u_int32_t*)(&ip6h->ip6_dst))[3] & 0xffffff00;
#endif
    }
    else 
    {
        p->iph = NULL;
    }

    switch(alert_status) {
     case IPV6_FRAG_ALERT:
        FragEvent(p, FRAG3_IPV6_BSD_ICMP_FRAG, FRAG3_IPV6_BSD_ICMP_FRAG_STR,
                 pv.decoder_flags.bsd_icmp_frag, 
                 pv.decoder_flags.drop_bad_ipv6_frag);
        break;
      case IPV6_FRAG_BAD_PKT:
        FragEvent(p, FRAG3_IPV6_BAD_FRAG_PKT, FRAG3_IPV6_BAD_FRAG_PKT_STR,
                 pv.decoder_flags.ipv6_bad_frag_pkt,
                 pv.decoder_flags.drop_bad_ipv6_frag);
        break;
      case IPV6_MIN_TTL_EXCEEDED:
        DecoderEvent(p, DECODE_IPV6_MIN_TTL, DECODE_IPV6_MIN_TTL_STR,
            pv.decoder_flags.decode_alerts, pv.decoder_flags.drop_alerts);
        break;
   
      case IPV6_IS_NOT:
        DecoderEvent(p, DECODE_IPV6_IS_NOT, DECODE_IPV6_IS_NOT_STR,
            pv.decoder_flags.decode_alerts, pv.decoder_flags.drop_alerts);
        break;
      case IPV6_TRUNCATED_EXT:
        DecoderEvent(p,DECODE_IPV6_TRUNCATED_EXT,DECODE_IPV6_TRUNCATED_EXT_STR,
                pv.decoder_flags.decode_alerts, pv.decoder_flags.drop_alerts);
        break;
      case IPV6_TRUNCATED:
        DecoderEvent(p,DECODE_IPV6_TRUNCATED,DECODE_IPV6_TRUNCATED_STR,
                pv.decoder_flags.decode_alerts, pv.decoder_flags.drop_alerts);
    };

    pc.discards++;
    return;
#else

    IP6RawHdr *hdr; 
    int payload_len;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ipv6++;
    else
        pc.ipv6++;
#else
    pc.ipv6++;
#endif

    hdr = (IP6RawHdr*)pkt;
    p->iph = (IPHdr*)pkt;

    if(len < IP6_HDR_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("IP6 header truncated! (%d bytes)\n", len);
        }

        DecoderEvent(p, DECODE_IPV6_TRUNCATED, DECODE_IPV6_TRUNCATED_STR,
                     pv.decoder_flags.decode_alerts, pv.decoder_flags.drop_alerts);

        goto decodeipv6_fail;
    }

#ifdef GRE
    if ((p->greh != NULL) && (GET_IPH_PROTO(p) == IPPROTO_GRE))
    {
        /* discard packet - multiple GRE encapsulation
         * only allowing one level of encapsulation */
        if(pv.verbose_flag)
            ErrorMessage("Multiple GRE encapsulations in packet");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        { 
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_GRE_MULTIPLE_ENCAPSULATION, 
                           1, DECODE_CLASS, 3, DECODE_GRE_MULTIPLE_ENCAPSULATION_STR, 0);

            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

        p->greh = NULL;
        p->iph = NULL;
        pc.discards++;

        return;
    }
#endif

    /* Verify version in IP6 Header agrees */
    if((hdr->ip6vfc >> 4) != 6) 
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("Not IPv6 datagram! ([ver: 0x%x][len: 0x%x])\n", 
                    (hdr->ip6vfc >> 4), hdr->ip6plen + IP6_HDR_LEN);
        }

        DecoderEvent(p, DECODE_IPV6_IS_NOT, 
                DECODE_IPV6_IS_NOT_STR, 
                pv.decoder_flags.decode_alerts,
                pv.decoder_flags.drop_alerts);

        goto decodeipv6_fail;
    }

    payload_len = ntohs(hdr->ip6plen) + IP6_HDR_LEN;

    if(payload_len != len)
    {
        if (payload_len > len) 
        {
#ifdef DEBUG
            if (pv.verbose_flag)
                ErrorMessage("IP Len field is %d bytes bigger"
                        " than captured length.\n"
                        "    (ip.len: %lu, cap.len: %lu)\n",
                        payload_len - len, payload_len, len);
#endif
            DecoderEvent(p, DECODE_IPV6_DGRAM_GT_IPHDR, 
                    DECODE_IPV6_DGRAM_GT_IPHDR_STR, 
                    pv.decoder_flags.oversized_alert,
                    pv.decoder_flags.oversized_drop);

            goto decodeipv6_fail;
        }
        else
        {
#ifdef DEBUG
            if (pv.verbose_flag)
                ErrorMessage("IP Len field is %d bytes "
                        "smaller than captured length.\n"
                        "    (ip.len: %lu, cap.len: %lu)\n",
                        payload_len - len, payload_len, len);
#endif

        }
    }

    /* Check TTL */
    if(hdr->ip6hops < pv.min_ttl) 
    {
        DecoderEvent(p, DECODE_IPV6_MIN_TTL, DECODE_IPV6_MIN_TTL_STR, 
                    pv.decoder_flags.decode_alerts,
                    pv.decoder_flags.drop_alerts);
    }

    /* Build Packet structure's version of the IP6 header */
    sfiph_build(p, hdr, AF_INET6);

    /*
     * Some IP Header tests
     * Land Attack(same src/dst ip)
     * Loopback (src or dst in 127/8 block)
     * Modified: 2/22/05-man for High Endian Architecture.
    */
    if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)    
    {
        /* some points in the code assume an IP of 0.0.0.0 matches anything, but
         * that is not so here.  The sfip_cmp makes that assumption for 
         * compatibility, but sfip_contains does not.  Hence, sfip_contains
         * is used here in the interrim. */
        if( sfip_contains(&p->ip6h.ip_src, &p->ip6h.ip_dst) == SFIP_CONTAINS)
        {
            DecoderEvent(p, DECODE_BAD_TRAFFIC_SAME_SRCDST,
                            DECODE_BAD_TRAFFIC_SAME_SRCDST_STR,
                            pv.decoder_flags.decode_alerts,
                            pv.decoder_flags.drop_alerts);
        }
    
        if(sfip_is_loopback(&p->ip6h.ip_src) || sfip_is_loopback(&p->ip6h.ip_dst))
        {
            DecoderEvent(p, DECODE_BAD_TRAFFIC_LOOPBACK,
                            DECODE_BAD_TRAFFIC_LOOPBACK_STR,
                            pv.decoder_flags.decode_alerts,
                            pv.decoder_flags.drop_alerts);
        }
    }

    {
#ifdef GRE
        /* If delivery header for GRE encapsulated packet is IP and it 
         * had options, the packet's ip options will be refering to this
         * outer IP's options
         * Zero these options so they aren't associated with this inner IP
         * since p->iph will be pointing to this inner IP
         */
        if (p->greh != NULL)
        {
            p->ip_options_data = NULL;
            p->ip_options_len = 0;
            memset(&(p->ip_options[0]), 0, sizeof(p->ip_options));
            p->ip_lastopt_bad = 0;
        }
#endif
        p->ip_option_count = 0;
    }

// XXX-IPv6 redundant field?
    /* set the real IP length for logging */
//    p->actual_ip_len = IP6_HDR_LEN + extension headers?

    DecodeIPV6Extensions(GET_IPH_PROTO(p), pkt + IP6_HDR_LEN, ntohs(p->ip6h.len), p);
    return;

decodeipv6_fail:
    pc.discards++;
    pc.ipv6disc++;
    p->iph = NULL;  
#endif
}

/*
 * Function: DecodeEthLoopback(u_int8_t *, u_int32_t)
 *
 * Purpose: Just like IPX, it's just for counting.
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeEthLoopback(const u_int8_t *pkt, u_int32_t len, Packet *p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "EthLoopback is not supported.\n"););

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_loopback++;
    else
        pc.ethloopback++;
#else
    pc.ethloopback++;
#endif

    return;
}


/*
 * Function: DecodeIPX(u_int8_t *, u_int32_t)
 *
 * Purpose: Well, it doesn't do much of anything right now...
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 */
void DecodeIPX(const u_int8_t *pkt, u_int32_t len, Packet *p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IPX is not supported.\n"););

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ipx++;
    else
        pc.ipx++;
#else
    pc.ipx++;
#endif

    return;
}


#ifdef GRE
/*
 * Function: DecodeGRE(u_int8_t *, u_int32_t, Packet *)
 *
 * Purpose: Decode Generic Routing Encapsulation Protocol
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 *
 * Notes: see RFCs 1701 and 2784
 */
void DecodeGRE(const u_int8_t *pkt, const u_int32_t len, Packet *p)
{
    u_int8_t flags;
    u_int32_t hlen;    /* GRE header length */
    u_int32_t payload_len;
   
    if (len < GRE_HEADER_LEN)
    {
        if(pv.verbose_flag)
            ErrorMessage("GRE header length > rest of packet length");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        { 
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_GRE_DGRAM_LT_GREHDR, 
                           1, DECODE_CLASS, 3, DECODE_GRE_DGRAM_LT_GREHDR_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

        p->greh = NULL;
        pc.discards++;
        return;
    }

    if (p->greh != NULL)
    {
        /* discard packet - multiple GRE encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        if(pv.verbose_flag)
            ErrorMessage("Multiple GRE encapsulations in packet");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        { 
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_GRE_MULTIPLE_ENCAPSULATION, 
                           1, DECODE_CLASS, 3, DECODE_GRE_MULTIPLE_ENCAPSULATION_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

        p->greh = NULL;
        pc.discards++;
        return;
    }

    /* Note: Since GRE doesn't have a field to indicate header length and 
     * can contain a few options, we need to walk through the header to 
     * figure out the length
     */

    p->greh = (GREHdr *)pkt;
    hlen = GRE_HEADER_LEN;

    flags = p->greh->flags;
    flags &= 0xF8;

    /* check flags */
    if (flags & (GRE_CHECKSUM_FLAG | GRE_ROUTING_FLAG))
    {
        hlen += GRE_CHECKSUM_LEN + GRE_OFFSET_LEN;
    }

    if (flags & GRE_KEY_FLAG)
    {
        hlen += GRE_KEY_LEN;
    }   

    if (flags & GRE_SEQNO_FLAG)
    {
        hlen += GRE_SEQNO_LEN;
    }

    /* if this flag is set, we need to walk through all of the
     * Source Route Entries
     */
    if (flags & GRE_ROUTING_FLAG)
    {
        u_int16_t sre_addrfamily;
        u_int8_t sre_offset;
        u_int8_t sre_length;
        u_int8_t *sre_ptr;
       
        sre_ptr = pkt + hlen;

        while (1)
        {
            hlen += GRE_SRE_HEADER_LEN;
            if (hlen > len)
                break;

            sre_addrfamily = ntohs(*((u_int16_t *)sre_ptr));
            sre_ptr += sizeof(sre_addrfamily);

            sre_offset = *((u_int8_t *)sre_ptr);
            sre_ptr += sizeof(sre_offset);

            sre_length = *((u_int8_t *)sre_ptr);
            sre_ptr += sizeof(sre_length);

            if (sre_addrfamily == 0 && sre_length == 0)
                break;

            hlen += sre_length;
            sre_ptr += sre_length;
        }
    }

    if (hlen > len)
    {
        if(pv.verbose_flag)
            ErrorMessage("GRE header length > rest of packet length");

        if((runMode == MODE_IDS) && pv.decoder_flags.decode_alerts)
        { 
            SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_GRE_DGRAM_LT_GREHDR, 
                           1, DECODE_CLASS, 3, DECODE_GRE_DGRAM_LT_GREHDR_STR, 0);
            if ((InlineMode()) && pv.decoder_flags.drop_alerts)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                InlineDrop(p);
            }
        }

        p->greh = NULL;
        pc.discards++;
        return;
    }

    payload_len = len - hlen;

    /* Send to next protocol decoder */
    /* As described in RFC 2784 the possible protocols are listed in
     * RFC 1700 under "ETHER TYPES"
     * See also "Current List of Protocol Types" in RFC 1701
     */
    switch (ntohs(p->greh->ether_type))
    {
        case ETHERNET_TYPE_IP:
            DecodeIP(pkt + hlen, payload_len, p);
            return;

        case GRE_TYPE_TRANS_BRIDGING:
            DecodeTransBridging(pkt + hlen, payload_len, p); 
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(pkt + hlen, payload_len, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(pkt + hlen, payload_len, p); 
            return;

        case ETHERNET_TYPE_IPX:
            DecodeIPX(pkt + hlen, payload_len, p); 
            return;

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(pkt + hlen, payload_len, p);
            return; 

        default:
            pc.other++;
            p->data = pkt + hlen;
            p->dsize = (u_int16_t)payload_len;
            return;
    }
}

/*
 * Function: DecodeTransBridging(u_int8_t *, const u_int32_t, Packet)
 *
 * Purpose: Decode Transparent Ethernet Bridging
 *
 * Arguments: pkt => pointer to the real live packet data
 *            len => length of remaining data in packet
 *            p => pointer to the decoded packet struct
 *            
 *
 * Returns: void function
 *
 * Note: This is basically the code from DecodeEthPkt but the calling
 * convention needed to be changed and the stuff at the beginning 
 * wasn't needed since we are already deep into the packet
 */
void DecodeTransBridging(const u_int8_t *pkt, const u_int32_t len, Packet *p)
{
    pc.gre_eth++;

    if(len < ETHERNET_HEADER_LEN)
    {
        if(pv.verbose_flag)
        {
            ErrorMessage("GRE encapsulated ethernet header truncated! (%d bytes)\n", len);
        }

        return;
    }

    /* The Packet struct's ethernet header will now point to the inner ethernet
     * header of the packet
     */
    p->eh = (EtherHdr *)pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "GRE encapsulated ethernet header\n %X   %X\n", 
                            *p->eh->ether_src, *p->eh->ether_dst););

    switch (ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "GRE encapsulated IP datagram size calculated to be %lu bytes\n",
                                   (unsigned long)(len - ETHERNET_HEADER_LEN)););

            DecodeIP(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_IPX:
            DecodeIPX(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return; 

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return; 

        default:
            pc.other++;
            p->data = pkt + ETHERNET_HEADER_LEN;
            p->dsize = (u_int16_t)(len - ETHERNET_HEADER_LEN);
            return;
    }

    return;
}

#endif


/** 
 * Validate that the length is an expected length AND that it's in bounds
 *
 * EOL and NOP are handled separately
 * 
 * @param option_ptr current location
 * @param end the byte past the end of the decode list
 * @param len_ptr the pointer to the length field
 * @param expected_len the number of bytes we expect to see per rfc KIND+LEN+DATA, -1 means dynamic.
 * @param tcpopt options structure to populate
 * @param byte_skip distance to move upon completion
 *
 * @return returns 0 on success, < 0 on error
 */
static inline int OptLenValidate(const u_int8_t *option_ptr,
                                    const u_int8_t *end,
                                    const u_int8_t *len_ptr,
                                    int expected_len,
                                    Options *tcpopt,
                                    u_int8_t *byte_skip)
{
    *byte_skip = 0;
    
    if(len_ptr == NULL)
    {
        return TCP_OPT_TRUNC;
    }
    
    if(*len_ptr == 0 || expected_len == 0 || expected_len == 1)
    {
        return TCP_OPT_BADLEN;
    }
    else if(expected_len > 1)
    {
        if((option_ptr + expected_len) > end)
        {
            /* not enough data to read in a perfect world */
            return TCP_OPT_TRUNC;
        }

        if(*len_ptr != expected_len)
        {
            /* length is not valid */
            return TCP_OPT_BADLEN;
        }
    }
    else /* expected_len < 0 (i.e. variable length) */
    {
        if(*len_ptr < 2)
        {
            /* RFC sez that we MUST have atleast this much data */
            return TCP_OPT_BADLEN;
        }
           
        if((option_ptr + *len_ptr) > end)
        {
            /* not enough data to read in a perfect world */
            return TCP_OPT_TRUNC;
        }
    }

    tcpopt->len = *len_ptr - 2;

    if(*len_ptr == 2)
    {
        tcpopt->data = NULL;
    }
    else
    {
        tcpopt->data = option_ptr + 2;
    }

    *byte_skip = *len_ptr;
    
    return 0;
}

/*
 * Function: DecodeTCPOptions(u_int8_t *, u_int32_t, Packet *)
 *
 * Purpose: Fairly self explainatory name, don't you think?
 *
 *          TCP Option Header length validation is left to the caller
 *
 *          For a good listing of TCP Options, 
 *          http://www.iana.org/assignments/tcp-parameters 
 *
 *   ------------------------------------------------------------
 *   From: "Kastenholz, Frank" <FKastenholz@unispherenetworks.com>
 *   Subject: Re: skeeter & bubba TCP options?
 *
 *   ah, the sins of ones youth that never seem to be lost...
 *
 *   it was something that ben levy and stev and i did at ftp many
 *   many moons ago. bridgham and stev were the instigators of it.
 *   the idea was simple, put a dh key exchange directly in tcp
 *   so that all tcp sessions could be encrypted without requiring
 *   any significant key management system. authentication was not
 *   a part of the idea, it was to be provided by passwords or
 *   whatever, which could now be transmitted over the internet
 *   with impunity since they were encrypted... we implemented
 *   a simple form of this (doing the math was non trivial on the
 *   machines of the day). it worked. the only failure that i 
 *   remember was that it was vulnerable to man-in-the-middle 
 *   attacks.
 *   
 *   why "skeeter" and "bubba"? well, that's known only to stev...
 *   ------------------------------------------------------------
 *
 * 4.2.2.5 TCP Options: RFC-793 Section 3.1
 *
 *    A TCP MUST be able to receive a TCP option in any segment. A TCP
 *    MUST ignore without error any TCP option it does not implement,
 *    assuming that the option has a length field (all TCP options
 *    defined in the future will have length fields). TCP MUST be
 *    prepared to handle an illegal option length (e.g., zero) without
 *    crashing; a suggested procedure is to reset the connection and log
 *    the reason.
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeTCPOptions(const u_int8_t *start, u_int32_t o_len, Packet *p)
{
    const u_int8_t *option_ptr = start;
    const u_int8_t *end_ptr = start + o_len; /* points to byte after last option */
    const u_int8_t *len_ptr;
    u_int32_t opt_count = 0;
    u_char done = 0; /* have we reached TCPOPT_EOL yet?*/
    u_char experimental_option_found = 0;      /* are all options RFC compliant? */
    u_char obsolete_option_found = 0;
    u_char ttcp_found = 0;
    
    int code = 2;
    u_int8_t byte_skip;

    /* Here's what we're doing so that when we find out what these
     * other buggers of TCP option codes are, we can do something
     * useful
     * 
     * 1) get option code
     * 2) check for enough space for current option code
     * 3) set option data ptr
     * 4) increment option code ptr
     *
     * TCP_OPTLENMAX = 40 because of
     *        (((2^4) - 1) * 4  - TCP_HEADER_LEN)
     *      
     */

    if(o_len > TCP_OPTLENMAX)
    {
        /* This shouldn't ever alert if we are doing our job properly
         * in the caller */        
        p->tcph = NULL; /* let's just alert */
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                                "o_len(%u) > TCP_OPTLENMAX(%u)\n",
                                o_len, TCP_OPTLENMAX));
        return;
    }
    
    while((option_ptr < end_ptr) && (opt_count < TCP_OPTLENMAX) && (code >= 0) && !done)
    {
        p->tcp_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }
        
        switch(*option_ptr)
        {
        case TCPOPT_EOL:
            done = 1; /* fall through to the NOP case */
        case TCPOPT_NOP:
            p->tcp_options[opt_count].len = 0; 
            p->tcp_options[opt_count].data = NULL;
            byte_skip = 1;
            code = 0;
            break;
        case TCPOPT_MAXSEG:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MAXSEG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;            
        case TCPOPT_SACKOK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_SACKOK,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;            
        case TCPOPT_WSCALE:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_WSCALE,
                                  &p->tcp_options[opt_count], &byte_skip);
            if (code == 0)
            {
                if ((runMode == MODE_IDS) &&
                    ((u_int16_t) p->tcp_options[opt_count].data[0] > 14))
                {
                    /* LOG INVALID WINDOWSCALE alert */
                    if(pv.decoder_flags.tcpopt_decode)
                    {
                        SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                            DECODE_TCPOPT_WSCALE_INVALID, 1, DECODE_CLASS, 3, 
                            DECODE_TCPOPT_WSCALE_INVALID_STR, 0);

                        if ((InlineMode()) && pv.decoder_flags.drop_tcpopt_decode)
                        {
                            DEBUG_WRAP( DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                            InlineDrop(p);
                        }
                    }
                }
            }
            break;            
        case TCPOPT_ECHO: /* both use the same lengths */
        case TCPOPT_ECHOREPLY:
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_ECHO,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_MD5SIG:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MD5SIG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_SACK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            if(p->tcp_options[opt_count].data == NULL)
                code = TCP_OPT_BADLEN;

            break;
        case TCPOPT_CC_ECHO:
            ttcp_found = 1;
            /* fall through */
        case TCPOPT_CC:  /* all 3 use the same lengths / T/TCP */
        case TCPOPT_CC_NEW:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_CC,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_TRAILER_CSUM:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TRAILER_CSUM,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;

        case TCPOPT_TIMESTAMP:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TIMESTAMP,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
    
        case TCPOPT_SKEETER:
        case TCPOPT_BUBBA:
        case TCPOPT_UNASSIGNED:
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        default:
        case TCPOPT_SCPS:  
        case TCPOPT_SELNEGACK:
        case TCPOPT_RECORDBOUND:
        case TCPOPT_CORRUPTION:
        case TCPOPT_PARTIAL_PERM:
        case TCPOPT_PARTIAL_SVC:
        case TCPOPT_ALTCSUM:
        case TCPOPT_SNAP:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        }

        if(code < 0)
        {
            if(runMode == MODE_IDS)
            {
                if(code == TCP_OPT_BADLEN && pv.decoder_flags.tcpopt_decode)
                {
                    SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                                   DECODE_TCPOPT_BADLEN, 1, DECODE_CLASS, 3, 
                                   DECODE_TCPOPT_BADLEN_STR, 0);

                    if ((InlineMode()) && pv.decoder_flags.drop_tcpopt_decode)
                    {
                        DEBUG_WRAP( DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                        InlineDrop(p);
                    }
                }
                else if(code == TCP_OPT_TRUNC && pv.decoder_flags.tcpopt_decode)
                {
                    SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                                   DECODE_TCPOPT_TRUNCATED, 1, DECODE_CLASS, 3, 
                                   DECODE_TCPOPT_TRUNCATED_STR, 0);

                    if ((InlineMode()) && pv.decoder_flags.drop_tcpopt_decode)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                        InlineDrop(p);
                    }
                }
            }

            /* set the option count to the number of valid
             * options found before this bad one
             * some implementations (BSD and Linux) ignore
             * the bad ones, but accept the good ones */
            p->tcp_option_count = opt_count;

            return;
        }

        opt_count++;

        option_ptr += byte_skip;
    }

    p->tcp_option_count = opt_count;

    if(runMode == MODE_IDS &&
       experimental_option_found && pv.decoder_flags.tcpopt_experiment)
    {
        SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_TCPOPT_EXPERIMENT, 1, 
                       DECODE_CLASS, 3, DECODE_TCPOPT_EXPERIMENT_STR, 0);

        if ((InlineMode()) && pv.decoder_flags.drop_tcpopt_experiment)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
            InlineDrop(p);
        }

    }
    else if(runMode == MODE_IDS &&
            obsolete_option_found && pv.decoder_flags.tcpopt_obsolete)
    {
        SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_TCPOPT_OBSOLETE, 1, 
                       DECODE_CLASS, 3, DECODE_TCPOPT_OBSOLETE_STR, 0);

        if ((InlineMode()) && pv.decoder_flags.drop_tcpopt_obsolete)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
            InlineDrop(p);
        }

    }
    else if(runMode == MODE_IDS &&
            ttcp_found && pv.decoder_flags.tcpopt_ttcp)
    {
        SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_TCPOPT_TTCP, 1, 
                       DECODE_CLASS, 3, DECODE_TCPOPT_TTCP_STR, 0);

        if ((InlineMode()) && pv.decoder_flags.drop_tcpopt_ttcp)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
            InlineDrop(p);
        }

    }

    return;
}


/*
 * Function: DecodeIPOptions(u_int8_t *, u_int32_t, Packet *)
 *
 * Purpose: Once again, a fairly self-explainatory name
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeIPOptions(const u_int8_t *start, u_int32_t o_len, Packet *p)
{
    const u_int8_t *option_ptr = start;
    u_char done = 0; /* have we reached IP_OPTEOL yet? */
    const u_int8_t *end_ptr = start + o_len;
    u_int32_t opt_count = 0; /* what option are we processing right now */
    u_int8_t byte_skip;
    const u_int8_t *len_ptr;
    int code = 0;  /* negative error codes are returned from bad options */
    

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,  "Decoding %d bytes of IP options\n", o_len););


    while((option_ptr < end_ptr) && (opt_count < IP_OPTMAX) && (code >= 0))
    {
        p->ip_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }

        switch(*option_ptr)
        {
        case IPOPT_NOP:
        case IPOPT_EOL:
            /* if we hit an EOL, we're done */
            if(*option_ptr == IPOPT_EOL)
                done = 1;
            
            p->ip_options[opt_count].len = 0;
            p->ip_options[opt_count].data = NULL;
            byte_skip = 1;
            break;
        default:
            /* handle all the dynamic features */
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->ip_options[opt_count], &byte_skip);
        }

        if(code < 0)
        {
            if(runMode == MODE_IDS)
            {
                /* Yes, we use TCP_OPT_* for the IP option decoder.
                */
                if(code == TCP_OPT_BADLEN && pv.decoder_flags.ipopt_decode)
                {
                    SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                            DECODE_IPV4OPT_BADLEN, 1, DECODE_CLASS, 3, 
                            DECODE_IPV4OPT_BADLEN_STR, 0);

                    if ((InlineMode()) && pv.decoder_flags.drop_ipopt_decode)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                        InlineDrop(p);
                    }
                }
                else if(code == TCP_OPT_TRUNC && pv.decoder_flags.ipopt_decode)
                {
                    SnortEventqAdd(GENERATOR_SNORT_DECODE, 
                            DECODE_IPV4OPT_TRUNCATED, 1, DECODE_CLASS, 3, 
                            DECODE_IPV4OPT_TRUNCATED_STR, 0);
                    
                    if ((InlineMode()) && pv.decoder_flags.drop_ipopt_decode)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
                        InlineDrop(p);
                    }
                }
            }

            return;
        }

        if(!done)
            opt_count++;

        option_ptr += byte_skip;
    }
    
    p->ip_option_count = opt_count;

    return;
}


/** 
 * Setup all the flags for the decoder alerts
 */
void InitDecoderFlags(void)
{
    /* turn on decoder alerts by default -- useful for bug reports.. */
    pv.decoder_flags.decode_alerts          = 1;
    pv.decoder_flags.oversized_alert        = 0;
    pv.decoder_flags.oversized_drop         = 0;
    pv.decoder_flags.drop_alerts            = 0;
    pv.decoder_flags.tcpopt_experiment      = 1;
    pv.decoder_flags.drop_tcpopt_experiment = 0;
    pv.decoder_flags.tcpopt_obsolete        = 1;
    pv.decoder_flags.drop_tcpopt_obsolete   = 0;
    pv.decoder_flags.tcpopt_ttcp            = 1;
    pv.decoder_flags.drop_tcpopt_ttcp       = 0;
    pv.decoder_flags.tcpopt_decode          = 1;
    pv.decoder_flags.drop_tcpopt_decode     = 0;
    pv.decoder_flags.ipopt_decode           = 1;
    pv.decoder_flags.drop_ipopt_decode      = 0;
    pv.decoder_flags.ipv6_bad_frag_pkt      = 1;
    pv.decoder_flags.bsd_icmp_frag          = 1;
    pv.decoder_flags.drop_bad_ipv6_frag     = 1;

}

#if defined(WORDS_MUSTALIGN) && !defined(__GNUC__)
u_int32_t
EXTRACT_32BITS (u_char *p)
{
  u_int32_t __tmp;

  memmove(&__tmp, p, sizeof(u_int32_t));
  return (u_int32_t) ntohl(__tmp);
}
#endif /* WORDS_MUSTALIGN && !__GNUC__ */
