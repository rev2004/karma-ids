/*
 * dcerpc.c
 *
 * Copyright (C) 2006 Sourcefire,Inc
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif

#include "debug.h"
#include "sf_snort_packet.h"
#include "bounds.h"

#include "smb_structs.h"
#include "snort_dcerpc.h"
#include "dcerpc_util.h"
#include "dcerpc.h"

extern u_int16_t _max_frag_size;

extern DCERPC         *_dcerpc;
extern SFSnortPacket  *_dcerpc_pkt;
extern u_int8_t        _disable_dcerpc_fragmentation;
extern u_int8_t        _debug_print;

/* Check to see if we have a full DCE/RPC fragment
 * Guarantees:
 *  There is enough data to slap header on and grab fields from
 *  Is most likely a DCE/RPC packet
 *  DCE/RPC fragment length is greater than the size of request header
 *  DCE/RPC fragment length is less than or equal to size of data remaining
 */
int IsCompleteDCERPCMessage(const u_int8_t *data, u_int16_t size)
{
    const DCERPC_HDR *dcerpc;
    u_int16_t       frag_length;

    if ( size <= sizeof(DCERPC_REQ) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Error: Not enough data for DCERPC structure.\n"););
        return 0;
    }

    /* Check to see if this is a valid DCE/RPC packet */
    dcerpc = (const DCERPC_HDR *) data;

    /*  Check for version and packet type - mark as DCERPC session */
    if ( dcerpc->version != 5 || 
        (dcerpc->packet_type != DCERPC_REQUEST && dcerpc->packet_type != DCERPC_BIND) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Error: Not a DCERPC bind or request.\n"););
        return 0;
    }

    frag_length = dcerpc_ntohs(dcerpc->byte_order, dcerpc->frag_length);

    if (frag_length <= sizeof(DCERPC_REQ))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Error: DCERPC frag length <= size of request header.\n"););
        return 0;
    }

    /* Wait until we have the whole DCE/RPC message */
    if ( frag_length > size )
        return 0;
    
    return 1;
}

/* Return 1 if successfully parsed at least one message */
/* TODO After collecting full DCE/RPC fragments, there might be part of a
 * fragment left - need to tell caller that there is some data left and 
 * where it is, i.e. return a pointer to it and the size left.
 */
int ProcessDCERPCMessage(const u_int8_t *smb_hdr, u_int16_t smb_hdr_len, const u_int8_t *data, u_int16_t size)
{
    const DCERPC_HDR *dcerpc;
    u_int16_t       current_size = size;
    const u_int8_t  *current_data = data;
    u_int16_t       frag_length;

    if ( !IsCompleteDCERPCMessage(data, size) )
        return 0;

    _dcerpc->state = STATE_IS_DCERPC;
   
    /* Check fragmentation - got at least one full fragment */
    while (current_size > 0 )
    {
        dcerpc = (DCERPC_HDR *) current_data;
        frag_length = dcerpc_ntohs(dcerpc->byte_order, dcerpc->frag_length);

        if ( DCERPC_Fragmentation(current_data, current_size, frag_length) == 1 )
        {
            ReassembleDCERPCRequest(smb_hdr, smb_hdr_len, current_data);
        }

        current_size -= frag_length;
        current_data += frag_length;

        /* see if we have another full fragment in this packet */
        if ( !IsCompleteDCERPCMessage(current_data, current_size) )
            break;
    }

    return 1;
}


/*
    Return  0 if not fragmented OR if fragmented and not last fragment
    Return  1 if fragmented and last fragment
 */
int DCERPC_Fragmentation(const u_int8_t *data, u_int16_t data_size, u_int16_t frag_length)
{
    DCERPC_HDR     *dcerpc_hdr;
    int ret = 0;

    if ( _dcerpc->state == STATE_IS_DCERPC )
    {
        if ( data_size <= sizeof(DCERPC_REQ) )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Error: Not a DCERPC request.\n"););
            return -1;
        }

        dcerpc_hdr = (DCERPC_HDR *) data;

        if ( _disable_dcerpc_fragmentation )
        {
            return 0;
        }

        if ( frag_length <= sizeof(DCERPC_REQ) )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Invalid frag length in DCERPC request.\n"););
            return -1;
        }

        if ( frag_length > _max_frag_size )
        {
            frag_length = _max_frag_size;
        }
        
        if ( !(_dcerpc->fragmentation & SUSPEND_FRAGMENTATION) )
        {
            if ( _dcerpc->fragmentation & RPC_FRAGMENTATION )
            {
                /* Already fragmented, get more buffer space if needed */
                if ( dcerpc_hdr->packet_type == DCERPC_REQUEST )
                {
                    u_int16_t    dcerpc_len;
                    u_int16_t    old_buf_size = _dcerpc->dcerpc_req_buf_size;

                    dcerpc_len = frag_length - sizeof(DCERPC_REQ);

                    if ( _dcerpc->dcerpc_req_buf_size >= (0xFFFF - dcerpc_len) )
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC fragmentation overflow.\n"););

                        DCERPC_FragFree(_dcerpc->dcerpc_req_buf, 0);
                        _dcerpc->dcerpc_req_buf_len = 0;
                        _dcerpc->dcerpc_req_buf_size = 0;
                        _dcerpc->dcerpc_req_buf = NULL;
                        _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;

                        return 0;
                    }

                    if ( dcerpc_len > (data_size - sizeof(DCERPC_REQ)) )
                    {
                        dcerpc_len = data_size - sizeof(DCERPC_REQ);
                    }

                    if ( _dcerpc->dcerpc_req_buf_size < (_dcerpc->dcerpc_req_buf_len + dcerpc_len) )
                    {
                        while ( _dcerpc->dcerpc_req_buf_size < (_dcerpc->dcerpc_req_buf_len + dcerpc_len) )
                        {
                            if ( _dcerpc->dcerpc_req_buf_size > 0x7FFF )
                            {
                                _dcerpc->dcerpc_req_buf_size = 0xFFFF;
                                break;
                            }
                            else
                            {
                                _dcerpc->dcerpc_req_buf_size *= 2;
                            }
                        }

                        if ( _dcerpc->dcerpc_req_buf_size > _dpd.altBufferLen )
                            _dcerpc->dcerpc_req_buf_size = (u_int16_t) _dpd.altBufferLen;

                        _dcerpc->dcerpc_req_buf = DCERPC_FragAlloc(_dcerpc->dcerpc_req_buf, old_buf_size,
                                                                            &_dcerpc->dcerpc_req_buf_size);

                        if ( _dcerpc->dcerpc_req_buf_size == old_buf_size )
                        {
                            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Memcap reached, suspending DCE/RPC fragmentation reassembly.\n"););

                            _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;
                        }

                        if ( !_dcerpc->dcerpc_req_buf )
                            DynamicPreprocessorFatalMessage("Failed to reallocate space for DCE/RPC fragmented request\n");

                    }

                    if ( _dcerpc->dcerpc_req_buf_len < _dcerpc->dcerpc_req_buf_size )
                    {                   
                        if ( _dcerpc->dcerpc_req_buf_len + dcerpc_len > _dcerpc->dcerpc_req_buf_size )
                        {
                            dcerpc_len = _dcerpc->dcerpc_req_buf_size - _dcerpc->dcerpc_req_buf_len;
                        }

                        ret = SafeMemcpy(_dcerpc->dcerpc_req_buf + _dcerpc->dcerpc_req_buf_len,
                                         data + sizeof(DCERPC_REQ), dcerpc_len,
                                         _dcerpc->dcerpc_req_buf, _dcerpc->dcerpc_req_buf + _dcerpc->dcerpc_req_buf_size);

                        if (ret == 0)
                        {
                            DCERPC_FragFree(_dcerpc->dcerpc_req_buf, 0);
                            _dcerpc->dcerpc_req_buf_len = 0;
                            _dcerpc->dcerpc_req_buf_size = 0;
                            _dcerpc->dcerpc_req_buf = NULL;
                            _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;

                            return 0;
                        }

                        _dcerpc->dcerpc_req_buf_len += dcerpc_len;

                        if ( _debug_print )
                            PrintBuffer("DCE/RPC fragment", data + sizeof(DCERPC_REQ), dcerpc_len);
                    }
                }
            }
            else
            {
                /* Check for DCE/RPC fragmentation */
                if ( (dcerpc_hdr->flags & DCERPC_FIRST_FRAG) && !(dcerpc_hdr->flags & DCERPC_LAST_FRAG) )
                {
                    u_int16_t  alloc_size = DCERPC_FRAG_ALLOC;

                    _dcerpc->dcerpc_req_buf_len = frag_length - sizeof(DCERPC_REQ);

                    if ( _dcerpc->dcerpc_req_buf_len > (data_size - sizeof(DCERPC_REQ)) )
                    {
                        _dcerpc->dcerpc_req_buf_len = data_size - sizeof(DCERPC_REQ);
                    }

                    if ( _dcerpc->dcerpc_req_buf_len > DCERPC_FRAG_ALLOC )
                    {
                        alloc_size = _dcerpc->dcerpc_req_buf_len;
                    }
                    _dcerpc->dcerpc_req_buf = (u_int8_t *) DCERPC_FragAlloc(NULL, 0, &alloc_size);

                    if ( alloc_size == 0 )
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Memcap reached, ignoring DCE/RPC fragmentation reassembly.\n"););

                        DCERPC_FragFree(_dcerpc->dcerpc_req_buf, 0);
                        _dcerpc->dcerpc_req_buf_len = 0;
                        _dcerpc->dcerpc_req_buf_size = 0;
                        _dcerpc->dcerpc_req_buf = NULL;
                        _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;

                        return 0;
                    }

                    if ( !_dcerpc->dcerpc_req_buf )
                        DynamicPreprocessorFatalMessage("Failed to allocate space for first DCE/RPC fragmented request\n");


                    if ( _dcerpc->dcerpc_req_buf_len > alloc_size )
                    {
                        _dcerpc->dcerpc_req_buf_len = alloc_size;
                    }

                    _dcerpc->dcerpc_req_buf_size = alloc_size;

                    ret = SafeMemcpy(_dcerpc->dcerpc_req_buf, data + sizeof(DCERPC_REQ), _dcerpc->dcerpc_req_buf_len,
                                     _dcerpc->dcerpc_req_buf, _dcerpc->dcerpc_req_buf + _dcerpc->dcerpc_req_buf_size);

                    if (ret == 0)
                    {
                        DCERPC_FragFree(_dcerpc->dcerpc_req_buf, 0);
                        _dcerpc->dcerpc_req_buf_len = 0;
                        _dcerpc->dcerpc_req_buf_size = 0;
                        _dcerpc->dcerpc_req_buf = NULL;
                        _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;

                        return 0;
                    }

                    _dcerpc->fragmentation |= RPC_FRAGMENTATION;

                    if ( _debug_print )
                        PrintBuffer("DCE/RPC fragment", data + sizeof(DCERPC_REQ), _dcerpc->dcerpc_req_buf_len);                
                }
                else
                {
                    return 0;
                }
            }
        }
      
        /* Check for last frag */
        if ( (_dcerpc->fragmentation & RPC_FRAGMENTATION) && dcerpc_hdr->flags & DCERPC_LAST_FRAG )
        {
            return 1;
        }
    }

    return 0;
}

void ReassembleDCERPCRequest(const u_int8_t *smb_hdr, u_int16_t smb_hdr_len, const u_int8_t *data)
{
    DCERPC_REQ      fake_req;
    unsigned int    dcerpc_req_len = sizeof(DCERPC_REQ);
    int             ret;

    /* Make sure we have room to fit into alternate buffer */
    if ( (smb_hdr_len + dcerpc_req_len + _dcerpc->dcerpc_req_buf_len) > (u_int16_t) _dpd.altBufferLen )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Reassembled DCE/RPC packet greater than %d bytes, skipping.", _dpd.altBufferLen));
        return;
    }
   
    /* Mock up header */
    ret = SafeMemcpy(&fake_req, data, dcerpc_req_len, &fake_req, (u_int8_t *)&fake_req + dcerpc_req_len);
    
    if (ret == 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC header, skipping DCERPC reassembly."));
        goto dcerpc_frag_free;
    }

    fake_req.dcerpc_hdr.frag_length = dcerpc_req_len + _dcerpc->dcerpc_req_buf_len;
    fake_req.dcerpc_hdr.flags &= ~DCERPC_FIRST_FRAG;
    fake_req.dcerpc_hdr.flags &= ~DCERPC_LAST_FRAG;
    fake_req.alloc_hint = _dcerpc->dcerpc_req_buf_len;

    /* Copy headers into buffer */
    _dcerpc_pkt->normalized_payload_size = 0;

    if ( smb_hdr )
    {
        ret = SafeMemcpy(_dpd.altBuffer, _dcerpc_pkt->payload, sizeof(NBT_HDR),
                                                    _dpd.altBuffer, _dpd.altBuffer + _dpd.altBufferLen);
        if ( ret == 0 )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC header, skipping DCERPC reassembly."));
            goto dcerpc_frag_free;
        }
        _dcerpc_pkt->normalized_payload_size = sizeof(NBT_HDR);
        ret = SafeMemcpy(_dpd.altBuffer + _dcerpc_pkt->normalized_payload_size, smb_hdr, smb_hdr_len,
                                                    _dpd.altBuffer, _dpd.altBuffer + _dpd.altBufferLen);
        if ( ret == 0 )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC header, skipping DCERPC reassembly."));
            goto dcerpc_frag_free;
        }
        _dcerpc_pkt->normalized_payload_size += smb_hdr_len;
    }

    ret = SafeMemcpy(_dpd.altBuffer + _dcerpc_pkt->normalized_payload_size, &fake_req, dcerpc_req_len,
                                                    _dpd.altBuffer, _dpd.altBuffer + _dpd.altBufferLen);
    if ( ret == 0 )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC header, skipping DCERPC reassembly."));
        goto dcerpc_frag_free;
    }
    _dcerpc_pkt->normalized_payload_size += dcerpc_req_len;

    /* Copy data into buffer */
    ret = SafeMemcpy(_dpd.altBuffer + _dcerpc_pkt->normalized_payload_size, _dcerpc->dcerpc_req_buf, _dcerpc->dcerpc_req_buf_len,
                                                    _dpd.altBuffer, _dpd.altBuffer + _dpd.altBufferLen);
    if ( ret == 0 )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC data, skipping DCERPC reassembly."));
        goto dcerpc_frag_free;
    }
    _dcerpc_pkt->normalized_payload_size += _dcerpc->dcerpc_req_buf_len;

    _dcerpc_pkt->flags |= FLAG_ALT_DECODE;

    if ( _debug_print )
        PrintBuffer("DCE/RPC reassembled fragment", (u_int8_t *)_dpd.altBuffer, _dcerpc_pkt->normalized_payload_size);

dcerpc_frag_free:    
    /* Get ready for next write */
    DCERPC_FragFree(_dcerpc->dcerpc_req_buf, _dcerpc->dcerpc_req_buf_size);
    _dcerpc->dcerpc_req_buf = NULL;
    _dcerpc->dcerpc_req_buf_len = 0;
    _dcerpc->dcerpc_req_buf_size = 0;
    _dcerpc->fragmentation &= ~RPC_FRAGMENTATION;
    _dcerpc->fragmentation &= ~SUSPEND_FRAGMENTATION;
}


