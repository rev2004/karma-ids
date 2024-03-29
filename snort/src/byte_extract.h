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
 
#ifndef _BYTE_EXTRACT_H
#define _BYTE_EXTRACT_H

#define BIG    0
#define LITTLE 1

#define PARSELEN 10

int string_extract(int bytes_to_grab, int base, const u_int8_t *ptr,
                   const u_int8_t *start, const u_int8_t *end,
                   u_int32_t *value);

int byte_extract(int endianess, int bytes_to_grab, const u_int8_t *ptr,
                 const u_int8_t *start, const u_int8_t *end,
                 u_int32_t *value);

#endif /* _BYTE_EXTRACT_H */
