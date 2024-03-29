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
 
/**
 * @file   util_math.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 27 10:12:57 2003
 * 
 * @brief  math related util functions
 * 
 * Place simple math functions that are useful all over the place
 * here.
 */

#ifndef _UTIL_MATH_H
#define _UTIL_MATH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"

double calc_percent(double amt, double total);
double calc_percent64(UINT64 amt, UINT64 total);

#endif /* _UTIL_MATH_H */


