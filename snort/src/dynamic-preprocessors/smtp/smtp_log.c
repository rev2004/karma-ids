/****************************************************************************
 *
 * Copyright (C) 2005-2007 Sourcefire Inc.
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
  
/************************************************************************** 
 *
 * smtp_log.c
 *
 * Author: Andy Mullican
 *
 * Description:
 *
 * This file handles SMTP alerts.
 *
 * Entry point functions:
 *
 *    SMTP_GenerateAlert()
 *
 *
 **************************************************************************/

#include <stdarg.h>
#include <stdio.h>

#include "debug.h"
#include "smtp_config.h"
#include "smtp_log.h"
#include "sf_dynamic_preprocessor.h"

extern SMTPConfig _smtp_config;
extern DynamicPreprocessorData _dpd;

char _smtp_event[SMTP_EVENT_MAX][EVENT_STR_LEN];


void SMTP_GenerateAlert(int event, char *format, ...)
{
    va_list ap;

    if (_smtp_config.no_alerts)
    {
#ifdef DEBUG
        va_start(ap, format);

        _smtp_event[event][0] = '\0';
        vsnprintf(&_smtp_event[event][0], EVENT_STR_LEN - 1, format, ap);
        _smtp_event[event][EVENT_STR_LEN - 1] = '\0';

        DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Ignoring alert: %s\n", _smtp_event[event]););

        va_end(ap);
#endif

        return;
    }

    va_start(ap, format);

    _smtp_event[event][0] = '\0';
    vsnprintf(&_smtp_event[event][0], EVENT_STR_LEN - 1, format, ap);
    _smtp_event[event][EVENT_STR_LEN - 1] = '\0';

    _dpd.alertAdd(GENERATOR_SMTP, event, 1, 0, 3, &_smtp_event[event][0], 0);

    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "SMTP Alert generated: %s\n", _smtp_event[event]););

    va_end(ap);
}

