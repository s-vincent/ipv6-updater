/*
 Copyright (C) 2006-2008 Sebastien Vincent.

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.

 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 PERFORMANCE OF THIS SOFTWARE.
*/

/**
 * \file dbg.c
 * \brief Some routines to print debug message.
 * \author Sebastien Vincent
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#ifdef _MSC_VER
#include <windows.h>
/* replacement for stdint.h */
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#include <sys/time.h>
#endif

#include <time.h>
#include "dbg.h"

#ifdef __cplusplus
extern "C"
{
#endif

    void dbg_print(const char* f, int line, char* format, ...)
    {
        va_list args;

#ifdef _MSC_VER
        SYSTEMTIME tlt;
        GetLocalTime (&tlt);
        fprintf(stderr, "%02d:%02d:%02d.%03u|[%s:%d]", tlt.wHour, tlt.wMinute, tlt.wSecond, tlt.wMilliseconds, f, line);
#else
        struct timeval lt;
        struct tm* tlt=NULL;
        gettimeofday(&lt, NULL);
        tlt=localtime((time_t*)&lt.tv_sec);
        fprintf(stderr, "%02d:%02d:%02d.%06u|[%s:%d]", tlt->tm_hour, tlt->tm_min, tlt->tm_sec, (uint32_t)lt.tv_usec, f, line);
#endif

        va_start(args, format);
        vfprintf(stderr, format, args);

        /*	fprintf(stderr, "%02d:%02d:%02d.%06u|[%s:%d] %s", tlt->tm_hour, tlt->tm_min, tlt->tm_sec, (uint32_t)lt.tv_usec, file, line, msg); */
    }

    void dbg_print_null(const char* f, int line, char* format, ...)
    {
        /* to avoid compilation warnings */
        f=format;
        line=0;
        return;
    }

    void dbg_print_hexa(const char* f, int line, char* buf, size_t len, char* format, ...)
    {
        unsigned int i=0;
        va_list args;


#ifdef _MSC_VER
        SYSTEMTIME tlt;
        GetLocalTime (&tlt);
        fprintf(stderr, "%02d:%02d:%02d.%03u|[%s:%d]", tlt.wHour, tlt.wMinute, tlt.wSecond, tlt.wMilliseconds, f, line);
#else
        struct timeval lt;
        struct tm* tlt=NULL;
        gettimeofday(&lt, NULL);
        tlt=localtime((time_t*)&lt.tv_sec);
        fprintf(stderr, "%02d:%02d:%02d.%06u|[%s:%d]", tlt->tm_hour, tlt->tm_min, tlt->tm_sec, (uint32_t)lt.tv_usec, f, line);
#endif

        va_start(args, format);
        vfprintf(stderr, format, args);

        for (i=0;i<len;i++)
        {
            fprintf(stderr, "%02x ", (unsigned char)buf[i]);
        }

        fprintf(stderr, "\n");
    }

#ifdef __cplusplus
}
#endif

