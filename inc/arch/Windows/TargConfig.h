/**
 *     ____             _________                __                _
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/
 *                                                       /____/
 *
 *                 SharkSSL Embedded SSL/TLS Stack
 ****************************************************************************
 *   PROGRAM MODULE
 *
 *   $Id: TargConfig.h 4893 2021-11-05 22:54:26Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2010 - 2021
 *
 *   This software is copyrighted by and is the sole property of Real
 *   Time Logic LLC.  All rights, title, ownership, or other interests in
 *   the software remain the property of Real Time Logic LLC.  This
 *   software may only be used in accordance with the terms and
 *   conditions stipulated in the corresponding license agreement under
 *   which the software has been supplied.  Any unauthorized use,
 *   duplication, transmission, distribution, or disclosure of this
 *   software is expressly forbidden.
 *
 *   This Copyright notice may not be removed or modified without prior
 *   written consent of Real Time Logic LLC.
 *
 *   Real Time Logic LLC. reserves the right to modify this software
 *   without notice.
 *
 *               http://www.realtimelogic.com
 *               http://www.sharkssl.com
 ****************************************************************************
 *
 */
#ifndef _SharkSsl_TargConfig_h
#define _SharkSsl_TargConfig_h

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#ifdef __TINYC__
#define mktime mktimeNotUsed
#include <time.h>
#undef mktime
#define mktime _mktime64
#define BaTime long long
#endif

/**
 *  baMalloc  should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful.
 *  baRealloc should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful or NOT available.
 */

#ifndef NDEBUG
#define baAssert(x)        ((x) ? 0 : printf("failed assertion %s %d\n", __FILE__, __LINE__))
#else
#define baAssert(x)
#endif

/* x86, remove if different architecture */
#ifndef B_LITTLE_ENDIAN
#define B_LITTLE_ENDIAN
#endif
#define SHARKSSL_BIGINT_WORDSIZE     32
#define SHARKSSL_UNALIGNED_ACCESS    1


/* WINDOWS */
#include <stdio.h>

#if 1
#include <stdlib.h>        /* malloc/realloc/free */
#define baMalloc(s)        malloc(s)      /* should return 32-bit aligned address */
#define baRealloc(m, s)    realloc(m, s)  /* as above */
#define baFree(m)          free(m)
#else
#include "../../../examples/malloc/umm_malloc.h"
#define baMalloc(s)        umm_malloc(s)
#define baRealloc(m, s)    umm_realloc(m, s)
#define baFree(m)          umm_free(m)
#endif

#if 1  /* set to 0 if your Visual Studio compiler does not support C99 */
#include <stdint.h>
typedef uint8_t            U8;
typedef int8_t             S8;
typedef uint16_t           U16;
typedef int16_t            S16;
typedef uint32_t           U32;
typedef int32_t            S32;
typedef uint64_t           U64;
typedef int64_t            S64;
#else
typedef unsigned char      U8;
typedef signed   char      S8;
typedef unsigned short     U16;
typedef signed   short     S16;
typedef unsigned long      U32;
typedef signed   long      S32;
typedef unsigned long long U64;
typedef signed   long long S64;
#endif
typedef U8 BaBool;


#include <time.h>
#define baGetUnixTime()    ((U32)time(0))

#include <windows.h>
typedef struct ThreadMutexBase
{
   CRITICAL_SECTION section;
} ThreadMutexBase;

#define ThreadMutex_constructor(o) InitializeCriticalSection(&(o)->section)
#define ThreadMutex_destructor(o)  DeleteCriticalSection(&(o)->section)
#define ThreadMutex_set(o)         EnterCriticalSection(&(o)->section)
#define ThreadMutex_release(o)     LeaveCriticalSection(&(o)->section)



/* The following is not required by SharkSSL, but is used by some of the examples */

#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#endif  /* _SharkSsl_TargConfig_h */
