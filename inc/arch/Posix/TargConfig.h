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
 *   $Id: TargConfig.h 4769 2021-06-11 17:29:36Z gianluca $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2010
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


#if !defined(B_LITTLE_ENDIAN) && !defined(B_BIG_ENDIAN)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define B_LITTLE_ENDIAN
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define B_BIG_ENDIAN
#endif
#endif


/**
 *  baMalloc  should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful.
 *  baRealloc should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful or NOT available.
 */

#ifndef NDEBUG
#include <assert.h>
#define baAssert(x)        assert(x)
#else
#define baAssert(x)
#endif

#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif


/* Linux/Posix */
#include <stdlib.h>        /* malloc/realloc/free */
#include <stdio.h>

#define baMalloc(s)        malloc(s)      /* should return 32-bit aligned address */
#define baRealloc(m, s)    realloc(m, s)  /* as above */
#define baFree(m)          free(m)

#ifndef INTEGRAL_TYPES
#define INTEGRAL_TYPES
#if (__STDC_VERSION__ >= 199901L) || defined( __GNUC__)
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
typedef unsigned int       U32;
typedef signed   int       S32;
typedef unsigned long long U64;
typedef signed   long long S64;
#endif
#endif
typedef U8 BaBool;


#include <time.h>
#define baGetUnixTime()    ((U32)time(0))

#include <pthread.h>
typedef struct ThreadMutexBase
{
   pthread_mutex_t mutex;
} ThreadMutexBase;

#define ThreadMutex_destructor(o)  pthread_mutex_destroy(&(o)->mutex)
#define ThreadMutex_set(o)         pthread_mutex_lock(&(o)->mutex)
#define ThreadMutex_release(o)     pthread_mutex_unlock(&(o)->mutex)
#define ThreadMutex_constructor(o) pthread_mutex_init(&(o)->mutex,0)



/* The following is not required by SharkSSL, but is used by some of the examples */

#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#endif  /* _SharkSsl_TargConfig_h */
