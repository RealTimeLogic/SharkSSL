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

/**
 *  baMalloc  should return aligned addresses when succesful,
 *                          (void*)0 when not succesful.
 *  baRealloc should return aligned addresses when succesful,
 *                          (void*)0 when not succesful or NOT available.
 */

#ifndef NDEBUG
#include <stdio.h>         /* printf */
#define baAssert(x)        ((x) ? (void)0 : printf("failed assertion %s %d\n", __FILE__, __LINE__))
#else
#define baAssert(x)
#endif

#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif


/* MUST BE ADAPTED TO THE ARCHITECTURE */
#include <stdlib.h>        /* malloc/realloc/free */

#define baMalloc(s)        malloc(s)      /* should return 32-bit aligned address */
#define baRealloc(m, s)    0
#define baFree(m)          free(m)

/**
 *  set SHARKSSL_UNALIGNED_MALLOC to 1 if malloc
 *  doesn't return a 32-bit aligned address
 *  { in such case: #define baRealloc(m,s) 0 }
 */
#define SHARKSSL_UNALIGNED_MALLOC     0

/**
 *  machine-dependent settings
 */
#define UPTR                          U16  /* 16-bit pointers */
#define SHARKSSL_ALIGNMENT            2    /* 16-bit alignment */
#define SHARKSSL_BIGINT_WORDSIZE      16   /* 16x16 multiplications */
#define SHARKSSL_UNALIGNED_ACCESS     1    /* support for unaligned accesses */


typedef unsigned char      U8;
typedef signed   char      S8;
typedef unsigned short     U16;
typedef signed   short     S16;
typedef unsigned long      U32;
typedef signed   long      S32;
typedef unsigned long long U64;
typedef signed   long long S64;
typedef U8 BaBool;

/**
 * baGetUnixTime demo implementation
 */
#ifdef _SHARKSSL_C_
static U32 sharkSslDemoTime = 0;

U32 baGetUnixTime(void)
{
   return sharkSslDemoTime++;
}

#else
extern
#ifdef __cplusplus
"C"
#endif
U32 baGetUnixTime(void);

#endif  /* _SHARKSSL_C_ */

/**
 * possible baGetUnixTime alternate implementation
 * #define baGetUnixTime()    0    -- TO BE IMPLEMENTED
 */


typedef struct ThreadMutexBase
{
   U32 mutex;                      /* TO BE IMPLEMENTED */
} ThreadMutexBase;

#define ThreadMutex_destructor(o)  /* TO BE IMPLEMENTED */
#define ThreadMutex_set(o)         /* TO BE IMPLEMENTED */
#define ThreadMutex_release(o)     /* TO BE IMPLEMENTED */
#define ThreadMutex_constructor(o) /* TO BE IMPLEMENTED */

#endif  /* _SharkSsl_TargConfig_h */
