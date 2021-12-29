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
 *  baMalloc  should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful.
 *  baRealloc should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful or NOT available.
 */

#ifndef NDEBUG
#include <stdio.h>         /* printf */
#define baAssert(x)        ((x) ? 0 : printf("failed assertion %s %d\n", __FILE__, __LINE__))
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
#define baRealloc(m, s)    realloc(m, s)  /* as above - see also #define below    */
#define baFree(m)          free(m)

/**
 *  set SHARKSSL_UNALIGNED_MALLOC to 1 if either malloc
 *  or realloc don't return a 32-bit aligned address
 */
#define SHARKSSL_UNALIGNED_MALLOC     0


#if (__STDC_VERSION__ >= 199901L)  /* C99: '-std=c99' in GCC */
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
