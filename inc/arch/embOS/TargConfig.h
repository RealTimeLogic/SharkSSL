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
#include <stdio.h>
#define baAssert(x)     ((x) ? 0 : printf("failed assertion %s %d\n", __FILE__, __LINE__))
#else
#define baAssert(x)
#endif


/* embOS */
#include <RTOS.h>

#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif


#if OS_SUPPORT_OS_ALLOC
#define baMalloc(s)        OS_malloc(s)      /* should return 32-bit aligned address */
#define baRealloc(m, s)    OS_realloc(m, s)  /* as above - see also #define below    */
#define baFree(m)          OS_free(m)

#else
#include <stdlib.h>        /* standard malloc/realloc/free */
#define baMalloc(s)        malloc(s)         /* should return 32-bit aligned address */
#define baRealloc(m, s)    realloc(m, s)     /* as above - see also #define below    */
#define baFree(m)          free(m)

#endif


typedef OS_U8   U8;
typedef OS_I8   S8;
typedef OS_U16  U16;
typedef OS_I16  S16;
typedef OS_U32  U32;
typedef OS_I32  S32;
typedef unsigned long long U64;
typedef   signed long long S64;
typedef U8 BaBool;


typedef struct ThreadMutexBase
{
   OS_RSEMA mutex;
} ThreadMutexBase;

#define ThreadMutex_constructor(o)  OS_CREATERSEMA(&(o)->mutex)
#define ThreadMutex_destructor(o)   OS_DeleteRSema(&(o)->mutex)
#define ThreadMutex_set(o)          OS_Use(&(o)->mutex)
#define ThreadMutex_release(o)      OS_Unuse(&(o)->mutex)

extern
#ifdef __cplusplus
"C"
#endif
U32 baGetUnixTime(void);

#ifdef _SHARKSSL_C_
U32 baGetUnixTime(void)
{
   return (U32)OS_GetTime32() / 1000;  /* one tick each ms */
}
#endif  /* _SHARKSSL_C_ */

#endif  /* _SharkSsl_TargConfig_h */
