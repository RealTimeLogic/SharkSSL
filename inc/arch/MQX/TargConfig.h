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
#define baAssert(x)     ((x) ? 0 : printf("failed assertion %s %d\n", __FILE__, __LINE__))
#else
#define baAssert(x)
#endif

#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif


/* MQX */
#include <mqx.h>
#include <mutex.h>
#include <bsp.h>        /* printf */

#define baMalloc(s)     _mem_alloc_system(s)      /* should return 32-bit aligned address */
#define baRealloc(m, s) (void*)0
#define baFree(m)       _mem_free(m)

#if MQX_VERSION > 400
typedef uint8_t  U8;
typedef int8_t   S8;
typedef uint16_t U16;
typedef int16_t  S16;
typedef uint32_t U32;
typedef int32_t  S32;
typedef uint64_t U64;
typedef int64_t  S64;
#else
typedef uint_8   U8;
typedef int_8    S8;
typedef uint_16  U16;
typedef int_16   S16;
typedef uint_32  U32;
typedef int_32   S32;
typedef uint_64  U64;
typedef int_64   S64;
#endif
typedef U8 BaBool;

typedef struct ThreadMutexBase
{
   MUTEX_STRUCT mutex;
} ThreadMutexBase;

#define ThreadMutex_constructor(o)   _mutex_init(&(o)->mutex,0)
#define ThreadMutex_destructor(o)    _mutex_destroy(&(o)->mutex)
#define ThreadMutex_set(o)           _mutex_lock(&(o)->mutex)
#define ThreadMutex_release(o)       _mutex_unlock(&(o)->mutex)

extern
#ifdef __cplusplus
"C"
#endif
U32 baGetUnixTime(void);

#ifdef _SHARKSSL_C_
U32 baGetUnixTime(void)
{
   TIME_STRUCT t;
   _time_get(&t);
   return t.SECONDS;
}
#endif  /* _SHARKSSL_C_ */

#endif  /* _SharkSsl_TargConfig_h */
