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
 *   COPYRIGHT:  Real Time Logic LLC, 2014 - 2017
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


 The following file shows how to configure SharkSSL for bare metal (no RTOS).

 The allocators are mapped to lwIP's allocator lib

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


#ifndef NDEBUG
#pragma GCC diagnostic ignored "-Wunused-value"
#define baAssert(exp) ( (exp) ? (void)0 : sharkAssert(__FILE__, __LINE__) )
#else
#define baAssert(x)
#endif

#ifdef _SHARKSSL_C_
#ifndef NDEBUG
const char* assert_file;
int assert_line;
void sharkAssert(const char* file, int line)
{
   assert_file = file;
   assert_line = line;
   for(;;);
}
#endif
#endif

#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define B_LITTLE_ENDIAN
#elif BYTE_ORDER == BIG_ENDIAN
#define B_BIG_ENDIAN
#else
#error fix endian
#endif

/**
 *  baMalloc  should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful.
 */

#ifdef __PIC32__
#ifndef UMM_MALLOC
#define UMM_MALLOC
#endif
#endif

#ifdef UMM_MALLOC
#include "../../../examples/malloc/umm_malloc.h"
#define baMalloc(s)        umm_malloc(s)
#define baRealloc(m, s)    umm_realloc(m, s)
#define baFree(m)          umm_free(m)
#else
#include <lwip/mem.h>
#include <lwip/sys.h>
/* should return 32-bit aligned address */
#define baMalloc(s)        mem_malloc(s)
/* not implemeneted, which is OK */
#define baRealloc(m, s)    0
#define baFree(m)          mem_free(m)
#endif


#include <stdint.h>
typedef uint8_t            U8;
typedef int8_t             S8;
typedef uint16_t           U16;
typedef int16_t            S16;
typedef uint32_t           U32;
typedef int32_t            S32;
typedef uint64_t           U64;
typedef int64_t            S64;
typedef U8 BaBool;


typedef U8 ThreadMutexBase;
#define ThreadMutex_constructor(o)
#define ThreadMutex_destructor(o)
#define ThreadMutex_set(o)
#define ThreadMutex_release(o)

#ifdef __PIC32__
#include <system/tmr/sys_tmr.h>
#define baGetUnixTime() \
  SYS_TMR_SystemCountGet()/SYS_TMR_SystemCountFrequencyGet()
#else
/* Assume LwIP */
#define baGetUnixTime() sys_now()
#endif

#endif  /* _SharkSsl_TargConfig_h */
