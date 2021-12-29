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
 *   COPYRIGHT:  Real Time Logic LLC, 2016 - 2018
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

#include <cmsis_os.h>
#include <time.h>


#if !defined(B_BIG_ENDIAN) && !defined(B_LITTLE_ENDIAN)
#ifdef __ARM_BIG_ENDIAN
#define B_BIG_ENDIAN
#else
#define B_LITTLE_ENDIAN
#endif
#endif


#ifndef NDEBUG
#define baAssert(exp) ( (exp) ? (void)0 : sharkAssert(__FILE__, __LINE__) )
#else
#define baAssert(x)
#endif

#ifdef __cplusplus
extern "C" {
#endif
void sharkAssert(const char* file, int line);
#ifdef __cplusplus
}
#endif

#ifdef _SHARKSSL_C_
const char* assert_file;
int assert_line;
void sharkAssert(const char* file, int line)
{
   assert_file = file;
   assert_line = line;
   for(;;);
}
#endif



/* The following is not required by SharkSSL, but is used by some of
   the examples.
*/

#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/**
 *  baMalloc  should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful.
 *  baRealloc should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful or NOT available.
 */

#define UMM_MALLOC

#ifdef UMM_MALLOC
#include <umm_malloc.h>
#define baMalloc(s)        umm_malloc(s)
#define baRealloc(m, s)    umm_realloc(m, s)
#define baFree(m)          umm_free(m)
#define UMM_CRITICAL_ENTRY umm_critical_entry
#define UMM_CRITICAL_EXIT  umm_critical_exit
void umm_critical_entry(void);
void umm_critical_exit(void);
void umm_init(void);
#else
#include <stdlib.h>
#define baMalloc(s)        malloc(s) /* should return 32-bit aligned address */
#define baRealloc(m, s)    realloc(m, s)  /* as above */
#define baFree(m)          free(m)
#endif

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

#ifdef EXT_SHARK_LIB
U32 baGetUnixTime(void);
char *sharkStrchr(const char *s, int c);
char *sharkStrstr(const char *haystack, const char *needle);
#else
/* FIXME */
#define baGetUnixTime()    osKernelSysTick()
#endif

typedef struct ThreadMutexBase
{
   osMutexId mid;
   osMutexDef_t mdef;
#ifdef __MBED_CMSIS_RTOS_CA9
    int32_t mdata[4];
#else
    int32_t mdata[3];
#endif
} ThreadMutexBase;

void ThreadMutex_destructor(ThreadMutexBase* o);
void ThreadMutex_set(ThreadMutexBase* o);
void ThreadMutex_release(ThreadMutexBase* o);
void ThreadMutex_constructor(ThreadMutexBase* o);

#ifdef _SHARKSSL_C_
#include <string.h>
void ThreadMutex_constructor(ThreadMutexBase* o)
{
   memset(o->mdata, 0, sizeof(o->mdata));
   o->mdef.mutex = o->mdata;
   o->mid = osMutexCreate(&o->mdef);
   baAssert(o->mid);
}

void ThreadMutex_destructor(ThreadMutexBase* o)
{
   osMutexDelete(o->mid);
}

void ThreadMutex_set(ThreadMutexBase* o)
{
   osMutexWait(o->mid, osWaitForever);
}

void ThreadMutex_release(ThreadMutexBase* o)
{
   osMutexRelease(o->mid);
}

#ifdef UMM_MALLOC

static ThreadMutexBase ummMutex;

void umm_critical_entry(void)
{
   osMutexWait(ummMutex.mid, osWaitForever);
}

void umm_critical_exit(void)
{
   osMutexRelease(ummMutex.mid);
}

void umm_init(void)
{
   ThreadMutex_constructor(&ummMutex);
}

#endif

#endif


#endif  /* _SharkSsl_TargConfig_h */
