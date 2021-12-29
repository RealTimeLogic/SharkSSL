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
 *   $Id: TargConfig.h 4963 2021-12-17 00:32:59Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2015 - 2021
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

#ifdef ESP_PLATFORM
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <freertos/timers.h>
#else
#include <FreeRTOS.h>
#include <task.h>
#include <semphr.h>
#endif

/**
 *  baMalloc  should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful.
 *  baRealloc should return 32-bit aligned addresses when succesful,
 *                          (void*)0 when not succesful or NOT available.
 */

#ifndef NDEBUG
#define baAssert(exp) ( (exp) ? (void)0 : sharkAssert(__FILE__, __LINE__) )
#else
#define baAssert(x)
#endif


void sharkAssert(const char* file, int line);
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

#ifdef UMM_MALLOC
#include "../../../examples/malloc/umm_malloc.h"
#define baMalloc(s)        umm_malloc(s)
#define baRealloc(m, s)    umm_realloc(m, s)
#define baFree(m)          umm_free(m)
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


#ifdef ESP_PLATFORM
#define baGetUnixTime() ((U32)time(0))
#else
#define baGetUnixTime()    (U32)(((U64)xTaskGetTickCount() * (U64)portTICK_PERIOD_MS) / 1000)
#endif

#if !configUSE_MUTEXES
#error Set configUSE_MUTEXES in FreeRTOS.h
#endif


typedef struct ThreadMutexBase
{
   SemaphoreHandle_t mutex;
} ThreadMutexBase;

#if 0
#define ThreadMutex_destructor(o)  vSemaphoreDelete((o)->mutex)
#define ThreadMutex_set(o)         xSemaphoreTake((o)->mutex,portMAX_DELAY)
#define ThreadMutex_release(o)     xSemaphoreGive((o)->mutex)
#define ThreadMutex_constructor(o) (o)->mutex=xSemaphoreCreateMutex()
#else
#define ThreadMutex_destructor(o)
#define ThreadMutex_set(o)
#define ThreadMutex_release(o)
#define ThreadMutex_constructor(o)
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

#endif  /* _SharkSsl_TargConfig_h */
