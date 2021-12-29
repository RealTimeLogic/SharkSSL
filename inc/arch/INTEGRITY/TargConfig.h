/*
 *     ____             _________                __                _     
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__  
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/  
 *                                                       /____/          
 *
 *                  Barracuda Embedded Web-Server
 *
 ****************************************************************************
 *			      HEADER
 *
 *   $Id$
 *
 *   COPYRIGHT:  Real Time Logic, 2020
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
 ****************************************************************************
 *
 * Platform: INTEGRITY.
 *
 */
#ifndef _SharkSsl_TargConfig_h
#define _SharkSsl_TargConfig_h

#include <INTEGRITY.h>

#if defined(__LittleEndian) || defined(LittleEndian) || defined(TM_LITTLE_ENDIAN)
  #ifdef B_BIG_ENDIAN
    #error ENDIANESS MISMATCH!
  #endif
  #ifndef B_LITTLE_ENDIAN
    #define B_LITTLE_ENDIAN
  #endif
#elif defined(__BigEndian) || defined(BigEndian) || defined(TM_BIG_ENDIAN)
  #ifdef B_LITTLE_ENDIAN
    #error ENDIANESS MISMATCH!
  #endif
  #ifndef B_BIG_ENDIAN
    #define B_BIG_ENDIAN
  #endif
#else
#error Missing little/big endian declaration
#endif

#ifndef NDEBUG
#include <assert.h>
#define baAssert(x)        assert(x)
#else
#define baAssert(x)
#endif

/* The following is not required by SharkSSL, but is used by some of the examples */

#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef SHARKSSL_API
//#define SHARKSSL_API
#endif
#define BaBool Boolean

#define baMalloc(s)        malloc(s)      /* should return 32-bit aligned address */
#define baRealloc(m, s)    realloc(m, s)  /* as above */
#define baFree(m)          free(m)

#include <time.h>
#define baGetUnixTime()    ((U32)time(0))

#include <stdint.h>
typedef uint8_t            U8;
typedef int8_t             S8;
typedef uint16_t           U16;
typedef int16_t            S16;
typedef uint32_t           U32;
typedef int32_t            S32;
typedef uint64_t           U64;
typedef int64_t            S64;

#if defined(NDEBUG) && !defined(BA_OS_CHECK) 
#define Thread_ce(x) x 
#else 
#ifdef __cplusplus 
extern "C" { 
#endif 
void Thread_cef(Error status, const char* file, int line); 
#ifdef __cplusplus 
} 
#endif 
#define Thread_ce(x) baAssert(Success==x) 
#endif

typedef struct ThreadMutexBase
{
      Value tid; /* Lock owner */
      LocalMutex mutex;
} ThreadMutexBase;

#define ThreadMutex_constructor(o) \
  Thread_ce(CreateLocalMutex(&(o)->mutex))

#define ThreadMutex_destructor(o) \
  Thread_ce(CloseLocalMutex((o)->mutex))

#define ThreadMutex_set(o) do {\
   Thread_ce(WaitForLocalMutex((o)->mutex));\
   Thread_ce(GetTaskUniqueId(CurrentTask(), &(o)->tid));\
} while(0)

#define ThreadMutex_release(o) do{\
   (o)->tid=0;\
   Thread_ce(ReleaseLocalMutex((o)->mutex));\
} while(0)




#endif
