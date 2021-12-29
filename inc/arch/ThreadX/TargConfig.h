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
#define baAssert(x)          ((x) ? 0 : sharkAssert(__FILE__, __LINE__))
#else
#define baAssert(x)
#endif

/* ThreadX */
#include <tx_api.h>

#define baMalloc(size)       sharkSslTxByteAlloc((U32)size)  /* should return 32-bit aligned address */
#define baRealloc(ptr, size) (void*)0;                       /* not implemented */
#define baFree(ptr)          tx_byte_release((VOID*)ptr)

typedef unsigned char        U8;
typedef signed   char        S8;
typedef unsigned short       U16;
typedef signed   short       S16;
typedef ULONG                U32;
typedef signed int           S32;
typedef unsigned long long   U64;
typedef signed   long long   S64;
typedef U8 BaBool;


typedef struct ThreadMutexBase
{
      TX_MUTEX mutex;
} ThreadMutexBase;

#define ThreadMutex_constructor(o) tx_mutex_create(&(o)->mutex, "SM", TX_INHERIT)
#define ThreadMutex_destructor(o)  tx_mutex_delete(&(o)->mutex)
#define ThreadMutex_set(o)         tx_mutex_get(&(o)->mutex,TX_WAIT_FOREVER)
#define ThreadMutex_release(o)     tx_mutex_put(&(o)->mutex)


#ifdef _SHARKSSL_C_
static U32 sharkSslUnixTime;
static TX_BYTE_POOL *sharkSslBytePool;


#ifndef NDEBUG
void sharkAssert(char *fileName, int line)
{
   (void)fileName;
   line++;  /* dummy code to place a breakpoint, don't optimize out */
   for(;;);
}
#endif


static void oneSecondTimer(U32 notUsed)
{
   (void)notUsed;
   sharkSslUnixTime++;
}


void baInitTxUnixTime(U32 time, U32 ticksPerSecond)
{
   static TX_TIMER timer;
   sharkSslUnixTime = time;
   memset(&timer, 0, sizeof(TX_TIMER));
   tx_timer_create(&timer, "S sec tick", oneSecondTimer, 0,
                   ticksPerSecond, ticksPerSecond,
                   TX_AUTO_ACTIVATE);
}


U32 baGetUnixTime(void)
{
   return sharkSslUnixTime;
}


void baSetTxBytePool (TX_BYTE_POOL *pool)
{
   sharkSslBytePool = pool;
}


void *sharkSslTxByteAlloc (U32 size)
{
   void *p;
   if(tx_byte_allocate(sharkSslBytePool, &p, size, TX_NO_WAIT))
     return 0;

   baAssert(0 == ((U32)p & 0x03));
   return p;
}

#else
#ifdef __cplusplus
#ifndef NDEBUG
extern "C" int   sharkAssert(char *fileName, int line);
#endif
extern "C" U32   baGetUnixTime(void);
extern "C" void  baInitTxUnixTime(U32 time, U32 ticksPerSecond);
extern "C" void  baSetTxBytePool(TX_BYTE_POOL *pool);
extern"C"  void *sharkSslTxByteAlloc(U32 size);

#else
#ifndef NDEBUG
extern int   sharkAssert(char *fileName, int line);
#endif
extern U32   baGetUnixTime(void);
extern void  baInitTxUnixTime(U32 time, U32 ticksPerSecond);
extern void  baSetTxBytePool(TX_BYTE_POOL *pool);
extern void *sharkSslTxByteAlloc(U32 size);

#endif  /* __cplusplus */




/* The following is not required by SharkSSL, but is used by some of the examples */

#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif


#endif  /* _SHARKSSL_C_ */

#endif  /* _SharkSsl_TargConfig_h */
