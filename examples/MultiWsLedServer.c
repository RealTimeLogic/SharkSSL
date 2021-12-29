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
 *   $Id: WsLedServer.c 4329 2018-11-26 22:49:59Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2020 - 2021
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
 *               http://sharkssl.com
 ****************************************************************************
 */


#include <MSLib.h>
#include "certificates/device_RSA_2048.h"
#include "ledctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <process.h> /* Windows _beginthreadex */

/*

  A WsLedServer.c clone which supports concurrent WebSockets.
  The code uses the Windows thread function _beginthreadex to spawn
  new threads. Change this to your applicable RTOS primitive.
*/


/****************************************************************************
 **************************-----------------------***************************
 **************************| BOARD SPECIFIC CODE |***************************
 **************************-----------------------***************************
 ****************************************************************************/

#if  HOST_PLATFORM

/* Include the simulated LED environment/functions */
#include "led-host-sim.ch"

#ifndef USE_ZIP_FILE
#include <sys/types.h> 
#include <sys/stat.h>
static int
fetchPage(void* hndl, MST* mst, U8* path)
{
   char* ptr;
   FILE* fp;
   struct stat fstat;
   U8* sbuf=MST_getSendBufPtr(mst); /* Using zero copy SharkSSL API */
   int sblen=MST_getSendBufSize(mst);

   (void)hndl;

   /* Use shark buffer as temporary storage for file (string) location */
   strcpy((char*)sbuf, "www/Led");
   strcat((char*)sbuf,(char*)path);
   if( (ptr=strrchr((char*)path, '/')) !=0 && !ptr[1] )
      strcat((char*)sbuf, "index.html");
   /* Do we have this file ? */
   if((stat((char*)sbuf, &fstat) == 0) && 
      (fp = fopen((char*)sbuf, "rb")) != NULL)
   { /* Yes, send HTTP header (msRespCT) and send file */
      int len=sblen;
      if(msRespCT(sbuf, &len, fstat.st_size, 0) && 
         MST_write(mst, 0, sblen-len) > 0) /* MST_write: flush zero copy */
      {
         while((len=fread(sbuf, 1, sblen, fp)) > 0)
         {
            if(MST_write(mst, 0, len) < 0)
               break;
         }
      }
      fclose(fp);
      return 1; /* found */
   }
   xprintf(("Page not found: %s (%s)\n",path,sbuf));
   return 0; /* not found */
}
#endif




/* Remove this function and replace with a task/thread that calls
 * function mainTask (Ref-Ta). Note: function mainTask will not return
 * unless the connection cannot be established or if the server wants
 * the connection to close. The caller can for example toggle all
 * LEDs, in an endless loop, if this function returns.
 */
#ifndef NO_MAIN
int
main()
{

   /* Info printed to the console when the program starts
    */
   static const char info[] = {
      "Concurrent Websocket LED server demo.\n"
      "\n"
      "See the following link for details:\n"
      "\thttp://realtimelogic.com/products/sharkssl/minnow-server/\n"
   };
   xprintf(("%s",info));

#ifdef _WIN32
   /* Windows specific: Start winsock library */
   { WSADATA wsaData; WSAStartup(MAKEWORD(1,1), &wsaData); }
#endif
   
   mainTask(0);
   xprintf(("Exiting...\n"));
   return 0;
}
#endif
#endif /* HOST_PLATFORM */


/****************************************************************************
 **************************----------------------****************************
 **************************| GENERIC CODE BELOW |****************************
 **************************----------------------****************************
 ****************************************************************************/

#ifdef USE_ZIP_FILE
#include "ZipFileSystem.h"
extern ZipReader* getLedZipReader(void);
#endif

/* Sends a a string to the online web-service. The binary format is
 * length (one byte) + non zero terminated string. See command S in the
 * binary protocol format for more information (Ref-Prot).
 */
static int
sendString2Browser(MS* ms, const char* str)
{
   int rc;
   if((rc=MS_writeText(ms, (U8*)str, strlen(str))) < 0)
   {
      return rc;
   }
   return 0;
}


/* Used at startup when registering the LEDs with the online
 * service. See command R in the binary protocol format for more
 * information (Ref-Prot).
 */
static int
sendLedInfo2Browser(MS* ms, U8 ledId,
                    LedColor color, const char* name)
{
   int rc;
   U8 cmd[2];
   cmd[0] = 0x40 | ((U8)color << 4) | ledId;
   cmd[1] = getLedState(ledId) ? 1 : 0;
   if( (rc=MS_writeBin(ms, &cmd, 2)) < 0 || 
       (rc = sendString2Browser(ms, name)) < 0)
   {
      return rc;
   }
   return 0;
}


/* Send the device name and LED list (Ref-LED) to the online
 * web-service at startup.  This function enables the server to
 * present a LED web page, with LED buttons, that shows the LEDs
 * available in this device.
 */
static int
sendDevInfo2Browser(MS* ms)
{
   int i,rc,ledLen;
   const LedInfo* ledInfo = getLedInfo(&ledLen);
   U8 endCmd=0;

   if( (rc=sendString2Browser(ms,getDevName())) != 0 )
      return rc;

   for(i = 0 ; i < ledLen ; i++)
   {
      if( (rc=sendLedInfo2Browser(
              ms,(U8)ledInfo[i].id,ledInfo[i].color,ledInfo[i].name))
          != 0 )
      {
         return rc;
      }
   }
   return MS_writeBin(ms, &endCmd, 1);
}


/* Manages the one command the server can send to the device (Ref-Prot).
 */
static int
manageCommandFromBrowser(U8 cmd)
{
   if(0x20 & cmd) /* T */
      setLed(0x0F & cmd, 0x10 & cmd ? 1 : 0);
   else
      return -1; /* unknown */
   return 0;
}


static int
openServerSock(SOCKET* sock)
{
   int status;
   U16 port;
   port=443;
   status = se_bind(sock, port);
   if(status)
   {
      port=9442;
      while(status == -3 && ++port < 9460)
         status = se_bind(sock, port);
   }
   if(!status)
   {
      xprintf(("WebSocket server listening on %d\n", (int)port));
   }
   return status;
}


typedef struct {
   MS ms;
   SOCKET sock;
   SharkSsl* sharkSsl;
   SharkSslCon* scon;
} WsArgs;


static unsigned __stdcall
runWebSocketServer(void* args)
{
   int rc;
   WsArgs* wsArgs=(WsArgs*)args;
   if( (rc=sendDevInfo2Browser(&wsArgs->ms)) == 0 )
   {
      U8* buf;
      while((rc=MS_read(&wsArgs->ms,&buf,50)) >= 0)
      {
         if(rc) /* incomming data from server */
         {
            while (rc--)
            {
               int status=manageCommandFromBrowser(*buf++);
               if(status)
               {
                  rc=status;
                  break;
               }
            }
         }
         else /* timeout (Ref-D) */
         {
            int ledId,on;
            if(setLedFromDevice(&ledId,&on))
            {
               U8 T;
               /* Send command T: setLed(ledId, on) */
               T = 0x20 | (on ? 0x10 : 0) | (U8)ledId;
               if( (rc=MS_writeBin(&wsArgs->ms, &T, 1)) < 0)
                  break;
            }
         }
      }
   }
   se_close(&wsArgs->sock);
   SharkSsl_terminateCon(wsArgs->sharkSsl, wsArgs->scon);
   baFree(wsArgs);
   xprintf(("Closing WS connection: ecode = %d\n",rc));
   return 0;
}


void
mainTask(SeCtx* ctx)
{
   static SharkSsl sharkSsl;
   static WssProtocolHandshake wph={0};
   static SOCKET listenSock;
   static MS ms;
   static SOCKET* listenSockPtr = &listenSock;

   static SOCKET sock;
   static SOCKET* sockPtr = &sock;

#ifdef USE_ZIP_FILE
   // https://realtimelogic.com/ba/doc/en/C/shark/group__ZipFileSystem.html
   static ZipFileSystem zfs;
   wph.fetchPage = msInitZipFileSystem(&zfs, getLedZipReader());
   wph.fetchPageHndl=&zfs;
#else
   wph.fetchPage = fetchPage;
#endif

   MS_constructor(&ms);
   SOCKET_constructor(listenSockPtr, ctx);
   SOCKET_constructor(sockPtr, ctx);

   if(openServerSock(listenSockPtr))
   {
      return;
   }

   /* The in buffer (inBuf) can grow dynamically if too small, but we
    * do not need a large buffer since the client does not send a
    * certificate, hence the buffer will not need to be larger than 500.
    */
   SharkSsl_constructor(&sharkSsl,
                        SharkSsl_Server,
                        10,   /* SSL cache size */
                        500,  /* inBuf size */
                        3500); /*outBuf size is fixed and must fit server cert*/

   /* At least one server certificate is required */
   SharkSsl_addCertificate(&sharkSsl, sharkSSL_RTL_device);

   /* It is very important to seed the SharkSSL RNG generator */
   sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)&sharkSsl);
   while(se_accept(&listenSockPtr, INFINITE_TMO, &sockPtr) == 1)
   {
      SharkSslCon* scon = SharkSsl_createCon(&sharkSsl);
      if(scon)
      {
         /* Keep seeding (make it more secure) */
         sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)scon);
         MS_setSharkCon(&ms, scon, sockPtr);
         if( ! MS_webServer(&ms, &wph) )
         {
            WsArgs* wsArgs = baMalloc(sizeof(WsArgs));
            if(wsArgs)
            {
               wsArgs->ms = ms;
               wsArgs->sock = *sockPtr;
               wsArgs->sharkSsl = &sharkSsl;
               wsArgs->scon = scon;
               MS_setSharkCon(&wsArgs->ms, scon, &wsArgs->sock);

               MS_constructor(&ms); /* reset */

               /* runWebSocketServer(wsArgs); in a separate thread */
               _beginthreadex(NULL,1000, runWebSocketServer, wsArgs, 0, 0);
               continue; /* Back to accept */
            }
         }
         se_close(sockPtr);
         SharkSsl_terminateCon(&sharkSsl, scon);
      }
      else
      {
         xprintf(("Cannot create SharkSslCon object.\n"));
         se_close(sockPtr);
      }
   }
   /* We get here if 'accept' fails. This is probably where you reboot. */
   se_close(listenSockPtr);
}
