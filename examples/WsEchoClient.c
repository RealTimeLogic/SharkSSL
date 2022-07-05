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
 *   $Id: WsEchoClient.c 5120 2022-03-24 15:25:13Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2013 - 2021
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


Secure WebSocket Example

WebSocket (WS) is a new standard enabling full duplex asynchronous
communication between a web server and a client and vice versa. WS can
be used as a base for M2M communication. See the following page for an
introduction to the protocol: http://en.wikipedia.org/wiki/WebSocket

The example is by default connecting to the WebSocket echo service at
realtimelogic.info. Compiling the code with ECHO_EX makes the example
connect to ws.ifelse.io.

The WebSocket service at realtimelogic.info can respond to both RSA
and ECC clients, but the echo service ws.ifelse.io will only
respond with an RSA certificate. For this reason, connecting to
ws.ifelse.io will fail if you have compiled SharkSSL with the
option to exclude RSA and to only include support for ECC.

The WebSocket service at realtimelogic.info, ELIZA the Psychotherapist:
https://realtimelogic.info/WS-ELIZA/
*/

#include "WsClientLib.h"
#include <stddef.h>


/*
  1: Connect to realtimelogic.info and ELIZA the Psychotherapist (default)
  2: Connect to ws.ifelse.io if ECHO_EX is defined
*/
#ifdef ECHO_EX
#define WSHOST "ws.ifelse.io"
#define WSURI "/"
#else
#define WSHOST "realtimelogic.info"
#define WSURI "/WS-ELIZA/"
#endif


/* Include root (CA) certificate list. Ref: CA-LIST
   We use the generic CA list when connecting to ws.ifelse.io
   and the RTL ECC root cert when connecting to the ELIZA server.
*/
#ifdef ECHO_EX
#include "CA-list.h"
#else
#include "certificates/CA_RTL_EC_256.h"
#endif

/* This example defaults to using secure connection, but it can be set to non secure by defining WSC_NONSEC
 * Macro WSC_DUAL must be defined when using non secure mode.
*/
#if defined(WSC_NONSEC) && !defined(WSC_DUAL)
#error WSC_DUAL must be defined when WSC_NONSEC is set
#endif

#if  HOST_PLATFORM == 1

/************************* Helper functions ******************************/


/* Example code and selib.c use function xprintf.
 */
void _xprintf(const char* fmt, ...)
{
   va_list varg;
   va_start(varg, fmt);
   vprintf(fmt, varg);
   va_end(varg);
#ifndef _WIN32
   fflush(stdout);
#endif
} 


/**************************************************************************
The following code is designed specifically for this example and
enables non blocking read from the console. The example's main loop is
single threaded and we most therefore use non blocking functions for
reading from the console.
***************************************************************************/


/* Function pollkb requires non blocking keyboard I/O. The following
 * code sets this up for WIN and UNIX.
 */
#include <ctype.h>
#ifdef _WIN32
#include <conio.h>
#define xkbhit _kbhit
#define xgetch  _getch
#else
#define UNIXMODE
#include <termios.h>

/* UNIX kbhit and getch simulation */

static int
xkbhit()
{
   struct timeval tv = { 0L, 0L };
   fd_set fds;
   struct termios orgTs;
   struct termios asyncTs;
   int set;
   tcgetattr(0, &orgTs);
   memcpy(&asyncTs, &orgTs, sizeof(asyncTs));
   cfmakeraw(&asyncTs);
   asyncTs.c_oflag=orgTs.c_oflag;
   tcsetattr(0, TCSANOW, &asyncTs);
   FD_ZERO(&fds);
   FD_SET(STDIN_FILENO, &fds);
   set = select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
   tcsetattr(0, TCSANOW, &orgTs);
   return set;
}

static int
xgetch(void)
{
   int r;
   unsigned char c;
   if ((r = read(0, &c, sizeof(c))) < 0)
      return r;
   if(c == 3) /* CTRL-C Linux */
      exit(0);
   return c;
}
#endif /* End UNIX kbhit and getch simulation */


/* Platform specific function for non blocking keyboard read.
 */
static int
pollkb(void)
{
   if(xkbhit())
   {
      int c = xgetch();
      return c=='\r' ? '\n' : c;
   }
   return 0;
}
#else /*  HOST_PLATFORM */
extern int pollkb(void);
#define resetTerminalMode()
#endif /*  HOST_PLATFORM */


/************ End non blocking console functions ***********************/

/* Force ECC certificate authentication for ELIZA server
 */
#if SHARKSSL_ENABLE_SELECT_CIPHERSUITE == 1 && !defined(ECHO_EX)
static void
setChaChaCipher(SharkSslCon* scon)
{
   if(scon)
      SharkSslCon_selectCiphersuite(
         scon, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
}
#else
#define setChaChaCipher(scon)
#endif


/*
  The main function connects to a WS echo server, by using the generic
  WS functions defined above.

  The function connects to the server defined by the macro #WSHOST. See
  WsClientLib.h for details.
*/
void
mainTask(SeCtx* ctx)
{
   /* Info printed to the console when the program starts
    */
   static const char info[] = {
      "SharkSSL Websocket client demo.\n"
      "Copyright (c) 2016 Real Time Logic.  All rights reserved.\n"
   };

#ifndef WSC_NONSEC
   SharkSsl sharkSsl;
#endif
   SharkSslCon* sharkSslCon;
   int rc,status;
   WscState wss={0};
   static SOCKET sock; /* Must be static if SeCtx is used */

#ifdef WSC_NONSEC
   /* Must set the following when not in secure mode */
   U8 sendBuf[512];
   U8 recBuf[512];
   wss.recBuf=recBuf;
   wss.recBufLen=sizeof(recBuf);
   wss.sendBuf=sendBuf;
   wss.sendBufLen=sizeof(sendBuf);
#endif

   SOCKET_constructor(&sock, ctx);
   wss.sock=&sock;

   xprintf(("%s",info));
   /*! [inline doc] */
   xprintf(("Connecting to " WSHOST "...\n"));
   /* Port 443 is the listen port for secure servers i.e. HTTPS */
#ifdef WSC_NONSEC
   status=se_connect(&sock, WSHOST, 80);
#else
   status=se_connect(&sock, WSHOST, 443);
#endif
   if(status)
   {
      const char* msg;
      switch(status)
      {
         case -1: msg="Socket error!";
            break;
         case -2: msg="Cannot resolve IP address for " WSHOST ".";
            break;
         default:  msg="Cannot connect to " WSHOST ".";
      }
      xprintf((
         "%s\n%s",
         msg,
         status == -1 ? "" :
         "Note: this example is not designed to connect via a HTTP proxy.\n"));
      return ;
   }

   /* It is common to create one (or several) SharkSsl object(s) at
      system start and to keep these objects for the lifetime of the
      program/firmware.
    */
#ifndef WSC_NONSEC
   SharkSsl_constructor(&sharkSsl,
                        SharkSsl_Client, /* Two options: client or server */
                        0,      /* Not using SSL cache */
                        4000,   /* initial inBuf size: Can grow */
                        4000);   /* outBuf size: Fixed */
   /* Enable server certificate validation. See Ref: CA-LIST
    */
#ifdef ECHO_EX
   SharkSsl_setCAList(&sharkSsl, sharkSslCAList);
#else
   SharkSsl_setCAList(&sharkSsl, sharkSSL_New_RTL_ECC_CA);
#endif
   
   /* It is very important to seed the SharkSSL RNG generator (Ref-seed) */
   sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)&sharkSsl);

   if( (sharkSslCon = SharkSsl_createCon(&sharkSsl)) == 0)
      xprintf(("Cannot create SharkSslCon object.\n"));
   else /* We are now connected to the server. */
#else /* WSC_NONSEC */
   sharkSslCon=0;
#endif /* WSC_NONSEC */
   {
      wss.scon=sharkSslCon;
      setChaChaCipher(sharkSslCon);
      /* Keep seeding (Make it more secure: Ref-seed) */
#ifndef WSC_NONSEC
      sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)&sharkSsl);
#endif
      /* Establish a WS connection */
      if( (status=wscProtocolHandshake(&wss,6000,WSHOST,WSURI,0)) > 0 )
      {
         U8 sbuf[255];
         int sbufIx=0; /* sbuf cursor */
         U8* rbuf; /* Receive buffer is managed by SharkSSL */
         int idleCounter=0;

         if(sharkSslCon && status !=
#if SHARKSSL_CHECK_DATE
            SharkSslConTrust_CertCnDate
#else
            SharkSslConTrust_CertCn
#endif
            )
         {
            /* See Ref: CA-LIST */
            xprintf(("%cWARNING: certificate received from %s not trusted!\n",
                     7,WSHOST));
         }
#ifdef ECHO_EX
         xprintf(("\n------\nConnected\nEnter data and press the ENTER key\n"));
#endif
         while((rc = wscRead(&wss,&rbuf,50)) >= 0)
         {
            if(rc) /* incomming data from server */
            {
               idleCounter=0;
#ifdef ECHO_EX
               xprintf(("Received %d bytes from server:\n",wss.frameLen));
#endif
               do
               {
                  int len=rc;
                  while(len--)
                     xprintf(("%c", *rbuf++));
                  if(wss.bytesRead == wss.frameLen)
                     break; /* We are done receiving the current frame */
               } while( (rc=wscRead(&wss,&rbuf,10000)) > 0 );
#ifdef ECHO_EX
               xprintf(("\nEnd WS frame.\n"));
#endif
               if(rc <= 0) break;
            }
            else /* 50 ms timeout */
            {
               int c;
               /* Check if we have console data i.e. if user
                * entered text into the console. */
               while((c=pollkb())!=0)
               {
#ifndef UNIXMODE
                  xprintf(("%c",c));
#endif
                  sbuf[sbufIx++] = (U8)c;
                  /* Flush on ENTER or if buffer is full */
                  if(c == '\n' || sbufIx == sizeof(sbuf))
                  {
                     /* Send console data to server */
                     rc = wscSendBin(&wss,sbuf,sbufIx);
                     sbufIx=0;
                     idleCounter=0;
                     if(c != '\n')
                        xprintf(("\n"));
                     break;
                  }
               }
               if(rc < 0) break;
            }
            if(rc == 0)
            {
               if(++idleCounter == 100) /* 50ms * 100: 5 sec */
               {
                  static const U8 msg[]={"Are you still there?"};
                  idleCounter=0;
                  /* There are no WS requirements for sending
                   * pings. This is just an example. (Ref-Ping). Note,
                   * ping payload data is not required.
                   */
                  rc=wscSendCtrl(&wss,WSOP_Ping,msg,sizeof(msg)-1);
                  if(rc < 0) break;
               }
            }
         }
      }
      /* Release resources used by sharkSslCon */
#ifndef WSC_NONSEC
      SharkSsl_terminateCon(&sharkSsl, sharkSslCon);
#endif
   }

#ifndef WSC_NONSEC
   SharkSsl_destructor(&sharkSsl);
#endif
   se_close(&sock);
   /*! [inline doc] */
   xprintf(("\nServer connection closed!\nPress ENTER to continue."));
   getchar();
}

#if  HOST_PLATFORM == 1 && !defined(NO_MAIN)

int main()
{
#ifdef _WIN32
   /* Windows specific: Start winsock library */
   { WSADATA wsaData; WSAStartup(MAKEWORD(1,1), &wsaData); }
#endif
   mainTask(0);
   return 0;
}
#endif
