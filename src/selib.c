/*
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
 *   $Id: selib.c 5414 2023-03-27 05:34:37Z gianluca $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2013 - 2022
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
 *               http://realtimelogic.com
 *               http://sharkssl.com
 ****************************************************************************


SharkSSL example socket library. The example library is used by all
examples. Porting layers for this library can be found in the 'arch'
directory.

Macro BASIC_TRUST_CHECK:
The example socket library can optionally validate the peer's
certificate and common name (domain name) for client connections. By
default, function SharkSslCon_trusted is used. This function can be
found in the optional SharkSSL file SharkSslEx.c. You can exclude this
file from your build and define BASIC_TRUST_CHECK to enable a much
more basic inline common name check in this file. The basic check can
verify an identical match for common name and is unable to verify
wildcard certificates and Subject Alternative Names (SAN).

Macro XPRINTF:
The library prints out various debug information if this macro is defined.

All other macros: See the SharkSSL documentation.
*/

#define SELIB_C

#include "selib.h"

#ifdef BASIC_TRUST_CHECK
#include <ctype.h>
#else
#include <SharkSslEx.h>
#endif

#if XPRINTF
static int traceDisabled=FALSE;
void se_disableTrace(int disable)
{
   traceDisabled=disable;
}
#define NTD if( ! traceDisabled )
#else
#define NTD
#endif


#if XPRINTF && SHARKSSL_ENABLE_INFO_API
void printCiphersuite(U16 cipherSuite)
{
   #define _case_printf(c) case c: xprintf((#c)); break
   switch (cipherSuite)
   {
      #if SHARKSSL_TLS_1_3
      _case_printf(TLS_AES_128_GCM_SHA256);
      _case_printf(TLS_AES_256_GCM_SHA384);
      _case_printf(TLS_CHACHA20_POLY1305_SHA256);
      #endif  /* SHARKSSL_TLS_1_3 */
      #if SHARKSSL_TLS_1_2
      _case_printf(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
      _case_printf(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
      _case_printf(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
      _case_printf(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
      _case_printf(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
      _case_printf(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
      _case_printf(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
      _case_printf(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
      _case_printf(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
      #endif  /* SHARKSSL_TLS_1_2 */
   default:
      xprintf(("ERROR: UNKNOWN"));
      break;
   }
   #undef _case_printf
}


/* Called when SSL Handshake is complete
 */
static void
printProtocolInfo(SharkSslCon *s)
{
   if(traceDisabled) return;
   xprintf(("handshake complete"));
   xprintf(("\nnegotiated protocol: "));
   switch (SharkSslCon_getProtocol(s))
   {
      #if SHARKSSL_TLS_1_2
      case SHARKSSL_PROTOCOL_TLS_1_2:
         xprintf(("TLS 1.2"));
         break;
      #endif

      #if SHARKSSL_TLS_1_3
      case SHARKSSL_PROTOCOL_TLS_1_3:
         xprintf(("TLS 1.3"));
         break;
      #endif

      default:
         xprintf(("ERROR: UNKNOWN"));
         break;
   }
   xprintf(("\nnegotiated ciphersuite: "));
   printCiphersuite(SharkSslCon_getCiphersuite(s));
   xprintf(("\n"));
}
#else
#define printCertInfo(notused)
#define printProtocolInfo(notused)
#endif


#if XPRINTF
static void
printCertSerial(SharkSslCertInfo* ci)
{
   if(traceDisabled) return;
   if(ci)
   {
      int i;
      xprintf(("---Received certificate---\n"));
      xprintf(("serial number: "));
      for(i=0; i<ci->snLen; i++)
         xprintf(("%02X", ci->sn[i]));
      xprintf(("\n"));
   }
}
#else
#define printCertSerial(ci)
#endif

#if SHARKSSL_ENABLE_CA_LIST

#ifdef BASIC_TRUST_CHECK
static int
strCaseCmp(const char *a, const char *b, int len)
{
   register int n=-1;
   while((len) && 
         ((n = tolower((unsigned char)*a) - tolower((unsigned char)*b)) == 0))
   {
      len--;
      a++, b++;
   }
   return n;
}
#endif

static SharkSslConTrust
getCertTrustInfo(SharkSslCon *s, const char* commonName)
{
#ifdef BASIC_TRUST_CHECK
   SharkSslCertInfo* ci = SharkSslCon_getCertInfo(s);
   if(ci)
   {
      printCertSerial(ci);
      if(commonName &&
         !strCaseCmp(commonName,(char*)ci->subject.commonName,ci->subject.commonNameLen))
      {
         return SharkSslCon_trustedCA(s) ?
            SharkSslConTrust_CertCn :
            SharkSslConTrust_Cn;
      }
      if(SharkSslCon_trustedCA(s))
         return SharkSslConTrust_Cert;
   }
   else
   {
      /* empty certificate handshake message */
      xprintf(("Peer has no certificate\n"));
   }
   return SharkSslConTrust_None;
#else
   /* Default: use a more advanced method for checking the common name */
   SharkSslCertInfo* ci;
   SharkSslConTrust status = SharkSslCon_trusted(s, commonName, &ci);
   printCertSerial(ci);
   return status;
#endif
}
#else
#define getCertTrustInfo(s,n) SharkSslConTrust_None
#endif


/* Prints out the SharkSSL error and returns -1
 */
static int
SharkSslCon_handleError(
   SharkSslCon *s, SOCKET* sock, SharkSslCon_RetVal errorCode)
{
   switch (errorCode)
   {
      case SharkSslCon_AlertSend: /* SSL alert message sent to peer. */
         /* One can retrieve the alert level and description through:
          * SharkSslCon_getAlertLevel(s)
          * SharkSslCon_getAlertDescription(s)
          */
         xprintf(("SharkSSL : Sent alert message, level %d, description %d\n",
                  SharkSslCon_getAlertLevel(s),
                  SharkSslCon_getAlertDescription(s)));
         baAssert(SharkSslCon_getAlertDataLen(s));
         se_send(sock, (void*)SharkSslCon_getAlertData(s),
                 SharkSslCon_getAlertDataLen(s));
         break;

      case SharkSslCon_AlertRecv: /* Alert message received from peer. */
         /* One can retrieve the alert level & description through:
          * SharkSslCon_getAlertLevel(s)
          * SharkSslCon_getAlertDescription(s)
          */
         if ((SharkSslCon_getAlertLevel(s) == SHARKSSL_ALERT_LEVEL_WARNING) &&
             (SharkSslCon_getAlertDescription(s)==SHARKSSL_ALERT_CLOSE_NOTIFY))
         {
            xprintf(("SharkSSL : Received closure alert \n"));
         }
         else
         {
            xprintf(("SharkSSL : Received alert, level %d, description %d\n",
                     SharkSslCon_getAlertLevel(s),
                     SharkSslCon_getAlertDescription(s)));
         }
         break;

      case SharkSslCon_Error:
         xprintf(("SharkSSL : Internal failure\n"));
         break;

      case SharkSslCon_CertificateError:
         xprintf(("SharkSSL : Certificate error\n"));
         break;

      case SharkSslCon_AllocationError:
         xprintf(("SharkSSL : Allocation error\n"));
         break;

      default:
         baAssert(0);
         return -1;
   }

   return -errorCode;
}


#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough="
#endif

static int
seSec_readOrHandshake(
   SharkSslCon *s, SOCKET* sock, U8 **buf, U32 timeout, const char* commonName)
{
   SharkSslCon_RetVal retVal;
   int nb, readLen = 0;
   #if SHARKSSL_ENABLE_CA_LIST == 0
   (void)commonName;
   #endif
   for (;;)
   {
      switch (retVal = SharkSslCon_decrypt(s, (U16)readLen))
      {
         case SharkSslCon_NeedMoreData:
            readLen = se_recv(sock, (void*)SharkSslCon_getBuf(s),
                              SharkSslCon_getBufLen(s), timeout);
            if (readLen <= 0)
               return readLen; /* 0 (no data) or -1 (socket error) */
            if (NULL == buf)  /* seSec_handshake */
            {
               NTD xprintf(("received %d handshake bytes\n", readLen));
            }
            break; /* decrypt next record */

         case SharkSslCon_Handshake:
            /* First: send pending data if any */
            if ((nb = SharkSslCon_getHandshakeDataLen(s)) != 0)
            {
               #if 1
               int sentbytes = se_send(sock, (void *)SharkSslCon_getHandshakeData(s), nb);
               #else  /* test */
               int sentbytes = se_send(sock, (void *)SharkSslCon_getHandshakeData(s), (nb > 10 ? (nb >> 1) : nb));
               #endif
               if (sentbytes < 0)
               {
                  return -1;
               }
               else if (sentbytes < nb)  /* HS buffer partially sent */
               {
                  /* new API function */
                  SharkSslCon_setHandshakeDataSent(s, (U16)sentbytes);
                  NTD xprintf(("sent %d/%d handshake bytes\n", sentbytes, nb));
               }
               else
               {
                  NTD xprintf(("sent %d handshake bytes\n", sentbytes));
               }
            }

            /** 
             * Second: check if handshake is complete - if so, get certificate 
			    * unless there are session tickets pending; in such case, process
			    * first the tickets, then return the certificate
			    */
            if ((nb = SharkSslCon_isHandshakeComplete(s)) != 0)
            {
               if ((NULL == buf) && (1 == nb))  /* seSec_handshake */
               {
                  printProtocolInfo(s);
                  return getCertTrustInfo(s, commonName);
               }
            }
            readLen = 0;
            break;

         case SharkSslCon_Decrypted:
            baAssert(buf);
            readLen = SharkSslCon_getDecData(s, buf);
            if (SharkSslCon_decryptMore(s) && (readLen == 0))
            {
               break; /* decrypt next record */
            }
            return readLen;

         case SharkSslCon_AlertSend:
            if (SharkSslCon_getAlertLevel(s) == SHARKSSL_ALERT_LEVEL_WARNING)
            {
               se_send(sock,(void*)SharkSslCon_getAlertData(s),
                       SharkSslCon_getAlertDataLen(s));
               return 0;
            }
            /* else fall through */

         default:
            return SharkSslCon_handleError(s, sock, retVal);
      }
   }
}


/*
  Performs the SSL handshaking using an asymmetric cipher in order to establish
  establish cipher settings and a shared key for the session. This function
  must be called only one time for each new connection and renegotiation.
*/
int
seSec_handshake(
   SharkSslCon *s, SOCKET* sock, U32 timeout, const char* commonName)
{
   #if (SHARKSSL_ENABLE_SNI && SHARKSSL_SSL_CLIENT_CODE)
   if (commonName)
   {
      SharkSslCon_setSNI(s, commonName, (U16)strlen(commonName)); 
   }
   #endif
   return seSec_readOrHandshake(s, sock, NULL, timeout, commonName);
}


int
seSec_read(SharkSslCon *s, SOCKET* sock, U8 **buf, U32 timeout)
{
   return seSec_readOrHandshake(s, sock, buf, timeout, 0);
}


int seSec_write(SharkSslCon *s, SOCKET* sock, U8* buf, int maxLen)
{
   SharkSslCon_RetVal retVal;
   int nb;
   if(maxLen > 0xFFFF)
      return -1;
   for (;;)
   {
      switch (retVal = SharkSslCon_encrypt(s, buf, (U16)maxLen))
      {
         case SharkSslCon_Encrypted:
            nb = SharkSslCon_getEncDataLen(s);
            if (nb != se_send(sock, (void*)SharkSslCon_getEncData(s), nb))
            {
               return -1;
            }
            /*
             * Returns true if the unencrypted buffer is larger than
             * what fits into the SharkSSL output buffer. SharkSSL
             * solves this by breaking the buffer into multiple chunks.
             */
            if (SharkSslCon_encryptMore(s))
            {
               break;
            }
            return maxLen; /* All data encrypted and sent. */

         case SharkSslCon_AlertSend:
            if (SharkSslCon_getAlertLevel(s) == SHARKSSL_ALERT_LEVEL_WARNING)
            {
               se_send(sock,(void*)SharkSslCon_getAlertData(s),
                       SharkSslCon_getAlertDataLen(s));
               return 0;
            }
            /* else fall through */

         default:
            return SharkSslCon_handleError(s, sock, retVal);
      }
   }
}


#ifndef NO_BSD_SOCK

#if !defined(_WIN32) && !defined(closesocket)
#define INVALID_SOCKET -1
#define closesocket close
#endif


/* Wait 'tmo' milliseconds for socket 'read' activity.
   Returns 0 on pending data and -1 on timeout.
*/
#ifndef X_readtmo
static int readtmo(SOCKET sock, U32 tmo)
{
   fd_set recSet;
   struct timeval tv;
   tv.tv_sec = tmo / 1000;
   tv.tv_usec = (tmo % 1000) * 1000;
   FD_ZERO(&recSet);
#ifdef WINFD_SET
   WINFD_SET(sock, &recSet);
#else
   FD_SET(sock, &recSet);
#endif
   return select(sock+1, &recSet, 0, 0, &tv) > 0 ? 0 : -1;
}
#endif

#ifndef X_se_connect
int se_connect(SOCKET* sock, const char* address, U16 port)
{
   unsigned int ip;
   struct sockaddr_in addr;
   struct hostent* hostInfo = gethostbyname(address);
   *sock=-1;
   if(hostInfo)
      ip=((struct in_addr *)hostInfo->h_addr)->s_addr;
   else
   {
      ip=inet_addr(address);
      if(ip == INADDR_NONE)
         return -2;
   }
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);
   addr.sin_addr.s_addr = ip;
   if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      return -1;
   if(connect(*sock, (struct sockaddr*)&addr, sizeof(addr)) != INVALID_SOCKET)
      return 0;
   se_close(sock);
   return -3;
}
#endif


#ifndef X_se_bind
int se_bind(SOCKET* sock, U16 port)
{
   struct sockaddr_in  addr;
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);
   addr.sin_addr.s_addr = INADDR_ANY;
   if((*sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
   {
      xprintf(("Socket error\n"));
      return -1;
   }
   if(bind(*sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
   {
      xprintf(("Bind error: port %d\n", (int)port));
      se_close(sock);
      return -3;
   }
   if(listen(*sock, SOMAXCONN) < 0)
   {
      xprintf(("Listen error\n"));
      se_close(sock);
      return -2;
   }
   return 0;
}
#endif



/*
  Extract the first connection on the queue of pending connections,
  create a new socket, and allocate a new file descriptor for that
  socket.

  Returns:
  1: Success
  0: timeout
  -1: error

*/
int se_accept(SOCKET** listenSock, U32 timeout, SOCKET** outSock)
{
   if(timeout != INFINITE_TMO)
   {
      **outSock = -1;
      if(readtmo(**listenSock,timeout))
         return 0;
   }
   if( (**outSock=accept(**listenSock, 0, 0)) < 0 )
      return -1;
   return 1;
}


void se_close(SOCKET* sock)
{
   closesocket(*sock);
   *sock=-1;
}


int se_sockValid(SOCKET* sock)
{
   return *sock > 0 ? 1 : 0;
}


S32 se_send(SOCKET* sock, const void* buf, U32 len)
{
   return send(*sock,(void*)buf,len,0);
}


#ifndef X_se_recv
S32 se_recv(SOCKET* sock, void* buf, U32 len, U32 timeout)
{
   int recLen;
   if(*sock < 0)
      return -1;
   if(timeout != INFINITE_TMO)
   {
      if(readtmo(*sock,timeout))
         return 0;
   }

   recLen = recv(*sock,buf,len,0);
   if (recLen <= 0)
   {
      /* If the virtual circuit was closed gracefully, and
       * all data was received, then a recv will return
       * immediately with zero bytes read.
       * We return -1 for above i.e. if(recLen == 0) return -1;
       * Note: this construction does not work with non blocking sockets.
       */
      return -1;
   }
   return recLen;
}
#endif



#endif /* NO_BSD_SOCK */
