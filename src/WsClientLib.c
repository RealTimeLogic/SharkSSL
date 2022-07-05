/**
 *     ____             _________                __                _
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/
 *                                                       /____/
 *
 *                    WebSocket Client Library
 *                 SharkSSL Embedded SSL/TLS Stack
 ****************************************************************************
 *   PROGRAM MODULE
 *
 *   $Id: WsClientLib.c 5120 2022-03-24 15:25:13Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2014 - 2022
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

#include "WsClientLib.h"
#include <ctype.h>
#include <stddef.h>


/* The WS HTTP Header:

The HTTP header sent to the WS server. You can use this HTTP header
when connecting to any WS enabled server.

The following is a short explanation on the HTTP headers used.

Host:
   This header is not required by WebSocket, but may be required if
   the server is multihomed, i.e. if the server hosts multiple domains.

Origin:
   A security related header required when using WebSocket from
   browsers. This header is not required for non-browser clients;
   however, some servers may require this header. The header is
   commented out in this example.

Sec-WebSocket-Key:
   The value of this header field MUST be a nonce consisting of a
   randomly selected 16-byte value that has been base64-encoded.

Sec-WebSocket-Version:
   The WebSocket version. We use the version specified in RFC6455.

Connection and Upgrade:
  These headers tell the server that this is a WebSocket request.
*/

static const U8 httpCmd[] = {
/* The following is filled in by the code below. It is just shown here
   so you can see what the data sent on the wire looks like.

   "GET /the/path HTTP/1.1\r\n"
   "Host: www.websocket.org"
   "\r\nOrigin: https://www.websocket.org"
*/
   "\r\nSec-WebSocket-Key: U2hhcmtTU0xLaWNrc0Fzcw==\r\n"
   "Sec-WebSocket-Version: 13\r\n"
   "Connection: Upgrade\r\n"
   "Upgrade: websocket\r\n"
   "\r\n" /* End HTTP header */
};


/************************* Helper functions ******************************/

/* strstrn:
  Similar to the standard ANSI function strstr, except for that it
  does not rely on str being a zero terminated string. The compare is
  also case insensitive.

  str: String to search.
  slen: str len
  substr: Substring to try to find in str.
*/
static U8*
strstrn(U8* str, int slen, const U8* substr)
{
   const U8 *a, *b, *e;
   b = substr;
   e=str+slen;
   for ( ; str < e; str++)
   {
      if (tolower(*str) != tolower(*b))
         continue;
      a = str;
      while(a < e)
      {
         if (*b == 0)
            return str;
         if (tolower(*a++) != tolower(*b++))
            break;
      }
      if (*b == 0)
         return str;
      b = substr;
   }
   return 0;
}


static U8*
msCpAndInc(U8* dest, int* dlen, const U8* src, int slen)
{
   if(!dest || *dlen < 0) return 0;
   if(!slen) slen=strlen((char*)src);
   *dlen -= slen;
   memcpy(dest,src,slen);
   return dest+slen;
}



/************************ End helper functions ***************************/

/* wscProtocolHandshake: WS HTTP request/response handshake.
 *
 * This function sends the HTTP header and validates the server's HTTP
 * response header -- the function simulates a very basic HTTP client
 * library. The function is designed to be as simple as possible and
 * the code is, for this reason, making a few assumptions that could
 * fail when used with a non traditional HTTP server. Most HTTP
 * servers will send a complete HTTP response as one chunk, and the
 * call to function seSec_read below assumes that we read the complete
 * HTTP response when in secure mode (Ref-Underflow). The function
 * will fail and return a negative value if it does not receive the
 * complete HTTP response.
 */
int
wscProtocolHandshake(WscState* wss, U32 tmo, const char* host,
                     const char* path, const char* origin)
{
   int rc=1; /* Status or len */
   int hs=-1; /* handshake status */
   U8* ptr;

   if(!wss->sock)
      return -100;

   /* SSL is a client server protocol and we must initiate the
    * connection by sending SSL hello. The following function (in
    * selib.c) performs the initial SSL handshake.  Note: we are not
    * validating the server cert in this example. See the 'certcheck.c'
    * example for how to validate the server.
    */
   if( 
#ifdef WSC_DUAL
      wss->scon &&
#endif
      (rc = seSec_handshake(wss->scon, wss->sock, tmo, host)) <= 0 )
   {
      xprintf(("SSL handshake failed\n"));
   }
   else
   {
      static const U8 xg[] = {"GET "};
      static const U8 xp[] = {" HTTP/1.1\r\n"};
      static const U8 xh[] = {"Host: "};
      static const U8 xo[] = {"\r\nOrigin: "};
      int sblen;
      U8* sbuf;
#ifdef WSC_DUAL
      if(wss->scon)
      {
         /* Using zero copy SharkSSL API */
         sblen=SharkSslCon_getEncBufSize(wss->scon);
         sbuf=SharkSslCon_getEncBufPtr(wss->scon);
      }
      else
      {
         sblen=wss->sendBufLen;
         sbuf=wss->sendBuf;
         if(!sblen || !sbuf || !wss->recBufLen || !wss->recBuf)
            return -101;
      }
#else
      /* Using zero copy SharkSSL API */
      sblen=SharkSslCon_getEncBufSize(wss->scon);
      sbuf=SharkSslCon_getEncBufPtr(wss->scon);
#endif
      ptr=msCpAndInc(sbuf,&sblen,xg,sizeof(xg)-1);
      hs=rc;
      ptr=msCpAndInc(ptr,&sblen,(U8*)path,0);
      ptr=msCpAndInc(ptr,&sblen,xp,sizeof(xp)-1);
      ptr=msCpAndInc(ptr,&sblen,xh,sizeof(xh)-1);
      ptr=msCpAndInc(ptr,&sblen,(U8*)host,0);
      if(origin)
      {
         ptr=msCpAndInc(ptr,&sblen,xo,sizeof(xo)-1);
         ptr=msCpAndInc(ptr,&sblen,(U8*)origin,0);
      }
      ptr=msCpAndInc(ptr,&sblen,httpCmd,sizeof(httpCmd)-1);
      if(!ptr)
         return -102; /* The send buffer is too small */
      /* Send the WebSocket HTTP header */
#ifdef WSC_DUAL
      if((rc=(wss->scon ? seSec_write(wss->scon, wss->sock, 0, ptr-sbuf) :
              se_send(wss->sock, sbuf, ptr-sbuf)) ) < 0)
#else
      if((rc=seSec_write(wss->scon, wss->sock, 0, ptr-sbuf)) < 0)
#endif
      {
         xprintf(("Sending HTTP header failed\n"));
      }
      else
      {
         U8* buf;
#ifdef WSC_DUAL
         if(wss->scon)
         {
            /* We assume a complete HTTP response is received within
             * the TLS frame received.
             */ 
            rc=seSec_read(wss->scon,wss->sock,&buf,tmo);
         }
         else
         {
            /* Keep reading until the complete HTTP response has been
             * received.
             */
            int rcx=0;
            int len=wss->recBufLen;
            ptr=buf=wss->recBuf;
            for(;;)
            {
               if( (rc = se_recv(wss->sock,ptr,len,tmo)) <= 0)
                  break;
               rcx+=rc;
               if(strstrn(buf, len, (U8*)"\r\n\r\n"))
               {
                  rc=rcx;
                  break;
               }
               len-=rc;
               ptr+=rc;
               if(len <=0)
                  return -103;/* recBuf must be larger */
            }
         }
#else
         if( ! wss->scon )
            return -104;
         rc = seSec_read(wss->scon,wss->sock,&buf,tmo);
#endif
         if( rc <= 0 )
         {
            xprintf(("HTTP response header error: %s.\n",
                     rc == 0 ? "timeout" : "connection closed"));
            rc=-1;
         }
         else
         {  /* Parse (validate) server's HTTP response */
            int len=rc;
            ptr=buf;
            /* The value in Sec-WebSocket-Accept is designed for
             * browsers so they can detect malicious JavaScript
             * code. The security concept is not relevant to non
             * browser clients. We only check for the header. The
             * server resource is not a WS if the response does not
             * include Sec-WebSocket-Accept.
             */
            if(!strstrn(buf, len, (U8*)"Sec-WebSocket-Accept"))
               xprintf(("WebSocket connection not accepted by server\n"));
            else
            {
                /* Find end of HTTP response */
               ptr=strstrn(buf, len, (U8*)"\r\n\r\n");
               if(!ptr) /* Ref-Underflow */
               {
                  xprintf(("Cannot validate HTTP header response\n"));
                  rc=-2;
               }
               else /* Successful HTTP and WS handshake */
               {
                  rc=ptr-buf+4;
                  if(rc < len)
                  {
                     wss->overflowPtr=ptr+4;
                     wss->overflowLen=len-rc;
                  }
                  rc=0; /* Success */
               }
            }
         }
      }
   }
   wss->frameHeaderIx = 0;
   return rc ? rc : hs; /*Status on sock error, otherwise return SSL handshake*/
}


/* wscRawWrt: Send binary/text frame or control frames to server.
 *
 * The function appends the WS frame header, masks the payload data
 * 'buf', and sends the data securely to the WS server by calling
 * seSec_write. See RFC6455: "5.1. Overview" for an introduction
 * to masking.
 *
 * Note: this function is using the zero copy SharkSSL API. The
 * masked data is inserted directly into the SharkSSL buffer and the
 * 'buf' parameter in seSec_write is set to zero to signal that
 * we are using the zero copy API.
 *
 * Note: this is an internal function. You should use wscSendBin.
 */
static int
wscRawWrt(WscState* wss, U8 opCode,const U8* buf,int len)
{
   int i, frameLen;
   U8* sbuf;
   U8* ptr;
   U8* maskPtr;
#ifdef WSC_DUAL
   if(wss->scon)
   {
      if(len+8 > SharkSslCon_getEncBufSize(wss->scon))
         return -1;
      sbuf=SharkSslCon_getEncBufPtr(wss->scon);
   }
   else
   {
      if(len+8 > wss->sendBufLen)
         return -1;
      sbuf=wss->sendBuf;
   }
#else
   if(len+8 > SharkSslCon_getEncBufSize(wss->scon))
      return -1; /* Crank up the SharkSSL buffer size or use smaller messages */
   sbuf=SharkSslCon_getEncBufPtr(wss->scon); /* Using zero copy SharkSSL API */
#endif
   sbuf[0] = opCode;
   if(len <= 125) /* Standard "Payload len" */
   {
      if(len)
      {
         sbuf[1] = 0x80 | (U8)len; /* Mask bit set + len */
         maskPtr=sbuf+2;
         frameLen=len+6;
      }
      else
      {
         sbuf[1] = 0; /* Mask bit not set since we do not have payload */
#ifdef WSC_DUAL
         return wss->scon ? seSec_write(wss->scon, wss->sock, 0, 2) :
            se_send(wss->sock, sbuf, 2);
#else
         return seSec_write(wss->scon, wss->sock, 0, 2);
#endif
      }
   }
   else /* Extended payload */
   {
      if(len > 0xFFFF) return -1; /* We accept a max length of 2^16 */
      sbuf[1] = 0x80 | 126; /* 126 -> 16 bit extended payload */
      sbuf[2] = (U8)((unsigned)len >> 8); /* high */
      sbuf[3] = (U8)len; /* low */
      maskPtr=sbuf+4;
      frameLen=len+8;
   }

   /* The WS mask is required, however the security concept does not
    * apply to non browsers so we can safely use any value. RFC6455
    * 5.3. The 4 byte mask is whatever random mumber (uninitialized
    * value) that is stored in the buffer 'maskPtr', except for the
    * first byte, which is set to 0x55.
    */
   maskPtr[0]=0x55;
   ptr=maskPtr+4; /* ptr: Payload start */

   /* Mask payload data: RFC6455 5.3.  Client-to-Server Masking */
   for(i=0 ; i < len; i++,ptr++,buf++)
   {
      /* orig-octet-i = masked-octet-i XOR (maskPtr[i MOD 4]) */
      *ptr = *buf ^ maskPtr[i&3];
   }

#ifdef WSC_DUAL
   return wss->scon ? seSec_write(wss->scon, wss->sock, 0, frameLen) :
      se_send(wss->sock, sbuf, frameLen);
#else
   /* We must set length to zero when using the zero copy SharkSSL API */
   return seSec_write(wss->scon, wss->sock, 0, frameLen);
#endif
}


/* wscSendBin: send binary data to server.
 *
 */
int
wscSendBin(WscState* wss, U8* buf, int len)
{
   return wscRawWrt(wss, WSOP_Binary, buf, len);
}


/* wscSendCtrl: send a WebSocket control frame.
 * 
 */
int
wscSendCtrl(WscState* wss, U8 opCode, const U8* buf,int len)
{
   if(len > 125) return -1; /* Max control frame payload is 125 */
   return wscRawWrt(wss, opCode, buf, len);
}


/* wscClose: Sends a WS close control frame to the server.
 * statusCode values: RFC6455 7.4.1
 */
int
wscClose(WscState* wss, int statusCode)
{
   U8 ctrlBuf[2]; /* 2 byte status code RFC6455 5.5.1 */
   ctrlBuf[0] = (U8)((unsigned)statusCode >> 8); /* high */
   ctrlBuf[1] = (U8)statusCode; /* low */
   wscSendCtrl(wss, WSOP_Close,ctrlBuf, statusCode > 0 ? 2 : 0);
   se_close(wss->sock);
   return statusCode < 0 ? statusCode : -statusCode;
}


/* wscRawRead: Reads and decodes WebSocket frames received
 * from the server.
 *
 * This function reads socket data by calling seSec_read. The
 * function decodes the WebSocket frame from the data on the TCP stream and
 * keeps track of the frame payload cursor. The frame information is
 * stored in WscState.
 *
 * Note: this is an internal function. You should use wscRead.
 */
static int
wscRawRead(WscState* wss,U8 **buf,U32 timeout)
{
   U8* ptr;
   int len;
   int newFrame=FALSE;
   if(wss->overflowPtr) /* Previous frame: Consumed more than frame length */
   {
      len = wss->overflowLen;
      ptr = wss->overflowPtr;
      wss->overflowPtr=0;
   }
   else
   {
     L_readMore:
#ifdef WSC_DUAL
      *buf=wss->recBuf;
      if( (len=(wss->scon ? seSec_read(wss->scon, wss->sock, buf, timeout) :
           se_recv(wss->sock, *buf, wss->recBufLen, timeout)) ) <= 0 )
#else
      if( (len=seSec_read(wss->scon, wss->sock, buf, timeout)) <= 0 )
#endif
      {
         if(len == 0)
            wss->isTimeout = TRUE;
         else
            wss->frameHeaderIx = 0;
         return len;
      }
      ptr = *buf;
   }
   wss->isTimeout=0;
   /* Do we have a complete frame header ? */
   while(wss->frameHeaderIx < 2 ||
         (wss->frameHeaderIx < 4 && (wss->frameHeader[1] & 0x7F) > 125))
   {
      if(len == 0)
         goto L_readMore; /* Read from socket */
      newFrame=TRUE;
      wss->frameHeader[wss->frameHeaderIx++] = *ptr++;
      len--;
   }
   if(newFrame) /* Start of new frame */
   {
      wss->bytesRead=0;
      if(wss->frameHeaderIx == 2)
      {
         /* We do not check MASK since servers must not use it */
         wss->frameLen = wss->frameHeader[1];
      }
      else
      {
         baAssert(wss->frameHeaderIx == 4);
         /* We only accept 16 bit extended frames */
         if((wss->frameHeader[1] & 0x7F) > 126)
            return wscClose(wss, 1009);
         wss->frameLen = (int)(((U16)wss->frameHeader[2]) << 8);
         wss->frameLen |= wss->frameHeader[3];
      }
   }
   *buf = ptr; /* Adjust payload for consumed header (rec or overflow data) */
   wss->bytesRead += len;
   if(wss->bytesRead >= wss->frameLen)
   {
      if(wss->bytesRead > wss->frameLen) /* Read overflow */
      {
         wss->overflowLen = wss->bytesRead - wss->frameLen;
         wss->bytesRead = wss->frameLen;
         len -= wss->overflowLen;
         baAssert(len >= 0);
         wss->overflowPtr = ptr + len;
      }
      wss->frameHeaderIx=0; /* Prepare for next frame */
   }
   return len;
}


/* wscRead: 
 * Use this function to read WebSocket frames sent from the server.
 *
 * The function calls wscRawRead and decodes the frame
 * information. Control frames are managed internally. The function
 * returns the length of text and binary frames or -1 on socket close,
 * including WebSocket close messages received from server.
 *
 * Note: larger WebSocket frames may be split into chunks. The member
 * values 'bytesRead' and 'frameLen' in struct WscState notifies
 * you on the total frame length and how much data you have read from
 * the socket for the current frame. See the example code for how to
 * use this function.
 */
int
wscRead(WscState* wss, U8 **buf, U32 timeout)
{
   int len;
   U8 ctrlBuf[125]; /* max control frame payload */
  L_readMore:
   len = wscRawRead(wss, buf, timeout);
   if(len >= 0 && !wss->isTimeout)
   {
      switch(wss->frameHeader[0])
      {
         case WSOP_Text:
         case WSOP_Binary:
            break;

         /* Control frames below */

         case WSOP_Close:
            return wscClose(wss, 1000);

         case WSOP_Ping:
         case WSOP_Pong: /* RFC allows unsolicited pongs */
            if(wss->frameLen)
            {
               /* Cursor is bytesRead - len */
               if(wss->frameLen > 125) /* not allowed */
                  return wscClose(wss, 1002);
               memcpy(ctrlBuf + wss->bytesRead - len, *buf, len);
               if(wss->bytesRead < wss->frameLen)
                  goto L_readMore;
            }
            if(wss->frameHeader[0] == WSOP_Ping)
               wscSendCtrl(wss,WSOP_Pong,ctrlBuf,wss->frameLen);
            goto L_readMore;

         default:  /* Unkown opcode (rsp 1002) or FIN=0 (rsp 1008) */
            return wscClose(wss, 0x80 & wss->frameHeader[0] ? 1002 : 1008);
      }
   }
   return len;
}
