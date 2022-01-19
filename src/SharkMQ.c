/**
 *     ____             _________                __                _
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/
 *                                                       /____/
 *
 ****************************************************************************
 *   PROGRAM MODULE
 *
 *   This file is part of SharkMQ:
 *            https://realtimelogic.com/products/simplemq/
 *   SharkMQ is a secure SMQ client.
 *   See the example program for how to use SMQ: m2m-led-SharkMQ.c 
 *
 *   $Id: SharkMQ.c 5029 2022-01-16 21:32:09Z wini $
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


#include "SMQ.h"
#include <ctype.h>

#ifdef ENABLE_PROXY
#include "proxy.ch"
#endif

#define MSG_INIT         1
#define MSG_CONNECT      2
#define MSG_CONNACK      3
#define MSG_SUBSCRIBE    4
#define MSG_SUBACK       5
#define MSG_CREATE       6
#define MSG_CREATEACK    7
#define MSG_PUBLISH      8
#define MSG_UNSUBSCRIBE  9
#define MSG_DISCONNECT   11
#define MSG_PING         12
#define MSG_PONG         13
#define MSG_OBSERVE      14
#define MSG_UNOBSERVE    15
#define MSG_CHANGE       16
#define MSG_CREATESUB    17
#define MSG_CREATESUBACK 18
#define MSG_PUBFRAG      19

#ifndef EXT_SHARK_LIB
#define sharkStrchr strchr
#endif


#define SharkMQ_S_VERSION 1
#define SharkMQ_C_VERSION 2

#if defined(B_LITTLE_ENDIAN)
static void
netConvU16(U8* out, const U8* in)
{
   out[0] = in[1];
   out[1] = in[0];
}
static void
netConvU32(U8* out, const U8* in)
{
   out[0] = in[3];
   out[1] = in[2];
   out[2] = in[1];
   out[3] = in[0];
}
#elif defined(B_BIG_ENDIAN)
#define netConvU16(out, in) memcpy(out,in,2)
#define netConvU32(out, in) memcpy(out,in,4)
#else
#error ENDIAN_NEEDED_Define_one_of_B_BIG_ENDIAN_or_B_LITTLE_ENDIAN
#endif


static int
SharkMQ_setErrStatus(SharkMQ* o, int status)
{
   baAssert(status < 0);
   if(SMQ_TIMEOUT != status)
   {
      o->sharkBufIx=o->bufIx=o->frameLen=o->bytesRead=0;
      o->sharkBuf=0;
      se_close(&o->sock);
   }
   return o->status = status;
}

/* Read 'len' bytes or less.
   Returns 'len' on success and a negative val on error.
 */
static int
SharkMQ_recv(SharkMQ* o, U16 len, U8** data)
{
   U16 left;
   if( ! o->sharkBuf )
   {
      int rlen;
      if( (rlen=seSec_read(o->scon, &o->sock, &o->sharkBuf,o->timeout)) <= 0)
         return SharkMQ_setErrStatus(o, rlen == 0 ? SMQ_TIMEOUT : rlen);
      o->sharkBufLen = (U16)rlen;
      o->bufIx = o->sharkBufIx = 0;
   }
   o->status = 0;
   *data = o->sharkBuf + o->sharkBufIx;
   left = o->sharkBufLen - o->sharkBufIx;
   if(len >= left)
   {
      o->sharkBuf = 0;
      return (int)left;
   }
   o->sharkBufIx += len;
   return len;
}


/*
  Read and copy recdata to o->buf and advance o->bufIx, where max
  index is 'maxIx'.
  Returns zero on success or a value on error.
 */
static int
SharkMQ_recHeader(SharkMQ* o, U16 maxIx)
{
   U8* buf;
   int len;
   baAssert(o->bufIx < maxIx); /* Should not be called if already at this pos */
   if(maxIx > o->bufLen)
      return SharkMQ_setErrStatus(o, SMQE_BUF_OVERFLOW);
   while(o->bufIx < maxIx)
   {
      if( (len=SharkMQ_recv(o, maxIx - o->bufIx, &buf)) < 0)
         return len;
      memcpy(o->buf+o->bufIx, buf, len);
      o->bufIx += (U16)len;
      if(o->bufIx >= 2)
         netConvU16((U8*)&o->frameLen, o->buf);
   }
   return 0;
}


/* Reads a complete frame.
   Designed to be used by control frames.
   Returns zero on success or a value (error code) less than zero on error.
*/
static int
SharkMQ_readFrame(SharkMQ* o)
{
   if(o->bufIx < 3 && SharkMQ_recHeader(o, 3))
      return o->status;
   if(SharkMQ_recHeader(o, o->frameLen))
      return o->status;
   o->bufIx=0; /* Prepare for next SMQ frame */
   return 0;
}

static int
SharkMQ_flushb(SharkMQ* o)
{
   if(o->sendBufIx)
   {
      int x = seSec_write(o->scon, &o->sock, 0, o->sendBufIx);
      o->sendBufIx = 0;
      if(x < 0)
         return SharkMQ_setErrStatus(o,x);
   }
   return 0;
}

static int
SharkMQ_putb(SharkMQ* o, const void* data, int len)
{
   U16 bufLen = SharkSslCon_getEncBufSize(o->scon);
   U8* buf = SharkSslCon_getEncBufPtr(o->scon);
   if(len < 0)
      len = strlen((char*)data);
   if(bufLen <= (o->sendBufIx + len))
      return -1;
   memcpy(buf + o->sendBufIx, data, len);
   o->sendBufIx += (U16)len;
   return 0;
}



static int
SharkMQ_writeb(SharkMQ* o, const void* data, int len)
{
   U16 bufLen = SharkSslCon_getEncBufSize(o->scon);
   U8* buf = SharkSslCon_getEncBufPtr(o->scon);
   if(len < 0)
      len = strlen((char*)data);
   if(bufLen <= (o->sendBufIx + len))
   {
      if(SharkMQ_flushb(o)) return o->status;
      if((len+20) >= bufLen)
      {
         len = seSec_write(o->scon, &o->sock, (U8*)data, len);
         if(len < 0)
            return SharkMQ_setErrStatus(o,len);
         return 0;
      }
   }
   memcpy(buf + o->sendBufIx, data, len);
   o->sendBufIx += (U16)len;
   return 0;
}


void
SharkMQ_constructor(SharkMQ* o, U8* buf, U16 bufLen)
{
   memset(o, 0, sizeof(SharkMQ));
   o->buf = buf;
   o->bufLen = bufLen;
   o->timeout = 60 * 1000;
   o->pingTmo = 20 * 60 * 1000;
}


int
SharkMQ_init(SharkMQ* o, SharkSslCon* scon, const char* url, U32* rnd)
{
   int x;
   const char* path;
   const char* eohn; /* End Of Hostname */
   U16 portNo=0;
   U8* buf = o->buf;
   U32 savedTimeout=o->timeout;
   o->scon = scon;
   if(strncmp("https://",url,8))
      return SMQE_INVALID_URL;
   url+=8;
   path=sharkStrchr(url, '/');
   if(!path)
      return o->status = SMQE_INVALID_URL;
   if(path > url && isdigit((unsigned char)*(path-1)))
   {
      for(eohn = path-2 ; ; eohn--)
      {
         if(path > url)
         {
            if( ! isdigit((unsigned char)*eohn) )
            {
               const char* ptr = eohn;
               if(*ptr != ':')
                  goto L_defPorts;
               while(++ptr < path)
                  portNo = 10 * portNo + (*ptr-'0');
               break;
            }
         }
         else
            return o->status = SMQE_INVALID_URL;
      }
   }
   else
   {
     L_defPorts:
      portNo=443;
      eohn=path; /* end of eohn */
   }
   /* Write hostname */
   o->sendBufIx = (U16)(eohn-url); /* save hostname len */
   if((o->sendBufIx+1) >= o->bufLen)
      return o->status = SMQE_BUF_OVERFLOW;
   memcpy(buf, url, o->sendBufIx); 
   buf[o->sendBufIx]=0;

   /* connect to 'hostname' */
#ifdef ENABLE_PROXY
   if(o->proxy)
   {
      ProxyArgs args;
      args.buf=(char*)baMalloc(500);
      if(!args.buf)
         return -1;
      args.bufLen=500;
      args.sock=&o->sock;
      args.host=(char*)buf;
      args.port=portNo;
      x = o->proxy->connect(o->proxy, &args);
      baFree(args.buf);
      if(x)
         return o->status = x;
   }
   else
#endif
      if( (x = se_connect(&o->sock, (char*)buf, portNo)) != 0 )
         return o->status = x;

   if( (x = seSec_handshake(
           scon, &o->sock, o->timeout < 2000 ? 2000 :  o->timeout,
           (char*)buf)) <= 0 )
   {
      se_close(&o->sock);
      return o->status = (x == 0 ? SMQ_TIMEOUT : x);
   }
   /* Send HTTP header. Host is included for multihomed servers */
   o->sendBufIx=0;
   if(SharkMQ_writeb(o, SMQSTR("GET ")) ||
      SharkMQ_writeb(o, path, -1) ||
      SharkMQ_writeb(o,SMQSTR(" HTTP/1.0\r\nHost: ")) ||
      SharkMQ_writeb(o, url, eohn-url) ||
      SharkMQ_writeb(o, SMQSTR("\r\nSimpleMQ: 1\r\n")) ||
      SharkMQ_writeb(o, SMQSTR("User-Agent: SimpleMQ/1\r\n\r\n")) ||
      SharkMQ_flushb(o))
   {
      return o->status;
   }
   /* Get the Init message */
   if(o->timeout < 2000)  o->timeout=2000;
   SharkMQ_readFrame(o);
   o->timeout=savedTimeout;
   if(o->status)
      return o->status;
   buf = o->buf;
   if(o->frameLen < 11 || buf[2] != MSG_INIT || buf[3] != SharkMQ_S_VERSION)
      return SharkMQ_setErrStatus(o,SMQE_PROTOCOL_ERROR);
   if(rnd)
      netConvU32((U8*)rnd,buf+4);
   memmove(buf, buf+8, o->frameLen-8);
   buf[o->frameLen-8]=0;
   return o->status = x; /* Response from seSec_handshake */
}



int
SharkMQ_connect(SharkMQ* o, const char* uid, int uidLen,
                const char* credentials, U8 credLen,
                const char* info, int infoLen,
                U16 maxTlsFrameSize)
{
   U8* buf;
   if(SMQ_TIMEOUT != o->status)
   {
      buf = SharkSslCon_getEncBufPtr(o->scon);
      if(SharkSslCon_getEncBufSize(o->scon) < 5+uidLen+credLen+infoLen)
         return SharkMQ_setErrStatus(o,SMQE_BUF_OVERFLOW);
      o->sendBufIx = 2;
      buf[o->sendBufIx++] = MSG_CONNECT;
      buf[o->sendBufIx++] = SharkMQ_C_VERSION;
      netConvU16(buf+o->sendBufIx, (U8*)&maxTlsFrameSize);
      o->sendBufIx+=2;
      buf[o->sendBufIx++] = (U8)uidLen;
      SharkMQ_putb(o,uid,uidLen);
      buf[o->sendBufIx++] = credLen;
      if(credLen)
         SharkMQ_putb(o,credentials,credLen);
      if(info)
         SharkMQ_putb(o,info,infoLen);
      netConvU16(buf, (U8*)&o->sendBufIx); /* Frame Len */
      if(SharkMQ_flushb(o)) return o->status;
   }
   /* Get the response message Connack */
   if(SharkMQ_readFrame(o))
      return SMQ_TIMEOUT == o->status ? 0 : o->status;
   buf = o->buf;
   if(o->frameLen < 8 || buf[2] != MSG_CONNACK)
      return SharkMQ_setErrStatus(o,SMQE_PROTOCOL_ERROR);
   netConvU32((U8*)&o->clientTid, buf+4);
   if(buf[3] != 0)
   {
      memmove(buf, buf+8, o->frameLen-8);
      buf[o->frameLen-8]=0;
   }
   else
      buf[0]=0; /* No error message */
   o->status = (int)buf[3]; /* OK or error code */
   return o->status;
}


void
SharkMQ_disconnect(SharkMQ* o)
{
   if(se_sockValid(&o->sock))
   {
      U8* buf = SharkSslCon_getEncBufPtr(o->scon);
      if(buf)
      {
         o->sendBufIx = 3;
         netConvU16(buf, (U8*)&o->sendBufIx); /* Frame Len */
         buf[2] = MSG_DISCONNECT;
         SharkMQ_flushb(o);
         while(SharkMQ_getMessage(o, &buf) > 0);
      }
      se_close(&o->sock);
   }
}


void
SharkMQ_destructor(SharkMQ* o)
{
   if(se_sockValid(&o->sock))
      se_close(&o->sock);
}

/* Send MSG_SUBSCRIBE, MSG_CREATE, or MSG_CREATESUB */
static int
SharkMQ_subOrCreate(SharkMQ* o,const char* topic,int msg)
{
   U8* buf = SharkSslCon_getEncBufPtr(o->scon);
   int len = strlen(topic);
   if( ! len ) return SharkMQ_setErrStatus(o,SMQE_PROTOCOL_ERROR);
   if((3+len) > SharkSslCon_getEncBufSize(o->scon))
      return SharkMQ_setErrStatus(o,SMQE_BUF_OVERFLOW);
   o->sendBufIx = 2;
   buf[o->sendBufIx++] = (U8)msg;
   SharkMQ_putb(o,topic,len);
   netConvU16(buf, (U8*)&o->sendBufIx); /* Frame Len */
   return SharkMQ_flushb(o);
}


int
SharkMQ_subscribe(SharkMQ* o, const char* topic)
{
   return SharkMQ_subOrCreate(o,topic, MSG_SUBSCRIBE);
}


int
SharkMQ_create(SharkMQ* o, const char* topic)
{
   return SharkMQ_subOrCreate(o,topic,MSG_CREATE);
}


int
SharkMQ_createsub(SharkMQ* o, const char* topic)
{
   return SharkMQ_subOrCreate(o,topic,MSG_CREATESUB);
}


static int
SharkMQ_sendMsgWithTid(SharkMQ* o, int msgType, U32 tid)
{
   U8* buf = SharkSslCon_getEncBufPtr(o->scon);
   o->sendBufIx=7;
   netConvU16(buf, (U8*)&o->sendBufIx); /* Frame Len */
   buf[2] = (U8)msgType;
   netConvU32(buf+3, (U8*)&tid);
   return SharkMQ_flushb(o) ? o->status : 0;
}


int
SharkMQ_unsubscribe(SharkMQ* o, U32 tid)
{
   return SharkMQ_sendMsgWithTid(o, MSG_UNSUBSCRIBE, tid);
}


int
SharkMQ_publish(SharkMQ* o, const void* data, int len, U32 tid, U32 subtid)
{
   U16 tlen=(U16)len+15;
   if(tlen <= SharkSslCon_getEncBufSize(o->scon))
   {
      U8* buf = SharkSslCon_getEncBufPtr(o->scon);
      netConvU16(buf, (U8*)&tlen); /* Frame Len */
      buf[2] = MSG_PUBLISH;
      netConvU32(buf+3, (U8*)&tid);
      netConvU32(buf+7,(U8*)&o->clientTid);
      netConvU32(buf+11,(U8*)&subtid);
      o->sendBufIx = 15;
      if(data)
      {
         if(SharkMQ_writeb(o, data, len) || SharkMQ_flushb(o)) return o->status;
      }
      else /* Using zero copy API */
      {  /* Note, not boundary checks. Application using SMQ must check this */
         o->sendBufIx += (U16)len;
         if(SharkMQ_flushb(o)) return o->status;
      }
   }
   else
   {
      U8 buf[15];
      netConvU16(buf, (U8*)&tlen); /* Frame Len */
      buf[2] = MSG_PUBLISH;
      netConvU32(buf+3, (U8*)&tid);
      netConvU32(buf+7,(U8*)&o->clientTid);
      netConvU32(buf+11,(U8*)&subtid);
      o->status=seSec_write(o->scon,&o->sock, buf, 15);
      if(o->status < 0) return SharkMQ_setErrStatus(o,o->status);
      o->status=seSec_write(o->scon,&o->sock, (U8*)data, len);
      if(o->status < 0) return SharkMQ_setErrStatus(o,o->status);
      o->status=0;
   }
   return 0;
}


int
SharkMQ_wrtstr(SharkMQ* o, const char* data)
{
   return SharkMQ_write(o,data,strlen(data));
}


int
SharkMQ_write(SharkMQ* o,  const void* data, int len)
{
   U16 bufLen = SharkSslCon_getEncBufSize(o->scon);
   U8* buf = SharkSslCon_getEncBufPtr(o->scon);
   U8* ptr = (U8*)data;
   while(len > 0)
   {
      int chunk,left;
      if(!o->sendBufIx)
         o->sendBufIx = 15;
      left = bufLen - o->sendBufIx;
      chunk = len > left ? left : len;
      memcpy(buf+o->sendBufIx, ptr, chunk);
      ptr += chunk;
      len -= chunk;
      o->sendBufIx += (U16)chunk;
      if(o->sendBufIx >= bufLen && SharkMQ_pubflush(o, 0, 0))
         return o->status;
   }
   return 0;
}


int
SharkMQ_pubflush(SharkMQ* o, U32 tid, U32 subtid)
{
   U8* buf = SharkSslCon_getEncBufPtr(o->scon);
   if(!o->sendBufIx)
      o->sendBufIx = 15;
   netConvU16(buf, (U8*)&o->sendBufIx); /* Frame Len */
   buf[2] = MSG_PUBFRAG;
   netConvU32(buf+3, (U8*)&tid);
   netConvU32(buf+7,(U8*)&o->clientTid);
   netConvU32(buf+11,(U8*)&subtid);
   o->status=seSec_write(o->scon, &o->sock, buf, o->sendBufIx);
   o->sendBufIx=0;    
   if(o->status < 0) return SharkMQ_setErrStatus(o,o->status);
   o->status=0;
   return 0;
}



int
SharkMQ_observe(SharkMQ* o, U32 tid)
{
   return SharkMQ_sendMsgWithTid(o, MSG_OBSERVE, tid);
}


int
SharkMQ_unobserve(SharkMQ* o, U32 tid)
{
   return SharkMQ_sendMsgWithTid(o, MSG_UNOBSERVE, tid);
}


int
SharkMQ_getMessage(SharkMQ* o, U8** msg)
{
   int x;
   if(o->bytesRead)
   {
      if(o->bytesRead < o->frameLen)
      {
         U16 left = o->frameLen - o->bytesRead;
         x = SharkMQ_recv(o, left, msg);
         if(x > 0) o->bytesRead += (U16)x;
         else if(SMQ_TIMEOUT == x) return 0;
         else o->bytesRead = 0;
         return x;
      }
      o->bytesRead = 0;
   }

L_readMore:

   if(o->bufIx < 3 && SharkMQ_recHeader(o, 3))
   {
      /* Timeout is not an error in between frames */
      if(o->status == SMQ_TIMEOUT)
      {
         if(o->pingTmoCounter >= 0)
         {
            o->pingTmoCounter += o->timeout;
            if(o->pingTmoCounter >= o->pingTmo)
            {
               U16 frameLen = 3;
               U8* buf = SharkSslCon_getEncBufPtr(o->scon);
               o->pingTmoCounter = -10000; /* PONG tmo hard coded to 10 sec */
               netConvU16(buf, (U8*)&frameLen); /* Frame Len */
               buf[2] = MSG_PING;
               if( (x=seSec_write(o->scon,&o->sock, 0, 3)) < 0)
                  return SharkMQ_setErrStatus(o, x);
            }
         }
         else
         {
            o->pingTmoCounter += o->timeout;
            if(o->pingTmoCounter >= 0)
               return SharkMQ_setErrStatus(o,SMQE_PONGTIMEOUT);
         }
      }
      return o->status;
   }
   o->pingTmoCounter=0;
   switch(o->buf[2])
   {
      case MSG_DISCONNECT:
         if(SharkMQ_readFrame(o))
            o->buf[0]=0;
         else
         {
            memmove(o->buf, o->buf+3, o->frameLen-3);
            o->buf[o->frameLen-3]=0;
         }
         if(msg) *msg = o->buf;
         return SharkMQ_setErrStatus(o,SMQE_DISCONNECT);

      case MSG_CREATEACK:
      case MSG_CREATESUBACK:
      case MSG_SUBACK:
         if(SharkMQ_readFrame(o))
            return SMQ_TIMEOUT == o->status ? 0 : o->status;
         if(o->frameLen < 9)
            return SharkMQ_setErrStatus(o,SMQE_PROTOCOL_ERROR);
         if(o->buf[3]) /* Denied */
         {
            o->ptid=0;
            o->status=SMQE_ONACK_DENIED;
            if(msg) *msg = 0;
         }
         else
         {
            netConvU32((U8*)&o->ptid, o->buf+4);
            o->status = 0;
         }
         switch(o->buf[2])
         {
            case MSG_CREATEACK:    x = SMQ_CREATEACK;    break;
            case MSG_CREATESUBACK: x = SMQ_CREATESUBACK; break;
            default:               x = SMQ_SUBACK;
         }
         memmove(o->buf, o->buf+8, o->frameLen-8);
         o->buf[o->frameLen-8]=0;
         if(msg) *msg = o->buf; /* topic name */
         return x;

      case MSG_PUBLISH:
         if(o->frameLen < 15) 
            return SharkMQ_setErrStatus(o,SMQE_PROTOCOL_ERROR);
         if(o->bufIx < 15 && SharkMQ_recHeader(o, 15))
            return SMQ_TIMEOUT == o->status ? 0 : o->status;
         o->bufIx=0; /* Prepare for next SMQ frame */
         netConvU32((U8*)&o->tid, o->buf+3);
         netConvU32((U8*)&o->ptid, o->buf+7);
         netConvU32((U8*)&o->subtid, o->buf+11);
         if(o->frameLen > 15)
         {
            if((x = SharkMQ_recv(o, o->frameLen - 15, msg)) > 0)
               o->bytesRead = (U16)x+15;
            return x;
         }
         /* Payload is zero ! */
         o->bytesRead=o->frameLen;
         *msg = (U8*)"";
         return 0;

      case MSG_PING:
      case MSG_PONG:
         o->bufIx=0; /* Prepare for next SMQ frame */
         if(o->frameLen != 3)
            return SharkMQ_setErrStatus(o,SMQE_PROTOCOL_ERROR);
         if(o->buf[2] == MSG_PING)
         {
            o->buf[2] = MSG_PONG;
            if(SharkMQ_flushb(o)) return o->status;
         }
         goto L_readMore;

      case MSG_CHANGE:
         if(o->frameLen != 11)
            return SharkMQ_setErrStatus(o,SMQE_PROTOCOL_ERROR);
         if(SharkMQ_readFrame(o))
            return SMQ_TIMEOUT == o->status ? 0 : o->status;
         netConvU32((U8*)&o->ptid, o->buf+7);
         o->status = (int)o->ptid;
         netConvU32((U8*)&o->ptid, o->buf+3);
         return SMQ_SUBCHANGE;

      default:
         return SharkMQ_setErrStatus(o,SMQE_PROTOCOL_ERROR);
   }
}
