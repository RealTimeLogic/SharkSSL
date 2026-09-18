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
 *   $Id: MSLib.c 6042 2026-09-17 05:36:34Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2013 - 2026
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

#include "MSLib.h"
#include <ctype.h>

/* Default end of HTTP respons */
static const U8 httpEOR[]={
   "\r\nConnection: Close\r\nServer: SharkSSL WebSocket Server\r\n\r\n"};


/************************* Helper functions ******************************/


U8*
msCpAndInc(U8* dest, int* dlen, const U8* src, int slen)
{
   int len=*dlen;
   if(!slen) slen=strlen((char*)src);
   len -= slen;
   if(!dest || len < 0) return 0;
   *dlen = len;
   memcpy(dest,src,slen);
   return dest+slen;
}


U8*
msB64Encode(U8* dest, int* dlen, const U8* src, int slen)
{
   static const char b64alpha[] = {
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
   };
   int maxlen;
   if(!dest) return 0;
   maxlen = *dlen;
   while( slen >= 3 )
   {
      maxlen -= 4;
      if(maxlen < 0) return 0;
      *dest++ = b64alpha[*src>>2];
      *dest++ = b64alpha[(*src&0x03)<<4 | src[1]>>4];
      *dest++ = b64alpha[(src[1]&0x0F)<<2 | src[2]>>6];
      *dest++ = b64alpha[src[2] & 0x3F];
      slen -= 3;
      src += 3;
   }
   switch(slen)
   {
      case 2:
         maxlen -= 4;
         if(maxlen < 0) return 0;
         *dest++ = b64alpha[src[0]>>2];
         *dest++ = b64alpha[(src[0] & 0x03)<<4 | src[1]>>4];
         *dest++ = b64alpha[(src[1] & 0x0F)<<2];
         *dest++ = (U8)'=';
         break;

      case 1:
         maxlen -= 4;
         if(maxlen < 0) return 0;
         *dest++ = b64alpha[src[0]>>2];
         *dest++ = b64alpha[(src[0] & 0x03)<<4];
         *dest++ = (U8)'=';
         *dest++ = (U8)'=';
         break;

   }
   *dlen = maxlen;
   return dest;
}


U8*
msstrstrn(U8* str, int slen, const U8* substr)
{
   const U8 *a, *b, *e;
   b = substr;
   e=str+slen;
   for ( ; str < e && *str; str++)
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


U8*
msi2a(U8* dest, int* dlen, U32 n)
{
   U8* ptr = dest;
   int l = *dlen;
   if(!dest) return 0;
   while(n && l)
   {
      *ptr++ = '0' + n % 10;
      n /= 10;
      l--;
   }
   if(l >= 0)
   {
      U8 tmp;
      U8* head=dest;
      U8* end=ptr;
      *dlen=l;
      while(ptr > head)
      {
         tmp=*--ptr;
         *ptr=*head;
         *head++=tmp;
      }
      return end;
   }
   return 0;
}



U8*
msRespCT(U8* dest, int* dlen, int contentLen, const U8* extHeader)
{
   static const U8  httpRespCL[] = {"HTTP/1.0 200 OK\r\nContent-Length: "};
   dest=msCpAndInc(dest,dlen,httpRespCL,sizeof(httpRespCL)-1);
   dest=msi2a(dest,dlen,contentLen);
   if(extHeader)
      dest = msCpAndInc(dest,dlen,extHeader, 0);
   return msCpAndInc(dest,dlen,httpEOR,sizeof(httpEOR)-1);
}



static U8*
getKeyVal(U8* key)
{
   U8* val=(U8*)strchr((char*)key,':');
   U8* end;
   if(!val) return 0;
   *val++=0;
   while(*val==' ' || *val=='\t') val++;
   end=val+strlen((char*)val);
   while(end>val && (end[-1]==' ' || end[-1]=='\t')) *--end=0;
   return val;
}

static int
msEqual(const U8* a, const char* b)
{
   while(*a && tolower(*a)==tolower((U8)*b)) { a++; b++; }
   return !*a && !*b;
}

static int
msToken(const U8* value, const char* token)
{
   int len=(int)strlen(token);
   while(*value)
   {
      const U8* end;
      const U8* next;
      while(*value==' ' || *value=='\t') value++;
      end=value;
      while(*end && *end!=',') end++;
      next=*end ? end+1 : end;
      while(end>value && (end[-1]==' ' || end[-1]=='\t')) end--;
      if(end-value==len && msstrstrn((U8*)value,len,(const U8*)token)==value)
         return TRUE;
      value=next;
   }
   return FALSE;
}


static int
wssCheckCredentials(WssProtocolHandshake* wph, U8* auth)
{
   if(wph->b64Credent)
   {
      if(auth)
      {
         while(*auth && *auth != ' ') auth++;
         while(*auth && *auth == ' ') auth++;
         if(*auth)
         {
            const U8* ptr=wph->b64Credent;
            for(ptr=wph->b64Credent; *ptr && *ptr == *auth; ptr++,auth++);
            return *ptr || (*auth && *auth!=10) ? -1 : 0;
         }
      }
      return -1;
   }
   return 0;
}

/************************ End helper functions ****************************/

#ifdef MS_SEC
static int
MST_nonSecRead(struct MST* o,U8 **buf,U32 timeout)
{
   *buf = o->u.b.recBuf;
   return se_recv(o->sock, *buf, o->u.b.recBufSize, timeout);
}

static int
MST_nonSecWrite(struct MST* o,U8* buf, int len)
{
   return se_send(o->sock, buf ? buf : o->u.b.sendBuf, len);
}

U8* MST_getSendBufPtr(MST* o)
{
   return  o->isSecure ?
      SharkSslCon_getEncBufPtr(o->u.sc) : o->u.b.sendBuf;
}

U16 MST_getSendBufSize(MST* o)
{
   return  o->isSecure ?
      SharkSslCon_getEncBufSize(o->u.sc) : o->u.b.sendBufSize;
}
#else
U8* MST_getSendBufPtr(MST* o)
{
   return o->b.sendBuf;
}

U16 MST_getSendBufSize(MST* o)
{
   return o->b.sendBufSize;
}
#endif

int
MST_read(struct MST* o,U8 **buf,U32 timeout)
{
#ifdef MS_SEC
   return  o->isSecure ?
      seSec_read(o->u.sc,o->sock,buf,timeout) : MST_nonSecRead(o,buf,timeout);
#else
   *buf = o->b.recBuf;
   return se_recv(o->sock, *buf, o->b.recBufSize, timeout);
#endif
}

int
MST_write(struct MST* o,U8* buf, int len)
{
#ifdef MS_SEC
   return  o->isSecure ?
      seSec_write(o->u.sc,o->sock,buf,len) : MST_nonSecWrite(o,buf,len);
#else
   return se_send(o->sock, buf ? buf : o->b.sendBuf, len);
#endif
}


U8*
MS_respCT(MS* o, int* dlen, int contentLen, const U8* extHeader)
{
   *dlen = MST_getSendBufSize(&o->mst);
   return msRespCT(MST_getSendBufPtr(&o->mst), dlen, contentLen, extHeader);
}


int
MS_webServer(MS* o, WssProtocolHandshake* wph)
{
   static const U8 httpEndMarker[]={"\r\n\r\n"};

   int i,rc;
   int sblen=0;
   U8* end;
   U8* rbuf;
   U8* sbuf=0;
   U8* ptr=0;
   int hIx=0; /* HTTP header index */
   int delayOnSend=FALSE;

   /* Extracted HTTP header values */
   U8* key=0;
   U8* auth=0;
   U8* version=0;
   U8* host=0;
   int upgrade=0,connection=0,invalid=0;
   wph->request=0;
   wph->origin=0;

#ifdef MS_SEC
   if(o->mst.isSecure)
   {
      if( (rc = seSec_handshake(o->mst.u.sc, o->mst.sock, 3000, 0)) <= 0 )
      {
         xprintf(("SSL handshake failed %d\n", rc));
         return MS_ERR_SSL_HANDSHAKE;
      }
   }
#endif

   for(;;)
   {
      if( (rc = MST_read(&o->mst,&rbuf,100)) <= 0 )
      {
         xprintf(("HTTP request header error: %s.\n",
                  rc == 0 ? "timeout" : "connection closed"));
         return rc == 0 ? MS_ERR_READ_TMO :  MS_ERR_READ;
      }
      end=msstrstrn(rbuf, rc, httpEndMarker);
      if(end && !ptr) /*Most browsers send the complete header in first frame*/
         break; 
      /* We use the SharkSSL send buffer for temp storage */
      if(!ptr)
      {
         sbuf=ptr=MST_getSendBufPtr(&o->mst);
         sblen=MST_getSendBufSize(&o->mst);
      }
      if(sblen < rc)
      {
         xprintf(("HTTP request header too big\n"));
         return MS_ERR_HTTP_HEADER_OVERFLOW;
      }
      memcpy(ptr,rbuf,rc);
      ptr+=rc;
      sblen-=rc;
      if((end=msstrstrn(sbuf, ptr-sbuf, httpEndMarker)) != 0)
      {
         int headerEnd=(int)(end-sbuf);
         int capacity;
         rc=(int)(ptr-sbuf);
#ifdef MS_SEC
         if(o->mst.isSecure)
         {
            rbuf=SharkSslCon_getBuf(o->mst.u.sc);
            capacity=SharkSslCon_getBufLen(o->mst.u.sc);
         }
         else
         {
            rbuf=o->mst.u.b.recBuf;
            capacity=o->mst.u.b.recBufSize;
         }
#else
         rbuf=o->mst.b.recBuf;
         capacity=o->mst.b.recBufSize;
#endif
         if(rc>capacity) return MS_ERR_HTTP_HEADER_OVERFLOW;
         memcpy(rbuf,sbuf,rc);
         end=rbuf+headerEnd;
         break;
      }
   }
   end+=(sizeof(httpEndMarker)-1);
   o->rs.overflowLen=rc-(int)(end-rbuf);
   o->rs.overflowPtr=o->rs.overflowLen ? end : 0;
   for(ptr = rbuf ; ptr < end;)
   {
      U8* next;
      next = msstrstrn(ptr, end-ptr, (U8*)"\r\n");
      if(next)
      {
         *next = 0;
         if(next==ptr) break;
         if(wph->request)
         {
            wph->hKeys[hIx]=ptr;
            wph->hVals[hIx]=getKeyVal(ptr);
            if(!wph->hVals[hIx]) return MS_ERR_INVALID_HTTP;
            hIx++;
            if(hIx == MAX_HTTP_H_SIZE)
               return MS_ERR_HTTP_HEADER_OVERFLOW;
         }
         else
            wph->request=ptr;
         ptr = next + 2;
      }
      else break;
   }
   wph->hKeys[hIx]=wph->hVals[hIx]=0;
   if(!wph->request)
   {
      xprintf(("Cannot validate HTTP request header\n"));
      return MS_ERR_INVALID_HTTP;
   }
   for(i = 0; i < hIx; i++)
   {
      ptr = wph->hKeys[i];
      if(msEqual(ptr,"Sec-WebSocket-Key"))
      {
         if(key) invalid=TRUE;
         key=wph->hVals[i];
      }
      else if(msEqual(ptr,"Sec-WebSocket-Version"))
      {
         if(version) invalid=TRUE;
         version=wph->hVals[i];
      }
      else if(msEqual(ptr,"Host"))
      {
         if(host) invalid=TRUE;
         host=wph->hVals[i];
      }
      else if(msEqual(ptr,"Upgrade"))
         upgrade|=msToken(wph->hVals[i],"websocket");
      else if(msEqual(ptr,"Connection"))
         connection|=msToken(wph->hVals[i],"Upgrade");
      else if(!auth && msEqual(ptr,"Authorization")) auth=wph->hVals[i];
      else if(msEqual(ptr,"Origin")) wph->origin=wph->hVals[i];
      else if(msEqual(ptr,"User-Agent") &&
              msstrstrn(wph->hVals[i],200,(U8*)"Safari"))
         delayOnSend=TRUE;
   }
   if(key || version || upgrade)
   {
      U8* http=(U8*)strrchr((char*)wph->request,' ');
      if(invalid || !key || !version || !host || !*host || !upgrade ||
         !connection || strncmp((char*)wph->request,"GET ",4) || !http ||
         strcmp((char*)http," HTTP/1.1") || strcmp((char*)version,"13") ||
         strlen((char*)key)!=24 ||
         strspn((char*)key,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")!=22 ||
         key[22]!='=' || key[23]!='=' || !strchr("AQgw",key[21]))
         invalid=TRUE;
   }
   sblen=MST_getSendBufSize(&o->mst);
   sbuf=MST_getSendBufPtr(&o->mst); /* Using zero copy SharkSSL API */
   if(wssCheckCredentials(wph, auth))
   {
      static const U8 ecode[]={"<h1>Unauthorized</h1>"};
      static const U8 rsp[] = {
         "HTTP/1.0 401 Unauthorized\r\n"
         "Content-Length: 21\r\n"
         "WWW-Authenticate: Basic realm=\""};
      const U8* realm = wph->realm ? wph->realm : (const U8*)"SharkSSL";
      ptr=msCpAndInc(sbuf,&sblen,rsp,sizeof(rsp)-1);
      ptr=msCpAndInc(ptr,&sblen,realm,strlen((char*)realm));
      ptr=msCpAndInc(ptr,&sblen,(const U8*)"\"",1);
      ptr=msCpAndInc(ptr,&sblen,httpEOR,sizeof(httpEOR)-1);
      if((ptr=msCpAndInc(ptr,&sblen,ecode,21)) != 0)
      {
         rc=MS_ERR_AUTHENTICATION;
      }
      else
         rc=MS_ERR_ALLOC;
   }
   else if(invalid)
   {
      static const U8 rsp[]={"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"};
      ptr=msCpAndInc(sbuf,&sblen,rsp,sizeof(rsp)-1);
      rc=ptr ? MS_ERR_INVALID_HTTP : MS_ERR_ALLOC;
   }
   else if(key) /* Valid WebSocket request */
   {
      static const U8 wsUpgrade[]={
         "HTTP/1.1 101 Switching Protocols\r\n"
         "Upgrade: websocket\r\n"
         "Connection: Upgrade\r\n"
         "Sec-WebSocket-Accept: "}; 
      static const U8 guid[]={"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"};
      U8 digest[20];
      SharkSslSha1Ctx ctx;
      SharkSslSha1Ctx_constructor(&ctx);
      SharkSslSha1Ctx_append(&ctx,key,strlen((char*)key));
      SharkSslSha1Ctx_append(&ctx,guid,sizeof(guid)-1);
      SharkSslSha1Ctx_finish(&ctx,digest);
      ptr=msCpAndInc(sbuf,&sblen,wsUpgrade,sizeof(wsUpgrade)-1);
      ptr=msB64Encode(ptr, &sblen, digest, 20);
      if((ptr=msCpAndInc(ptr,&sblen,(U8*)"\r\n\r\n", 4)) != 0)
         rc=0; /* OK */
      else
         rc = MS_ERR_ALLOC;
   }
   else /* Not a WebSocket connection. Check if it's a GET request */
   {
      int found=0;
      rc = MS_ERR_NOT_WEBSOCKET;
      ptr = wph->request;
      if(ptr[0] == 'G' && ptr[1] == 'E' && ptr[2] == 'T')
      {
         ptr+=3;
         while(*ptr && *ptr == ' ') ptr++;
         end=ptr;
         while(*end && *end != ' ') end++;
         if(*end && wph->fetchPage)
         {
            *end=0;
            found = wph->fetchPage(wph->fetchPageHndl,&o->mst,ptr);
            if(found) /* found or err */
            {
               ptr=0; /* HTTP response sent */
               if(delayOnSend)
                  MST_read(&o->mst,&rbuf,300);
            }
         }
      }
      if( ! found )
      {
         static const U8 ecode[]={"<h1>Not Found</h1>"};
         static const U8 rsp[] = {
            "HTTP/1.0 404 Not Found\r\n"
            "Content-Length: 18"};
         ptr=msCpAndInc(sbuf,&sblen,rsp,sizeof(rsp)-1);
         ptr=msCpAndInc(ptr,&sblen,httpEOR,sizeof(httpEOR)-1);
         if((ptr=msCpAndInc(ptr,&sblen,ecode,18)) == 0)
            rc = MS_ERR_ALLOC;
      }
   }
   if(ptr && rc != MS_ERR_ALLOC)
   {
      /* Flush using zero copy API i.e. buf is 0 (NULL) */
      if(MST_write(&o->mst, 0, ptr-sbuf) < 0)
         rc = MS_ERR_WRITE;
   }
   return rc;
}


U8*
MS_prepSend(MS* o, int extSize, int* maxSize)
{
   U8* buf=MST_getSendBufPtr(&o->mst);
   int len=MST_getSendBufSize(&o->mst);
   if(extSize)
   {
      buf[1] = 126;
      if(maxSize) *maxSize = len - 4;
      return buf+4;
   }
   buf[1] = 0;
   if(maxSize) *maxSize = len - 2;
   return buf+2;
}



int
MS_send(MS* o, U8 opCode, int len)
{
   U8* buf=MST_getSendBufPtr(&o->mst);
   buf[0] = opCode;
   if( buf[1] == 126 )
   {
      if(len < 126) return MS_ERR_BUF_UNDERFLOW;
      if(len > 0xFFFF) return MS_ERR_BUF_OVERFLOW; /* Max length of 2^16 */
      buf[2] = (U8)((unsigned)len >> 8); /* high */
      buf[3] = (U8)len; /* low */
   }
   else
   {
      if(len > 125) return MS_ERR_BUF_OVERFLOW;
      buf[1] = (U8)len;
   }
   /* We must set length to zero when using the zero copy SharkSSL API */
   return MST_write(&o->mst, 0, len + (buf[1] == 126 ? 4 : 2));
}


int
MS_write(MS *o, U8 opCode, const void* data, int len)
{
   int rc;
   U8* ptr = (U8*)data;
   for(;;)
   {
      int chunk;
      U8* buf;
      /*Note: rc is SharkSSL maxLen i.e. buffer size and this cannot be < 125*/
      buf = MS_prepSend(o, len > 125, &rc);
      chunk = len < rc ? len : rc;
      memcpy(buf,ptr,chunk);
      len -= chunk;
      if( (rc=MS_send(o,opCode,chunk)) < 0 )
         return rc;
      if(len == 0) break;
      ptr += chunk;
   }
   return 0;
}


int
MS_close(MS *o, int statusCode)
{
   if(se_sockValid(o->mst.sock))
   {
      U8* ctrlBuf=MS_prepSend(o, FALSE, 0);
      if(statusCode)
      {
         /* 2 byte status code RFC6455 5.5.1 */
         ctrlBuf[0] = (U8)((unsigned)statusCode >> 8); /* high */
         ctrlBuf[1] = (U8)statusCode; /* low */
         MS_send(o,WSOP_Close,2);
      }
      else
         MS_send(o,WSOP_Close,0);
   }
   se_close(o->mst.sock);
   return statusCode < 0 ? statusCode : -statusCode;
}


static int
MS_rawRead(MS* o, U8 **buf, U32 timeout)
{
   U8* ptr;
   int i,len,maxlen;
   int newFrame=FALSE;
   o->rs.isTimeout=0;
   if(o->rs.overflowPtr) /* Previous frame: Consumed more than frame length */
   {
      len = o->rs.overflowLen;
      ptr = o->rs.overflowPtr;
      o->rs.overflowPtr=0;
   }
   else
   {
     L_readMore:
      if( (len=MST_read(&o->mst, buf, timeout)) <= 0 )
      {
         if(len<0) o->rs.frameHeaderIx=0;
         o->rs.isTimeout = len==0;
         return len;
      }
      ptr = *buf;
   }
   while(o->rs.frameHeaderIx<2)
   {
      if(!len) goto L_readMore;
      newFrame=TRUE;
      o->rs.frameHeader[o->rs.frameHeaderIx++]=*ptr++;
      len--;
   }
   if(!(o->rs.frameHeader[1]&0x80) || (o->rs.frameHeader[0]&0x70) ||
      ((o->rs.frameHeader[0]&8) &&
       (!(o->rs.frameHeader[0]&0x80) || (o->rs.frameHeader[1]&0x7F)>125)))
      return MS_close(o,1002);
   if((o->rs.frameHeader[1]&0x7F)==127) return MS_close(o,1009);
   /*Do we have a complete frame header? Loop: cp header and decrement 'len' */
   while( o->rs.frameHeaderIx < 6 ||
          (o->rs.frameHeaderIx < 8 && (o->rs.frameHeader[1] & 0x7F) > 125) )
   {
      if(len == 0) /* If we need more data */
         goto L_readMore; /* Read from socket */
      newFrame=TRUE;
      o->rs.frameHeader[o->rs.frameHeaderIx++] = *ptr++;
      len--;
   }
   if(newFrame) /* Start of new frame */
   {
      o->rs.bytesRead=0;
      if(o->rs.frameHeaderIx == 6)
      {
         o->rs.frameLen = o->rs.frameHeader[1] & 0x7F;
         o->rs.maskPtr = o->rs.frameHeader+2;
      }
      else
      {
         baAssert(o->rs.frameHeaderIx == 8);
         o->rs.frameLen = (int)(((U16)o->rs.frameHeader[2]) << 8);
         o->rs.frameLen |= o->rs.frameHeader[3];
         if(o->rs.frameLen<126) return MS_close(o,1002);
         o->rs.maskPtr = o->rs.frameHeader+4;
      }
   }
   *buf = ptr; /* Adjust payload for consumed header (rec or overflow data) */
   /* payload data is masked: RFC6455 5.3.  Client-to-Server Masking */
   maxlen = o->rs.bytesRead+len;
   if(maxlen > o->rs.frameLen)
      maxlen = o->rs.frameLen;
   for(i=o->rs.bytesRead ; i < maxlen; i++,ptr++)
   {
      /* orig-octet-i = masked-octet-i XOR (maskPtr[i MOD 4]) */
      *ptr ^= o->rs.maskPtr[i&3];
   }
   o->rs.bytesRead += len;
   if(o->rs.bytesRead >= o->rs.frameLen)
   {
      if(o->rs.bytesRead > o->rs.frameLen) /* Read overflow */
      {
         o->rs.overflowLen = o->rs.bytesRead - o->rs.frameLen;
         o->rs.bytesRead = o->rs.frameLen;
         len -= o->rs.overflowLen;
         baAssert(len >= 0);
         o->rs.overflowPtr = ptr;
      }
      o->rs.frameHeaderIx=0; /* Prepare for next frame */
   }
   return len;
}


int
MS_read(MS* o, U8 **buf, U32 timeout)
{
   int len;
   U8* ctrlBuf=0;
  L_readMore:
   len = MS_rawRead(o, buf, timeout);
   /* A partial control frame must finish within this call's read timeout. */
   if(!len && o->rs.isTimeout && o->rs.frameHeaderIx &&
      (o->rs.frameHeader[0]&8))
      return MS_close(o,1001);
   if(len >= 0 && !o->rs.isTimeout)
   {
      switch(o->rs.frameHeader[0])
      {
         case WSOP_Text:
         case WSOP_Binary:
            break;

         /* Control frames below */

         case WSOP_Close:
         case WSOP_Ping:
         case WSOP_Pong: /* RFC allows unsolicited pongs */
            if(!ctrlBuf)
               ctrlBuf=MS_prepSend(o, FALSE, 0);
            if(MST_getSendBufSize(&o->mst)<o->rs.frameLen+2)
               return MS_close(o,1009);
            if(o->rs.frameLen)
            {
               /* Cursor is bytesRead - len */
               if(o->rs.frameLen > 125) /* not allowed */
                  return MS_close(o, 1002);
               memcpy(ctrlBuf + o->rs.bytesRead - len, *buf, len);
               if(o->rs.bytesRead < o->rs.frameLen)
                  goto L_readMore;
            }
            if(o->rs.frameHeader[0]==WSOP_Close)
            {
               int code=1000;
               if(o->rs.frameLen==1) return MS_close(o,1002);
               if(o->rs.frameLen>=2)
               {
                  code=((int)ctrlBuf[0]<<8)|ctrlBuf[1];
                  if(!((code>=1000 && code<=1014 && code!=1004 &&
                        code!=1005 && code!=1006) || (code>=3000 && code<5000)))
                     return MS_close(o,1002);
               }
               MS_close(o,1000);
               return -code;
            }
            if(o->rs.frameHeader[0] == WSOP_Ping)
               MS_send(o,WSOP_Pong,o->rs.frameLen);
            goto L_readMore;

         default:  /* Unkown opcode (rsp 1002) or FIN=0 (rsp 1008) */
            return MS_close(o, 0x80 & o->rs.frameHeader[0] ? 1002 : 1008);
      }
   }
   return len;
}
