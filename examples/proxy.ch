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
 *   $Id: proxy.ch 4002 2017-02-23 19:52:40Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2016
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
 *
 */


typedef struct ProxyArgs
{
   SOCKET* sock;
   const char* host;
   char* buf;
   U16 cursor;
   U16 port;
   U16 bufLen;
} ProxyArgs;


static int
ProxyArgs_addS(ProxyArgs* o, const char* str)
{
   U16 len = (U16)strlen(str);
   if(o->cursor + len >= o->bufLen)
   {
      if(se_send(o->sock, o->buf, o->cursor) < 0)
         return E_PROXY_CLOSED;
      o->cursor = 0; /* Reset */
   }
   memcpy(o->buf + o->cursor, str, len);
   o->cursor+=len;
   return 0;
}

static int
ProxyArgs_addC(ProxyArgs* o, const char c)
{
   char buf[2];
   buf[0]=c;
   buf[1]=0;
   return ProxyArgs_addS(o, buf);
}

#ifdef ENABLE_SOCKS_PROXY

static int
ProxyArgs_readBytes(ProxyArgs* o, int len)
{
   int ix=0;
   while(ix != len)
   {
      int rsp;
      if( (rsp=se_recv(o->sock, o->buf+ix, len-ix, 5000)) <= 0 )
         return E_PROXY_CLOSED;
      ix += rsp;
   }
   return 0;
}


/* The SOCKS request/response is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order

          o  X'01'

   the address is a version-4 IP address, with a length of 4 octets

          o  X'03'

   the address field contains a fully-qualified domain name.  The first
   octet of the address field contains the number of octets of name that
   follow, there is no terminating NUL octet.

          o  X'04'

   the address is a version-6 IP address, with a length of 16 octets.
 */
static int
Proxy_socksSendConnect(Proxy* o, ProxyArgs* args)
{
   int dn;
   char* bufp = args->buf;
   int status;
   (void)o;
   *bufp++=5; /* VER */
   *bufp++=1; /* connect */
   *bufp++=0;  /* RSV */
   dn = strlen(args->host);
   *bufp++=3; /* DOMAINNAME */
   *bufp++ = (U8)dn;
   memcpy(bufp, args->host, dn);
   bufp+=dn;
   *bufp++ = (U8)(args->port >> 8);
   *bufp++ = (U8)(args->port);
   if( se_send(args->sock,args->buf,bufp-args->buf) < 0 ||
       ProxyArgs_readBytes(args, 4) )
   {
      return E_PROXY_CLOSED;
   }
   if(args->buf[1])
   {
      switch(args->buf[1])
      {
         case 1: /* general SOCKS server failure */
            return E_PROXY_GENERAL;
         case 2: /* connection not allowed by ruleset */
            return  E_PROXY_NOT_ALLOWED;
         case 3: /* Network unreachable */
            return E_PROXY_NETWORK;
         case 4: /* Host unreachable */
            return E_PROXY_HOST;
         case 5: /* Connection refused */
            return E_PROXY_REFUSED;
         case 6: /* TTL expired */
            return E_PROXY_TTL;
         case 7: /* Command not supported */
            return  E_PROXY_COMMAND_NOT_SUP;
         case 8: /* Address type not supported */
            return E_PROXY_ADDRESS_NOT_SUP;
         default:
            return E_PROXY_UNKNOWN;
      }
   }
   else
   {
      int size=0;
      if(args->buf[3] == 1) size = 4;
      else if(args->buf[3] == 4) size = 16;
      else if(args->buf[3] == 3) size = args->buf[4]+1;
      if(size)
         status=ProxyArgs_readBytes(args, size+2); /* Eat data. Not used */
      else
         return E_PROXY_UNKNOWN;
   }
   return status;
}



/*
   Username/Password Authentication for SOCKS V5
   https://www.ietf.org/rfc/rfc1929.txt
           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +----+------+----------+------+----------+

 */
static int
Proxy_socksSendPassword(Proxy* o, ProxyArgs* args)
{
   char* passp = strchr(o->proxyUserPass, ':');
   char* bufp = args->buf;
   int size=3;
   int len;
   *bufp++=1; /* VER */
   len = (passp - o->proxyUserPass);
   size+=len;
   *bufp++=(U8)len; /* ULEN */
   memcpy(bufp, o->proxyUserPass, len);
   bufp+=len;
   passp++;
   len = strlen(passp);
   size+=len;
   *bufp++=(U8)len; /* PLEN */
   memcpy(bufp, passp, len);
   if(se_send(args->sock,args->buf,size) < 0 ||
      ProxyArgs_readBytes(args, 2))
   {
      return E_PROXY_CLOSED;
   }
   /*
     +----+--------+
     |VER | STATUS |
     +----+--------+
     | 1  |   1    |
     +----+--------+
     
     A STATUS field of X'00' indicates success. If the
     server returns a `failure' (STATUS value other than
     X'00') status, it MUST close the connection.
   */
   if(args->buf[1]) /* Invalid username/password */
      return E_PROXY_AUTH;
   return Proxy_socksSendConnect(o, args);
}


/* SOCKS Protocol Version 5
   http://www.ietf.org/rfc/rfc1928.txt
 */
static int
Proxy_socks(Proxy* o, ProxyArgs* args)
{
   int status;
   if( args->bufLen <
       (30 + (o->proxyUserPass ? strlen(o->proxyUserPass) : 0)) ||
       args->bufLen < (30 + strlen(args->host)) )
   {
      return -1;
   }
   /* Else: buf large enough for all 'socks' buf management */

   if(se_connect(args->sock, o->proxyName, o->proxyPortNo))
      return E_PROXY_CANNOTCONNECT;
   args->buf[0] = 5;  /* version */
   args->buf[1]= 2; /* Two methods: 0: no auth, 2 USERNAME/PASSWORD */
   args->buf[2] = 0; /* no authentication */
   args->buf[3] = 2; /* username/password */
   if(se_send(args->sock,args->buf,4) < 0)
      return E_PROXY_CLOSED;
   if(ProxyArgs_readBytes(args, 2))
      return E_PROXY_CLOSED;
   if(args->buf[0] != 5)
      return E_PROXY_NOT_COMPATIBLE;
   if(args->buf[1] == 2)
   {
      if(o->proxyUserPass)
         status=Proxy_socksSendPassword(o, args);
      else
         return E_PROXY_AUTH;
   }
   else if(args->buf[1] == 0)
      status=Proxy_socksSendConnect(o, args);
   else
      return E_PROXY_UNKNOWN;
   return status;
}

#endif /* ENABLE_SOCKS_PROXY */


#ifdef ENABLE_HTTPS_PROXY

static int
Proxy_setHttpAuth(Proxy* o, ProxyArgs* args)
{
   static const char b64alpha[] = {
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
   };
   const char* src = o->proxyUserPass;
   int slen = strlen(src);
   if(ProxyArgs_addS(args, "Proxy-Authorization: Basic "))
      return E_PROXY_CLOSED;
   while( slen >= 3 )
   {
      if(ProxyArgs_addC(args,b64alpha[*src>>2]) ||
         ProxyArgs_addC(args,b64alpha[(*src&0x03)<<4 | src[1]>>4]) ||
         ProxyArgs_addC(args,b64alpha[(src[1]&0x0F)<<2 | src[2]>>6]) ||
         ProxyArgs_addC(args, b64alpha[src[2] & 0x3F]) )
      {
         return E_PROXY_CLOSED;
      }
      src += 3;
      slen -= 3;
   }
   switch(slen)
   {
      case 2:
         if(ProxyArgs_addC(args, b64alpha[src[0]>>2]) ||
            ProxyArgs_addC(args, b64alpha[(src[0] & 0x03)<<4 | src[1]>>4]) ||
            ProxyArgs_addC(args, b64alpha[(src[1] & 0x0F)<<2]) ||
            ProxyArgs_addC(args, (U8)'='))
         {
            return E_PROXY_CLOSED;
         }
         break;

      case 1:
         if(ProxyArgs_addC(args, b64alpha[src[0]>>2]) ||
            ProxyArgs_addC(args, b64alpha[(src[0] & 0x03)<<4]) ||
            ProxyArgs_addS(args,"=="))
         {
            return E_PROXY_CLOSED;
         }
         break;

      default:
         baAssert(slen == 0);
   }
   return ProxyArgs_addS(args,"\r\n");
}


static int
Proxy_https(Proxy* o, ProxyArgs* args)
{
   char* ptr;
   int status;
   U16 ix,r;
   char portNoBuf[6];
   if(se_connect(args->sock, o->proxyName, o->proxyPortNo))
      return E_PROXY_CANNOTCONNECT;
   args->cursor=0;
   if(ProxyArgs_addS(args,"CONNECT ") ||
      ProxyArgs_addS(args, args->host) ||
      ProxyArgs_addC(args, ':'))
   {
      return E_PROXY_CLOSED;
   }
   ix = (U16)sizeof(portNoBuf);
   portNoBuf[--ix]=0;
   do {
      r = args->port % 10U;
      args->port /= 10U;
      portNoBuf[--ix] = (char)('0' + r);
   } while(args->port && ix);
   if( ProxyArgs_addS(args, portNoBuf+ix) ||
       ProxyArgs_addS(args," HTTP/1.0\r\nUser-Agent: SMQ Client\r\n") ||
       (o->proxyUserPass && Proxy_setHttpAuth(o, args)) ||
       ProxyArgs_addS(args,"\r\n") )
   {
      return E_PROXY_CLOSED;
   }
   if(args->cursor && se_send(args->sock, args->buf, args->cursor) < 0)
      return E_PROXY_CLOSED;
   ptr=args->buf;
   status = se_recv(args->sock, ptr, args->bufLen-1, 5000);
   if(status > 14) /* Expect: HTTP/1.x 200 OK */
   {
      ptr[status]=0;
      while( ! isspace(*ptr) ) ptr++;
      while(   isspace(*ptr) ) ptr++;
      if(ptr[0] == '2' && ptr[1] == '0' && ptr[2] == '0')
      {
         static const char fsm[]={"\r\n\r\n"};
         int ix=0;
         for(;;ptr++)
         {
            if(ptr >= (args->buf+status))
            {
               if(se_recv(args->sock, args->buf, args->bufLen-1, 5000) <= 0)
                  return E_PROXY_CLOSED;
               ptr=args->buf;
            }
            if(*ptr == fsm[ix])
            {
               if(++ix >= 4)
                  return 0; /* Found end of HTTP response message */
            }
            else
               ix=0;
         }
      }
      if(ptr[0] == '4')
         return ptr[2] == '4' ? E_PROXY_HOST : E_PROXY_AUTH;
      return E_PROXY_GENERAL;
   }
   return E_PROXY_GENERAL;
}

#endif /* ENABLE_HTTPS_PROXY */



void
Proxy_constructor(Proxy* o, const char* proxyName,
                     U16 proxyPortNo, const char* proxyUserPass,
                     int socks)
{
   o->proxyName=proxyName;
   o->proxyPortNo=proxyPortNo;
   o->proxyUserPass=proxyUserPass;
#if defined(ENABLE_HTTPS_PROXY) && defined(ENABLE_SOCKS_PROXY)
   o->connect = socks ? Proxy_socks : Proxy_https;
#elif defined(ENABLE_HTTPS_PROXY)
   (void)socks;
   o->connect = Proxy_https;
#elif defined(ENABLE_SOCKS_PROXY)
   (void)socks;
   o->connect = Proxy_socks;
#else
#error Incorrect use
#endif
}


