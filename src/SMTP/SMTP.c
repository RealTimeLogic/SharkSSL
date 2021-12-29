/*
 *     ____             _________                __                _
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/
 *                                                       /____/
 *
 *                  SMTP example program
 ****************************************************************************
 *
 *   $Id: SMTP.c 4874 2021-10-14 23:13:51Z wini $
 *
 *   COPYRIGHT:  Real Time Logic, 2013 - 2021
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
 */


/*
  See RFC 821 for more info.
  http://www.ietf.org/rfc/rfc821.txt
*/

#include "SMTP.h"
#include <ctype.h>
#include <stddef.h>
#if SHARKSSL_ENABLE_CLONE_CERTINFO
#include <SharkSslEx.h>
#endif

#ifdef USE_STD_TIMEFUNCS
#include <time.h>
#define SharkTm tm
#define shtime_t time_t
#else
#define shtime_t U32

struct SharkTm
{
      /** seconds after the minute */
      int       tm_sec;
      /** minutes after the hour */
      int       tm_min;
      /** hours since midnight */
      int       tm_hour;
      /** day of the month */
      int       tm_mday;
      /** months since January */
      int       tm_mon;
      /** Years since 1900 */
      int       tm_year;
      /** days since Sunday */
      int       tm_wday;
      /** days since January 1 */
      int       tm_yday;
      int       tm_isdst;
};

static const U16 monthTable[2][13] = {
   /* Normal years.  */
   { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
   /* Leap years.  */
   { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
};


static int
isLeap(int year)
{
   return year % 400? ( year % 100 ? ( year % 4 ? 0 : 1 ) : 0 ) : 1;
}


#define	SECS_PER_HOUR	(60 * 60)
#define	SECS_PER_DAY	(SECS_PER_HOUR * 24)
#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))
static void
time2tm(struct SharkTm *tmP, shtime_t t)
{
   S32 rem;
   long int y,days;
   const U16* ip;
   days = (long int)(t / SECS_PER_DAY);
   rem = (long int)(t % SECS_PER_DAY);
   while (rem < 0)
   {
      rem += SECS_PER_DAY;
      --days;
   }
   while (rem >= SECS_PER_DAY)
   {
      rem -= SECS_PER_DAY;
      ++days;
   }
   tmP->tm_hour = rem / SECS_PER_HOUR;
   rem %= SECS_PER_HOUR;
   tmP->tm_min = rem / 60;
   tmP->tm_sec = rem % 60;
   /* January 1, 1970 was a Thursday. */
   tmP->tm_wday = (4 + days) % 7;
   if (tmP->tm_wday < 0)
      tmP->tm_wday += 7;
  y = 1970;
  
  while (days < 0 || days >= (isLeap(y) ? 366 : 365))
  {
     /* Guess a corrected year, assuming 365 days per year. */
     S32 yg = y + days / 365 - (days % 365 < 0);

      /* Adjust DAYS and Y to match the guessed year. */
      days -= ((yg - y) * 365
	       + LEAPS_THRU_END_OF (yg - 1)
	       - LEAPS_THRU_END_OF (y - 1));
      y = yg;
    }
  tmP->tm_year = y - 1900;
  tmP->tm_yday = days;
  ip = monthTable[isLeap(y)];
  for (y = 11; days < (long int) ip[y]; --y)
     continue;
  days -= ip[y];
  tmP->tm_mon = y;
  tmP->tm_mday = days + 1;
}

#endif /* USE_STD_TIMEFUNCS */


static const char*
month2str(S32 month)
{
   switch(month)
   {
      case 0: return "Jan";
      case 1: return "Feb";
      case 2: return "Mar";
      case 3: return "Apr";
      case 4: return "May";
      case 5: return "Jun";
      case 6: return "Jul";
      case 7: return "Aug";
      case 8: return "Sep";
      case 9: return "Oct";
      case 10: return "Nov";
   }
   return "Dec";
}


static int SMTP_flushBuffer(SMTP* o, unsigned int argNotUsed);
static int SMTP_getResponse(SMTP* o);
static int SMTP_initWrite(SMTP* o);
static int SMTP_syncSend(SMTP* o, const char* fmt, ...);
static int SMTP_asyncSend(SMTP* o, const char* fmt, ...);
static int SMTP_vSend(SMTP* o, const char* fmt, va_list varg);
static int SMTP_sendData(SMTP* o, const char* data, int len);
static int SMTP_sslHandshake(SMTP* o);

void
SMTP_constructor(SMTP* o,
                 const char* from,
                 const char* to,
                 const char* subject,
                 const char* smtpServer,
                 int port,
                 SharkSsl* sharkSsl,
                 int startTLS,
                 const char* username,
                 const char* password,
                 const char* clientDomainName,
                 const char* serverDomainName,
                 SeCtx* ctx)
{
   int status;
   char* ptr;
   memset(o,0,sizeof(SMTP));
   SOCKET_constructor(&o->sock, ctx);
   BufPrint_constructor(&o->bp, 0, (BufPrint_Flush)SMTP_flushBuffer);
   o->bp.buf = o->printBuf;
   o->bp.bufSize = sizeof(o->printBuf);
   o->bp.buf[0]=0;
   o->eCode = SMTP_ErrHostName;
   o->from = from;
   o->to = to;
   o->subject = subject;
   o->clientDomainName = clientDomainName ? clientDomainName : "localhost";
   o->serverDomainName=serverDomainName;

   status=se_connect(&o->sock, smtpServer, (U16)port);
   if(status)
   {
      switch(status)
      {
         case -1: o->eCode = SMTP_ErrSocketCreate; break;
         case -2: o->eCode = SMTP_ErrHostName; break;
         default: o->eCode = SMTP_ErrConnect;
      }
      return;
   }

   if(sharkSsl)
   {
      /* Secure SMTP (SMTPS) handshaking */
      o->sharkSsl=sharkSsl;
      if( (o->sharkSslCon = SharkSsl_createCon(sharkSsl)) == 0 )
      {
         o->eCode = SMTP_ErrSslCon;
         return;
      }
      sharkssl_entropy((ptrdiff_t)o->sharkSslCon + baGetUnixTime());
      if(!startTLS)
      {
         if(SMTP_sslHandshake(o))
            return;
         o->isSecure=TRUE;
      }
   }
   else
      o->sharkSslCon=0;

   if(SMTP_getResponse(o)) /* Consume server greeting message */
      return; /* error in o->eCode */

   /* EHLO
      Extended SMTP (ESMTP), sometimes referred to as Enhanced SMTP,
      is a definition of protocol extensions to the Simple Mail
      Transfer Protocol standard.
   */
   if(SMTP_syncSend(o,"EHLO %s\r\n",o->clientDomainName))
   {
      o->eCode = SMTP_ErrHELO;
      return ;
   }
   o->eightBit = strstr(o->bp.buf,"8BITMIME") ? TRUE : FALSE;
   if(!o->isSecure && sharkSsl)
   {
      if(strstr(o->bp.buf, "STARTTLS"))
      { /* STARTTLS handshaking (RFC 3207) */
         if(SMTP_syncSend(o,"STARTTLS\r\n"))
         {
            o->eCode = SMTP_ErrSslCon;
            return ;
         }
         if(SMTP_sslHandshake(o))
            return;
         o->isSecure=TRUE;
         if(SMTP_syncSend(o,"EHLO %s\r\n",o->clientDomainName))
         {
            o->eCode = SMTP_ErrHELO;
            return ;
         }
      }
      else if(username && password) /* No STARTTLS and credentials */
      { /* We are assuming that the user does not want to reveal the
         * credentials i.e. send them in plaintext
         */
         o->eCode = SMTP_ErrSslCon;
         return;
      }
   }
   ptr = strstr(o->bp.buf, "AUTH");
   if(ptr)
   {
      if(!username || !password)
      {
         o->eCode = SMTP_ErrAuth;
         return;
      }
      if(strstr(ptr, "PLAIN"))
      {  /* This code prepares an 'AUTH PLAIN' message. We use the print
          * buffer for temporary storage. The b64 encoded data is
          * moved to the correct location and the buffer cursor is
          * updated to the correct position. The code could fail if
          * the username and password are very long, but the code will
          * not crash. The authentication will simply fail.
          */
         int cursor;
         o->bp.cursor = 0;
         BufPrint_printf(&o->bp,"AUTH PLAIN ");
         BufPrint_printf(
            &o->bp,"%s%c%s%c%s",username,0,username,0,password);
         cursor=o->bp.cursor;
         BufPrint_b64Encode(&o->bp,o->bp.buf+11,cursor-11);
         if(o->bp.cursor < cursor)
         { /* Flushed: buffer too small */
            o->eCode = SMTP_ErrAuth;
            return;
         }
         memmove(o->bp.buf+11,o->bp.buf+cursor,o->bp.cursor-cursor);
         o->bp.cursor = o->bp.cursor - cursor +11;
         if(SMTP_syncSend(o,"\r\n", from))
            goto L_Auth;
      }
      else if(strstr(ptr, "LOGIN"))
      {
         int i;
         if(SMTP_syncSend(o,"AUTH LOGIN\r\n"))
            goto L_Auth;
         for(i=0 ; i < 2 ; i++)
         {
            o->bp.cursor = 0;
            switch(o->bp.buf[4])
            {
               case 'V': /* VXNlcm5hbWU6 -> Username */
                  BufPrint_b64Encode(&o->bp,username,strlen(username));
                  break;
               case 'U': /* UGFzc3dvcmQ6 -> Password */
                  BufPrint_b64Encode(&o->bp,password,strlen(password));
                  break;
               default:
                  goto L_Auth;
            }
            if(SMTP_syncSend(o,"\r\n", from))
               goto L_Auth;
         }
      }
      else
      {
        L_Auth:
         o->eCode = SMTP_ErrNoAuthSup;
         return;
      }
   }
   if(SMTP_syncSend(o,"MAIL FROM:<%s>%s\r\n",
                    from, o->eightBit ? " BODY=8BITMIME" : ""))
   {
      o->eCode = SMTP_ErrMAILFROM;
   }
   else
   {
      o->eCode = SMTP_NoError;
      SMTP_addRecipient(o,to);
   }
}


void
SMTP_destructor(SMTP* o)
{
   SMTP_commit(o);
}


int
SMTP_addRecipient(SMTP* o, const char* to)
{
   if(o->eCode != SMTP_NoError)
      return -1;
   if(o->writeStarted)
   {
      o->eCode = SMTP_ErrWriteStarted;
      return -1;
   }
   if(SMTP_syncSend(o,"RCPT TO:<%s>\r\n", to))
   {
      o->eCode = SMTP_ErrRCPTTO;
      return -1;
   }
   return 0;
}


int
SMTP_write(SMTP* o, const char* txt, int len)
{
   if(SMTP_initWrite(o))
      return -1;
   if(len < 0)
      len = strlen(txt);
   if(BufPrint_write(&o->bp, txt, len) < 0)
      return -1;
   return 0;
}


int
SMTP_printf(SMTP* o, const char* fmt, ...)
{
   int retv;
   va_list varg;

   if(SMTP_initWrite(o))
      return -1;

   va_start(varg, fmt);
   retv = BufPrint_vprintf(&o->bp, fmt, varg);

   va_end(varg);
   return retv;
}

const char*
SMTP_getEmsg(SMTP* o)
{
   const char* e = BufPrint_getBuf(&(o)->bp);
   if(e && *e)
      return e;
   return 0;
}



int
SMTP_vprintf(SMTP* o, const char* fmt, va_list varg)
{
   if(SMTP_initWrite(o))
      return -1;

   return BufPrint_vprintf(&o->bp, fmt, varg);
}


int
SMTP_commit(SMTP* o)
{
   int retv=0;
   if(se_sockValid(&o->sock))
   {
      if( o->eCode == SMTP_NoError && ! SMTP_initWrite(o) )
      {
         if(SMTP_syncSend(o,"\r\n.\r\nQUIT\r\n")) retv = -1;
      }
      se_close(&o->sock);
   }
   if(o->sharkSslCon)
   {
      SharkSsl_terminateCon(o->sharkSsl, o->sharkSslCon);
      o->sharkSslCon=0;
   }
   return o->eCode == SMTP_NoError ? retv : o->eCode;
}


static int
SMTP_initWrite(SMTP* o)
{
   if(o->eCode != SMTP_NoError)
      return -1;
   if( ! o->writeStarted )
   {
      BufPrint bp;
#ifndef USE_STD_TIMEFUNCS
      struct SharkTm tm;
#endif
      struct SharkTm* ptm;
      char buf[100];
      shtime_t t=baGetUnixTime();
      BufPrint_constructor(&bp, 0, 0);
      bp.buf = buf;
      bp.bufSize = sizeof(buf)-1;
      o->writeStarted = 1;
      if(SMTP_syncSend(o,"DATA\r\n"))
      {
         o->eCode = SMTP_ErrDATA;
         return -1;
      }
#ifdef USE_STD_TIMEFUNCS
      ptm=gmtime(&t);
#else
      time2tm(&tm, t);
      ptm=&tm;
#endif
      BufPrint_printf(&bp,"%d %s %d %02d:%02d:%02d",
                      ptm->tm_mday, month2str(ptm->tm_mon), 
                      1900+ptm->tm_year, ptm->tm_hour, ptm->tm_min,
                      ptm->tm_sec);
      buf[bp.cursor]=0;
      if(SMTP_asyncSend(
            o,
            "MIME-Version: 1.0\r\n"
            "From: %s\r\n"
            "To: %s\r\n"
            "Content-Type: %s\r\n"
            "Date: %s +0000\r\n"
            "Subject: %s\r\n"
            "Content-Transfer-Encoding : 8bit\r\n"
            "\r\n",
            o->from,
            o->to,
            o->contentType ? o->contentType : "text/plain; charset=utf-8",
            buf,
            o->subject))
      {
         return -1;
      }
   }
   return 0;
}


static int
SMTP_syncSend(SMTP* o, const char* fmt, ...)
{
   int retv;
   va_list varg;
   va_start(varg, fmt);
   retv = SMTP_vSend(o, fmt, varg);
   va_end(varg);
   if(retv)
      o->bp.buf[0]=0;
   else
      retv = SMTP_getResponse(o);
   return retv;
}


static int
SMTP_asyncSend(SMTP* o, const char* fmt, ...)
{
   int retv;
   va_list varg;
   va_start(varg, fmt);
   retv = SMTP_vSend(o, fmt, varg);
   va_end(varg);
   return retv;
}


static int
SMTP_vSend(SMTP* o, const char* fmt, va_list varg)
{
   return BufPrint_vprintf(&o->bp, fmt, varg) < 0 ? -1 : 0;
}


static int
SMTP_flushBuffer(SMTP* o, unsigned int argNotUsed)
{
   int retv = 0;
   (void)argNotUsed;
   if(o->bp.cursor)
   {
      retv = SMTP_sendData(o, o->bp.buf,o->bp.cursor);
      o->bp.cursor = 0; /* Reset */
   }
   return retv;
}


static int
SMTP_sendData(SMTP* o, const char* data, int len)
{
   if( ( o->isSecure ?
         seSec_write(o->sharkSslCon, &o->sock, (U8*)data, len) :
         se_send(&o->sock, data, len)
       ) == len)
   {
      return 0;
   }
   return -1;
}


static int
SMTP_getResponse(SMTP* o)
{
   int len;
   if(SMTP_flushBuffer(o, 0))
      return -1;
   o->bp.buf[0]=0;
   if(o->isSecure)
   {
      U8* buf;
      len = seSec_read(o->sharkSslCon, &o->sock, &buf, 20000);
      if(len >= 0)
      {
         if((len+1) > o->bp.bufSize)
         {
            o->eCode = SMTP_ErrSmtpResponseCode;
            return -1;
         }
         memcpy(o->bp.buf,buf,len);
      }
   }
   else
   {
      /* The buffer is empty. We can now use it for reading */
      len = se_recv(&o->sock,o->bp.buf,o->bp.bufSize-1,20000);
      if(len > 0)
      {
         char* ptr = o->bp.buf+len;
         while(len < (o->bp.bufSize-1))
         {
            int dl = se_recv(&o->sock,ptr,o->bp.bufSize-1-len,1);
            if(dl <=0 )
               break;
            ptr += dl;
            len += dl;
         }
      }
   }
   if(len <= 0)
   {
      o->eCode = SMTP_ErrSocketClosed;
      return -1;
   }
   o->bp.buf[len]=0;

   /* Assume everything is OK if the return code starts with 2 or 3.
    * See RFC 821 for more info.
    */
   if(o->bp.buf[0] =='2' || o->bp.buf[0] == '3') return 0;
   o->eCode = SMTP_ErrSmtpResponseCode;
   return -1;
}


static int
SMTP_sslHandshake(SMTP* o)
{
   int rc = seSec_handshake(o->sharkSslCon,&o->sock,3000,o->serverDomainName);
   if(rc <= 0)
   {
      o->eCode=SMTP_ErrSocketClosed;
      return -1;
   }
   if(o->serverDomainName && rc !=
#if SHARKSSL_CHECK_DATE
      SharkSslConTrust_CertCnDate
#else
      SharkSslConTrust_CertCn
#endif
      )
   {
      o->eCode=SMTP_ErrCertNotTrusted;
      return -1;
   }
   return 0;
}
