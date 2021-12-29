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
 *   $Id: SMTP-example.c 4769 2021-06-11 17:29:36Z gianluca $
 *
 *   COPYRIGHT:  Real Time Logic, 2013 - 2016
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



#include "SMTP.h"

/* List of trusted root certificates: See sharkSslCAList in SharkSsl
 * constructor below.
 */
#include <CA-list.h>

#if HOST_PLATFORM

static char* emailAddress;

/* Function used by selib.
 * Replace with function that prints to a console or create a stub
 * that does nothing.
 */
void _xprintf(const char* fmt, ...)
{
   va_list varg;
   va_start(varg, fmt);
   vprintf(fmt, varg);
   va_end(varg);
}
#else
extern char* emailAddress;
#endif

static const char* ecode2Msg(int ecode)
{
   switch(ecode)
   {
      case SMTP_ErrHostName: return "SMTP_ErrHostName";
      case SMTP_ErrSocketCreate: return "SMTP_ErrSocketCreate";
      case SMTP_ErrConnect: return "SMTP_ErrConnect";
      case SMTP_ErrHELO: return "SMTP_ErrHELO";
      case SMTP_ErrMAILFROM: return "SMTP_ErrMAILFROM";
      case SMTP_ErrDATA: return "SMTP_ErrDATA";
      case SMTP_ErrRCPTTO: return "SMTP_ErrRCPTTO";
      case SMTP_ErrSocketClosed: return "SMTP_ErrSocketClosed";
      case SMTP_ErrSmtpResponseCode: return "SMTP_ErrSmtpResponseCode";
      case SMTP_ErrWriteStarted: return "SMTP_ErrWriteStarted";
      case SMTP_ErrNoAuthSup: return "SMTP_ErrNoAuthSup";
      case SMTP_ErrAuth: return "SMTP_ErrAuth";
      case SMTP_ErrSslCon: return "SMTP_ErrSslCon";
      case SMTP_ErrCertNotTrusted: return "SMTP_ErrCertNotTrusted";
   }
   return "OK";
}


void mainTask(SeCtx* ctx)
{
   static SharkSsl sharkSsl;
   static SMTP smtp;

   if(!emailAddress)
   {
      xprintf(("Warning (mainTask): no email address, sending to RTL\n"));
      emailAddress="ginfo@realtimelogic.com";
   }

   SharkSsl_constructor(&sharkSsl,
                        SharkSsl_Client,
                        0,                /* cache size */
                        1400,     /* initial inBuf size */
                        3500);     /* outBuf size - fixed */

   /* CA list from CA-list.h */
   SharkSsl_setCAList(&sharkSsl, sharkSslCAList); /* Ref-CA */


#error Remove this line and insert your SMTP credentials. See examples below.


#if 0
   SMTP_constructor(
      &smtp,
      "XXXXXXX@gmail.com", //const char* from,
      emailAddress, //const char* to,
      "Poem sent via Gmail", //const char* subject,
      "smtp.gmail.com", //const char* smtpServer,
      465, //int port,
      &sharkSsl,
      FALSE, //int startTLS,
      "XXXXXXX@gmail.com", //const char* username,
      "XXXXXXX",
      0, //const char* clientDomainName,
      "smtp.gmail.com", //const char* serverDomainName
      ctx);
#endif

#if 0
   SMTP_constructor(
      &smtp,
      "XXXXXXXXX@hotmail.com", //const char* from,
      emailAddress, //const char* to,
      "Poem sent via Hotmail", //const char* subject,
      "smtp.live.com", //const char* smtpServer,
      587, //int port,
      &sharkSsl,
      TRUE, //int startTLS,
      "XXXXXXXXX@hotmail.com", //const char* username,
      "XXXXXXX",
      0, //const char* clientDomainName,
      "smtp.live.com", //const char* serverDomainName
      ctx);
#endif

   if(SMTP_getEcode(&smtp) == SMTP_NoError)
   {
      xprintf(("8BITMIME support: %s\n", SMTP_bit8(&smtp) ? "YES" : "NO"));

      SMTP_addRecipient(&smtp,"gsupport@realtimelogic.com");
   }

   if(SMTP_getEcode(&smtp) == SMTP_NoError)
      SMTP_printf(&smtp,"%s\n",
                  "Two roads diverged in a yellow wood,\n"
                  "And sorry I could not travel both\n"
                  "And be one traveler, long I stood\n"
                  "And looked down one as far as I could\n"
                  "To where it bent in the undergrowth;\n");
   if(SMTP_getEcode(&smtp) == SMTP_NoError)
      SMTP_printf(&smtp,"%s\n",
                  "Then took the other, as just as fair,\n"
                  "And having perhaps the better claim\n"
                  "Because it was grassy and wanted wear,\n"
                  "Though as for that the passing there\n"
                  "Had worn them really about the same,\n");
   if(SMTP_getEcode(&smtp) == SMTP_NoError)
      SMTP_printf(&smtp,"%s\n",
                  "And both that morning equally lay\n"
                  "In leaves no step had trodden black.\n"
                  "Oh, I marked the first for another day!\n"
                  "Yet knowing how way leads on to way\n"
                  "I doubted if I should ever come back.\n");
   if(SMTP_getEcode(&smtp) == SMTP_NoError)
      SMTP_printf(&smtp,"%s\n",
                  "I shall be telling this with a sigh\n"
                  "Somewhere ages and ages hence:\n"
                  "Two roads diverged in a wood, and I,\n"
                  "I took the one less traveled by,\n"
                  "And that has made all the difference.\n");
   if( !SMTP_commit(&smtp) )
      xprintf(("Email sent\n")); //Success.
   else
   {
      const char* emsg=SMTP_getEmsg(&smtp);
      xprintf(("Sending email failed: %s\n",ecode2Msg(SMTP_getEcode(&smtp))));
      if(emsg)
         xprintf(("SMTP response %s\n", emsg));
   }
   SMTP_destructor(&smtp);
   xprintf(("\nWe are done!\nPress return to continue."));
   getchar();
#if HOST_PLATFORM
   exit(0);
#endif
}

#if HOST_PLATFORM && !defined(NO_MAIN)
int main(int argc, char **argv)
{
#ifdef _WIN32
   {
      WSADATA wsaData;
      WSAStartup(MAKEWORD(1,1), &wsaData);
   }
#endif

   if(argc != 2)
   {
      printf("Usage:\n%s <email-address>\n",argv[0]);
      exit(1);
   }
   emailAddress = argv[1];
   mainTask(0);
   return 0;
}
#endif

