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
 *   $Id: CertCheck.c 4939 2021-12-14 18:14:31Z wini $
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
 *               http://realtimelogic.com
 *               http://sharkssl.com
 ****************************************************************************
 *
 */

/* This SharkSSL client example shows how to validate the certificate
   returned by an SSL enabled server.
 */


/*
Comment out macro USE_PARSED_CA_LIST if you want to read the
Certificate Authority file (CA_list_example.p7b) from the file system
and use the SharkSSL certificate store functions.

SharkSSL uses a binary certificate format optimized for
size and speed. This demo program uses the pre-parsed Certificate
Authority list (CA) found in the header file CA_list_example.h when
the macro USE_PARSED_CA_LIST is defined. The CA_list_example.h header
file is created from running the CA_list_example.p7b CA list through
the SharkSSL command line tool SharkSSLParseCAList.

You can also load a pre-parsed binary certificate from the file system
in addition to the two methods used by this example program. See the
command line program SharkSSLParseCAList and the option -b for more
information.

Note: you can make the SharkSSL code base smaller if you use the
SharkSSLParseCAList to convert the certificates and if you do not
use the certificate store functions. See the macro
SHARKSSL_ENABLE_CERTSTORE_API in SharkSSL_cfg.h for more info.

For more info; search the code below for: USE_PARSED_CA_LIST
*/
#define USE_PARSED_CA_LIST


#include "selib.h"
#include <SharkSslEx.h>
#include <ctype.h>
#include <stdio.h>
#include <stddef.h>

#if !defined(SHARKSSL_ENABLE_CA_LIST) || defined(SHARKSSL_DISABLE_RSA)
#error SHARKSSL_ENABLE_CA_LIST is required (see SharkSSL_cfg.h).
#endif

#ifdef USE_PARSED_CA_LIST
#include "CA-list.h"
#else
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef SHARKSSL_ENABLE_CERTSTORE_API
#error SHARKSSL_ENABLE_CERTSTORE_API is required (see SharkSSL_cfg.h).
#endif
#endif


#if HOST_PLATFORM == 1

#ifdef _WIN32
#define getMilliSec() GetTickCount()
#else
#include <sys/time.h>
#include <unistd.h>
static U32 getMilliSec(void)
{
   struct timespec t;
   if(clock_gettime(0, &t))
      return 0;
   return (U32)(1000*t.tv_sec + t.tv_nsec/1000000);
}
#endif

/* Replace with a function that prints to a console or create a stub
 * that does nothing.
 */
void _xprintf(const char* fmt, ...)
{
   va_list varg;
   va_start(varg, fmt);
   vprintf(fmt, varg);
   va_end(varg);
} 
#else /* HOST_PLATFORM */
extern U32 getMilliSec(void);
#endif  /* HOST_PLATFORM */


/* Prints out the certificate chain and the info for each certificate
 * chain node.
 */
static void printCertField(const U8 *field, int len)
{
   if (field)
   {
      xprintf((" "));
      while (len--)
      {
         xprintf(("%c", *field++));
      }
      xprintf(("\n"));
   }
}

static void printCertInfo(SharkSslCertInfo* ci)
{
   if( ! ci )
   {
      xprintf(("No certificate!!!"));
      return;
   }

   xprintf(("-------- Begin Cert Info -----------\n"));
   while (ci)
   {
      SharkSslCertDN *dn = &(ci->subject);  
      xprintf(("certificate content:\r\n"));
      xprintf(("Subject:\n"));
      printCertField(dn->countryName, dn->countryNameLen);
      printCertField(dn->province, dn->provinceLen);
      printCertField(dn->locality, dn->localityLen);
      printCertField(dn->organization, dn->organizationLen);
      printCertField(dn->commonName, dn->commonNameLen);      
      if (ci->subjectAltNamesLen)
      {
         SubjectAltNameEnumerator se;
         SubjectAltName s;
            
         SubjectAltNameEnumerator_constructor(
            &se, ci->subjectAltNamesPtr, ci->subjectAltNamesLen);
         xprintf((" subject's alternate DNS names/IP addresses:\n"));
            
         for (SubjectAltNameEnumerator_getElement(&se, &s); 
               SubjectAltName_isValid(&s); 
               SubjectAltNameEnumerator_nextElement(&se, &s))
         {
            U16 l  = SubjectAltName_getLen(&s);
            U8 *tp = SubjectAltName_getPtr(&s);

            if (SUBJECTALTNAME_IPADDRESS == SubjectAltName_getTag(&s))
            {
               xprintf(("  IP address: "));
               while (l--)
               {
                  xprintf(("%d", *tp++));
                  if (l)
                  {
                     xprintf(("."));
                  }
               }
               xprintf(("\n"));
            }
            else if (SUBJECTALTNAME_DNSNAME == SubjectAltName_getTag(&s))
            {
               xprintf(("  DNS name: "));
               while (l--)
               {
                  xprintf(("%c", *tp++));
               }
               xprintf(("\n"));
            }
         }
         xprintf(("\n"));
      }
      dn = &(ci->issuer);
      xprintf(("Issuer:\n"));
      printCertField(dn->countryName, dn->countryNameLen);
      printCertField(dn->province, dn->provinceLen);
      printCertField(dn->locality, dn->localityLen);
      printCertField(dn->organization, dn->organizationLen);
      printCertField(dn->commonName, dn->commonNameLen);
      if (ci->parent)
      {
         xprintf(("\nparent's "));
         ci = ci->parent;
      }
      else
         break;
   }
   xprintf(("--------- End Cert Info ------------\n"));
}




void mainTask(SeCtx* ctx)
{
   /* A list of web servers used in the certificate tests */
   const char* servers[]= {
      "realtimelogic.com", /* A Barracuda Application Server powered server */
      "sharkssl.com", /* Same server as above, but wrong domain name for cert */
      "www.google.com",
      "www.paypal.com", /* triple chain */
      "www.sslshopper.com", /* chain with CA */
      "www.ssllabs.com"
   };

   int i;
   SharkSsl sharkSsl;
   SharkSslCAList caList=0;

#ifdef USE_PARSED_CA_LIST
   caList = sharkSslCAList; /* From CA_list_example.h */
#else
   FILE *fCA;
   struct stat fstat;
   U8 *fCA_content;
   int fCA_size, len;
   SharkSslCertStore certStore;
   /* Fetch file: wget https://curl.haxx.se/ca/cacert.pem
      See README.txt for details.
   */
   const char fCA_name[] = "cacert.pem";
   if ((stat(fCA_name, &fstat) == 0) && (fCA = fopen(fCA_name, "rb")) != NULL)
   {
      fCA_content = (U8*)baMalloc(fstat.st_size);
      if (fCA_content)
      {
         fCA_size = 0;
         while (((len = fread(fCA_content + fCA_size, sizeof(char), 512,
                                    fCA)) > 0) && (fCA_size < fstat.st_size))
         {
            fCA_size += len;
         }
         SharkSslCertStore_constructor(&certStore);
         SharkSslCertStore_add(
            &certStore, (const char*)fCA_content, (U32)fCA_size);
         SharkSslCertStore_assemble(&certStore, &caList);
         baFree(fCA_content);
      }
      fclose(fCA);
   }
   else
   {
      baAssert(0); /* Cannot open certificate file. See above */
   }
#endif


#ifdef _WIN32
   /* Start winsock on Windows */
   { WSADATA wsaData; WSAStartup(MAKEWORD(1,1), &wsaData); }
#endif

   /* It is common to create one (or several) SharkSsl object(s) at
      system start and to keep these objects for the lifetime of the
      program/firmware.

      Notice the large receive buffer size: we are receiving large
      packets (SSL frames) from the server. The 8000 bytes setting is
      sufficiently large to prevent the buffer from growing
      dynamically.
    */
   SharkSsl_constructor(&sharkSsl,
                        SharkSsl_Client, /* Two options: client or server */
                        0,      /* Not using SSL cache */
                        8000,   /* initial inBuf size: */
                        3072);  /* outBuf size: Fixed */

   /* Certificate Authority list from CA-list.h */
   SharkSsl_setCAList(&sharkSsl, caList);
   
   /* It is very important to seed the SharkSSL RNG generator */
   sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)&sharkSsl);

   /* Loop and connect to all servers listed in 'servers' */
   for(i=0 ; i < sizeof(servers)/sizeof(servers[0]); i++)
   {
      SharkSslCon* sharkSslCon;

      /* The HTTP command sent to the server */
      static const char httpCmd[] = 
         "GET / HTTP/1.0\r\n"
         "User-Agent: The-worlds-most-basic-HTTP-client\r\n"
         "\r\n";

      /* Standard BSD socket stuff */
      SOCKET sock;
      int rc;

      /* HTTPS servers listen on 443 */
      if( (rc=se_connect(&sock, servers[i], 443)) != 0)
      {
         const char* msg;
         switch(rc)
         {
            case -1: msg="Socket error!"; break;
            case -2: msg="Cannot resolve IP address for %s."; break;
            default:  msg="Cannot connect to %s."; break;
         }
         xprintf((msg,servers[i]));
         xprintf((
            "\n%s",
            rc == -1 ? "" :
            "Note: this client is not designed to connect via a HTTP proxy.\n"));
         continue;
      }
      xprintf(("\n=============================================\n"));
      xprintf(("Connecting to HTTPS server %s\n",servers[i]));
      if( (sharkSslCon = SharkSsl_createCon(&sharkSsl)) == 0)
         xprintf(("Cannot create SharkSslCon object\n"));
      else
      {
         U32 startT;
         /* Keep seeding (Make it more secure) */
         sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)&sharkSsl ^ i);

         /* Make sure we get the correct certificate from the server */
         SharkSslCon_setSNI(sharkSslCon, servers[i], (U16)strlen(servers[i]));

         /* The following function (in selib.c) performs the initial
          * SSL handshake.
          */
         startT = getMilliSec();
         if((rc=seSec_handshake(sharkSslCon,&sock,3000, 0))<=0)
         {
            xprintf(("SSL handshake failed\n"));
         }
         else
         {
            SharkSslCertInfo *ci;
            xprintf(("Handshake completed in %u ms.\n\n",
                     getMilliSec() - startT));
            switch(SharkSslCon_trusted(sharkSslCon,servers[i],&ci))
            {
#if SHARKSSL_CHECK_DATE
               case SharkSslConTrust_CertCnDate:
                  xprintf(("Certificate trusted: %s.\n",
                           servers[i]));
                  break;

               case SharkSslConTrust_CertCn:
                  xprintf(("Certificate and domain name trusted, but cert has expired: %s.\n",
                           servers[i]));
                  break;
#else
               case SharkSslConTrust_CertCn:
                  xprintf(("Certificate and domain name trusted (cert exp. time not checked): %s.\n",
                           servers[i]));
                  break;
#endif

               case SharkSslConTrust_Cn:
                  xprintf(("Certificate not trusted (maybe expired): %s.\n",
                           servers[i]));
                  break;

               case SharkSslConTrust_Cert:
                  xprintf(("Domain mismatch: %s.\n",servers[i]));
                  break;

               case SharkSslConTrust_None:
                  xprintf(("Certificate and domain name NOT trusted: %s!!!\n",
                           servers[i]));
                  break;

               default: baAssert(0);
            }
            printCertInfo(ci);
            if(seSec_write(
                  sharkSslCon, &sock, (U8*)httpCmd, sizeof(httpCmd)-1) > 0)
            {
               U8* buf;
               int recLen=0;
               while((rc=seSec_read(sharkSslCon,&sock,&buf,10000)) > 0)
               {
                  recLen+=rc;
                  /* Enable the next code line if you want to print
                     out the returned data
                  */
                  /* while (rc--) xprintf(("%c", *buf++)); */
               }
               xprintf(("\nReceived a total of %d bytes from %s\n",
                        recLen,servers[i]));
            }
         }
         /* Release resources used by sharkSslCon */
         SharkSsl_terminateCon(&sharkSsl, sharkSslCon);
      }
      se_close(&sock);
   }

   SharkSsl_destructor(&sharkSsl);
   xprintf(("We are done!\nPress return to continue."));
   getchar();
}


#if  HOST_PLATFORM == 1
int main()
{
   mainTask(0);
   return 0;
}
#endif
