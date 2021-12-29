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
 *   $Id: SharkSSLParseKey.c 4563 2020-09-07 09:26:17Z gianluca $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2010
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
 *               http://www.sharkssl.com
 ****************************************************************************
 *
 */


/** 
 * COMPILATION - command line from within the tools subdir
 *
 * WINDOWS:
 * cl /O2 SharkSslParseKey.c -I..\inc -I..\inc\arch\Windows
 *
 * LINUX:
 * gcc SharkSslParseKey.c -I../inc -I../inc/arch/Posix -O3 -o SharkSSLParseKey
 */


#include "SharkSSLTools.h"


/**
 * main
 */
int main (int argc, char **argv)
{
   sharkssl_PEM_RetVal ret;
   unsigned char *keyBuf;
   char str[30], *type;
   SharkSslCert sharkSslCert;
   U8 cert_type;

   initVars();
   printRev("$Id: SharkSSLParseKey.c 4563 2020-09-07 09:26:17Z gianluca $");

   if (argc < 2)
   {
      print_usage:
      printf("Usage: %s <privkey file> [-p <passkey>] [-b <binary output file>]\n"
             "       %s <pubkey file> [-b <binary output file>]\n", argv[0], argv[0]);
      return 1;
   }

   if (argc > 2)
   {
      if (strcmp(argv[2], "-b") == 0)
      {
         if (argc != 4)
         {
            goto print_usage;
         }

         output_fmt = BINARY;
         binFName = argv[3];
      }

      else if (strcmp(argv[2], "-p") == 0)
      {
         if (argc == 6)
         {
            if (strcmp(argv[4], "-b") == 0)
            {
               output_fmt = BINARY;
               binFName = argv[5];
            }

            else
            {
               goto print_usage;
            }
         }

         else if (argc != 4)
         {
            goto print_usage;
         }

         passKey = argv[3];
      }

      else
      {
         goto print_usage;
      }
   }

   if (readFile(argv[1], &keyBuf) < 0)
   {
      printf("Error reading %s\n",argv[1]);
      return 1;
   }

   ret = sharkssl_PEM((const char*)0,
                      (const char*)keyBuf, (const char*)passKey,
                      &sharkSslCert);
                      
   baFree(keyBuf); 

   if ((ret != SHARKSSL_PEM_OK) && (ret != SHARKSSL_PEM_OK_PUBLIC))
   {
      printf("%s error\n", errorString(ret));
      return 1;
   }
   
   vect_size = SharkSslCert_vectSize_keyType(sharkSslCert, &cert_type);
   if (vect_size > 0) 
   {
      if (SHARKSSL_KEYTYPE_RSA == cert_type)
      {
         type = (char*)"RSA";
      }
      else if (SHARKSSL_KEYTYPE_EC == cert_type)
      {
         type = (char*)"EC";
      }
      else
      {
         goto _parsing_error;
      }
   }
   else
   {
      _parsing_error:
      printf("Parsing error\n");
      return 1;
   }
   pad_size = 1 + SHARKSSL_DIM_ARR(padv) - (vect_size & SHARKSSL_DIM_ARR(padv));
   pad_size &= SHARKSSL_DIM_ARR(padv);
   
   sprintf(str, "sharkSsl%s%sKey<name here>", (ret == SHARKSSL_PEM_OK_PUBLIC ? "Pub" : "Priv"), type);
   ret_val = outputVector((unsigned char*)sharkSslCert, str);
   baFree((void*)sharkSslCert);
   return ret_val;
}
 