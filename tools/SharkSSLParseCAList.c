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
 *   $Id: SharkSSLParseCAList.c 5006 2022-01-07 19:54:12Z gianluca $
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
 * cl /O2 SharkSslParseCAList.c -I..\inc -I..\inc\arch\Windows
 *
 * LINUX:
 * gcc SharkSslParseCAList.c -I../inc -I../inc/arch/Posix -O3 -o SharkSslParseCAList
 */


#include "SharkSSLTools.h"


static int SharkSslCertStore_assemble_2(SharkSslCertStore *o, unsigned char **outList)
{
   int list_off, cert_size, tot_cert_size;
   DoubleListEnumerator iter;
   SharkSslCSCert *cert;
   unsigned char *p;

   /* determine total vector size */
   list_off = 4 + (o->elements * SHARKSSL_CA_LIST_ELEMENT_SIZE);
   tot_cert_size = list_off;
   DoubleListEnumerator_constructor(&iter, &o->certList);
   for (cert = (SharkSslCSCert*)DoubleListEnumerator_getElement(&iter); cert;
        cert = (SharkSslCSCert*)DoubleListEnumerator_nextElement(&iter))
   {
      cert_size = SharkSslCert_len(cert->ptr);
      tot_cert_size += cert_size;
   }

   /* create vector */
   p = (unsigned char*)baMalloc(tot_cert_size);
   *outList = p;
   if (p == (void*)0)
   {
      return -1;
   }

   *p++ = SHARKSSL_CA_LIST_INDEX_TYPE;
   *p++ = 0;
   *p++ = (unsigned char)(((o->elements) >> 8));
   *p++ = (unsigned char)((o->elements) & 0xFF);

   DoubleListEnumerator_constructor(&iter, &o->certList);
   for (cert = (SharkSslCSCert*)DoubleListEnumerator_getElement(&iter); cert;
        cert = (SharkSslCSCert*)DoubleListEnumerator_nextElement(&iter))
   {
      memcpy(p, cert->name, SHARKSSL_CA_LIST_NAME_SIZE);
      p += SHARKSSL_CA_LIST_NAME_SIZE;
      *p++ = (unsigned char)(list_off >> 24);
      *p++ = (unsigned char)(list_off >> 16);
      *p++ = (unsigned char)(list_off >>  8);
      *p++ = (unsigned char)(list_off & 0xFF);
      cert_size = SharkSslCert_len(cert->ptr);
      memcpy(*outList + list_off, cert->ptr, cert_size);
      list_off += cert_size;
   }

   return tot_cert_size;
}


/**
 * main
 */
int main(int argc, char **argv)
{
   SharkSslCertStore certStore;
   unsigned char *caList, *outBuf;

   initVars();
   (void)errorString;  /* warning removal */
   printRev("$Id: SharkSSLParseCAList.c 5006 2022-01-07 19:54:12Z gianluca $");

   if (argc < 2)
   {
      print_usage:
      printf("Usage: %s [-b <binary output file>] <certfile> [certfile...]\n"
             "       where certfile is a .PEM, .DER or .P7B file containing\n"
             "       one or more certificates\n", argv[0]);
      return 1;
   }

   if (strcmp(argv[1], "-b") == 0)
   {
      if (argc < 4)
      {
         goto print_usage;
      }

      output_fmt = BINARY;
      binFName = argv[2];
   }

   SharkSslCertStore_constructor(&certStore);
   while (--argc >= ((output_fmt == BINARY) ? 3 : 1))
   {
      ret_val = readFile(argv[argc], &outBuf);
      if (ret_val < 0)
      {
         printf("Error parsing \"%s\"\n", argv[argc]);
         ret_val = 1;
         goto _end;
      }
      else
      {
         SharkSslCertStore_add(&certStore, (const char*)outBuf, (U32)ret_val);
         baFree(outBuf);
      }
   }

   vect_size = SharkSslCertStore_assemble_2(&certStore, &caList);
   if (vect_size > 0)
   {
      ret_val = outputVector(caList, "sharkSslCAList");
    }
   else
   {
      printf("Error allocating memory\n");
      ret_val = 1;
   }
   _end:
   SharkSslCertStore_destructor(&certStore);
   return ret_val;
}
 
