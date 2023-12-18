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
 *   $Id: SharkSSLTools.h 5390 2023-02-21 00:59:31Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2010 - 2023
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

/* Required if built by Real Time Logic's release script */
#ifdef BA_RELEASE
#include <ThreadLib.h>
#undef Thread_ce
#undef ThreadMutex_constructor
#undef ThreadMutex_destructor
#undef ThreadMutex_set
#undef ThreadMutex_release
#define Thread_ce(x)
#define ThreadMutex_constructor(x)
#define ThreadMutex_destructor(x)
#define ThreadMutex_set(x)
#define ThreadMutex_release(x)
#endif


/**
 * common code for SharkSSL command line tools
 */


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#undef  SHARKSSL_USE_AES_256
#undef  SHARKSSL_USE_AES_128
#undef  SHARKSSL_USE_3DES
#undef  SHARKSSL_SSL_CLIENT_CODE
#undef  SHARKSSL_SSL_SERVER_CODE
#undef  SHARKSSL_ENABLE_PEM_API
#undef  SHARKSSL_ENABLE_RSA_API
#undef  SHARKSSL_ENABLE_CERT_CHAIN
#undef  SHARKSSL_ENABLE_CERTSTORE_API
#undef  SHARKSSL_ENABLE_CLIENT_AUTH
#undef  SHARKSSL_ENABLE_RSA
#undef  SHARKSSL_USE_ECC
#undef  SHARKSSL_ENABLE_ECDSA
#undef  SHARKSSL_ECC_USE_SECP192R1
#undef  SHARKSSL_ECC_USE_SECP224R1
#undef  SHARKSSL_ECC_USE_SECP256R1
#undef  SHARKSSL_ECC_USE_SECP384R1
#undef  SHARKSSL_ECC_USE_SECP521R1
#undef  SHARKSSL_ENABLE_PSK

#define SHARKSSL_USE_AES_256           1
#define SHARKSSL_USE_AES_128           1
#define SHARKSSL_USE_3DES              1
#define SHARKSSL_ENABLE_PEM_API        1
#define SHARKSSL_ENABLE_RSA_API        1
#define SHARKSSL_ENABLE_CERT_CHAIN     1
#define SHARKSSL_ENABLE_CERTSTORE_API  1
#define SHARKSSL_ENABLE_CLIENT_AUTH    0
#define SHARKSSL_ENABLE_RSA            1
#define SHARKSSL_USE_ECC               1
#define SHARKSSL_ENABLE_ECDSA          1
#define SHARKSSL_ECC_USE_SECP192R1     1
#define SHARKSSL_ECC_USE_SECP224R1     1
#define SHARKSSL_ECC_USE_SECP256R1     1
#define SHARKSSL_ECC_USE_SECP384R1     1
#define SHARKSSL_ECC_USE_SECP521R1     1
#define SHARKSSL_ENABLE_PSK            1

/* Set to 1 for SharkSSL amalgamated */
#if 1
#define SHARKSSL_SSL_CLIENT_CODE       1
#define SHARKSSL_SSL_SERVER_CODE       1
#include "../src/SharkSSL.c"
#else
#define SHARKSSL_SSL_CLIENT_CODE       0
#define SHARKSSL_SSL_SERVER_CODE       0
#include "../src/SharkSslASN1.c"
#include "../src/SharkSslCert.c"
#include "../src/SharkSslCrypto.c"
#include "../src/SharkSslPublic.c"
#include "../src/SharkSslBigInt.c"
#include "../src/SharkSslECC.c"
#endif

static void printRev(char *svnId)
{
   char *p1, *p2;

   printf(" /**\n  *  ");
   p1 = strstr(svnId, "$Id: ");
   if (p1)
   {
      p1 += 5; /* strlen("$Id: ") */
      p2 = strstr(p1, ".");
      if (p2)
      {
         while (p1 != p2)
         {
            printf("%c", *p1++);
         }
         printf(".");
      }
      p1 = strstr(p2, " ");
      if (p1)
      {
         p1++;
         p2 = strstr(p1, " ");
         if (p2)
         {
            printf("  Build ");
            while (p1 != p2)
            {
               printf("%c", *p1++);
            }
            printf(".");
         }
      }
   }
   printf("\n  *  Copyright (c) ");
   if (p1)
   {
      printf("%c%c%c%c ", p1[1], p1[2], p1[3], p1[4]);
   }
   printf("Real Time Logic.\n  */\n\n");
}


static int readFile (char *fileName, unsigned char **outBuf)
{
   FILE  *fp;
   struct stat fstat;
   size_t tmp;
   int len;

   tmp = 0;
   len = 0;
   *outBuf = NULL;

   if (fileName == NULL)
   {
      return -1;
   }

   if ((stat(fileName, &fstat) != 0) || (fp = fopen(fileName, "rb")) == NULL)
   {
      return -1;  /* file not found */
   }

   *outBuf = baMalloc(fstat.st_size);
   if (*outBuf == NULL)
   {
      return -1;  /* allocation error */
   }

   while (((tmp = fread(*outBuf + len, sizeof(char), 512, fp)) > 0) && (len < fstat.st_size))
   {
      len += (int)tmp;
   }

   fclose(fp);
   return len;
}


static void printOutBytes (unsigned char *char_seq, int char_len)
{
   char i = 0;

   while (char_len > 0)
   {
      printf("0x%02X",*char_seq);
      char_seq++;
      char_len--;

      if (char_len > 0)
      {
         printf(", ");
      }

      i++;
      if (i >= 8 /* bytes per row */)
      {
         if (char_len)
         {
            i = 0;
            printf("\n   ");
         }
      }
   }
}


static char *errorString (sharkssl_PEM_RetVal retCode)
{
   switch (retCode)
   {
      case SHARKSSL_PEM_ALLOCATION_ERROR:
         return "Memory allocation";
      case SHARKSSL_PEM_KEY_PARSE_ERROR:
         return "Key parsing";
      case SHARKSSL_PEM_KEY_WRONG_IV:
         return "Wrong IV in key,";
      case SHARKSSL_PEM_KEY_WRONG_LENGTH:
         return "Wrong key length";
      case SHARKSSL_PEM_KEY_PASSPHRASE_REQUIRED:
         return "Passphrase required,";
      case SHARKSSL_PEM_KEY_UNRECOGNIZED_FORMAT:
         return "Unrecognized key format,";
      case SHARKSSL_PEM_KEY_UNSUPPORTED_FORMAT:
         return "Unsupported key format,";
      case SHARKSSL_PEM_KEY_UNSUPPORTED_VERSION:
         return "Unsupported key version,";
      case SHARKSSL_PEM_KEY_UNSUPPORTED_MODULUS_LENGTH:
         return "Unsupported modulus length in key,";
      case SHARKSSL_PEM_KEY_UNSUPPORTED_ENCRYPTION_TYPE:
         return "Unsupported encryption type,";
      case SHARKSSL_PEM_KEY_CERT_MISMATCH:
         return "Certificate and Key are not related,";
      case SHARKSSL_PEM_CERT_UNRECOGNIZED_FORMAT:
         return "Unrecognized certificate format,";
      case SHARKSSL_PEM_CERT_UNSUPPORTED_TYPE:
         return "Unsupported certificate format,";
      default:
         return "Internal";
   }
}


BA_API void baFatalEf(unsigned int ecode1, unsigned int ecode2,
                      const char* file, int line)
{
   fprintf(stderr,"Fatal err: %d %d: %s:%d\n",ecode1,ecode2,file,line);
   exit(1);
}


enum
{
   C_VECTOR = 1,
   BINARY
};


static const unsigned char padv[7] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static int output_fmt, vect_size, pad_size, ret_val;
static char *binFName, *passKey;


static void initVars (void)
{
   output_fmt = C_VECTOR;
   passKey = binFName = NULL;
   vect_size = pad_size = ret_val = 0;
}


static int outputVector (unsigned char *vect, char *vectName)
{
   if (output_fmt == C_VECTOR)
   {
      /* output the vector to be used by SharkSSL */
      printf("#include \"TargConfig.h\"\n\n");
      printf("const U8 %s[%d] =\n{\n   ", vectName, vect_size + pad_size);
      printOutBytes(vect, vect_size);
      if (pad_size)
      {
         printf(", ");
         printOutBytes((unsigned char*)padv, pad_size);
      }   
      printf("\n};\n\n");
   }

   else
   {
      FILE *fp;
      unsigned char *p = vect;
      if ((fp = fopen(binFName, "wb")) == NULL)
      {
         printf("Unable to create the binary file %s\n", binFName);
         return 1;
      }
      while (vect_size--)
      {
         fputc(*p++, fp);
      }
      p = (unsigned char*)padv;
      while (pad_size--)
      {
         fputc(*p++, fp);
      }
      fclose(fp);
   }

   return 0;
}
