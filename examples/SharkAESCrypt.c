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
 *   $Id: SharkAESCrypt.c 5076 2022-02-10 16:59:48Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2018
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
 * Decrypt files encrypted with https://www.aescrypt.com/
 * See end of file for example program.
 */

#include <SharkSslCrypto.h>

#ifdef _WIN32
typedef wchar_t sharkWchar_t;
#else
typedef U16 sharkWchar_t;
#endif


typedef struct {
   char aes[3];
   unsigned char version;
   unsigned char lastBlockSize;
} SharkAESCryptHdr; 
#define AESCryptHdrSize 5

#define SHARKAESCRYPT_EFILE_TOO_SHORT  -10
#define SHARKAESCRYPT_EBAD_HEADER      -11
#define SHARKAESCRYPT_EUNSUPPORTED_AES -12
#define SHARKAESCRYPT_EPASSWORD        -13
#define SHARKAESCRYPT_ECORRUPT         -14
#define SHARKAESCRYPT_EWRITE           -15
#define SHARKAESCRYPT_EWBUFLEN         -16

typedef int (*SharkAESCrypt_Read)(void* o, void* buf, int size, int* eof);
typedef int (*SharkAESCrypt_Write)(void* o, void* buf, int size);
 

typedef struct SharkAESCrypt
{
   SharkAESCrypt_Read read;
   void* oRead;
   SharkAESCrypt_Write write;
   void* oWrite;
} SharkAESCrypt;

#define SharkAESCrypt_constructor(o, readMA, readObj, writeMA, writeObj) do{ \
   (o)->read = readMA;                                                  \
   (o)->oRead = readObj;                                                \
   (o)->write = writeMA;                                                \
   (o)->oWrite = writeObj;                                              \
   } while(0)



/*
 *  decrypt_stream
 *
 *  This function is called to decrypt the open data steam "infp".
 */
int SharkAESCrypt_decryptW(
   SharkAESCrypt* o, const sharkWchar_t* passwd, int passlen)
{
   SharkSslAesCtx     aesCtx;
   SharkSslSha256Ctx  shaCtx;
   SharkAESCryptHdr        aesHdr;
   U8                 digest[SHARKSSL_SHA256_HASH_LEN];
   unsigned char      IV[16];
   unsigned char      iv_key[48];
   int                i, j, n, bytesRead;
   unsigned char      buffer[64], buffer2[32];
   unsigned char      *head, *tail;
   unsigned char      ipad[64], opad[64];
   int                reachedEOF = 0;
    
   // Read the file header
   if ((bytesRead = o->read(o->oRead,&aesHdr,AESCryptHdrSize,&reachedEOF)) !=
       AESCryptHdrSize)
   {
      return SHARKAESCRYPT_EFILE_TOO_SHORT;
   }

   if (!(aesHdr.aes[0] == 'A' && aesHdr.aes[1] == 'E' &&
         aesHdr.aes[2] == 'S'))
   {
      return SHARKAESCRYPT_EBAD_HEADER;
   }

   // Validate the version number and take any version-specific actions
   if (aesHdr.version == 0)
   {
      // Let's just consider the least significant nibble to determine
      // the size of the last block
      aesHdr.lastBlockSize = (aesHdr.lastBlockSize & 0x0F);
   }
   else if (aesHdr.version > 0x02)
   {
      return SHARKAESCRYPT_EUNSUPPORTED_AES;
   }

   // Skip over extensions present v2 and later files
   if (aesHdr.version >= 0x02)
   {
      do
      {
         if ((bytesRead = o->read(o->oRead, buffer, 2, &reachedEOF)) != 2)
         {
            return SHARKAESCRYPT_EFILE_TOO_SHORT;
         }
         // Determine the extension length, zero means no more extensions
         i = j = (((int)buffer[0]) << 8) | (int)buffer[1];
         while (i--)
         {
            if ((bytesRead = o->read(o->oRead, buffer, 1, &reachedEOF)) != 1)
            {
               return SHARKAESCRYPT_EFILE_TOO_SHORT;
            }
         }
      } while(j);
   }

   // Read the initialization vector from the file
   if ((bytesRead = o->read(o->oRead, IV, 16, &reachedEOF)) != 16)
   {
      return SHARKAESCRYPT_EFILE_TOO_SHORT;
   }

   // Hash the IV and password 8192 times
   memset(digest, 0, 32);
   memcpy(digest, IV, 16);
   for(i=0; i<8192; i++)
   {
      SharkSslSha256Ctx_constructor(  &shaCtx);
      SharkSslSha256Ctx_append(&shaCtx, digest, 32);
      SharkSslSha256Ctx_append(
         &shaCtx,
         (unsigned char*)passwd,
         (unsigned long)(passlen * sizeof(sharkWchar_t)));
      SharkSslSha256Ctx_finish(&shaCtx, digest);
   }

   // Set the AES encryption key
   SharkSslAesCtx_constructor(
      &aesCtx, SharkSslAesCtx_Decrypt, digest, sizeof(digest));

   // Set the ipad and opad arrays with values as
   // per RFC 2104 (HMAC).  HMAC is defined as
   //   H(K XOR opad, H(K XOR ipad, text))
   memset(ipad, 0x36, 64);
   memset(opad, 0x5C, 64);

   for(i=0; i<32; i++)
   {
      ipad[i] ^= digest[i];
      opad[i] ^= digest[i];
   }

   SharkSslSha256Ctx_constructor(&shaCtx);
   SharkSslSha256Ctx_append(&shaCtx, ipad, 64);

   // If this is a version 1 or later file, then read the IV and key
   // for decrypting the bulk of the file.
   if (aesHdr.version >= 0x01)
   {
      for(i=0; i<48; i+=16)
      {
         if ((bytesRead = o->read(o->oRead, buffer, 16, &reachedEOF)) != 16)
         {
            return SHARKAESCRYPT_EFILE_TOO_SHORT;
         }

         memcpy(buffer2, buffer, 16);

         SharkSslSha256Ctx_append(&shaCtx, buffer, 16);
         SharkSslAesCtx_decrypt(&aesCtx, buffer, buffer);

         // XOR plain text block with previous encrypted
         // output (i.e., use CBC)
         for(j=0; j<16; j++)
         {
            iv_key[i+j] = (buffer[j] ^ IV[j]);
         }

         // Update the IV (CBC mode)
         memcpy(IV, buffer2, 16);
      }

      // Verify that the HMAC is correct
      SharkSslSha256Ctx_finish(&shaCtx, digest);
      SharkSslSha256Ctx_constructor(&shaCtx);
      SharkSslSha256Ctx_append(&shaCtx, opad, 64);
      SharkSslSha256Ctx_append(&shaCtx, digest, 32);
      SharkSslSha256Ctx_finish(&shaCtx, digest);

      if ((bytesRead = o->read(o->oRead, buffer, 32, &reachedEOF)) != 32)
      {
         return SHARKAESCRYPT_EFILE_TOO_SHORT;
      }

      if (memcmp(digest, buffer, 32))
      {
         return SHARKAESCRYPT_EPASSWORD;
      }

      // Re-load the IV and encryption key with the IV and
      // key to now encrypt the datafile.  Also, reset the HMAC
      // computation.
      memcpy(IV, iv_key, 16);

      // Set the AES encryption key
      SharkSslAesCtx_constructor(
         &aesCtx, SharkSslAesCtx_Decrypt, iv_key+16, sizeof(digest));

      // Set the ipad and opad arrays with values as
      // per RFC 2104 (HMAC).  HMAC is defined as
      //   H(K XOR opad, H(K XOR ipad, text))
      memset(ipad, 0x36, 64);
      memset(opad, 0x5C, 64);

      for(i=0; i<32; i++)
      {
         ipad[i] ^= iv_key[i+16];
         opad[i] ^= iv_key[i+16];
      }

      // Wipe the IV and encryption mey from memory
      memset(iv_key, 0, 48);

      SharkSslSha256Ctx_constructor(&shaCtx);
      SharkSslSha256Ctx_append(&shaCtx, ipad, 64);
   }
    
   // Decrypt the balance of the file

   // Attempt to initialize the ring buffer with contents from the file.
   // Attempt to read 48 octets of the file into the ring buffer.
   if ((bytesRead = o->read(o->oRead, buffer, 48, &reachedEOF)) < 48)
   {
      if (!reachedEOF)
      {
         return SHARKAESCRYPT_EFILE_TOO_SHORT;
      }
      else
      {
         // If there are less than 48 octets, the only valid count
         // is 32 for version 0 (HMAC) and 33 for version 1 or
         // greater files ( file size modulo + HMAC)
         if ((aesHdr.version == 0x00 && bytesRead != 32) ||
             (aesHdr.version >= 0x01 && bytesRead != 33))
         {
            return SHARKAESCRYPT_ECORRUPT;
         }
         else
         {
            // Version 0 files would have the last block size
            // read as part of the header, so let's grab that
            // value now for version 1 files.
            if (aesHdr.version >= 0x01)
            {
               // The first octet must be the indicator of the
               // last block size.
               aesHdr.lastBlockSize = (buffer[0] & 0x0F);
            }
            // If this initial read indicates there is no encrypted
            // data, then there should be 0 in the lastBlockSize field
            if (aesHdr.lastBlockSize != 0)
            {
               return SHARKAESCRYPT_ECORRUPT;
            }
         }
         reachedEOF = 1;
      }
   }
   head = buffer + 48;
   tail = buffer;

   while(!reachedEOF)
   {
      // Check to see if the head of the buffer is past the ring buffer
      if (head == (buffer + 64))
      {
         head = buffer;
      }

      if ((bytesRead = o->read(o->oRead, head, 16, &reachedEOF)) < 16)
      {
         if (!reachedEOF)
         {
            return SHARKAESCRYPT_EFILE_TOO_SHORT;
         }
         else
         {
            // The last block for v0 must be 16 and for v1 it must be 1
            if ((aesHdr.version == 0x00 && bytesRead > 0) ||
                (aesHdr.version >= 0x01 && bytesRead != 1))
            {
               return SHARKAESCRYPT_ECORRUPT;
            }

            // If this is a v1 file, then the file modulo is located
            // in the ring buffer at tail + 16 (with consideration
            // given to wrapping around the ring, in which case
            // it would be at buffer[0])
            if (aesHdr.version >= 0x01)
            {
               if ((tail + 16) < (buffer + 64))
               {
                  aesHdr.lastBlockSize = (tail[16] & 0x0F);
               }
               else
               {
                  aesHdr.lastBlockSize = (buffer[0] & 0x0F);
               }
            }

            // Indicate that we've reached the end of the file
            reachedEOF = 1;
         }
      }

      // Process data that has been read.  Note that if the last
      // read operation returned no additional data, there is still
      // one one ciphertext block for us to process if this is a v0 file.
      if ((bytesRead > 0) || (aesHdr.version == 0x00))
      {
         // Advance the head of the buffer forward
         if (bytesRead > 0)
         {
            head += 16;
         }

         memcpy(buffer2, tail, 16);

         SharkSslSha256Ctx_append(&shaCtx, tail, 16);
         SharkSslAesCtx_decrypt(&aesCtx, tail, tail);

         // XOR plain text block with previous encrypted
         // output (i.e., use CBC)
         for(i=0; i<16; i++)
         {
            tail[i] ^= IV[i];
         }

         // Update the IV (CBC mode)
         memcpy(IV, buffer2, 16);

         // If this is the final block, then we may
         // write less than 16 octets
         n = ((!reachedEOF) ||
              (aesHdr.lastBlockSize == 0)) ? 16 : aesHdr.lastBlockSize;

         // Write the decrypted block
         if ((i = o->write(o->oWrite, tail, n)) != n)
         {
            return SHARKAESCRYPT_EWRITE;
         }
            
         // Move the tail of the ring buffer forward
         tail += 16;
         if (tail == (buffer+64))
         {
            tail = buffer;
         }
      }
   }

   // Verify that the HMAC is correct
   SharkSslSha256Ctx_finish(&shaCtx, digest);
   SharkSslSha256Ctx_constructor(&shaCtx);
   SharkSslSha256Ctx_append(&shaCtx, opad, 64);
   SharkSslSha256Ctx_append(&shaCtx, digest, 32);
   SharkSslSha256Ctx_finish(&shaCtx, digest);

   // Copy the HMAC read from the file into buffer2
   if (aesHdr.version == 0x00)
   {
      memcpy(buffer2, tail, 16);
      tail += 16;
      if (tail == (buffer + 64))
      {
         tail = buffer;
      }
      memcpy(buffer2+16, tail, 16);
   }
   else
   {
      memcpy(buffer2, tail+1, 15);
      tail += 16;
      if (tail == (buffer + 64))
      {
         tail = buffer;
      }
      memcpy(buffer2+15, tail, 16);
      tail += 16;
      if (tail == (buffer + 64))
      {
         tail = buffer;
      }
      memcpy(buffer2+31, tail, 1);
   }
   if(memcmp(digest, buffer2, 32))
   {
      return SHARKAESCRYPT_EPASSWORD;
   }
   return 0;
}


int SharkAESCrypt_decrypt(SharkAESCrypt* o, const char* passwd, int passwdLen,
                          sharkWchar_t* wbuf, int wbufLen)
{
   int wl;
   for(wl=0; passwdLen > 0 && wbufLen > wl; passwdLen--,passwd++,wl++)
   {
      unsigned char c = passwd[0];
      if (c < 0xc0)
      {
         wbuf[wl] = (sharkWchar_t)c;
      }
      else if (c < 0xe0)
      {
         if ((passwd[1] & 0xc0) == 0x80)
         {
            wbuf[wl] = ((c & 0x1f) << 6) | (passwd[1] & 0x3f);
            ++passwd;
         }
         else
            wbuf[wl] = c;
      }
      else
         return SHARKAESCRYPT_EWBUFLEN;
   }
   return SharkAESCrypt_decryptW(o, wbuf, wl);
}









/************************************************************************
                              TEST/EXAMPLE CODE
************************************************************************/
#ifdef TEST

static int SharkAESCrypt_read(void* fp, void* buf, int size, int* eof)
{
   int len = (int)fread(buf, 1, size, fp);
   *eof = feof(fp);
   return len;
}

static int SharkAESCrypt_write(void* o, void* buf, int size)
{
   return fwrite(buf, 1, size, o);
}

int main()
{
   SharkAESCrypt crypt;
   sharkWchar_t wbuf[100];
   int ecode;
   FILE* ifp = fopen("Readme.txt.aes","rb");
   FILE* ofp=fopen("out.txt","wb");
   char* passwd="apples";
   SharkAESCrypt_constructor(&crypt,
                             SharkAESCrypt_read, ifp,
                             SharkAESCrypt_write, ofp);
   ecode = SharkAESCrypt_decrypt(
      &crypt, passwd, strlen(passwd), wbuf, 100);
   if(ecode)
      printf("FAILED: %d\n",ecode);
   else if(fflush(ofp))
   {
      fprintf(stderr, "Error: Could not flush output file buffer\n");
      return -1;
   }
   fclose(ifp);
   fclose(ofp);

   printf("SUCCESS!\n");
   return 0;
}

#endif /* TEST */
