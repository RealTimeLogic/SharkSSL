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
 *   $Id: ZipFileSystem.c 4125 2017-12-15 17:59:48Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2013 - 2018
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

#include "ZipFileSystem.h"


static int
sendPage(ZipFileSystem* zfs, ZipFileHeader* zfh, MST* mst, int comp)
{
   static const U8 egz[] = {"\r\nContent-Encoding: gzip"};
   GzipTrailer* gt;
   U8* sptr;
   U32 fsize = comp ? ZipFileHeader_getCompressedSize(zfh) :
      ZipFileHeader_getUncompressedSize(zfh);
   int sblen=MST_getSendBufSize(mst);
   sptr = msRespCT(
      MST_getSendBufPtr(mst), &sblen, comp ? fsize+18 : fsize, egz);
   if(sptr && sblen > 10)
   {
      ZipFileInfo zfi;
      int x;
      ZipFileInfo_constructor(&zfi, zfh, (U8*)0);
      if(comp)
      {
         if(initGZipHeader(&zfi, (GzipHeader*)sptr))
            return MS_ERR_ENCRYPTED_ZIP;
         sptr+=10;
         sblen-=10;
      }
      while(fsize)
      {
         int chunkz;
         if(!sblen)
         {
            sblen=MST_getSendBufSize(mst);
            if(MST_write(mst, 0, sblen) < 0)
               return MS_ERR_WRITE;
            sptr=MST_getSendBufPtr(mst);
         }
         chunkz = (int)(fsize > (U32)sblen ? sblen : fsize);
         if(CspReader_read(zfs->reader, sptr, zfi.dataOffset, chunkz, FALSE))
            return MS_ERR_FILE_IO;
         fsize -= chunkz;
         sblen -= chunkz;
         zfi.dataOffset += chunkz;
         sptr += chunkz;
      }
      if(comp)
      {
         if(sblen < 8)
         {
            if(MST_write(mst,0,sptr-MST_getSendBufPtr(mst)) < 0)
               return MS_ERR_WRITE;
            sptr=MST_getSendBufPtr(mst);
         }
         gt = (GzipTrailer*)sptr;
         x = ZipFileInfo_getCrc32LittleEndian(&zfi);
         memcpy(gt->crc, &x, 4);
         x = ZipFileInfo_getUncompressedSizeLittleEndian(&zfi);
         memcpy(gt->uncompressedSize, &x, 4);
         sptr += 8;
      }
      if(sptr-MST_getSendBufPtr(mst) > 0)
      {
         return MST_write(mst,0,sptr-MST_getSendBufPtr(mst)) < 0 ? MS_ERR_WRITE : 1;
      }
      return 1;
   }
   return MS_ERR_ALLOC;
}


static int
fetchZipPage(void* hndl, MST* mst, U8* path)
{
   CentralDirIterator iter;
   U8* ptr=0;
   ZipFileSystem* zfs = (ZipFileSystem*)hndl;
   CentralDirIterator_constructor(&iter, &zfs->zc);
   if(*path == '/') path++;
   if(!*path || ((ptr=(U8*)strrchr((char*)path, '/')) !=0 && !ptr[1]))
   {
      ptr=MST_getSendBufPtr(mst);
      strcpy((char*)ptr, (char*)path);
      strcat((char*)ptr, "index.html");
      path=ptr;
   }
   do 
   {
      ZipFileHeader* zfh = CentralDirIterator_getElement(&iter);
      if( ! zfh )
      {
         return CentralDirIterator_getECode(&iter);
      }
      if( ! ZipFileHeader_isDirectory(zfh) )
      {
         const char* pathName = ZipFileHeader_getFn(zfh);
         int fnLen = ZipFileHeader_getFnLen(zfh);
         if(*path == *pathName)
         {
            const U8* ptr = path+1;
            while(--fnLen && *++pathName == *ptr++);
            if( ! fnLen && !*ptr )
            {
               switch(ZipFileHeader_getComprMethod(zfh))
               {
                  case ZipComprMethod_Stored:
                     return sendPage(zfs,zfh,mst,FALSE);
                  case ZipComprMethod_Deflated:
                     return sendPage(zfs,zfh,mst,TRUE);
                  default:
                     return ZipErr_Compression;
               }
            }
         }
      }
   } while(CentralDirIterator_nextElement(&iter)); 
   return 0;
}


MSFetchPage
msInitZipFileSystem(ZipFileSystem* zfs, ZipReader* zr)
{
   ZipContainer_constructor(&zfs->zc,zr,zfs->buf,sizeof(zfs->buf));
   zfs->reader=zr;
   return fetchZipPage;
}
