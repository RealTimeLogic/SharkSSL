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
 *			      HEADER
 *
 *   $Id: ZipFileSystem.h 4769 2021-06-11 17:29:36Z gianluca $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2013
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
 *  
 */

#ifndef _ZipFileSystem_h
#define _ZipFileSystem_h


#include <ZipFileIterator.h>
#include "MSLib.h"


/** @defgroup ZipFileSystem Minnow Server ZIP File System Plugin
    @ingroup MSLib

    \brief The ZipFileSystem is an optional plugin that requires the
    <a target="_blank"
    href="http://realtimelogic.com/products/barracuda-web-server/">
    Barracuda Web Server</a> ZipFileIterator plugin.

    The optional ZipFileSystem plugin for the Minnow Server lets you
    store the web presentation logic compressed in the
    device. Compressed web applications are typically only one-third
    of the original size. The compressed web pages are not
    uncompressed on the device. The web pages are extracted from
    within the ZIP file and sent "as is" to the browser. All modern
    browsers uncompress "compressed" data received from the servers.

    The optional ZipFileSystem plugin is available at an additional
    cost.

    The ZipFileSystem is a small plugin that includes the classes
    ZipContainer, CentralDirIterator, and ZipFileInfo. The
    complete ZipFileSystem does not come delivered with SharkSSL. 
@{
*/

/** The ZipFileSystem handle. See msInitZipFileSystem for more information.
 */
typedef struct {
   ZipReader* reader;
   ZipContainer zc;
   U8 buf[256];
} ZipFileSystem;

#ifdef __cplusplus
extern "C" {
#endif

/**
Initializes the ZIP File System and returns a WsFetchPage callback function.

\param zfs the ZipFileSystem to initialize

\param zipReader a device driver (interface object) between the Zip
File System and the ZIP file. The example below extern declares a
function that returns a ZipReader object. This function is typically
created automatically by our bin2c tool which converts a ZIP file into
a C array. The bin2c tool also generates a ZipReader object
automatically. You can also create your own ZipReader driver object if
you, for example, want to keep the ZIP file separate from your firmware.

<b>Example code:</b>
\code
extern ZipReader* getZipReader(void);
.
.
WssProtocolHandshake wph={0};
ZipFileSystem zfs;
wph.fetchPage = msInitZipFileSystem(&zfs, getZipReader());
wph.fetchPageHndl=&zfs;
\endcode

The following example shows a code snippet from a ZIP file converted
to C data by running the bin2c tool as follows:<br>bin2c -z getZipReader
www.zip www.c

\code
static const U8 zipfileData[] = { ZIP FILE CONTENT HERE };

//ZIP device driver function
int readFromZipFile(CspReader* o,void* data,U32 offset,U32 size,int blockStart)
{
   memcpy(data, zipfileData+offset, size); // Copy ZIP content at offset pos
   return 0; // OK
}

// Init and return a ZIP device driver
ZipReader* getZipReader(void)
{
   static ZipReader zipReader;
   ZipReader_constructor(&zipReader,readFromZipFile,sizeof(zipfileData));
   CspReader_setIsValid(&zipReader);
   return &zipReader;
}
\endcode
 */
MSFetchPage msInitZipFileSystem(ZipFileSystem* zfs, ZipReader* zipReader);

#ifdef __cplusplus
}
#endif


/** @} */ /* end group ZipFileSystem */ 

#endif
