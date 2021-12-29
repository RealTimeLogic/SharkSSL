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
 *			      HEADER
 *
 *   $Id: HttpServer.h 4769 2021-06-11 17:29:36Z gianluca $
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
 *
 *  
 *  Minnow Server: SharkSSL WebSocket Server
 */

/* Barracuda Server stub header used by the Zip File System */

#ifndef _HttpServer_h
#define _HttpServer_h

#define SharkSslStandalone
#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

#ifndef BA_API
#define BA_API
#endif

#define baFatalE(ecode1,ecode2) baAssert(0)
#define FE_INVALID_CSPREADER 1


#include <selib.h>


#endif
