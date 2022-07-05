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
 *   PROGRAM MODULE
 *
 *   $Id: proxy.h 5076 2022-02-10 16:59:48Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2016
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

#ifndef _proxy_h
#define _proxy_h

#define E_PROXY_AUTH -1000 /* Authentication required or wrong credentials */
#define E_PROXY_GENERAL -1001 /* general SOCKS server failure */
#define E_PROXY_NOT_ALLOWED -1002 /* connection not allowed by ruleset */
#define E_PROXY_NETWORK -1003 /* Network unreachable */
#define E_PROXY_HOST -1004 /* Host unreachable */
#define E_PROXY_REFUSED -1005 /* Connection refused */
#define E_PROXY_TTL -1006 /* TTL expired */
#define E_PROXY_COMMAND_NOT_SUP -1007 /* Command not supported */
#define E_PROXY_ADDRESS_NOT_SUP -1008 /* Address type not supported */
#define E_PROXY_NOT_COMPATIBLE -1009 /* Not a supported SOCKS version */
#define E_PROXY_UNKNOWN -1010 /* Unkown socks err */
#define E_PROXY_CLOSED -1011 /* Socket closed while communicating with proxy */
#define E_PROXY_CANNOTCONNECT -1012 /* Cannot resolve or connect to proxy */

struct Proxy;
struct ProxyArgs;

typedef int (*ProxyConnect)(struct Proxy* o, struct ProxyArgs* args);

typedef struct Proxy
{
   ProxyConnect connect;
   const char* proxyUserPass;
   const char* proxyName;
   U16 proxyPortNo;
} Proxy;

void Proxy_constructor(Proxy* o, const char* proxyName,
                          U16 proxyPortNo, const char* proxyUserPass,
                          int socks);

#endif
