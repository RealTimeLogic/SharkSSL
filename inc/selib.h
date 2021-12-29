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
 *   $Id: selib.h 4871 2021-10-14 18:42:00Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2013 - 2020
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

#ifndef _selib_h
#define _selib_h

#include <SharkSSL.h>
#include <SharkSslEx.h>

/* secure version of selib */
#define MS_SEC


/** @addtogroup SharkExamples

@{
 */


/** @defgroup selib SharkSSL Socket Example Lib
    @ingroup SharkExamples

The SharkSSL Socket Example Lib (selib.h/selib.c) is a basic module
that wraps the transport agnostic SharkSSL functions for encoding and
decoding into functions that interface to TCP/IP socket calls.

![Socket Example Lib](@ref SharkSSL-selib.jpg)

In addition, the file selib.c includes wrappers for standard BSD
socket calls at the end of the file. TCP/IP stacks not using the BSD
API must define NO_BSD_SOCK and implement the following functions in a
separate file: #se_bind, #se_accept, #se_connect, #se_close,
#se_sockValid, #se_send, and #se_recv.

@{
*/

/** Use INFINITE_TMO for standard blocking call. */
#define INFINITE_TMO (~((U32)0))

#include <selibplat.h>

#ifndef XPRINTF
#if HOST_PLATFORM
#define XPRINTF 1
#else
#define XPRINTF 0
#endif
#endif

#include <string.h>
#if XPRINTF
#include <stdarg.h>
#endif

#ifndef SE_CTX
#define SeCtx void
#endif

/** Infinite wait time option for socket read functions.
 */
#ifndef NO_BSD_SOCK
/** The SOCKET object/handle is an 'int' when using a BSD compatible
    TCP/IP stack. Non BSD compatible TCP IP stacks must set the macro
    NO_BSD_SOCK and define the SOCKET object. See the header file
    selib.h for details.
*/
#define SOCKET int
#endif

#ifndef SOCKET_constructor
#define SOCKET_constructor(o, ctx) (void)ctx,memset(o,0,sizeof(SOCKET))
#endif


#ifdef __cplusplus
extern "C" {
#endif

/** Disable/enable the trace when XPRINTF is defined
 */ 
#if XPRINTF
void se_disableTrace(int disable);
#else
#define se_disableTrace(disable)
#endif


/** Print the selected ciphersuite 
 */
#if XPRINTF && SHARKSSL_ENABLE_INFO_API
void printCiphersuite(U16 cipherSuite);
#else
#define printCiphersuite(notused)
#endif


/**
   Performs the initial SSL handshaking using an asymmetric cipher in
   order to establish cipher settings and a shared key for the session.

   The function also validates the server's certificate and compares
   the commonName provided in argument 3 with the common name in the
   certificate, if commonName is provided (not NULL). The domain name
   comparison works with and without the clone certificate API
   (#SHARKSSL_ENABLE_CLONE_CERTINFO).

   <b>Note:</b> the function only performs basic certificate domain
   name comparison and can only be used with server certificates that
   does not include Subject Alternative Names (SAN Certificate). Use
   the more advanced function #SharkSslCon_trusted for certificate
   trust management if the server uses a SAN Certificate.

   \param s the SharkSslCon object.
   \param sock the SOCKET object.
   \param timeout in milliseconds. The timeout can be set to #INFINITE_TMO.
   \param commonName is optional and is used for certificate domain
   name verification.

   \return

   - A negative value on error. The negative value is an inverted
     #SharkSslCon_RetVal value.
   - Zero on timeout.
   - The return value is #SharkSslConTrust for any return value
     greater than zero.
     */
   int seSec_handshake(
      SharkSslCon *s, SOCKET* sock, U32 timeout, const char* commonName);

/** Read data from socket stream and decode the encrypted data. The
    buffer is managed by SharkSSL and the data returned is valid until
    the next SharkSSL call. This function blocks until data is
    available or until 'timeout' milliseconds.

    \param s the SharkSslCon object.
    \param sock the SOCKET object.
    \param buf is a pointer set to the SharkSSL receive buffer offset to
    the WebSocket payload data.
    \param timeout in milliseconds. The timeout can be set to #INFINITE_TMO.
    \return The function returns the number of bytes available in
    'buf' on success. The function returns 0 on timeout and a negative
    value on error.
 */

int seSec_read(SharkSslCon *s,SOCKET* sock,U8 **buf,U32 timeout);

/** Encrypts and sends encrypted data to the connected peer side.
    \return Zero on success or a negative value on error.
*/
int seSec_write(SharkSslCon *s, SOCKET* sock, U8* buf, int maxLen);

/** Initializes a SOCKET object connected to a remote host/address at
 * a given port.
 \return  Zero on success.
   Error codes returned:
   \li \c -1 Cannot create socket: Fatal
   \li \c -2 Cannot resolve 'address'
   \li \c -3 Cannot connect
*/
int se_connect(SOCKET* sock, const char* address, U16 port);

/** Initializes a SOCKET object bound to a local port, ready to accept
    client connections.
 \return Zero on success.
   Error codes returned:
   \li \c -1 Cannot create socket: Fatal
   \li \c -2 Cannot listen: Fatal
   \li \c -3 Cannot bind: socket in use
 */
int se_bind(SOCKET* sock, U16 port);

/** Waits for remote connections on the server SOCKET object
   'listenSock', initialized by function se_bind, and initializes
   socket object 'outSock' to represent the new connection.

   \return
   \li \c 1 Success
   \li \c 0 timeout
   \li \c -1 error
*/
int se_accept(SOCKET** listenSock, U32 timeout, SOCKET** outSock);

/** Close a connected socket connection.
 */
void se_close(SOCKET* sock);

/** Returns TRUE if socket is valid (connected).
 */
int se_sockValid(SOCKET* sock);

/** Sends data to the connected peer.
 */
S32 se_send(SOCKET* sock, const void* buf, U32 len);

/** Waits for data sent by peer.

    \param sock the SOCKET object.
    \param buf is the data to send.
    \param len is the 'buf' length.
    \param timeout in milliseconds. The timeout can be set to #INFINITE_TMO.
    \returns the length of the data read, zero on timeout, or a
    negative value on error.
 */
S32 se_recv(SOCKET* sock, void* buf, U32 len, U32 timeout);


/* Macro function designed for IPv4
   sock: a pointer to SOCKET
   buf: a buf large enough to hold 4 bytes
   status: int pointer: out value is negative on error and 4 (len) on success
*/
#ifndef se_getSockName
#define se_getSockName(sock, buf, status) do {                  \
   struct sockaddr_in in; int size=sizeof(struct sockaddr_in);      \
   *(status) = getsockname(*(sock), (struct sockaddr *)&in, &size); \
   memcpy((buf), &in.sin_addr.s_addr, 4);                           \
   if(*(status) == 0) *(status) = 4;                                \
} while(0)
#endif

#if XPRINTF == 1
/** The macro xprintf expands to function _xprintf if the code is
    compiled with XPRINTF set to 1.
    \param data is standard printf arguments enclosed in parenthesis;
    thus you must use double parenthesis when using macro xprintf.
*/
#define xprintf(data) _xprintf data
/** The example code and macro xprintf requires this function when the
    code is compiled with macro XPRINTF set to 1.
    \param fmt the format string.
    \param ... variable arguments.
*/
#ifndef _xprintf  /* to handle #define _xprintf printf */
void _xprintf(const char* fmt, ...);
#endif
#else
#ifndef xprintf
#define xprintf(data)
#endif
#endif

/** Main entry for all example programs */
void mainTask(SeCtx* ctx);

#ifdef __cplusplus
}
#endif


/** @} */ /* end group selib */
/** @} */ /* end group Examples */

#endif
