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
 *   $Id: WsClientLib.h 4769 2021-06-11 17:29:36Z gianluca $
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
 */

#ifndef _WsClientLib_h
#define _WsClientLib_h


#include "selib.h"

/** @addtogroup WsClientLib
@{
*/

/** @defgroup WebSocketOpcodes WebSocket Opcodes
    @ingroup WsClientLib

    \brief WebSocket Opcodes

    RFC6455 Page 29 - Opcode -  4 bits

    WebSocket Opcodes with FIN=1. We do not manage WebSocket fragments
    (FIN=0/1) since it is rarely used and the complexity is not
    something you want in a tiny device.
@{
*/

/** Text */
#define WSOP_Text   0x81
/** Binary */
#define WSOP_Binary 0x82
/** RFC6455 5.5 -  Control Frame - Close */
#define WSOP_Close  0x88
/** RFC6455 5.5 -  Control Frame - Ping */
#define WSOP_Ping   0x89
/** RFC6455 5.5 - Control Frame - Pong */
#define WSOP_Pong   0x8A

/** @} */ /* end group WebSocketOpcodes */ 



/** The WebSocket protocol is frame based and the following struct keeps state
    information for #wscRead.
*/
typedef struct
{
   /** The WebSocket frame length */
   int frameLen;
   /** Read frame data until: frameLen - bytesRead = 0 */
   int bytesRead;

   U8* overflowPtr; /* Set if: consumed more data from stream than frame len */ 
   int overflowLen; /* overflowPtr len is used internally in wsRawRead */
   int frameHeaderIx; /* Cursor used when reading frameHeader from socket */
   U8 frameHeader[4]; /*[0] FIN+opcode, [1] Payload len, [2-3] Ext payload len*/

   /** Set when the read function returns due to a timeout. */
   U8 isTimeout;
} WscReadState;


#ifdef __cplusplus
extern "C" {
#endif


/** Upgrades (morphs) an HTTPS request/response pair to a WebSocket
  connection. Sends the HTTP request header to the server and
  validates the server's HTTP response header -- the function
  simulates a very basic HTTP client library. The function is designed
  to be as simple as possible and the code is, for this reason, making
  a few assumptions that could fail when used with a non traditional
  HTTP server. Read the comments in the source code file WsClientLib.c
  if you should experience problems.

  \param wss the WebSocket protocol state information is stored in this
  structure. All wss attributes must be initialized to zero before
  calling this function for the first time.
  \param s the SharkSslCon object
  \param sock the SOCKET object
  \param tmo in milliseconds. The timeout can be set to #INFINITE_TMO.
  \param host is the server's host name
  \param path is the path component of the wss URL and the path must
  be to the server's WebSocket service.
  \param origin some WebSocket server's may require an origin URL:
  http://tools.ietf.org/html/rfc6455#section-10.2. Set the parameter
  to NULL if it's not required by the server. The Origin header should
  only be required by a server when the request is sent from a
  browser.
   \return Zero success.
 */
int wscProtocolHandshake(WscReadState* wss,SharkSslCon *s,SOCKET* sock,U32 tmo,
                         const char* host,const char* path,const char* origin);


/** Sends binary data to server.

    The function sets the WS frame header's opcode to binary. The WS
    protocol supports two payload frame types, UTF8 and binary (RFC6455:
    5.6 Data Frames). We are assuming that you will be using the binary
    protocol for all data exchange.
*/
int wscSendBin(SharkSslCon *s, SOCKET* sock, U8* buf, int len);

/** Sends a WebSocket control frame.

    The code is used internally by the WebSocket functions. You can also use
    this function to send your own control frames such as #WSOP_Ping.
 
    See RFC6455: 5.5.  Control Frames
 */
int wscSendCtrl(
   SharkSslCon *s,SOCKET* sock,U8 opCode, const U8* buf,int len);

/** Sends a WebSocket close control frame to the server and closes the
    connection.

    \param s the SharkSslCon object.
    \param sock the SOCKET object.

    \param statusCode is a <a target="_blank" href=
    "http://tools.ietf.org/html/rfc6455#section-7.4">
    WebSocket status code</a>.
 */
int wscClose(SharkSslCon *s, SOCKET* sock, int statusCode);


/** Wait for WebSocket frames sent by the server. The function
    returns when data is available or on timeout. The function returns
    zero on timeout, but the peer can send zero length frames so you must
    verify that it is a timeout by checking the status of
    WscReadState#isTimeout.
  
    The WebSocket protocol is frame based, but the function can return
    a fragment before the complete WebSocket frame is received if the frame
    sent by the peer is larger than the SharkSSL receive buffer. The
    frame length is returned in WscReadState#frameLen and the data
    consumed thus far is returned in WscReadState#bytesRead. The
    complete frame is consumed when frameLen == bytesRead.

    \param wss is the WebSocket read state.

    \param s the SharkSslCon object.
    \param sock the SOCKET object.

    \param buf is a pointer set to the SharkSSL receive buffer offset to
    the start of the WebSocket payload data.

    \param timeout in milliseconds. The timeout can be set to #INFINITE_TMO.

    \return The payload data length or zero for zero length frames and
    timeout. The function returns a negative value on error.
*/
int wscRead(
   WscReadState* wss, SharkSslCon *s,SOCKET* sock, U8 **buf, U32 timeout);

#ifdef __cplusplus
}
#endif

/** @} */ /* end group WsClientLib */ 

#endif
