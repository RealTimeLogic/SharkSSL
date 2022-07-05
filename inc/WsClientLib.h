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
 *   $Id: WsClientLib.h 5120 2022-03-24 15:25:13Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2014 - 2022
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

#ifdef _DOXYGEN
/* For documentation purposes */
#define WSC_DUAL
#endif

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



/** WebSocket Client State Information, initialize using: WscState
    wss={0}; however, several members must be set.
*/
typedef struct
{
#ifdef WSC_DUAL
   /** The receive buffer must be set when not in secure mode */
   U8* recBuf;
   /** The send buffer must be set when not in secure mode */
   U8* sendBuf;
   /** The receive buffer length must be set to the recBuf length */
   int recBufLen;
   /** The send buffer length must be set to the sendBuf length */
   int sendBufLen;
#endif
   /** The SharkSslCon object must be set when using secure mode */
   SharkSslCon* scon;
   /** The SOCKET object must be set */
   SOCKET* sock;
   /** The WebSocket frame length */
   int frameLen;
   /** Read frame data until: frameLen - bytesRead = 0 */
   int bytesRead;

   /* Begin private */
   U8* overflowPtr; /* Set if: consumed more data from stream than frame len */ 
   int overflowLen; /* overflowPtr len is used internally in wsRawRead */
   int frameHeaderIx; /* Cursor used when reading frameHeader from socket */
   U8 frameHeader[4]; /*[0] FIN+opcode, [1] Payload len, [2-3] Ext payload len*/
   /* End private */

   /** Set when the read function returns due to a timeout. */
   U8 isTimeout;
} WscState;


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

  \param wss the WebSocket Client State information is stored in
  this structure. All WscState members must be initially initialized to
  zero and then the following members must be set: #WscState::scon,
  #WscState::sock. When in non secure mode, the following members must
  be set: #WscState::sock, #WscState::recBuf, #WscState::sendBuf,
  #WscState::recBufLen, #WscState::sendBufLen.

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
int wscProtocolHandshake(WscState* wss,U32 tmo, const char* host,
                         const char* path,const char* origin);


/** Sends binary data to server.

    The function sets the WS frame header's opcode to binary. The WS
    protocol supports two payload frame types, UTF8 and binary (RFC6455:
    5.6 Data Frames). We are assuming that you will be using the binary
    protocol for all data exchange.
*/
int wscSendBin(WscState* wss, U8* buf, int len);

/** Sends a WebSocket control frame.

    The code is used internally by the WebSocket functions. You can also use
    this function to send your own control frames such as #WSOP_Ping.
 
    See RFC6455: 5.5.  Control Frames
 */
int wscSendCtrl(WscState* wss, U8 opCode, const U8* buf,int len);

/** Sends a WebSocket close control frame to the server and closes the
    connection.
    \param wss is the WebSocket state.
    \param statusCode is a <a target="_blank" href=
    "http://tools.ietf.org/html/rfc6455#section-7.4">
    WebSocket status code</a>.
 */
int wscClose(WscState* wss, int statusCode);


/** Wait for WebSocket frames sent by the server. The function
    returns when data is available or on timeout. The function returns
    zero on timeout, but the peer can send zero length frames so you must
    verify that it is a timeout by checking the status of
    WscState#isTimeout.
  
    The WebSocket protocol is frame based, but the function can return
    a fragment before the complete WebSocket frame is received if the frame
    sent by the peer is larger than the SharkSSL receive buffer. The
    frame length is returned in WscState#frameLen and the data
    consumed thus far is returned in WscState#bytesRead. The
    complete frame is consumed when frameLen == bytesRead.

    \param wss is the WebSocket state.

    \param buf is a pointer set to the SharkSSL receive buffer offset to
    the start of the WebSocket payload data.

    \param timeout in milliseconds. The timeout can be set to #INFINITE_TMO.

    \return The payload data length or zero for zero length frames and
    timeout. The function returns a negative value on error.
*/
int wscRead(WscState* wss, U8 **buf, U32 timeout);

#ifdef __cplusplus
}
#endif

/** @} */ /* end group WsClientLib */ 

#endif
