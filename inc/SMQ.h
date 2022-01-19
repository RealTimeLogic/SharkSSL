/*
 *     ____             _________                __                _     
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__  
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/  
 *                                                       /____/          
 *
 ****************************************************************************
 *            HEADER
 *
 *   This file is part of SharkMQ:
 *            https://realtimelogic.com/products/sharkssl/SharkMQ/
 *
 *   $Id: SMQ.h 5029 2022-01-16 21:32:09Z wini $
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
 *               http://sharkssl.com
 ****************************************************************************
 *
 */

#ifndef __SharkMQ_h
#define __SharkMQ_h

#define SMQ_SEC

#include "selib.h"

#ifdef ENABLE_PROXY
#define ENABLE_HTTPS_PROXY
#define ENABLE_SOCKS_PROXY
#endif

#if defined(ENABLE_HTTPS_PROXY) || defined(ENABLE_SOCKS_PROXY)
#ifndef ENABLE_PROXY
#define ENABLE_PROXY
#endif
#include "proxy.h"
#endif


/** @addtogroup SMQLib
@{
*/

/** \defgroup SharkMQErrorCodes Error codes returned by function SharkMQ_getMessage
\ingroup SharkMQ
\anchor SharkMQErrorCodes Error codes returned by function #SharkMQ_getMessage
@{
*/

/** The buffer provided in SharkMQ_constructor is not sufficiently large.
 */
#define SMQE_BUF_OVERFLOW    -10000

/** Subscribe, Create, or Createsub denied.
 */
#define SMQE_ONACK_DENIED    -10000

/** The URL provided is invalid.
 */
#define SMQE_INVALID_URL     -10002 

/** TCP connection error
 */
#define SMQE_PROTOCOL_ERROR  -10003 

/** Server sent a disconnect message
 */
#define SMQE_DISCONNECT      -10004


/** No PONG response to PING: timeout
 */
#define SMQE_PONGTIMEOUT     -10005

/** @} */ /* end SharkMQErrorCodes */


/** \defgroup SharkMQRespCodes Response codes returned by function SharkMQ_getMessage
\ingroup SharkMQ
\anchor SharkMQRespCodes Response codes returned by function #SharkMQ_getMessage
@{
*/

/** Asynchronous #SharkMQ_subscribe response message received via
    #SharkMQ_getMessage.

    \li SharkMQ::ptid is set to the subscribed Topic ID.
    \li SharkMQ::status is set to zero (0) if the request was accepted and
    a negative value if the request was denied.
    \li the 'msg' out parameter in #SharkMQ_getMessage is set to the optional
    server's authentication response message if the request was
    denied.
 */
#define SMQ_SUBACK           -20000

/** Asynchronous #SharkMQ_create response message received via
    #SharkMQ_getMessage.

    \li SharkMQ::ptid is set to the created Topic ID.
    \li SharkMQ::status is set to zero (0) if the request was accepted and
    a negative value if the request was denied.
    \li the 'msg' out parameter in #SharkMQ_getMessage is set to the optional
    server's authentication response message if the request was
    denied.
 */
#define SMQ_CREATEACK        -20001

/** Asynchronous #SharkMQ_createsub response message received via
    #SharkMQ_getMessage.

    \li SharkMQ::ptid is set to the created Subtopic ID.
    \li SharkMQ::status is set to zero (0) if the request was accepted and
    a negative value if the request was denied.
 */
#define SMQ_CREATESUBACK     -20002

/** Change notification event (from observed tid). Observe events are
 * initiated via #SharkMQ_observe.

    \li SharkMQ::ptid is set to the observed Topic ID.
    \li SharkMQ::status is set to the number of clients subscribed to the topic.
 */
#define SMQ_SUBCHANGE        -20003

 /** The SharkMQ_getMessage call timed out.
  */
#define SMQ_TIMEOUT         -20004

/** @} */ /* end SharkMQRespCodes */


#define SMQSTR(str) str, (sizeof(str)-1)

/** SharkMQ structure.
 */
typedef struct SharkMQ
{
   SOCKET sock;
   SharkSslCon* scon;

   U8* sharkBuf; /* SharkSSL read buffer is set when we have data from Shark */
   U8* buf; /* buffer provided by user via constructor */

   U16 sharkBufLen; /* TLS frame len */
   U16 sharkBufIx; /* Current read index in sharkBuf */

   U16 bufLen; /* User buffer total len */
   U16 bufIx; /* Current read index in user buffer */


   /** Timeout in milliseconds to wait in functions waiting for server
       data
   */
   U32 timeout;
   S32 pingTmoCounter,pingTmo;
   U32 clientTid; /**< Client's unique topic ID */
   U32 tid;  /**< Topic: set when receiving MSG_PUBLISH from broker */
   U32 ptid; /**< Publisher's tid: Set when receiving MSG_PUBLISH from broker */
   U32 subtid; /**< Sub-tid: set when receiving MSG_PUBLISH from broker */
   int status; /**< Last known error code */
   U16 sendBufIx;
   U16 frameLen; /**< The SMQ frame size for the incomming data */
   /** Read frame data using SharkMQ_getMessage until: frameLen-bytesRead = 0 */
   U16 bytesRead;
#ifdef ENABLE_PROXY
   Proxy* proxy;
#endif

#ifdef __cplusplus

/** Create a secure SMQ client instance.
    \see SharkMQ_constructor
*/
   SharkMQ(U8* buf, U16 bufLen);


/** Initiate the SMQ server connection. 
    \see SharkMQ_init
*/
   int init(SharkSslCon* scon, const char* url, U32* rnd);

/** Connect/establish a persistent SMQ connection.
    \see SharkMQ_connect
*/
   int connect(const char* uid, int uidLen, const char* credentials,
               U8 credLen, const char* info, int infoLen,
               U16 maxTlsFrameSize);


/** Gracefully close the connection. 
    \see SharkMQ_disconnect
*/
   void disconnect();


/** Terminate an SMQ instance.
    \see SharkMQ_destructor
*/
   ~SharkMQ();


/** Create a topic an fetch the topic ID (tid).
    \see SharkMQ_create
*/
   int create(const char* topic);


/** Create a sub-topic and fetch the subtopic ID.
    \see SMQ:createsub
*/
   int createsub(const char* subtopic);


/** The response to SharkMQ_subscribe is asynchronous and returned as status
    #SMQ_SUBACK via #SharkMQ_getMessage.
    \see SharkMQ_subscribe
*/
   int subscribe(const char* topic);


/** Requests the broker to unsubscribe the server from a topic.
    \see SharkMQ_unsubscribe
*/
   int unsubscribe(U32 tid);


/** Publish messages to a topic and optionally to a sub-topic. Topic
    name must have previosly been been resolved by #SharkMQ_create and
    sub-topic should preferably have been created by #SharkMQ_createsub.
    \see SharkMQ_publish
*/
   int publish(const void* data, int len, U32 tid, U32 subtid);


/** Publish a message in chunks and request the broker to assemble the
    message before publishing to the subscriber(s).
    \see SharkMQ_wrtstr
*/
   int wrtstr(const char* str);

/** Publish a message in chunks and request the broker to assemble the
    message before publishing to the subscriber(s).
    \see SharkMQ_write
*/
   int write( const void* data, int len);

/** Flush the internal buffer and request the broker to assemble all
    stored fragments as one message.
    \see SharkMQ_pubflush
*/
   int pubflush(U32 tid, U32 subtid);


/** Request the broker to provide change notification events when the
    number of subscribers to a specific topic changes. Ephemeral topic
    IDs can also be observed.
    \see SharkMQ_observe
*/
   int observe(U32 tid);


/** Stop receiving change notifications for a topic ID or ephemeral topic ID.
    \see SharkMQ_unobserve
*/
   int unobserve(U32 tid);


/** Wait for messages sent from the broker.
    \see SharkMQ_getMessage
*/
   int getMessage(U8** msg);


/** Returns the message size, which is SMQ::frameLen - 15.
    \see SharkMQ_getMsgSize
*/
   int getMsgSize();

#endif

} SharkMQ;

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup SMQLib_C C API
\ingroup SMQLib
@{
*/


/** Create a secure SMQ client instance.
    \param o Uninitialized data of size sizeof(SharkMQ).
    \param buf is used for internal management and must not be less
    than 127 bytes and not smaller than the largest control
    frame. Function SharkMQ_getMessage will return #SMQE_BUF_OVERFLOW if
    the buffer is not sufficiently large.
    \param bufLen buffer length.
 */
void SharkMQ_constructor(SharkMQ* o, U8* buf, U16 bufLen);

#define SharkMQ_setProxy(o, proxyMA) (o)->proxy=proxyMA

/** Bare metal configuration. This macro must be called immediately
    after calling the constructor on bare metal systems.
    \param o the #SharkMQ instance.
    \param ctx an #SeCtx instance.
 */
#define SharkMQ_setCtx(o, ctx) SOCKET_constructor(&(o)->sock, ctx)


/** Zero copy API: Get start of send buffer.
    Returns SharkSslCon_getEncBufPtr() + 15.
    Use with #SharkMQ_publish and set "data argument"=NULL.
    \param o the #SharkMQ instance.
    \returns pointer to start of SMQ buffer area
 */
#define SharkMQ_getSendBufPtr(o) (SharkSslCon_getEncBufPtr((o)->scon) + 15)

/** Zero copy API: Get max buffer length.
    Returns SharkSslCon_getEncBufSize - 15.
    Use with #SharkMQ_getSendBufPtr.
    \param o the #SharkMQ instance.
    \returns SMQ send buffer size
 */
#define SharkMQ_getSendBufSize(o) (SharkSslCon_getEncBufSize((o)->scon) - 15)


/** Initiate the SharkMQ server connection. The connection phase is
    divided into two steps: (1) initiating and (2) connecting via
    SharkMQ_connect.
    \param o the SharkMQ instance.
    \param scon SharkSslCon instance created by calling #SharkSsl_createCon.
    \param url is a URL that starts with http:// and this URL
    must be to a server resource that initiates an SMQ connection.
    \param rnd (out param) a random number created by the server. This
    number can be used for securing hash based password encryption.
    \return

   - The return value is #SharkSslConTrust for any return value
     greater than zero.
   - A negative return value is one of:  an error code from #se_connect, or
    a [SMQ error code](\ref SharkMQErrorCodes).

    A return value greater than zero means that a connection is
    established, but the connection is not trusted unless the return
    value is #SharkSslConTrust_CertCn.

    On success, SharkMQ::buf is set to the IP address of the client as
    seen by the broker.
 */
int SharkMQ_init(SharkMQ* o, SharkSslCon* scon, const char* url, U32* rnd);

/** Connect/establish a persistent SMQ connection. The connection
    phase is divided into two steps: (1) initiating via SharkMQ_init and (2)
    connecting.
    \param o the SharkMQ instance.
    \param uid a universally unique client identifier (uid) must be
    unique across all clients connecting to the same broker
    instance. The uid is preferably a stringified version of the
    client's Ethernet MAC address.
    \param uidLen the uid length.
    \param credentials provide credentials if required by the broker instance.
    \param credLen credentials length.
    \param info a string that provides information to optional server
    code interacting with the broker. This string is also passed into
    the optional broker's authentication callback function.
    \param infoLen length of info.
    \param maxTlsFrameSize - Request server limits TLS frame size to
     this size. SMQ messages sent by server larger than this size is
     split up into smaller chunks.  The value zero means don't care.
    \returns 0 on success, error code from TCP/IP stack,
    [SimpleMQ error code](\ref SharkMQErrorCodes), or one of the
    following error codes from the broker:

    \li 0x01	Connection Refused: unacceptable protocol version
    \li 0x02	Connection Refused: server unavailable
    \li 0x03	Connection Refused: Incorrect credentials
    \li 0x04	Connection Refused: Client certificate required
    \li 0x05	Connection Refused: Client certificate not accepted
    \li 0x06	Connection Refused: Access denied

    The broker may optionally send a human readable string in addition
    to the above broker produced error codes. This string is avaiable
    via SharkMQ::buf.
 */
int SharkMQ_connect(SharkMQ* o, const char* uid, int uidLen,
                    const char* credentials, U8 credLen,
                    const char* info, int infoLen,
                    U16 maxTlsFrameSize);


/** Gracefully close the connection. You cannot publish any messages
    after calling this method.
    \param o the SharkMQ instance.
 */
void SharkMQ_disconnect(SharkMQ* o);


/** Terminate an SMQ instance.
    \param o the SharkMQ instance.
 */
void SharkMQ_destructor(SharkMQ* o);


/** Create a topic an fetch the topic ID (tid). The SharkMQ protocol is
    optimized and does not directly use a string when publishing, but a
    number. The server randomly a creates 32 bit number and
    persistently stores the topic name and number.

    The response to SharkMQ_create is asynchronous and returned as status
    #SMQ_CREATEACK via #SharkMQ_getMessage.

    \param o the SharkMQ instance.
    \param topic the topic name where you plan on publishing messages.
 */
int SharkMQ_create(SharkMQ* o, const char* topic);


/** Create a sub-topic and fetch the subtopic ID.

    The response to SharkMQ_subscribe is asynchronous and returned as status
    #SMQ_CREATESUBACK via #SharkMQ_getMessage.

    \param o the SharkMQ instance.
    \param subtopic the sub-topic name you want registered.
 */
int SharkMQ_createsub(SharkMQ* o, const char* subtopic);


/** Subscribe to topic.

    The response to SharkMQ_subscribe is asynchronous and returned as status
    #SMQ_SUBACK via #SharkMQ_getMessage.

    \param o the SharkMQ instance.
    \param topic the topic name to subscribe to.
 */
int SharkMQ_subscribe(SharkMQ* o, const char* topic);


/** Requests the broker to unsubscribe the client from a topic.
    \param o the SharkMQ instance.
    \param tid the topic name's Topic ID.
 */
int SharkMQ_unsubscribe(SharkMQ* o, U32 tid);


/** Publish messages to a topic and optionally to a sub-topic. Topic
    name must have previosly been been resolved by #SharkMQ_create and
    sub-topic should preferably have been created by #SharkMQ_createsub.
    \param o the SharkMQ instance.
    \param data message payload.
    \param len payload length.
    \param tid the topic ID (created with SharkMQ_create).
    \param subtid optional sub-topic ID preferably created with
    SharkMQ_createsub.
 */
int SharkMQ_publish(SharkMQ* o, const void* data, int len, U32 tid, U32 subtid);


/** Publish a message in chunks and request the broker to assemble the
    message before publishing to the subscriber(s). This method uses
    the internal SharkSSL send buffer and sends the message as a chunk
    when the internal buffer is full, thus sending the message as an
    incomplete message to the broker. The message is assembled by the
    broker when you flush the remaining bytes in the buffer by calling
    #SharkMQ_pubflush.

    \param o the SharkMQ instance.
    \param str a string.
 */
int SharkMQ_wrtstr(SharkMQ* o, const char* str);

/** Publish a message in chunks and request the broker to assemble the
    message before publishing to the subscriber(s). This method uses
    the internal SharkSSL send buffer and sends the message as a chunk
    when the internal buffer is full, thus sending the message as an
    incomplete message to the broker. The message is assembled by the
    broker when you flush the remaining bytes in the buffer by calling
    #SharkMQ_pubflush.


    \param o the SharkMQ instance.
    \param data message payload.
    \param len payload length.
 */
int SharkMQ_write(SharkMQ* o,  const void* data, int len);

/** Flush the internal buffer and request the broker to assemble all
    stored fragments as one message. This message is then published to
    topic 'tid', and sub-topic 'subtid'.

    \param o the SharkMQ instance.
    \param tid the topic ID (created with SharkMQ_create).
    \param subtid optional sub-topic ID preferably created with
    SharkMQ_createsub.

    Example:
    \code
    SharkMQ_wrtstr(smq, "Hello");
    SharkMQ_wrtstr(smq, " ");
    SharkMQ_wrtstr(smq, "World");
    SharkMQ_pubflush(smq,tid,subtid);
    \endcode

 */
int SharkMQ_pubflush(SharkMQ* o, U32 tid, U32 subtid);


/** Request the broker to provide change notification events when the
    number of subscribers to a specific topic changes. Ephemeral topic
    IDs can also be observed. The number of connected subscribers for
    an ephemeral ID can only be one, which means the client is
    connected. Receiving a change notification for an ephemeral ID
    means the client has disconnected and that you no longer will get
    any change notifications for the observed topic ID.

    Change notification events are received as #SMQ_SUBCHANGE via
    #SharkMQ_getMessage.

    \param o the SharkMQ instance.
    \param tid the Topic ID you which to observe.
 */
int SharkMQ_observe(SharkMQ* o, U32 tid);


/** Stop receiving change notifications for a topic ID or ephemeral topic ID.
    \param o the SharkMQ instance.
    \param tid the Topic ID you no longer want to observe.
 */
int SharkMQ_unobserve(SharkMQ* o, U32 tid);


/** Wait for messages sent from the broker.
    \param o the SharkMQ instance.
    \param msg a pointer to the response data (out param)
    \returns
    \li a negative value signals an
    [error code](\ref SharkMQErrorCodes) or an
    [asynchronous response code](\ref SharkMQRespCodes).
    \li zero signals timeout.
    \li a value greater than zero signals the reception of a full
    message or a message fragment. See receiving large frames for details.

    <b>Receiving large frames:</b><br>
    The SMQ protocol is frame based, but the function can return
    a fragment before the complete SMQ frame is received if the
    frame sent by the peer is larger than the provided buffer. The
    frame length is returned in SharkMQ::frameLen and the data consumed
    thus far is returned in SharkMQ::bytesRead. The complete frame is
    consumed when frameLen == bytesRead.

    <b>Note:</b> the default timeout value is set to one minute. You
    can set the timeout value by setting SharkMQ::timeout to the
    number of milliseconds you want to wait for incoming messages
    before the timeout triggers. Note: Setting a long timeout may
    interfere with the built in PING timer.

    \returns
      \li < 0: An error or a control message such as #SMQ_SUBACK
      \li >= 0: An SMQ message with this length

 */
int SharkMQ_getMessage(SharkMQ* o, U8** msg);


/** Returns the message size, which is SharkMQ::frameLen - 15.
    \param o the SharkMQ instance.
 */
#define SharkMQ_getMsgSize(o) ((o)->frameLen-15)

/** @} */ /* end group SMQLib_C */ 

#ifdef __cplusplus
}

inline SharkMQ::SharkMQ(U8* buf, U16 bufLen) {
   SharkMQ_constructor(this,buf, bufLen);
}

inline int SharkMQ::init(SharkSslCon* scon, const char* url, U32* rnd) {
   return SharkMQ_init(this, scon, url, rnd);
}

inline int SharkMQ::connect(const char* uid, int uidLen,
                            const char* credentials,
                            U8 credLen, const char* info, int infoLen,
                            U16 maxTlsFrameSize) {
   return SharkMQ_connect(
      this,uid,uidLen,credentials,credLen,info,infoLen,maxTlsFrameSize);
}

inline void SharkMQ::disconnect() {
   return SharkMQ_disconnect(this);
}

inline SharkMQ::~SharkMQ() {
   SharkMQ_destructor(this);
}

inline int SharkMQ::create(const char* topic) {
   return SharkMQ_create(this, topic);
}

inline int SharkMQ::createsub(const char* subtopic) {
   return SharkMQ_createsub(this, subtopic);
}

inline int SharkMQ::subscribe(const char* topic) {
   return SharkMQ_subscribe(this, topic);
}

inline int SharkMQ::unsubscribe(U32 tid) {
   return SharkMQ_unsubscribe(this, tid);
}

inline int SharkMQ::publish(const void* data, int len, U32 tid, U32 subtid) {
   return SharkMQ_publish(this, data, len, tid, subtid);
}

inline int SharkMQ::wrtstr(const char* str) {
   return SharkMQ_wrtstr(this, str);
}

inline int SharkMQ::write( const void* data, int len) {
   return SharkMQ_write(this, data, len);
}

inline int SharkMQ::pubflush(U32 tid, U32 subtid) {
   return SharkMQ_pubflush(this, tid, subtid);
}

inline int SharkMQ::observe(U32 tid) {
   return SharkMQ_observe(this, tid);
}

inline int SharkMQ::unobserve(U32 tid) {
   return SharkMQ_unobserve(this, tid);
}

inline int SharkMQ::getMessage(U8** msg) {
   return SharkMQ_getMessage(this, msg);
}

inline int SharkMQ::getMsgSize() {
   return SharkMQ_getMsgSize(this);
}

#endif



/** @} */ /* end group SMQLib */

#endif
