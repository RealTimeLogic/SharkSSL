/*
 *     ____             _________                __                _
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/
 *                                                       /____/
 ****************************************************************************
 *            HEADER
 *
 *   This file is part of SharkMQTT:
 *             https://realtimelogic.com/products/sharkmqtt/
 *
 *   $Id: SharkMQTT.h 5100 2022-02-19 16:23:57Z wini $
 *
 *   COPYRIGHT:  Real Time Logic, 2015 - 2022
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
 */

#ifndef _SharkMQTT_h
#define _SharkMQTT_h

#include <selib.h>
#include <DoubleList.h>



typedef enum
{
   MqttState_Invalid,
   MqttState_Pub,
   MqttState_PubRel,
   MqttState_PubRec,
   MqttState_SubOrUnsub
} MqttState;


/** MqttInFlightMsg.
 */
typedef struct
{
   DoubleLink super;
   U32 timeStamp;
   U16 packetId; /* [MQTT-2.3.1] Packet Identifier */
   U8 state; /* type MqttState */
} MqttInFlightMsg;



/** @addtogroup MQTTLib
@{
*/

/** \defgroup SharkMQTTErrorCodes Error codes returned by function SharkMQTT_getMessage
\ingroup SharkMQTT
\anchor SharkMQTTErrorCodes Error codes returned by function #SharkMQTT_getMessage
@{
*/

/** Error codes received from the TCP/IP stack are sent "as is". These
    error codes have a value greater than #SMQTTE_ERRORBASE.
 */
#define SMQTTE_SOCKET        -1

/** This code is not used. The code is the base for error codes returned by SharkMQ.
 */
#define SMQTTE_ERRORBASE        -10000

/** Similar to #SMQTT_TIMEOUT, but returned when a timeout was not expected.
 */
#define SMQTTE_TIMEOUT          -10001

/** The client sent a PING to the broker but did not receive a PONG response.
 */
#define SMQTTE_PONGTIMEOUT      -10002

/** Something's wrong.
 */
#define SMQTTE_PROTOCOL_ERROR   -10003

/** The SharkSSL output buffer is not sufficiently large for the operation
    you are attempting. Increase the buffer size.
 */
#define SMQTTE_OVERFLOW         -10005

/** Calling SharkMQ_connect when a connection is already established.
 */
#define SMQTTE_ALREADYCON       -10006

/** Broker refused the connection request. See #SharkMQTT_connackCode
    for details.
 */
#define SMQTTE_CONREFUSED       -10007

/** Returned by #SharkMQTT_connect if the MQTT broker is not
 * trusted. SharkMQTT_connect calls #seSec_handshake and expects the
 * return value from this function to be #SharkSslConTrust_CertCnDate
 * if the code is compiled with the flag #SHARKSSL_CHECK_DATE=1 and the
 * return value to be #SharkSslConTrust_CertCn if compiled without
 * this flag set.
 */
#define SMQTTE_SERVERNOTTRUSTED -10008


/** @} */ /* end SharkMQTTErrorCodes */


/** \defgroup SharkMQTTRespCodes Response codes returned by function SharkMQTT_getMessage
\ingroup SharkMQTT
\anchor SharkMQTTRespCodes Response codes returned by function #SharkMQTT_getMessage
@{
*/


/** #SharkMQTT_getMessage call timed out. The variable
    SharkMQTT::timeout controls the timout period.
 */
#define SMQTT_TIMEOUT -20000

/** Asynchronous #SharkMQTT_subscribe response message received via
    #SharkMQTT_getMessage.
 */
#define SMQTT_SUBACK -20001

/** Asynchronous #SharkMQTT_unsubscribe response message received via
    #SharkMQTT_getMessage.
 */
#define SMQTT_UNSUBACK -20002

/** @} */ /* end SharkMQTTRespCodes */


/** Optional MQTT Will Message; used when calling function SharkMQTT_connect.
 */
typedef struct
{
   const char* topic;  /*!< Will topic (utf-8). [MQTT-3.1.3.2] */
   const U8* message;  /*!< Will message (binary). [MQTT-3.1.3.3] */
   U16 msgLen;         /*!< Will message length */
   U8 qos;  /*!< Will QoS: 0, 1, or 2. [MQTT-3.1.2.6] */
   /** Specifies if the Will Message is to be Retained when it is published.
       [MQTT-3.1.2.7] Will Retain.
    */
   BaBool retain;
} MqttWillMsg;


/** Optional credentials used when calling function SharkMQTT_connect.
 */
typedef struct
{
   /** Optional User Name (utf-8). Set to NULL if not used. [MQTT-3.1.3.4] */
   const char* username;
   /** Optional Password (binary). Set to NULL if not
       used. [MQTT-3.1.3.5]. If username is set to NULL, the password
       MUST be set to NULL [MQTT-3.1.2-22].
   */
   const U8* password;
   /** You must provide a password length if 'password' is non NULL. */
   U16 pwdlen;
} MqttCredentials;


/** SharkMQTT structure.
    See [SharkMQ library](@ref MQTTLib) for details.
 */
typedef struct
{
   SOCKET sock;

   DoubleList recQueue; /* type MqttInFlightMsg: for QOS > 0 */
   DoubleList sendQueue; /* type MqttInFlightMsg: for QOS > 0 */

   SharkSslCon* scon;

   /** Time interval in seconds for MQTT PING messages sent to the
    * server. The default value is 20 minutes (1200 seconds).  Note:
    * the variable must be set before calling SharkMQTT_connect.
    */
   S32 pingTmo;

   S32 pongTmoCounter;
   U32 pingTickTime;

   U8* recPackHeader;    /* from constructor: buf */
   U16 recPackHeaderLen; /* from constructor: bufLen */
   
   U16 packetId; /* send packet ID counter */

   /** MQTT packet length
    */
   U32 packetLen; 

   /** Read packet data using #SharkMQTT_getMessage until:
       packetLen-bytesRead == 0.
       \sa SharkMQTT_msgConsumed
    */
   U32 bytesRead;

   /** MQTT message length
    */
   U32 msgLen;

   U8* overflowPtr; /* Set if: consumed more data from stream than frame len */ 
   int overflowLen; /* overflowPtr len is used internally in wsRawRead */
   int messageHeaderIx; /* Cursor used when reading recPackHeader from socket */

   /** Timeout in milliseconds to wait in functions waiting for server
       data
   */
   U32 timeout;

   U16 recPacketId; /* For received packets with QOS 1 or 2 */
   U8  recQOS; /* For received packets with QOS 1 or 2 */
} SharkMQTT;


/** Create a SharkMQTT client instance.
    \param o Uninitialized data of size sizeof(SharkMQTT).
    \param buf is used for internal management and must not be less
    than the size of the largest control message. Function
    SharkMQTT_getMessage will return #SMQTTE_OVERFLOW if the buffer is
    not sufficiently large.
    \param bufLen buffer length.
 */
void SharkMQTT_constructor(SharkMQTT* o, U8* buf, U16 bufLen);

/** Bare metal configuration. This macro must be called immediately
    after calling the constructor on bare metal systems.
    \param o the #SharkMQ instance.
    \param ctx an #SeCtx instance.
 */
#define SharkMQTT_setCtx(o, ctx) SOCKET_constructor(&(o)->sock, ctx)


/** Terminate a SharkMQTT instance.
    \param o SharkMQTT instance
*/
void SharkMQTT_destructor(SharkMQTT* o);


/** Read packet data using #SharkMQTT_getMessage until
    SharkMQTT_msgConsumed returns TRUE.
    \param o SharkMQTT instance
*/
#define SharkMQTT_msgConsumed(o) (((o)->packetLen - (o)->bytesRead) == 0)


/** Connection response (CONNACK) return code.
    This function should be called if SharkMQTT_connect returns
    #SMQTTE_CONREFUSED.
    \returns one of the following codes:
    - 0x00 Connection Accepted 
    - 0x01 Connection Refused, unacceptable protocol version 
    - 0x02 Connection Refused, identifier rejected 
    - 0x03 Connection Refused, Server unavailable 
    - 0x04 Connection Refused, bad user name or password 
    - 0x05 Connection Refused, not authorized 

    See [MQTT-3.2.2.3] for details.
 */
#define SharkMQTT_connackCode(o) (o)->recPackHeader[3]


/** Returns TRUE if a session is restored. This function can only be
    used immediately after calling function SharkMQTT_connect.

    See [MQTT-3.2.2.2] for details.

    \param o SharkMQTT instance

    \sa argument cleanSession in function #SharkMQTT_connect
 */
#define SharkMQTT_sessionPresent(o) ((o)->recPackHeader[2] & 1)

/** Returns SharkSslConTrust when SharkMQTT_connect returns
    #SMQTTE_SERVERNOTTRUSTED

    \param o SharkMQTT instance
*/
#define SharkMQTT_trustInfo(o) ((SharkSslConTrust)(o)->packetLen)


/** Establish (or re-establish) an MQTT session.

    \param o SharkMQTT instance
   \param scon SharkSslCon instance created by calling #SharkSsl_createCon.
   
   \param address the MQTT broker address
   \param port the MQTT broker listen port number (typically 8883)
   \param clientId a unique ID [MQTT-3.1.3.1]
   \param cred optional credentials
   \param cleanSession
   \param wm optional MQTT will message

   \returns a return value greater than zero means that a connection is
    established, but the connection is not trusted unless the return
    value is #SharkSslConTrust_CertCn.

    one of the following values on error.
   - #SMQTTE_ALREADYCON
   - #SMQTTE_CONREFUSED
   - #SMQTTE_TIMEOUT
   - #SMQTTE_OVERFLOW
   - #SMQTTE_SERVERNOTTRUSTED
   - -1
   - -2
   - -3

   Error codes -1 to -3 are error codes from #se_connect

   If #SMQTTE_CONREFUSED is returned, the reason for the refused
   connection is found by calling #SharkMQTT_connackCode.

   \sa #SharkMQTT_sessionPresent
 */
int SharkMQTT_connect(SharkMQTT* o, SharkSslCon* scon,
                      const char* address, U16 port,
                      const char* clientId, MqttCredentials* cred,
                      BaBool cleanSession, MqttWillMsg* wm);


/** Subscribe to topic.

    The response to SharkMQ_subscribe is asynchronous and returned as status
    #SMQTT_SUBACK via #SharkMQTT_getMessage.

    \param o SharkMQTT instance
    \param topic the topic name to subscribe to.
    \param qos Maximum Quality Of Zero on inbound messages can be set
    to 0, 1, or 2. Note that SharkMQTT must dynamically allocate and
    keep a small control structure for each received message
    with QOS 2. This structure is kept until the broker QOS 2
    handshaking has completed.
    \param packetId optional packet ID. The packetId can be matched
    when #SharkMQ_getMessage returns #SMQTT_SUBACK.
    \returns zero on success and a negative value on socket error.
 */
int SharkMQTT_subscribe(SharkMQTT* o, const char* topic, U8 qos, U16* packetId);


/** Requests the broker to unsubscribe the client from a topic.

    The response to SharkMQ_unsubscribe is asynchronous and returned as status
    #SMQTT_UNSUBACK via #SharkMQTT_getMessage.

    \param o SharkMQTT instance
    \param topic the topic name to unsubscribe from.
    \param packetId optional packet ID. The packetId can be matched
    when #SharkMQ_getMessage returns #SMQTT_UNSUBACK.
    \returns zero on success and a negative value on socket error.
 */
int SharkMQTT_unsubscribe(SharkMQTT* o, const char* topic, U16* packetId);


/** Prepare a zero copy publish by fetching the SharkSSL send buffer
    pointer and offset the pointer to the MQTT message payload.
    \param o SharkMQTT instance
    \param topic must match topic passed into function #SharkMQTT_publish
    \param qos must also match
    \param maxMsgLen is an out value and indicates the maximum number
    of bytes that can be copied into the pointer return by this
    function. The length is the SharkSSL buffer's out buffer size -
    the MQTT header size.

    \returns a pointer to where you can copy the message.

    Example:

    \code
    int maxMsgLen;
    U8* buf = SharkMQTT_zeroCopyPub(mqtt, "/message/", 1, &maxMsgLen);
    strcpy(buf, "Hello World")
    SharkMQTT_publish(mqtt, "/message/", NULL, strlen(buf), FALSE, 1);
    \endcode

    Notice that the message pointer is set to NULL when calling
    SharkMQTT_publish.
*/
U8* SharkMQTT_zeroCopyPub(
   SharkMQTT* o, const char* topic, U8 qos, int* maxMsgLen);


/** Publish a QOS 0 message and set the retain flag to FALSE.
    \param o SharkMQTT instance
    \param topic the topic name
    \param msg message payload.
    \param msgLen payload length.

    \returns zero on success and a negative value on socket error.
    \sa SharkMQTT_publish
 */
#define SharkMQTT_pub0(o, topic, msg, msgLen)        \
   SharkMQTT_publish(o, topic, msg, msgLen, FALSE, 0)


/** Publish messages to a topic.

   Messages with QOS 1 or 2 cannot be larger than the SharkSSL outbuf size.

   \param o SharkMQTT instance
   \param topic the topic name
   \param msg message payload. This pointer is set to
   NULL when used together with function #SharkMQTT_zeroCopyPub.
   \param msgLen payload length.
   \param retain flag is set to TRUE or FALSE [MQTT-3.3.1.3]
   \param qos Quality Of Zero is 0, 1, or 2. Note that SharkMQTT must
   dynamically allocate and keep messages with QOS 1 and 2 until the
   broker QOS handshaking has completed.

   \returns zero on success and a negative value on socket error.
   \sa SharkMQTT_pub0
 */
int SharkMQTT_publish(SharkMQTT* o, const char* topic,
                      const void* msg, int msgLen, U8 retain, U8 qos);


/** Returns packetId when the return value from #SharkMQTT_getMessage
    is #SMQTT_SUBACK or #SMQTT_UNSUBACK. 

    \param o SharkMQTT instance
*/
#define SharkMQTT_packetId(o) (o)->recPacketId

/** Returns the subscribe response code when the return value from
    #SharkMQTT_getMessage is #SMQTT_SUBACK.

    \param o SharkMQTT instance

    \returns
    - 0x00: Success - Maximum QoS 0
    - 0x01: Success - Maximum QoS 1
    - 0x02: Success - Maximum QoS 2
    - 0x80: Failure
*/
#define SharkMQTT_subAckCode(o) ((U16)(o)->recPackHeader[4])


/** Returns the dup flag (TRUE/FALSE) [MQTT-3.3.1.1] for received
    PUBLISH messages i.e. when #SharkMQTT_getMessage returns a value
    greater than zero.

    \param o SharkMQTT instance
 */
#define SharkMQTT_dup(o) (((o)->recPackHeader[0] & 8) ? TRUE : FALSE)

/**  Returns QOS (0, 1, or 2) [MQTT-3.3.1.2] for received
     PUBLISH messages i.e. when #SharkMQTT_getMessage returns a value
     greater than zero.
    \param o SharkMQTT instance
 */
#define SharkMQTT_QOS(o) (((o)->recPackHeader[0] >> 1) & 3)

/**  Returns the retain flag (TRUE/FALSE) [MQTT-3.3.1.3] for received
     PUBLISH messages i.e. when #SharkMQTT_getMessage returns a value
     greater than zero.
    \param o SharkMQTT instance
 */
#define SharkMQTT_retain(o) ((o)->recPackHeader[0] & 1)

/** Returns the topic name for received PUBLISH messages i.e. when
    #SharkMQTT_getMessage returns a value greater than zero.
    \param o SharkMQTT instance
 */
#define SharkMQTT_topic(o) ((const char*)((o)->recPackHeader+1))

/** Wait for messages sent from the broker.

    \param o SharkMQTT instance

    \param msg a pointer to the response data (out param)

    \returns
    \li a negative value signals an
    [error code](\ref SharkMQTTErrorCodes) or an
    [asynchronous response code](\ref SharkMQTTRespCodes).
    \li a value greater than zero signals the reception of a full
    message or a message fragment. See receiving large packets for details.

    <b>Receiving large packets:</b><br>
    The MQTT protocol is frame based, but the function can return a
    fragment before the complete MQTT packet is received if the packet
    sent by the broker is larger than the SharkSSL buffer. The message
    payload length is returned in SharkMQTT::packetLen and the data
    consumed thus far is returned in SharkMQTT::bytesRead. The
    complete frame is consumed when SharkMQTT::packetLen ==
    SharkMQTT::bytesRead. Function #SharkMQTT_msgConsumed returns TRUE
    when the complete packet has been received.

    <b>Note:</b> the default timeout value is set to one minute. You
    can set the timeout value by setting SharkMQTT::timeout to the
    number of milliseconds you want to wait for incoming messages
    before the timeout triggers. Note: Setting a long timeout may
    interfere with the built in PING timer.
 */
int SharkMQTT_getMessage(SharkMQTT* o, U8** msg);


/** Send a disconnect command to the broker and gracefully close the connection.
    \param o SharkMQTT instance
 */
void SharkMQTT_disconnect(SharkMQTT* o);

/** @} */ /* end group MQTTLib */

#endif
