/*
 *     ____             _________                __                _
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/
 *                                                       /____/
 ****************************************************************************
 *   PROGRAM MODULE
 *
 *
 *   This file is part of SharkMQTT:
 *             https://realtimelogic.com/products/sharkmqtt/
 *
 *   $Id: SharkMQTT.c 4895 2021-11-12 21:07:17Z wini $
 *
 *   COPYRIGHT:  Real Time Logic, 2015 - 2021
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

#include "SharkMQTT.h"

#define MQTT_MSG_CONNECT       (1<<4)
#define MQTT_MSG_CONNACK       (2<<4)
#define MQTT_MSG_PUBLISH       (3<<4)
#define MQTT_MSG_PUBACK        (4<<4)
#define MQTT_MSG_PUBREC        (5<<4)
#define MQTT_MSG_PUBREL        (6<<4)
#define MQTT_MSG_PUBCOMP       (7<<4)
#define MQTT_MSG_SUBSCRIBE     (8<<4)
#define MQTT_MSG_SUBACK        (9<<4)
#define MQTT_MSG_UNSUBSCRIBE  (10<<4)
#define MQTT_MSG_UNSUBACK     (11<<4)
#define MQTT_MSG_PINGREQ      (12<<4)
#define MQTT_MSG_PINGRESP     (13<<4)
#define MQTT_MSG_DISCONNECT   (14<<4)

#define SETB(bit, on) (on ? (1 << bit) : 0)

#if defined(B_LITTLE_ENDIAN)
static void
netConvU16(U8* out, const U8* in)
{
   out[0] = in[1];
   out[1] = in[0];
}
#elif defined(B_BIG_ENDIAN)
#define netConvU16(out, in) memcpy(out,in,2)
#else
#error ENDIAN_NEEDED_Define_one_of_B_BIG_ENDIAN_or_B_LITTLE_ENDIAN
#endif


static U8*
setBytes(U8* ptr, const U8* msg, U16 len)
{
   netConvU16(ptr, (U8*)&len);
   ptr += 2;
   memcpy(ptr, msg, len);
   return ptr + len;
}

static U8*
setString(U8* ptr, const char* msg)
{
   return setBytes(ptr, (U8*)msg, (U16)strlen(msg));
}

static MqttInFlightMsg*
createMqttInFlightMsg(DoubleList* list, U16 packetId, int extraSize)
{
   MqttInFlightMsg* iMsg;
   iMsg = (MqttInFlightMsg*)baMalloc(sizeof(MqttInFlightMsg) + extraSize);
   if(iMsg)
   {
      DoubleLink_constructor(iMsg);
      iMsg->timeStamp = baGetUnixTime();
      iMsg->packetId = packetId;
      DoubleList_insertLast(list, iMsg);
   }
   return iMsg;
}


static MqttInFlightMsg*
findInFlightMsg(DoubleList* list, U16 packetId)
{
   DoubleListEnumerator iter;
   DoubleLink* l;
   DoubleListEnumerator_constructor(&iter, list);
   for(l = DoubleListEnumerator_getElement(&iter) ; l ;
       l = DoubleListEnumerator_nextElement(&iter))
   {
      if(((MqttInFlightMsg*)l)->packetId == packetId)
         return (MqttInFlightMsg*)l;
   }
   return 0;
}


/* Remove the oldest element, if found and if expired ( > 30 secs)
 */
static void
terminateExpiredInFlightMsg(DoubleList* list, U32 tnow)
{
   MqttInFlightMsg* iMsg = (MqttInFlightMsg*)DoubleList_firstNode(list);
   if(iMsg && ((S32)(tnow - iMsg->timeStamp)) > 30) /* Max 30 secs */
   {
      DoubleLink_unlink(iMsg);
      baFree(iMsg);
   }
}


static void
updateTimeStamp(DoubleList* list)
{
   DoubleListEnumerator iter;
   DoubleLink* l;
   DoubleListEnumerator_constructor(&iter, list);
   for(l = DoubleListEnumerator_getElement(&iter) ; l ;
       l = DoubleListEnumerator_nextElement(&iter))
   {
      ((MqttInFlightMsg*)l)->timeStamp = baGetUnixTime();
   }
}


static void
terminateList(DoubleList* list)
{
   for(;;)
   {
      DoubleLink* l = DoubleList_firstNode(list);
      if( ! l )
         break;
      DoubleLink_unlink(l);
      baFree(l);
   }
}




/* [MQTT-2.3.1] Packet Identifier
   Must be set for:
     PUBLISH: QOS 1 OR 2
     PUBREL, SUBSCRIBE, UNSUBSCRIBE: QOS 1
*/
static U8*
SharkMQTT_setAndIncPacketId(SharkMQTT* o, U8* ptr)
{
   netConvU16(ptr, (U8*)&o->packetId);
   if(++o->packetId == 0) /* Section 2.3.1 must contain a non zero value */
      o->packetId = 1;
   return ptr+2;
}

static void
SharkMQTT_terminateCon(SharkMQTT* o)
{
   o->pongTmoCounter = 0;
   o->messageHeaderIx = 0;
   o->bytesRead = o->packetLen = o->msgLen = 0;
   o->overflowPtr = 0;
   o->overflowLen = 0;
   o->scon=0;
   se_close(&o->sock);
}


static int
SharkMQTT_rawRead(SharkMQTT* o, U8** buf)
{
   U8* ptr;
   int len;
   int newPacket = FALSE;
   if(o->overflowPtr)
   {
      len = o->overflowLen;
      ptr = o->overflowPtr;
      o->overflowPtr = 0;
   }
   else
   {
     L_readMore:
      if( ! o->scon )
         return -1;
      if((len = seSec_read(o->scon, &o->sock, buf, o->timeout)) <= 0)
      {
         if(len) /* sock err */
         {
            SharkMQTT_terminateCon(o);
            return len;
         }
         return SMQTT_TIMEOUT;
      }
      ptr = *buf;
   }
   /* Copy fixed header and payload length into frame header */
   while( (o->messageHeaderIx < 2) || /* fixed header */
          (o->messageHeaderIx < 5 && /* payload len */
           (o->recPackHeader[o->messageHeaderIx-1] & 0x80) == 0x80) )
   {
      if(len == 0)
         goto L_readMore;
      newPacket = TRUE;
      o->recPackHeader[o->messageHeaderIx++] = *ptr++;
      len--;
   }
   if(newPacket)
   {
      U32 digit;
      U32 multiplier = 1;
      o->bytesRead = o->packetLen = 0;
      *buf = ptr; /*Adjust payload for consumed header (rec or overflow data)*/
      /* Decode payload length: [MQTT-2.2.3:296] */
      ptr = o->recPackHeader+1;
      do
      {
         digit = *ptr++;
         o->packetLen += (digit & 127) * multiplier;
         multiplier *= 128;
      } while((digit & 128) != 0);
      
   }
   o->bytesRead += len;
   if(o->bytesRead > o->packetLen)  /* Read overflow */
   {
      o->overflowLen = o->bytesRead - o->packetLen;
      o->bytesRead = o->packetLen;
      len = (int)o->packetLen;
      o->overflowPtr = *buf + len;
   }
   return len;
}


/* Copy 'bytes2copy' bytes into SharkMQTT::recPackHeader.
 */
static int
SharkMQTT_copy2RecPackHeader(SharkMQTT* o,U8** msg,int msgLen,int bytes2copy)
{
   U8* buf = *msg;
   if( (o->messageHeaderIx + bytes2copy) > o->recPackHeaderLen )
      return SMQTTE_OVERFLOW;
   while(bytes2copy)
   {
      if(msgLen == 0)
      {
         if( (msgLen = SharkMQTT_rawRead(o, msg)) < 0)
            return msgLen;
         if(msgLen == 0)
            return -1; /* Unknown error */
         buf = *msg;
      }
      o->recPackHeader[o->messageHeaderIx++] = *buf++;
      bytes2copy--;
      msgLen--;
   }
   *msg = buf;
   return msgLen;
}


/* Send control message With Packet ID */
static int
SharkMQTT_sendCtrlMsgWPID(SharkMQTT* o, int msgType, U8 qos, U16 packetId)
{
   int status;
   U8* ptr = SharkSslCon_getEncBufPtr(o->scon);
   *ptr++ = (U8)(msgType | SETB(1, qos));
   *ptr++ = 2; /* length */
   netConvU16(ptr, (U8*)&packetId);
   if( (status=seSec_write(o->scon, &o->sock, 0, 4)) < 0 )
   {
      SharkMQTT_terminateCon(o);
      return status;
   }
   return 0;
}

static int
SharkMQTT_sendCtrlMsg(SharkMQTT* o, U8 msgType)
{
   int status;
   U8* ptr = SharkSslCon_getEncBufPtr(o->scon);
   if(ptr)
   {
      *ptr++ = msgType;
      *ptr = 0; /* length */
      if( (status=seSec_write(o->scon, &o->sock, 0, 2)) < 0 )
         return status;
      return 0;
   }
   return -1;
}


#define SharkMQTT_sendPing(o) SharkMQTT_sendCtrlMsg(o, MQTT_MSG_PINGREQ)


void
SharkMQTT_disconnect(SharkMQTT* o)
{
   if(o->scon)
   {
      U8* msg=0;
      if( ! SharkMQTT_sendCtrlMsg(o, MQTT_MSG_DISCONNECT) )
      {
         while(SharkMQTT_getMessage(o, &msg) > 0);
      }
      terminateList(&o->recQueue);
      terminateList(&o->sendQueue);
      SharkMQTT_terminateCon(o);
   }
}


/* Send MQTT_MSG_PUBREC or MQTT_MSG_PUBACK */
static void
SharkMQTT_managePubAck(SharkMQTT* o)
{
   if(o->recQOS == 2)
   {
      MqttInFlightMsg* iMsg = createMqttInFlightMsg(
         &o->recQueue,o->recPacketId,0);
      if(iMsg)
         iMsg->state = MqttState_PubRec;
      SharkMQTT_sendCtrlMsgWPID(o, MQTT_MSG_PUBREC, FALSE, o->recPacketId);
   }
   else
      SharkMQTT_sendCtrlMsgWPID(o,MQTT_MSG_PUBACK, FALSE, o->recPacketId);
}


/* Manage control message with packet ID */
static int
SharkMQTT_manageCtrlMsg(SharkMQTT* o)
{
   MqttInFlightMsg* iMsg;
   U16 packetId;
   int msgType = o->recPackHeader[0] & 0xF0;
   int status = 0;
   netConvU16((U8*)&packetId, o->recPackHeader+2);
   switch(msgType)
   {
      case MQTT_MSG_PUBACK:
      case MQTT_MSG_PUBCOMP:
      case MQTT_MSG_SUBACK:
      case MQTT_MSG_UNSUBACK:
         iMsg = findInFlightMsg(&o->sendQueue, packetId);
      L_release:
         if(iMsg)
         {
            DoubleLink_unlink(iMsg);
            baFree(iMsg);
         }
         break;

      case MQTT_MSG_PUBREL:
         status = SharkMQTT_sendCtrlMsgWPID(o,MQTT_MSG_PUBCOMP,FALSE,packetId);
         iMsg = findInFlightMsg(&o->recQueue, packetId);
         goto L_release;

      case MQTT_MSG_PUBREC:
         status = SharkMQTT_sendCtrlMsgWPID(o,MQTT_MSG_PUBREL,TRUE,packetId);
         iMsg = findInFlightMsg(&o->sendQueue, packetId);
         if(iMsg)
            iMsg->state = MqttState_PubRel;
         break;
   }
   return status;
}


static int
SharkMQTT_resendInFlightMsgs(SharkMQTT* o, DoubleList* list)
{
   int status;
   DoubleListEnumerator iter;
   MqttInFlightMsg* iMsg;
   U32 now = baGetUnixTime();
   DoubleListEnumerator_constructor(&iter, list);
   for(iMsg = (MqttInFlightMsg*)DoubleListEnumerator_getElement(&iter) ; iMsg ;
       iMsg = (MqttInFlightMsg*)DoubleListEnumerator_nextElement(&iter))
   {
      iMsg->timeStamp = now;
      if(iMsg->state == MqttState_PubRel || iMsg->state == MqttState_PubRec)
      {
         status=SharkMQTT_sendCtrlMsgWPID(
            o, iMsg->state == MqttState_PubRel ?
            MQTT_MSG_PUBREL : MQTT_MSG_PUBREC,TRUE,o->packetId);
      }
      else
      {
         U16* sizePtr;
         baAssert((iMsg->state == MqttState_Pub ||
                   iMsg->state == MqttState_SubOrUnsub));
         sizePtr = (U16*)(iMsg+1);
         status = seSec_write(o->scon, &o->sock, (U8*)(sizePtr+1), *sizePtr);
      }
      if(status < 0)
         return status;
   }
   return 0;
}



int
SharkMQTT_getMessage(SharkMQTT* o, U8** msg)
{
   int x;
   if( ! o->scon )
      return SMQTTE_SOCKET;
   if(o->bytesRead < o->packetLen) /* In process of reading a large message */
   {
      if( (x=SharkMQTT_rawRead(o, msg)) == SMQTT_TIMEOUT )
         return SMQTTE_TIMEOUT;
      if(o->bytesRead == o->packetLen)
      {
         o->messageHeaderIx = 0;  /* Prepare for next packet */
         if(o->recQOS)
            SharkMQTT_managePubAck(o);
      }
      return x;
   }
  L_getNextMsg:
   if( (x = SharkMQTT_rawRead(o, msg)) < 0)
   {
      if(x == SMQTT_TIMEOUT)
      {
         if(o->pongTmoCounter)
         {
            o->pongTmoCounter += o->timeout;
            if(o->pongTmoCounter > 0)
               return SMQTTE_PONGTIMEOUT;
         }
         else
         {
            U32 now = baGetUnixTime();
            if((S32)(now - o->pingTickTime) >=
               (o->pingTmo - (S32)(o->timeout/1000)))
            {
               o->pongTmoCounter = -10000; /*Max PONG tmo hardcoded to 10 sec*/
               o->pingTickTime = baGetUnixTime();
               if( (x=SharkMQTT_sendPing(o)) != 0 )
                  return x;
               return SMQTT_TIMEOUT;
            }
            terminateExpiredInFlightMsg(&o->sendQueue, now);
            terminateExpiredInFlightMsg(&o->recQueue, now);
         }
      }
      return x; /* tmo or sock err */
   }
   o->pongTmoCounter = 0;
   if((o->recPackHeader[0] & 0xF0) == MQTT_MSG_PUBLISH)
   {
      /* Packet structure [MQTT-3.3]:
           Header:    1
           Var len:   1- 4
           topic len: 2  (payloadIx is set to this location)
           topic:     N
           packetId:  2 (only inlcuded if QOS > 0)
           Data:      N
        Var packetLen comprises topic len to end of data
        Data len: packetLen - (qos ? 4 : 2) - topic len
      */
      U16 tlen;
      int len = x;
      int payloadIx = o->messageHeaderIx;
      x = o->recQOS = SharkMQTT_QOS(o);
      /* Read 2:topic-len or 4:(topic-len + packetId len) if QOS > 0 */
      if( (len=SharkMQTT_copy2RecPackHeader(o, msg, len, x ? 4 : 2)) < 0)
         return len; /* error */
      netConvU16((U8*)&tlen, o->recPackHeader+payloadIx);
      if( (len=SharkMQTT_copy2RecPackHeader(o, msg, len, tlen)) < 0)
         return len; /* error */
      o->msgLen = o->packetLen - tlen - (x ? 4 : 2);
      if(x) /* QOS > 0 */
      {
         netConvU16((U8*)&o->recPacketId, o->recPackHeader+payloadIx+2+tlen);
         if(findInFlightMsg(&o->recQueue, o->recPacketId))
         {
            /* Discard duplicate message */
            while(o->bytesRead < o->packetLen)
            {
               if( (x=SharkMQTT_rawRead(o, msg)) == SMQTT_TIMEOUT )
               {
                  SharkMQTT_terminateCon(o);
                  return SMQTTE_TIMEOUT;
               }
               if(x < 0)
                  return x;
            }
            goto L_getNextMsg;
         }
         if(o->bytesRead == o->packetLen)
            SharkMQTT_managePubAck(o);
      }
      /* reposition topic so macro SharkMQTT_topic() works and zero
       * terminate the string.
       */
      memmove(o->recPackHeader+1, o->recPackHeader+payloadIx+2, tlen);
      o->recPackHeader[tlen+1] = 0; /* Convert to C string */
      /* set x(return val) to data len or remaining chunk len:
         packetLen - (qos ? 4 : 2) - topic len
      */
      x = len;
      if(o->bytesRead == o->packetLen)
         o->messageHeaderIx = 0;  /* Prepare for next packet */
   }
   else
   {
      x=SharkMQTT_copy2RecPackHeader(o, msg, x, o->packetLen);
      if(x)
         return x; /* error */
      o->messageHeaderIx = 0;  /* Prepare for next packet */
      switch(o->recPackHeader[0] & 0xF0)
      {
         case MQTT_MSG_CONNACK:
            /* The invalid number zero is used as state info when
               called from SharkMQTT_connect (REF-INV).
            */
            if(o->packetId != 0)
            {
               SharkMQTT_terminateCon(o);
               return SMQTTE_PROTOCOL_ERROR;
            }
            break; /* OK: called from SharkMQTT_connect */

         case MQTT_MSG_SUBACK:
         case MQTT_MSG_UNSUBACK:
            x=SharkMQTT_manageCtrlMsg(o);
            if( ! x )
            {
               netConvU16((U8*)&o->recPacketId, o->recPackHeader+2);
               x = (o->recPackHeader[0] & 0xF0) == MQTT_MSG_SUBACK ?
                  SMQTT_SUBACK : SMQTT_UNSUBACK;
            }
            break;

         case MQTT_MSG_PUBACK:
         case MQTT_MSG_PUBREC:
         case MQTT_MSG_PUBCOMP:
         case MQTT_MSG_PUBREL:
            x=SharkMQTT_manageCtrlMsg(o);
            if(x)
               break; /* error */
            goto L_getNextMsg;

         case MQTT_MSG_PINGRESP:
            goto L_getNextMsg;
            
         default:
            return SMQTTE_PROTOCOL_ERROR;
      }
   }
   return x;
}


U8*
SharkMQTT_zeroCopyPub(SharkMQTT* o, const char* topic, U8 qos, int* maxMsgLen)
{
   int tlen = strlen(topic);
   int bufSize = (int)SharkSslCon_getEncBufSize(o->scon);
   U8* ptr = SharkSslCon_getEncBufPtr(o->scon);
   /* 2 bytes len encoding: 127*128+127 = max 16383. */
   if(bufSize > 16383)
      bufSize = 16383;
   if(qos)
      tlen += 2; /* 5 + 2 */
   *maxMsgLen = bufSize - 5 - tlen;
   return ptr + 5 + tlen; /*5: 1 byte header, 2 byte encoded len, 2 byte tlen*/
}


int
SharkMQTT_publish(SharkMQTT* o, const char* topic,
                 const void* msg, int msgLen, U8 retain, U8 qos)
{
   int packetSize,x;
   U8* ptr;
   U8* buf;
   int bufSize;
   int fixedSize=0;
   U16 packetId = o->packetId;
   if( ! o->scon )
      return SMQTTE_SOCKET;
   bufSize = (int)SharkSslCon_getEncBufSize(o->scon);
   if(qos > 2)
      qos = 2;
   o->pingTickTime = baGetUnixTime();
   ptr = buf = SharkSslCon_getEncBufPtr(o->scon);
   *ptr++ = (U8)(MQTT_MSG_PUBLISH | (qos<<1) | SETB(0, retain));

   /*
     A complete MQTT packet includes:
       1 byte: fixed header
       1 - 4 bytes: length of data below.
       2 bytes: topic length
       N bytes: topic
       2 bytes (but only if QOS 1 or 2): packet ID
       N bytes: payload
   */
   packetSize = 2+strlen(topic)+msgLen; /* 2: topic length */
   if(qos)
      packetSize += 2;
   if(msg)
   {
      fixedSize = 1;
      x=packetSize;
      /* Encode length. [MQTT-2.2.3:280] */
      do
      {
         *ptr = (U8)(x % 0x80);
         x /= 0x80;
         if(x)
            *ptr |= 0x80;
         fixedSize++;
         ptr++;
      } while(x);
   }
   else
   {
      fixedSize = 1 + 2;
      if(packetSize > 16383) /* 2 bytes len encoding: 127*128+127 */
         return SMQTTE_OVERFLOW;
      *ptr++ = (U8)(packetSize % 0x80) | 0x80;
      *ptr++ = (U8)(packetSize / 0x80);
   }
   ptr = setString(ptr, topic);
   if(qos)
      ptr = SharkMQTT_setAndIncPacketId(o, ptr);
   x = bufSize - (ptr - buf); /* Remaining buffer len */
   if(x >= msgLen)
   {
      
      if(msg)
         memcpy(ptr, msg, msgLen);
      /* else via SharkMQTT_zeroCopyPub */
      if(qos)
      {
         MqttInFlightMsg* iMsg = createMqttInFlightMsg(
            &o->sendQueue, packetId, 2 + fixedSize + packetSize);
         if(iMsg)
         {
            iMsg->state = MqttState_Pub;
            ptr = (U8*)(iMsg+1);
            *((U16*)ptr) = (U16)(fixedSize + packetSize); /* Easy size access */
            memcpy(ptr+2, buf, fixedSize + packetSize);
            ptr[2] |= SETB(3, 1); /* Set dup flag */
         }
         /* else. QOS > 0 will be downgraded to QOS 0 */
      }
      x = seSec_write(o->scon, &o->sock, 0, fixedSize + packetSize);
   }
   else
   {
       /* 
          not msg: via SharkMQTT_zeroCopyPub, thus mem corrupted.
          QOS messages cannot be larger than what fits into SharkSSL out buf.
       */
      if( ! msg || qos )
         return SMQTTE_OVERFLOW;
      memcpy(ptr, msg, x);
      msg = ((U8*)msg) + x;
      msgLen -= x;
      x = seSec_write(o->scon, &o->sock, 0, bufSize);
      while(x > 0 && msgLen > 0)
      {
         int chunk = bufSize > msgLen ? msgLen : bufSize;
         memcpy(buf, msg, chunk);
         msgLen -= chunk;
         msg = ((U8*)msg) + chunk;
         x = seSec_write(o->scon, &o->sock, 0, chunk);
      }
   }
   if(x < 0)
   {
      SharkMQTT_terminateCon(o);
      return x;
   }
   return 0;
}


static int
SharkMQTT_subOrUnsub(
   SharkMQTT* o, int msgType, const char* topic, U8 qos, U16* packetId)
{
   MqttInFlightMsg* iMsg; 
   U8* buf;
   U8* ptr;
   int x = 2 + 2 + strlen(topic); /* packetId + (thead + topic) */
   if(MQTT_MSG_SUBSCRIBE == msgType)
   {
      x++;
      if(qos > 2)
         qos = 2;
   }
   if( ! o->scon )
      return SMQTTE_SOCKET;
   if(x > 16383 || x > SharkSslCon_getEncBufSize(o->scon))
      return SMQTTE_OVERFLOW;
   ptr = buf = SharkSslCon_getEncBufPtr(o->scon);
   *ptr++ = (U8)(msgType | SETB(1, 1));
   *ptr++ = (x % 0x80) | 0x80;
   *ptr++ = (U8)(x / 0x80);
   if(packetId)
      *packetId = o->packetId;
   ptr = SharkMQTT_setAndIncPacketId(o, ptr);
   ptr = setString(ptr, topic);
   if(MQTT_MSG_SUBSCRIBE == msgType)
      *ptr = qos;
   if(qos)
   {
      iMsg = createMqttInFlightMsg(&o->sendQueue, o->packetId, 2 +  x + 3);
      if(iMsg)
      {
         iMsg->state = MqttState_SubOrUnsub;
         ptr = (U8*)(iMsg+1);
         *((U16*)ptr) = (U16)(x+3); /* Easy size access */
         memcpy(ptr+2, buf, x+3);
      }
   }
   if( (x=seSec_write(o->scon, &o->sock, 0, x+3)) < 0 )
      return x;
   return 0;
}


int
SharkMQTT_subscribe(SharkMQTT* o, const char* topic, U8 qos, U16* packetId)
{
   return SharkMQTT_subOrUnsub(o, MQTT_MSG_SUBSCRIBE, topic, qos, packetId);
}


int
SharkMQTT_unsubscribe(SharkMQTT* o, const char* topic, U16* packetId)
{
   return SharkMQTT_subOrUnsub(o, MQTT_MSG_UNSUBSCRIBE, topic, 0, packetId);
}


int
SharkMQTT_connect(SharkMQTT* o, SharkSslCon* scon,
                  const char* address, U16 port,
                  const char* clientId, MqttCredentials* cred,
                  BaBool cleanSession, MqttWillMsg* wm)
{
   static const U8 protoNameAndVer[] = {
      0x00,0x04, /* length */
      'M','Q','T','T',
      4 /* Version 3.1.1 */
   };
   int status,x;
   U8* ptr;
   U8* buf;
   U8* end;
   U16 x16, packetId;
   baAssert(sizeof(protoNameAndVer) == 7);
   if(o->scon)
      return SMQTTE_ALREADYCON;
   if( (status=se_connect(&o->sock, address, port)) != 0)
      return status;
   o->scon = scon;
   status = seSec_handshake(scon, &o->sock, o->timeout, address);
#if SHARKSSL_CHECK_DATE
   if (status <= 0 || (cred && status != SharkSslConTrust_CertCnDate))
#else
   if (status <= 0 || (cred && status != SharkSslConTrust_CertCn))
#endif
   {
      /* For security reasons, the connection is not accepted if a
       * password is provided and the server is not trusted.
       */
      SharkMQTT_terminateCon(o);
      if(status == 0)
         return SMQTTE_TIMEOUT;
      if(status < 0)
         return status;
      o->packetLen = (U32)status;
      return SMQTTE_SERVERNOTTRUSTED;
   }
   ptr = buf = SharkSslCon_getEncBufPtr(scon);
   end = buf + SharkSslCon_getEncBufSize(o->scon) - 50; /* some slack */
   *ptr++ = MQTT_MSG_CONNECT;
   ptr+=2; /* Size field */
   /* end of fixed size */
   memcpy(ptr, protoNameAndVer, sizeof(protoNameAndVer));
   ptr += sizeof(protoNameAndVer);
   *ptr = SETB(1,cleanSession);
   if(cred)
   {
      /* If the User Name Flag is set to 0, the Password Flag MUST be
         set to 0 [MQTT-3.1.2-22].
       */
      if( ! cred->username )
         cred=0;
      else
         *ptr |= SETB(7,cred->username) | SETB(6,cred->password);
   }
   if(wm)
   {
      if(wm->qos > 2)
         wm->qos = 2;
      *ptr |= SETB(5,wm->retain) |  (wm->qos << 1) | SETB(2,TRUE);
   }
   ptr++;
   x16 = (U16)o->pingTmo + 1;
   netConvU16(ptr, (U8*)&x16);
   ptr += 2;
   /* 3.1.3 Payload */
   ptr = setString(ptr, clientId); 
   if(wm)
   {
      if( (ptr + strlen(wm->topic) + wm->msgLen) > end )
         return SMQTTE_OVERFLOW;
      ptr = setString(ptr, wm->topic);
      ptr = setBytes(ptr, wm->message, wm->msgLen);
   }
   if(cred)
   {
      if(cred->username)
      {
         if( (ptr + strlen(cred->username)) > end )
            return SMQTTE_OVERFLOW;
         ptr = setString(ptr, cred->username);
      }
      if(cred->password)
      {
         if( (ptr + cred->pwdlen) > end )
            return SMQTTE_OVERFLOW;
         ptr = setBytes(ptr, cred->password,cred->pwdlen);
      }
   }
   x16 = (U16)(ptr - buf) - 3;
   if(x16 > 16383)
      return SMQTTE_OVERFLOW;
   buf[1] = (x16 % 0x80) | 0x80;
   buf[2] = (U8)(x16 / 0x80);
   if( (x=seSec_write(scon, &o->sock, 0, x16+3)) < 0 )
      return x;
   packetId = o->packetId;
   /* Set to invalid number. Used as state info in SharkMQTT_getMessage */
   o->packetId = 0; /* (REF-INV) */
   x = SharkMQTT_getMessage(o, &buf);
   o->packetId = packetId;
   if(x == 0 &&
      MQTT_MSG_CONNACK == (o->recPackHeader[0] & 0xF0) &&
      SharkMQTT_connackCode(o) == 0)
   {
      updateTimeStamp(&o->recQueue);
      updateTimeStamp(&o->sendQueue);
      if( SharkMQTT_resendInFlightMsgs(o, &o->recQueue) || 
          SharkMQTT_resendInFlightMsgs(o, &o->sendQueue) )
      {
         SharkMQTT_terminateCon(o);
         return SMQTTE_SOCKET;
      }
      o->pingTickTime = baGetUnixTime();
      return status; /* enum SharkSslConTrust */
   }
   SharkMQTT_terminateCon(o);
   if(x < 0) /* socket error */
      return x;
   /* Else: remove all pending QOS messages */
   terminateList(&o->recQueue);
   terminateList(&o->sendQueue);
   return MQTT_MSG_CONNACK == (o->recPackHeader[0] & 0xF0) ?
      SMQTTE_CONREFUSED : SMQTTE_PROTOCOL_ERROR;
}


void
SharkMQTT_constructor(SharkMQTT* o, U8* buf, U16 bufLen)
{
   memset(o, 0, sizeof(SharkMQTT));
   DoubleList_constructor(&o->recQueue);
   DoubleList_constructor(&o->sendQueue);
   o->recPackHeader = buf;
   o->recPackHeaderLen = bufLen - 2; /* Adjust for fixed size header */
   o->timeout = 60 * 1000;
   o->pingTmo = 20 * 60;
   o->packetId = 1;
}


void
SharkMQTT_destructor(SharkMQTT* o)
{
   SharkMQTT_terminateCon(o);
   terminateList(&o->recQueue);
   terminateList(&o->sendQueue);
   memset(o, 0, sizeof(SharkMQTT));
}
