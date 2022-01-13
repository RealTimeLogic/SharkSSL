/*
 *     ____             _________                __                _
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/
 *                                                       /____/
 *
 ****************************************************************************
 *   PROGRAM MODULE
 *
 *   $Id: LED-JSON.c 5021 2022-01-13 18:59:01Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2014 - 2021
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
 ****************************************************************************

 Secure version of the M2M LED JSON example. This example requires our JSON
 parser, which can be downloaded from:
 https://realtimelogic.com/products/json/

   * Unzip json.zip in the root of your SharkSSL installation such that
     the JSON directory is <shark-root>/JSON.

  * Navigate to JSON/inc and delete the file: TargConfig.h

  * Compile the code as shown in the example makefile.

  -----------------------------

  This client M2M C source code example is designed to run on an
  evaluation board with LEDs that can be controlled by software.

  An introduction to this M2M-LED example can be found on the following page:
  https://realtimelogic.com/ba/doc/en/C/reference/html/md_en_C_md_JSON.html

  This M2M-LED example connects to and establishes a 
  persistent socket connection with a web service running on:
  http://realtimelogic.info/IoT/led/json/

  Use your browser and navigate to the above URL for more information.

  This code is split into two sections:
    1: The board specific code must be adapted to the hardware and/or
       LED software API available on the evaluation board.
    2: The generic code manages the connection with the online service
       and does not require any porting.

  Note: when you see Ref-XX in the source code below, it means that
  you can find a reference to this elsewhere in the code. You can
  use any editor when searching for the other references.

 
*/

#include <JParser.h>
#include <JDecoder.h>
#include <JEncoder.h>
#include "ledctrl.h"


/* NOTE: change server name to the IP address where the M2M server
 * code runs.
 */
#define SERVERNAME "realtimelogic.info"
/* #define SERVERNAME "localhost" */



/****************************************************************************
 **************************-----------------------***************************
 **************************| BOARD SPECIFIC CODE |***************************
 **************************-----------------------***************************
 ****************************************************************************/

#if  HOST_PLATFORM

/* Include the simulated LED environment/functions */
#include "led-host-sim.ch"

/* Remove this function and replace with a task/thread that calls
 * function mainTask (Ref-Ta). Note: function mainTask will not return
 * unless the connection cannot be established or if the server wants
 * the connection to close. The caller can for example toggle all
 * LEDs, in an endless loop, if this function returns.
 */
void mainTask(SeCtx* ctx);
int
main()
{
#ifdef _WIN32
   /* Windows specific: Start winsock library */
   { WSADATA wsaData; WSAStartup(MAKEWORD(1,1), &wsaData); }
#endif
   
   mainTask(0);
   xprintf(("Exiting...\n"));
   return 0;
}

#ifdef _WIN32
#define millisleep(milliseconds) Sleep(milliseconds)
#else
#ifndef millisleep
#define millisleep(ms) do {                   \
      struct timespec tp;                       \
      tp.tv_sec = (ms)/1000;                    \
      tp.tv_nsec = ((ms) % 1000) * 1000000;     \
      nanosleep(&tp,0);                         \
   } while(0)
#endif
#endif

#else
#ifndef millisleep
#define millisleep(ms)
#endif
#endif /* HOST_PLATFORM */


/****************************************************************************
 **************************----------------------****************************
 **************************| GENERIC CODE BELOW |****************************
 **************************----------------------****************************
 ****************************************************************************/


static const char*
ledType2String(LedColor t)
{
   switch(t)
   {
      case LedColor_red: return "red";
      case LedColor_yellow: return "yellow";
      case LedColor_green: return "green";
      case LedColor_blue: return "blue";
   }
   baAssert(0);
   return "";
}


/*                   sharkSslCAList (Ref-CA)

The data from the include file below is a CA (Certificate Authority)
Root Certificate. The CA enables SharkSSL to verify the identity of
realtimelogic.com. We include data for only one CA in this example
since only the signer of realtimelogi.com's certificate is required
for validation in this example. See the "certcheck" example for how to
validate any type of certificate and for more options on how to store
certificates, in addition to embedding the CA as it is done in this
example.

The Certification Authority Root Certificate was
converted to 'sharkSslCAList' as follows:
SharkSSLParseCAList CA_RTL_EC_256.pem > CA_RTL_EC_256.h

An introduction to certificate management can be found here:
https://realtimelogic.com/blog/2013/10/Certificate-Management-for-Embedded-Systems
*/
#include "certificates/CA_RTL_EC_256.h"


/* Validate that a function returns 0. Non zero indicates program
 * error i.e. incorrect use of a function.
 */
#ifdef NDEBUG
#define VALIDATE(x) x
#else
#define VALIDATE(x) baAssert( !x )
#endif


/* Sleep (tick time) and heartbeat timeouts in millisecs */

#define TICK_TMO 50
#define PING_TMO_IN_TICKS 10*60*1000/TICK_TMO /* 10 minutes */
#define PONG_TMO_IN_TICKS  (PING_TMO_IN_TICKS + 3*1000/TICK_TMO)

/* Parsed strings cannot be larger than the following:
 */
#define MAX_STRING_LEN (256)


/* Container for secure connection data.
 */
typedef struct
{
   SOCKET sock;
   SharkSslCon* ssl;
} SecCon;


/* The two message types sent from the server with payload data:
 */

/* Message 'S' */
typedef struct {
   int id; /* LED ID */
   U8 on; /* on=TRUE, off=FALSE */
} MsgS;

/* Message 'C' */
typedef struct {
   char msg[MAX_STRING_LEN];
} MsgC;


/* Static allocator for JParser.
   (C version of C++ code in StaticAllocatorEx.cpp)
*/
typedef struct
{
   AllocatorIntf super; /* Inherits from AllocatorIntf */
   U8 buf[MAX_STRING_LEN];
} JParserAllocator;

#define JParserAllocator_constructor(o)                                 \
   AllocatorIntf_constructor((AllocatorIntf*)o,                         \
                             JParserAllocator_malloc,                   \
                             JParserAllocator_realloc,                  \
                             JParserAllocator_free)

/* Called one time */
static void*
JParserAllocator_malloc(AllocatorIntf* super, size_t* size)
{
   JParserAllocator* o = (JParserAllocator*)super;
   return *size <= MAX_STRING_LEN ? o->buf : 0;
}


/* Called when the one and only string buffer must grow. */
static void*
JParserAllocator_realloc(AllocatorIntf* super, void* memblock, size_t* size)
{
   JParserAllocator* o = (JParserAllocator*)super;
   (void)memblock;
   baAssert(memblock == o->buf);
   return *size <= MAX_STRING_LEN ? o->buf : 0;
}


/* Called when JParser terminates */
static void
JParserAllocator_free(AllocatorIntf* super, void* memblock)
{
   /* Do nothing */
   (void)super;
   (void)memblock;
}


/*
  BufPrint "flush" callback function used indirectly by JEncoder.
  The function is called when the buffer is full or if committed.
  See the reference manual for more information on the BufPrint class.
*/
static int
BufPrint_sockWrite(BufPrint* o, int sizeRequired)
{
   int status;
   SecCon* sc = (SecCon*)o->userData;
   (void)sizeRequired; /* Not used */
   /* Send JSON data to server */
   status = seSec_write(sc->ssl, &sc->sock, (U8*)o->buf, o->cursor);
   o->cursor = 0; /* Data flushed */
   if(status < 0)
   {
      xprintf(("Socket closed on write\n"));
      return status;
   }
   return 0; /* OK */
}

/* Parsed object member names cannot be larger than the following:
 */
#define MAX_MEMBER_NAME_LEN (10+1)


/* Size of buffer used by JDecoder and JEncoder */
#define IN_OUT_BUF_SIZE 256

/*
   M2MLED container object
 */
typedef struct
{
   JParserIntf super; /* Inherits from JParserIntf */
   BufPrint out; /* Used by JEncoder */
   JErr err;
   JEncoder encoder;
   JDecoder decoder;
   JParserAllocator pAlloc;
   JParser parser;
   SecCon* sc;
   /* Buffer used by JDecoder */
   U8 inBuf[IN_OUT_BUF_SIZE];

   /* The two message types sent from the server with payload data */
   union
   {
      MsgS S;
      MsgC C;
   } msg;
   int messageNumber;

   /* Buffer used by BufPrint via JEncoder */
   char outBuf[IN_OUT_BUF_SIZE];

   char memberName[MAX_MEMBER_NAME_LEN];
} M2MLED;


/* Send the device name and LED list (Ref-LED) to the online
 * web-service at startup.  This function enables the server to
 * present a LED web page, with LED buttons, that shows the LEDs
 * available in this device.
 */
static int
M2MLED_sendDevInfo2Server(M2MLED* o)
{
   int i, ledLen;
   const LedInfo* ledInfo = getLedInfo(&ledLen);
   JEncoder_beginArray(&o->encoder);
   JEncoder_setInt(&o->encoder,'R');
   JEncoder_beginObject(&o->encoder);
   /* Member 1 */
   JEncoder_setName(&o->encoder,"devname");
   JEncoder_setString(&o->encoder,getDevName());
   /* Member 2 */
   JEncoder_setName(&o->encoder,"leds");
   JEncoder_beginArray(&o->encoder);
   for(i = 0 ; i < ledLen ; i++)
   {
      JEncoder_set(&o->encoder, "{dss}",
                    JE_MEMBER(&ledInfo[i], id),
                    "color", ledType2String(ledInfo[i].color),
                    JE_MEMBER(&ledInfo[i], name));
   }
   JEncoder_endArray(&o->encoder);
   JEncoder_endObject(&o->encoder);
   JEncoder_endArray(&o->encoder);
   return JErr_isError(&o->err) || JEncoder_commit(&o->encoder) ? -1 : 0;
}



/* 
   Sends command 'S' to server when button clicked
 */
static int
M2MLED_sendSetLED(M2MLED* o, int ledId, int on)
{
   /*
     It is very unlikely that we would get a "send LED event" from say
     a button push on the device at the same time as we are in the
     process of parsing an incoming stream (a non completed
     object). However, we must ignore the event if this should occur
     since we use the same buffer for JDecoder and JEncoder. The
     solution is to use two buffers, one for JDecoder and one for
     JEncoder, in a system that sends and receives data at the same
     time.
   */
   if(JParser_getStatus(&o->parser) != JParsStat_NeedMoreData)
   {
      JEncoder_set(&o->encoder, "[d{db}]",
                   'S', /* message number */
                   "id", ledId, /* Cannot use helper macro JE_MEMBER */
                   "on", on);
      return JErr_isError(&o->err) || JEncoder_commit(&o->encoder) ? -1 : 0;
   }
   return 0; /* OK */
}


/*
   On idle, sends command 'P' to server
*/
static int
M2MLED_sendPing(M2MLED* o)
{
   /* The following would indicate that the connection is stuck */
   if(JParser_getStatus(&o->parser) == JParsStat_NeedMoreData)
   {
      return -1;
   }      
   JEncoder_set(&o->encoder, "[d]", 'P');
   return JErr_isError(&o->err) || JEncoder_commit(&o->encoder) ? -1 : 0;
}


/*
  Parser callback designed to manage the following value stream:

  [                 -- start array
     messageNumber, -- 'A', 'S', or 'C'
     messageObject  -- Delegated to chained parser callback
  ]                 -- end array
 */
static int
M2MLED_parserCallback(JParserIntf* super, JParserVal* v, int nLevel)
{
   M2MLED* o = (M2MLED*)super;
   if(nLevel) /* outer '[' and ']' will be at level 0 */
   {  /* We get here for messageNumber and messageObject */
      if(o->messageNumber) /* State: get messageObject */
      {
         /* Delegate to the JDecoder parser callback.
            Notice how we adjust the nesting level by removing outer array.
          */
         return JParserIntf_serviceCB((JParserIntf*)&o->decoder,v,nLevel-1);
      }
      else /* State: get messageNumber */
      {
         if(v->t != JParserT_Int)
         {
            xprintf(("Expected type 'int' for messageNumber\n"));
            return -1; /* Incorrect data from server */
         }
         o->messageNumber = v->v.d; /* Get message number */
         switch(o->messageNumber)
         {
            case 'A': /* Server Accepted the HTTP connection */
               /* No messageObject i.e. no payload */
               break;

            case 'S': /* Turn LED on/off */
               VALIDATE(JDecoder_get(&o->decoder,"{db}",
                                     JD_MNUM(&o->msg.S, id),
                                     JD_MNUM(&o->msg.S, on)));
               break;

            case 'P': /* Pong (response to ping) */
               /* No messageObject */
               break;

            case 'C': /* Server wants client to Close the connection */
               VALIDATE(JDecoder_get(&o->decoder,"{s}",
                                     JD_MSTR(&o->msg.C, msg)));
               break;

            default:
               setProgramStatus(ProgramStatus_InvalidCommandError);
               xprintf(("Received unknown command\n"));
               return -1;
         }
      }
   }
   else /* Basic validation of outer array */
   {
      if(v->t != JParserT_BeginArray && v->t != JParserT_EndArray)
      {
         xprintf(("Expected '[' or ']'\n"));
         return -1; /* Incorrect data from server */
      }
   }
   return 0; /* OK */
}
/* end */



/*
  Parse a chunk of data received on the socket stream
 */
static int
M2MLED_manage(M2MLED* o, U8* data, U32 dsize)
{
   int status;
   do
   {
      /*Method 'parse' triggers 'M2MLED_parserCallback' */
      status = JParser_parse(&o->parser, data, dsize);
      if(status) /* Complete object or error */
      {
         if(status > 0) /* A complete object parsed */
         {
            switch(o->messageNumber)
            {
               case 'A': /* Server Accepted the HTTP connection */
                  if( (status = M2MLED_sendDevInfo2Server(o)) == 0)
                  {
                     xprintf(("Browse to: "
                              "https://" SERVERNAME "/IoT/led/json/\n"));
                  }
                  break;

               case 'S': /* Turn LED on/off */
                  setLed(o->msg.S.id, o->msg.S.on);
                  status = 0; /* OK */
                  break;

               case 'P': /* Pong */
                  status = 0; /* OK */
                  break;

               case 'C': /* Server wants client to Close the connection */
                  setProgramStatus(ProgramStatus_CloseCommandReceived);
                  xprintf(("Connection close request from server: %s\n",
                           o->msg.C.msg));
                  /* status is 1: exit program in mainTask */
                  break;
               
               default:
                  baAssert(0); /* Managed in M2MLED_parserCallback */
            }
            /* Reset state machine in M2MLED_parserCallback */
            o->messageNumber = 0;
         }
         else /* Error */
         {
            /* Check 'enum JParsStat' in doc for actual values */
            xprintf(("JParser or parser callback error: %d\n",
                     JParser_getStatus(&o->parser)));
         }
      }
      /* else: Parser needs more data */
   } while(status == 0 && JParser_getStatus(&o->parser) == JParsStat_Done);
   
   /* Status: anything but 0 indicates that the connection must be closed */
   return status;
}
/* end */


/*
  Init the M2MLED container object
 */
static void
M2MLED_constructor(M2MLED* o, SecCon* sc)
{
   JParserIntf_constructor((JParserIntf*)o,  /* cast to base class */
                           M2MLED_parserCallback);
   BufPrint_constructor2(
      &o->out, o->outBuf, IN_OUT_BUF_SIZE, sc, BufPrint_sockWrite);
   JErr_constructor(&o->err);
   JEncoder_constructor(&o->encoder, &o->err, &o->out);
   JDecoder_constructor(&o->decoder, o->inBuf, IN_OUT_BUF_SIZE, 0);
   JParserAllocator_constructor(&o->pAlloc);
   JParser_constructor(&o->parser, (JParserIntf*)o, o->memberName,
                       MAX_MEMBER_NAME_LEN, (AllocatorIntf*)&o->pAlloc, 0);
   o->sc = sc;
   o->messageNumber = 0;
}


/*
  This example connects to a web server without requiring a HTTP
  client library, however, we still need to send a HTTP header since
  web servers only speak "HTTP". We do not need to do any buffering or
  parsing; we simply pump the following data out on the connected
  socket stream (Ref-A).

  The data will be parsed as valid HTTP by the receiving server and
  the server will then delegate the request to the web-service running
  on URL "http://SERVERNAME/IoT/led/json/". This service does not send
  back a HTTP response. Instead, the service on this URL converts (or
  morphs) the incoming request to a raw and persistent socket
  connection (Ref-B).

  Notice how easy it is to implement a proprietary password mechanism
  (Ref-C). The data below includes a "Device-Key", which must match
  the key used by the online web-service. This data is encrypted if
  sent over an HTTPS connection, using http://sharkssl.com.
*/
static const char httpCmd[] = {
   "GET /IoT/led/json/ HTTP/1.0\r\n" /* Send HTTP GET and path 2 service */
   "Host:" SERVERNAME "\r\n" /* Required since server is multihomed */
   "Device-Key:37840-48cd-4za35-jks2\r\n" /* Password (Ref-C) */
   "\r\n" /* End HTTP header */
};


/*
  The connect2Server function connects to SERVERNAME, sends the
  HTTP header, and enters a forever loop that can send data to the
  server and receive data from the server. The socket connection is
  maintained until the program is closed.  */
static int
connect2Server(SeCtx* ctx, SharkSsl* sharkSsl, int* retryConCounter)
{
   int rc,status;

   /* M2MLED is large and we do not want this to be on the stack. */
   static SecCon sc;
   static M2MLED m2m;

   xprintf(("Connecting to " SERVERNAME "...\n"));
   /* Port 443 is the secure listen port for web servers */
   setProgramStatus(ProgramStatus_Connecting);
   SOCKET_constructor(&sc.sock, ctx);
   status=se_connect(&sc.sock,SERVERNAME, 443);
   if(status)
   {
      const char* msg;
      switch(status)
      {
         case -1:
            msg="Socket error!";
            setProgramStatus(ProgramStatus_SocketError);
            break;
         case -2:
            msg="Cannot resolve IP address for " SERVERNAME ".";
            setProgramStatus(ProgramStatus_DnsError);
            break;
         default:
            msg="Cannot connect to " SERVERNAME ".";
            setProgramStatus(ProgramStatus_ConnectionError);
            break;
      }
      xprintf(("%s\n%s",
               msg,
               *retryConCounter > 0 || status == -1 ? "" :
               "Note: this client is not designed to connect via a proxy.\n"));
      return 1;
   }
   M2MLED_constructor(&m2m, &sc);
   sc.ssl = SharkSsl_createCon(sharkSsl);
   if( ! sc.ssl )
   {
      xprintf(("Cannot create SharkSslCon object.\n"));
      setProgramStatus(ProgramStatus_MemoryError);
      status = 1;
   }
   else
   {
#if SHARKSSL_ENABLE_SELECT_CIPHERSUITE == 1
      /* (Ref-CA)
        The following construction forces the server to authenticate itself by
        using an Elliptic Curve Certificate.

        CA_RTL_EC_256.pem is a Certificate Authority (CA) certificate
        and we use this certificate to validate that we are in fact
        connecting to realtimelogic.info and not someone pretending to
        be this server.

        The online server realtimelogic.info has two certificates
        installed: one standard RSA certificate, which you can see if
        you navigate to https://realtimelogic.info, and one Elliptic
        Curve Certificate (ECC).

        The online server is configured to favor the RSA certificate
        which will be presented to the client unless the client tells
        the server that it can only use ECC, at which point the server
        is forced to send its ECC certificate to the client.

        The following construction makes sure we only use ECC by
        either using a SharkSSL library compiled with ECC support only
        (no RSA) or by specifically setting a cipher using ECC.

        See the following link for more information:
        https://realtimelogic.com/ba/doc/en/C/shark/md_md_Certificate_Management.html
      */
      SharkSslCon_selectCiphersuite(
         sc.ssl, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
#endif
      /* Keep seeding (Make it more secure) */
      sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)sc.ssl);
      /* SSL is a client server protocol and we must initiate the
       * connection by sending SSL hello. The following function
       * (in selib.c) performs the initial SSL handshake.
       */
      setProgramStatus(ProgramStatus_SslHandshake);
      if((rc=seSec_handshake(sc.ssl, &sc.sock, 3000, SERVERNAME)) !=
#if SHARKSSL_CHECK_DATE
         SharkSslConTrust_CertCnDate
#else
         SharkSslConTrust_CertCn
#endif
         )
      {
         if(rc > 0)
         {
            xprintf(("Certificate received from %s not trusted!\n",SERVERNAME));
            setProgramStatus(ProgramStatus_CertificateNotTrustedError);
         }
         else
         {
            setProgramStatus(ProgramStatus_SslHandshakeError);
            xprintf(("SSL handshake failed\n"));
         }
         status = 1;
      }
      else
      {
         /* Send the initial HTTP header (Ref-A). */
         if(seSec_write(sc.ssl, &sc.sock,
                        (U8*)httpCmd, sizeof(httpCmd)-1) > 0)
         {  /* (Ref-B)
               The server does not send back a HTTP response. We
               * are at this point maintaining a persistent socket
               * connection with the web service at URL:
               * http://SERVERNAME/IoT/led/json/.
               */
            U8* buf;
            int pingTick=0; /* Ping server when idle */
            setProgramStatus(ProgramStatus_DeviceReady);
            while((rc=seSec_read(sc.ssl, &sc.sock,&buf,50)) >= 0)
            {
               if(rc) /* incomming data from server */
               {
                  /* Parse and manage data */
                  if( (status=M2MLED_manage(&m2m, buf, rc)) != 0)
                     break; /* Error */
                  pingTick=0;
                  *retryConCounter = 40;
               }
               else /* timeout (Ref-D) */
               {
                  int ledId,on;
                  if(setLedFromDevice(&ledId,&on)) /* LED button pressed */
                  {
                     if( (status=M2MLED_sendSetLED(&m2m, ledId, on)) != 0)
                        break; /* Error */
                  }
                  else if(++pingTick >= PING_TMO_IN_TICKS) /* 20 min */
                  {
                     if(pingTick == PING_TMO_IN_TICKS)
                     {
                        if( (status=M2MLED_sendPing(&m2m)) != 0)
                           break; /* Error */
                     }
                     else if(pingTick > PONG_TMO_IN_TICKS)
                     {
                        setProgramStatus(ProgramStatus_PongResponseError);
                        xprintf(("Timeout on expected pong msg\n"));
                        break;
                     }
                  }
               }
            }
         }
      }
      SharkSsl_terminateCon(sharkSsl, sc.ssl);
   }
   se_close(&sc.sock);
   xprintf(("\nServer connection closed!\n"));
   return status;
}


/* Main task will not return unless the connection to the online
 * server cannot be established (Ref-Ta).
 */
void
mainTask(SeCtx* ctx)
{
   SharkSsl sharkSsl;
   int retryConCounter = 0;

   SharkSsl_constructor(&sharkSsl,
                        SharkSsl_Client, /* Two options: client or server */
                        0,      /* Not using SSL cache */
                        1400,   /* initial inBuf size: Can grow */
                        2000);   /* outBuf size: Fixed */
   SharkSsl_setCAList(&sharkSsl, sharkSSL_New_RTL_ECC_CA); /* Ref-CA */
   /* It is very important to seed the SharkSSL RNG generator */
   sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)&sharkSsl);

   setProgramStatus(ProgramStatus_Starting);
   /* Connect and then reconnect, if possible. */
   while(connect2Server(ctx, &sharkSsl,&retryConCounter) != 1 &&
         retryConCounter > 0)
   {
      retryConCounter--;
      setProgramStatus(ProgramStatus_Restarting);
      millisleep(3000);
   }
   SharkSsl_destructor(&sharkSsl);
}

