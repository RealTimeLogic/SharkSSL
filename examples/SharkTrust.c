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
 *   PROGRAM MODULE
 *
 *   $Id: SharkTrust.c 5589 2024-11-12 21:59:54Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2021
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

 SharkTrust and Minnow Server Example

 SharkTrust:    https://realtimelogic.com/services/SharkTrust/
 Minnow Server: https://realtimelogic.com/products/sharkssl/minnow-server/

 This example shows how to use a SharkTrust service to dynamically
 update the certificate in a running Minnow Server.  When to call the
 SharkTrust service is managed by a rudimentary clock maintained by
 the global variable 'sharkTrustSleepCounter'.

 The SharkTrust service name used is sharktrustEC.realtimelogic.com,
 which uses an ECC certificate. This certificate was signed by the CA
 whose public certificate is stored in the header file:
 New-RTL-ECC-ca-pem.h.

 A SharkSsl object maintains input/output buffers, thus allocating
 memory after calling SharkSsl_constructor. We cannot use the SharkSsl
 server object for client requests; thus in order to save memory, the
 server object is terminated prior to creating a client object and
 calling the SharkTrust service.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <MSLib.h>

/* Include the auto generated code for de-obfuscating the zone key.
   Generate the header file as follows:

    1: Navigate to https://your-domain/login
    2: Login using your credentials
    3: Navigate to https://your-domain/cgen
    4: Download the generated header file and place file in the
       examples directory

   (*) 'your-domain' is the domain (the zone name) you registered with the
   SharkTrust service.
*/
#include "getzkey.ch"


/* Default server cert. Used if SharkTrust interaction fails. */
#include "certificates/device_RSA_2048.h"

/* CA cert for SharkTrustEC.realtimelogic.com */
#include "certificates/CA_ISRG_Root_X1.h"


/* The SharkTrust service instance name. Change this macro when you
   have your own SharkTrust service instance.
*/
#define SHARK_TRUST_SERVICE_NAME "equip.run"


/* 
   Timeout (in milliseconds) used by select() and read(). The timeout
   is used as the base for a rudimentary clock, which in turn drives
   the SharkTrust time poll calculation.
*/
#define SLEEP_TMO 50


/*
  The following functions are available for non embedded use.
 */
#if  HOST_PLATFORM == 1

#ifdef _WIN32
#include <WS2tcpip.h>
#endif

/************************* Helper functions ******************************/


/* If denied access */
static void terminate()
{
   printf("Press Enter to exit program\n");
   getchar();
   exit(1);
}


/* Returns the local (LAN) IP address.
   This function works when the 'SOCKET' type is 'int' (See selibplat.h)
 */
char* getIpAddr(SOCKET* sock)
{
   struct sockaddr_in in;
   socklen_t size=sizeof(struct sockaddr_in);
   int status=getsockname(*sock, (struct sockaddr *)&in, &size);
   if(status)
   {
      perror("getIpAddr");
      terminate();
   }
   return inet_ntoa(in.sin_addr);
}


/* This function should return a unique name for this particular
   device. The function may for example return the MAC address's 3
   last bytes (as hex).  This example simply uses the hostname.
*/
static const char*
deviceName(void)
{
   static char buf[30]={""};
   if(!buf[0])
   {
      gethostname(buf, sizeof(buf));
   }
   return buf;
}

/* Load the persistently stored device key (X-Dev)
 */
static int
readDeviceKey(char deviceKey[20])
{
   FILE* fp = fopen("DEVICE.KEY", "rb");
   if(fp)
   {
      size_t items = fread(deviceKey, 20, 1, fp);
      fclose(fp);
      return items == 1 ? 0 : -1;
   }
   return -1;
}

/* Persistently store the device key
 */
static void
saveDeviceKey(char deviceKey[20])
{
   FILE* fp = fopen("DEVICE.KEY", "wb");
   fwrite(deviceKey, 20, 1, fp);
   fclose(fp);
}



/* Example code and selib.c use function xprintf.
 */
void _xprintf(const char* fmt, ...)
{
   va_list varg;
   va_start(varg, fmt);
   vprintf(fmt, varg);
   va_end(varg);
#ifndef _WIN32
   fflush(stdout);
#endif
}


/* Remove this function and replace with a task/thread that calls
 * function mainTask (Ref-Ta). Note: function mainTask will not return
 * unless the connection cannot be established or if the server wants
 * the connection to close. The caller can for example toggle all
 * LEDs, in an endless loop, if this function returns.
 */
#ifndef NO_MAIN
int
main()
{

   /* Info printed to the console when the program starts
    */
   static const char info[] = {
      "SharkTrust and Minnow Server Demo.\n"
      "\n"
   };
   xprintf(("%s",info));

#ifdef _WIN32
   /* Windows specific: Start winsock library */
   { WSADATA wsaData; WSAStartup(MAKEWORD(1,1), &wsaData); }
#endif
   
   mainTask(0);
   xprintf(("Exiting...\n"));
   return 0;
}
#endif /* NO_MAIN */

#else  /* HOST_PLATFORM */
/* You can run this example in an embedded system, but the following
 * must be implemented:
*/
extern void terminate();
extern char* getIpAddr(SOCKET* sock);
extern const char* deviceName(void);
extern int readDeviceKey(char deviceKey[20]);
extern void saveDeviceKey(char deviceKey[20]);
#endif /* HOST_PLATFORM */


/*********************** Generic Helper functions ***************************/

#if defined(B_LITTLE_ENDIAN)
static void
netConvU16(U8* out, const U8* in)
{
   out[0] = in[1];
   out[1] = in[0];
}
static void
netConvU32(U8* out, const U8* in)
{
   out[0] = in[3];
   out[1] = in[2];
   out[2] = in[1];
   out[3] = in[0];
}
#elif defined(B_BIG_ENDIAN)
#define netConvU16(out, in) memcpy(out,in,2)
#define netConvU32(out, in) memcpy(out,in,4)
#else
#error ENDIAN_NEEDED_Define_one_of_B_BIG_ENDIAN_or_B_LITTLE_ENDIAN
#endif



/****************************************************************************
 **************************----------------------****************************
 *************************| SharkTrust Interface |****************************
 **************************----------------------****************************
 ****************************************************************************/

/* Container object used by the functions below
 */
typedef struct {
   SharkSsl ssl; /* SharkSsl client object */
   SOCKET sock; /* Connection to the SharkTrust service */
   SharkSslCon* scon; /* The secure part associated with sock */
   U8* sendBuf; /* index pointer into SharkSSL's zero copy API's send buf */
   U8* recBuf; /* pointer to start of SharkSSL's receive buffer */
} SharkTrustCon;


/* SharkTrust response codes
 */
#define RSP_SUCCESS     0
#define RSP_FORBIDDEN   1
#define RSP_UNKNOWN     2
#define RSP_PROCESSING  3
#define RSP_SERVERERROR 4
#define RSP_CLIENTERROR 5

/* Ticks down to zero when a command is sent to SharkTrust */
static U32 sharkTrustSleepCounter=0;
/* The certificate and private key received from the SharkTrust service */
static U8* sharkCert=0;



/* All HTTP SharkTrust commands start with:
 */
static const char sharkTrustRequestHeader[]={
   "GET /device/ HTTP/1.0\n"
   "X-Key: " /* Start of the header */
};

/* Register device */
static const char cmdRegister[]={
   "Register\n" /* X-Command: */
   "X-Info: SharkSSL SharkTrust Client Demo\n" /* Optional */
   "X-IpAddress: " /* Start of the header */
};

/* Download certificate */
static const char cmdGetCert[]={
   "GetCertificate\n" /* X-Command: */
   "X-CertType: Shark\n"
   "X-IpAddress: " /* Start of the header */
};


/* We are using the zero copy API for sending a response. The SharkSSL
 * response buffer is 3K and we simply assume the buffer is
 * sufficiently large for creating the HTTPS headers. This function
 * copies the data and advances SharkSSL write buffer pointer.
*/
static void
pushData(SharkTrustCon* stcon, const char* data, int len)
{
   if(len < 0) len = strlen((char*)data);
   memcpy(stcon->sendBuf, data, len);
   stcon->sendBuf+=len;
}


/* Push HTTP key/value header onto the SharkSSL send buffer.
 */
static void
pushHttpHeader(SharkTrustCon* stcon, const char* key, const char* val)
{
   if(key)
   {
      pushData(stcon, key, strlen(key));
      pushData(stcon, ":", 1);
   }
   pushData(stcon, val, strlen(val));
   pushData(stcon, "\n", 1);
}


/* 1: Open a secure link to the SharkTrust service.
   2: Send the data in the sharkTrustRequestHeader[]
   3: send the zone key
   4: Send the key value for the X-Command HTTP header.
 */
static int
openSharkTrustCon(SharkTrustCon* stcon)
{
   int status=se_connect(&stcon->sock,SHARK_TRUST_SERVICE_NAME,443);
   if(status)
   {
      const char* msg;
      switch(status)
      {
         case -1:
            msg="Socket error";
            break;
         case -2:
            msg="Cannot resolve IP address for " SHARK_TRUST_SERVICE_NAME;
            break;
         default:
            msg="Cannot connect to " SHARK_TRUST_SERVICE_NAME;
            break;
      }
      xprintf(("%s.\n",msg));
      return -1;
   }
   if(stcon->scon)
      SharkSsl_terminateCon(&stcon->ssl, stcon->scon);
   stcon->scon = SharkSsl_createCon(&stcon->ssl);
   if(!stcon->scon)
   {  /* alloc failed */
      se_close(&stcon->sock);
      return 0;
   }
   status=seSec_handshake(
      stcon->scon,&stcon->sock,3000,SHARK_TRUST_SERVICE_NAME);
#if SHARKSSL_CHECK_DATE
   if(SharkSslConTrust_CertCnDate != status)
#else
   if(SharkSslConTrust_CertCn != status)
#endif
   {
      if(status > 0)
      {
         xprintf(("\nCertificate received from %s not trusted!\n\n",
                  SHARK_TRUST_SERVICE_NAME));
      }
      else
      {
         xprintf(("\nSSL handshake failed\n\n"));
      }
      return -1;
   }
   stcon->sendBuf = SharkSslCon_getEncBufPtr(stcon->scon); /*zero copy API*/
   pushData(stcon, sharkTrustRequestHeader, sizeof(sharkTrustRequestHeader)-1);
   getZoneKey(stcon->sendBuf);
   stcon->sendBuf += 64;
   pushData(stcon, "\nX-Command: ", 12);
   return 0;
}


/* Get the complete SharkTrust response and validate the binary
 * response header.
 */
static int
getSharkTrustResponse(SharkTrustCon* stcon)
{
   int len;
   int status=-1;

   /* Flush HTTP Header request */
   pushData(stcon, "\n", 1); /* End of HTTP header */
   seSec_write(stcon->scon,&stcon->sock,
               0, /* Using zero copy API */
               stcon->sendBuf-SharkSslCon_getEncBufPtr(stcon->scon));

   len=seSec_read(stcon->scon,&stcon->sock,&stcon->recBuf,5000);
   if(len < 4)
   {
      xprintf(("SharkTrustResp: Socket error %d\n",len));
   }
   else
   {
      if(stcon->recBuf[0] != 0xFF || stcon->recBuf[1] != 0x55)
      {
         xprintf(("Response is not from SharkTrust!\n"
                  "This client is not designed to connect via a proxy.\n"));
      }
      else
      {
         const char* msg=0;
         switch(stcon->recBuf[2])
         {
            case RSP_SUCCESS: msg="Success"; break;
            case RSP_FORBIDDEN: msg="Forbidden"; break;
            case RSP_UNKNOWN: msg="Unknown"; break;
            case RSP_PROCESSING: msg="Processing"; break;
            case RSP_SERVERERROR: msg="ServerError"; break;
            case RSP_CLIENTERROR: msg="ClientError"; break;
            default:
               xprintf(("Invalid SharkTrust response %d\n",stcon->recBuf[2]));
               terminate();
         }
         xprintf(("SharkTrust response %d : %s\n",stcon->recBuf[2], msg));

         /* The following two error codes are fatal in this example,
          * however, the code RSP_FORBIDDEN can be a user error in
          * systems where the user sets up his own zone key.
          */

         switch(stcon->recBuf[2])
         {
            case RSP_FORBIDDEN: /* Invalid SHARK_TRUST_ZONE_KEY */
            case RSP_CLIENTERROR: /* Your client is not working (bug) */
               terminate();
         }
         status = 0;
      }
   }

   /* Close socket, but keep stcon->scon (we need the buffer)
    */
   se_close(&stcon->sock);

   return status;
}




/* Registers the device if not registered (no device key) and sends a
 * GetCertificate request. The GetCertificate response may fail if the
 * certificate is not ready. This function will be called again, until
 * a certificate is installed. The timeout for each call is controlled
 * by the global variable 'sharkTrustSleepCounter'.
 */
static void
getCertificate(SharkTrustCon* stcon)
{
   char deviceKey[21];
   U16 len;
   U32 secondsUntilExp; /* When cert expires */
   if( ! readDeviceKey(deviceKey) )
   {
      deviceKey[20]=0; /* So we can use it as a string */
   }
   else  /* If not registered */
   {
     L_mustRegister:
      if(openSharkTrustCon(stcon)) /* Prepare command Register */
         return;
      xprintf(("Sending Command: Register\n"));
      pushData(stcon, cmdRegister, sizeof(cmdRegister)-1);
      pushHttpHeader(stcon,0,getIpAddr(&stcon->sock));
      pushHttpHeader(stcon,"X-Name",deviceName());
      if(getSharkTrustResponse(stcon))
         return;
      /*
        Response can be one of: Success, Forbidden, ServerError, or
        ClientError.
        getSharkTrustResponse() manages: Forbidden and ClientError
      */
      if(stcon->recBuf[2]) /* Not OK: Can only be ServerError */
         return;
      /* Device key starts at position 4 and ends at 24 */
      memcpy(deviceKey,stcon->recBuf+4, 20);
      saveDeviceKey(deviceKey);
      deviceKey[20]=0; /* stringify */
      xprintf(("Our new device Key (X-Dev) %s\n",deviceKey));
   }

   /* The following code section, which fetches the full Domain Name
     (DN), is not required. The purpose with the code below is to
     print out the full domain name. Copy the printed URL and paste
     it into your browser's address field.
    */
   {
      static int oneTime=0;
      if(oneTime == 0)
      {
         oneTime=1;
         if( ! openSharkTrustCon(stcon) ) /* Prepare command GetDN */
         {
            xprintf(("Sending Command: GetDN\n"));
            pushHttpHeader(stcon,0, "GetDN");
            pushHttpHeader(stcon,"X-Dev",deviceKey);
            if( ! getSharkTrustResponse(stcon) &&
                RSP_SUCCESS == stcon->recBuf[2])
            {
               netConvU16((U8*)&len, stcon->recBuf+4); /* DN length */
               stcon->recBuf[6+len]=0; /* convert to string */
               xprintf(("--------------------------------------------\n"));
               xprintf(("Your server URL: https://%s\n",stcon->recBuf+6));
               xprintf(("Test DNS as follows: ping %s\n",stcon->recBuf+6));
               xprintf(("--------------------------------------------\n"));
            }
         }
      }
   }

   if(openSharkTrustCon(stcon)) /* Prepare command GetCertificate */
      return;
   xprintf(("Sending Command: GetCertificate\n"));
   pushData(stcon,cmdGetCert,sizeof(cmdGetCert)-1);
   pushHttpHeader(stcon,NULL, getIpAddr(&stcon->sock));
   pushHttpHeader(stcon,"X-Dev",deviceKey);
   /*
     Response can be any of the response codes
     getSharkTrustResponse manages: Forbidden and ClientError
   */
   if(getSharkTrustResponse(stcon))
      return;
   switch(stcon->recBuf[2])
   {
      case RSP_UNKNOWN: /* our device key has been invalidated by server */
         goto L_mustRegister;
      case RSP_PROCESSING:
         xprintf(("Certificate not ready\n"));
      case RSP_SERVERERROR:
         return;
   }
   /* Success */
   netConvU32((uint8_t*)&secondsUntilExp, stcon->recBuf+4);
   printf("Certificate expires in %u days\n",secondsUntilExp/86400);
   if(secondsUntilExp > 60*60*24*15)
      secondsUntilExp -= 60*60*24*15; /* 15 days before */
   else
      secondsUntilExp = 60*60*12;
   sharkTrustSleepCounter = secondsUntilExp * 1000 / SLEEP_TMO;
   netConvU16((uint8_t*)&len, stcon->recBuf+8);
   if(sharkCert) /* if old cert */
      baFree(sharkCert);
   sharkCert=(U8*)baMalloc(len);
   if(!sharkCert)
      return;
   memcpy(sharkCert,stcon->recBuf+10,len);
}


/* Prepares a SharkTrust request by setting up a TLS client object.

   ctx: Used in non RTOS systems.
   sslServer: uninitialized TLS server object.

   The sslServer is initialized as a TLS server object after sending a
   request to SharkTrust, thus minimizing memory use.  We either add a
   self signed certificate or the SharkTrust generated certificate to
   the sslServer object. The self signed certificate is added if the
   SharkTrust request failed, which it will do initially.
 */
static void
initiateCertReq(SeCtx* ctx, SharkSsl* sslServer)
{
   SharkTrustCon stcon;
   sharkTrustSleepCounter=0;
   /* The main TLS object used by the WebSocket server. Ideally, the
      initial inBuf size should be large enough to house the
      SharkTrust response message, which is around 3500 bytes when an
      RSA certificate and key is received in the SharkSSL format from
      the SharkTrust service.
   */
   SharkSsl_constructor(&stcon.ssl,
                        SharkSsl_Client,
                        0,      /* Not using SSL cache */
                        4000,   /* initial inBuf size: cert rsp ~3500 */
                        3000);    /* outBuf size : must fit SharkTrust cert. */
   /* We must validate the SharkTrust server's certificate;
      sharkSSL_CA_ISRG_Root_X1 -> header CA_ISRG_Root_X1.h
   */
   SharkSsl_setCAList(&stcon.ssl, sharkSSL_CA_ISRG_Root_X1);

   SOCKET_constructor(&stcon.sock, ctx); /* Set invalid state */
   stcon.scon=0;
   getCertificate(&stcon); /* Do the SharkTrust communication */
   if(stcon.scon)
      SharkSsl_terminateCon(&stcon.ssl, stcon.scon);
   SharkSsl_destructor(&stcon.ssl);

   /* Initialize the TLS object used by the WebSocket server.
     The in buffer (inBuf) can grow dynamically if too small, but we
     do not need a large buffer since the client does not send a
     certificate, hence the buffer will not need to be larger than 500.
    */
   SharkSsl_constructor(sslServer,
                        SharkSsl_Server,
                        10,   /* SSL cache size */
                        500,  /* inBuf size */
                        3500); /*outBuf size is fixed and must fit server cert*/


   if(sharkCert)
   {
      xprintf(("Installing certificate fetched from SharkTrust\n"));
      SharkSsl_addCertificate(sslServer, sharkCert);
   }
   else
   {
      xprintf(("Installing embedded default certificate\n"));
      SharkSsl_addCertificate(sslServer, sharkSSL_RTL_device);
   }
   if(0 == sharkTrustSleepCounter) /* if not set by getCertificate */
   {
      sharkTrustSleepCounter = 70 * 1000 / SLEEP_TMO; /* 70 seconds default */
      xprintf(("Next SharkTrust HTTP poll in 70 seconds\n"));
   }
}


/****************************************************************************
 **************************----------------------****************************
 *************************|  Minnow Server App  |****************************
 **************************----------------------****************************
 ****************************************************************************/


/* The web page opens a WebSocket connection to the origin server and
 * inject incmming WebSocket data into a <span> HTML element.
 */

static const char theOneAndOnlyPage[] = {
"<html>"
  "<body>"
    "<h1>SharkTrust Demo</h1>"
    "<p>Next SharkTrust poll in <span>?</span> ticks.</p>"
  "</body>"
  "<script src='https://code.jquery.com/jquery-3.4.1.slim.min.js'></script>"
  "<script>"
     "$(()=>{"
       "let l = window.location;"
       "let ws=new WebSocket('wss://'+l.hostname+(l.port?(':'+l.port):''));"
       "ws.onmessage=(evt)=>$('span').html(evt.data);"
     "});"
  "</script>"
"</html>"
};

/* Returns theOneAndOnlyPage[] for any URL */
static int
fetchPage(void* hndl, MST* mst, U8* path)
{
   U8* sbuf=MST_getSendBufPtr(mst); /* Using zero copy SharkSSL API */
   int blen=MST_getSendBufSize(mst);
   int len=blen;
   /* Copy HTTP header to sbuf */
   msRespCT(sbuf,&len, sizeof(theOneAndOnlyPage)-1, 0);
   /* Flush HTTP header (zero copy api) */
   MST_write(mst, 0, blen - len);
   /* Send the HTML page */
   MST_write(mst, (U8*)theOneAndOnlyPage, sizeof(theOneAndOnlyPage)-1);

   (void)hndl; /* not used */   
   (void)path; /* Ignore requested path (URL) */   
   return 1; /* Any URL is OK */
}


/* Tries to open port 443 and if this fails, tries to open a server
 * socket in the range 9442 - 9459.
 */
static int
openServerSock(SOCKET* sock)
{
   int status;
   U16 port;
#ifdef MS_SEC
   port=443;
#else
   port=80;
#endif
   status = se_bind(sock, port);
   if(status)
   {
      port=9442;
      while(status == -3 && ++port < 9460)
         status = se_bind(sock, port);
   }
   if(status)
      xprintf(("Cannot open server listening port: %d\n", status));
   else
      xprintf(("WebSocket server listening on %d\n", (int)port));
   return status;
}


/* Runs as long as we have a WebSocket connection. 

   The WS server waits SLEEP_TMO, updates the sharkTrustSleepCounter,
   and sends the counter to the client. The code shows how a
   rudimentary clock can be constructed for keeping track of when to
   renew the certificate. The counter only counts down to zero and
   stops. The certificate is not updated when we have an active WS
   connection.

   Notice: the WS server ignores incoming data;
   theOneAndOnlyPage[] is not sending any data.
 */
static void
runWebSocketServer(MS* ms, WssProtocolHandshake* wph)
{
   int rc; 
   if( ! MS_webServer(ms,wph) )
   {
      U8* buf; 
      xprintf(("New WS connection\n"));
      while((rc=MS_read(ms,&buf,SLEEP_TMO)) >= 0)
      {
         if(rc) /* incomming data from server */ 
         {
            xprintf(("Received = %d\n",rc));
         }
         else /* timeout (Ref-D) */
         {
            if(sharkTrustSleepCounter > 0)
            {
               sharkTrustSleepCounter--;
               if(sharkTrustSleepCounter % 5 == 0)
               {
                  char b[20];
                  sprintf(b,"%u", sharkTrustSleepCounter);
                  MS_writeText(ms,b,strlen(b));
               }
            }
         }
      }
   }
   xprintf(("Closing WS connection\n"));
}


void
mainTask(SeCtx* ctx)
{
   /* The main TLS object used by the WebSocket server.
      This object is initialized in initiateCertReq.
   */
   static SharkSsl sharkSsl;
   WssProtocolHandshake wph={0};
   static SOCKET listenSock;
   static SOCKET sock;
   static MS ms;
   SOCKET* listenSockPtr = &listenSock;
   SOCKET* sockPtr = &sock;
   int status;
   wph.fetchPage = fetchPage;
   se_disableTrace(TRUE); /* Less printouts */
   MS_constructor(&ms);
   SOCKET_constructor(listenSockPtr, ctx);
   SOCKET_constructor(sockPtr, ctx);

   if(openServerSock(listenSockPtr))
      return;

   /* It is very important to seed the SharkSSL RNG generator */
   sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)&sharkSsl);

   /* Send a message to SharkTrust and initialize sharkSsl
    */
   initiateCertReq(ctx, &sharkSsl);

   xprintf(("Minnow Server is running and waiting for connections.\n"));
   for(;;)
   {
      status=se_accept(&listenSockPtr, SLEEP_TMO, &sockPtr);
      if(status == 0)
      {
         /* Our rudimentary clock */
         if(sharkTrustSleepCounter == 0)
         {
            /* Time to send a request to the SharkTrust service.
               We must first terminate the old SharkSsl object.
            */
            SharkSsl_destructor(&sharkSsl);
            /* All buffers released and sharkSsl is now uninitialized.
               Function initiateCertReq() creates a new TLS server object.
            */
            initiateCertReq(ctx, &sharkSsl);
         }
         else
            sharkTrustSleepCounter--;
      }
      else if(status == 1)
      {
         SharkSslCon* scon = SharkSsl_createCon(&sharkSsl);
         if(scon)
         {
            /* Keep seeding (make it more secure) */
            sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)scon);
            MS_setSharkCon(&ms, scon, sockPtr);
            runWebSocketServer(&ms, &wph);
            SharkSsl_terminateCon(&sharkSsl, scon);
         }
         else
            xprintf(("Cannot create SharkSslCon object.\n"));
         se_close(sockPtr);
      }
      else
      {
         /* We get here if 'accept' fails. This is probably where you reboot. */
         se_close(listenSockPtr);
         break;
      }
   }
}
