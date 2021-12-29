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
 *   $Id: Chat-MQTT.c 4972 2021-12-27 19:37:51Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2015 - 2021
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
 *               https://realtimelogic.com
 ****************************************************************************
 
 SharkMQTT Chat Example Program

The example program is designed for console mode and can run on
HLOS such as Windows and Linux.

The chat example can operate in two modes:

* Mode 1 (the default): connects to broker.emqx.io
* Mode 2 (when LOCALHOST_TEST is defined): connects to a broker
  running on the same computer as the client -- i.e. connect to localhost.

Mode 1: The client connects to the public broker: broker.emqx.io.
Details: https://mntolia.com/10-free-public-private-mqtt-brokers-for-testing-prototyping/

Mode 2: The client connects to a broker running on localhost. You must
setup a broker on your own computer such as the Mosquitto broker. We
suggest that you download the example bundle from
https://realtimelogic.com/products/sharkmqtt/ and use the
pre-configured Mosquitto broker. The broker is configured for ECC (not
RSA) certificates. The broker is also configured such that a X.509
certificate is required from all clients connecting to the broker. In
other words, this example program shows how to use dual X.509
certificate authentication.


*** MQTT unique ID:
The MAC address is used for providing a unique ID. Starting a second
chat instance on the same computer makes the broker close the
connection to the first instance. However, the chat example is
designed to reconnect automatically, thus you will get an endless loop
of connect/disconnect between the two chat programs. You can run
multiple chat programs on separate computers or you can provide a one
character unique ID for each chat client started. For example, to
start two chat examples on the same computer with unique IDs, open a
console Window and start the examples as follows:

Windows:
  chat-SharkMQTT 1
  chat-SharkMQTT 2

Linux:
  chat-SharkMQTT eth0 1
  chat-SharkMQTT eth0 2
*/

/* MQTT broker and port number */
#ifdef LOCALHOST_TEST
#define MQTT_BROKER "localhost"
#define MQTT_BROKER_PORT 1883
#define MQTT_USERNAME "SharkMQTT"
#define MQTT_PASSWORD "pwd"
#else
#define MQTT_BROKER "broker.emqx.io"
#define MQTT_BROKER_PORT 8883
/* Not used: public broker */
#define MQTT_USERNAME ""
#define MQTT_PASSWORD ""
#endif

#include "SharkMQTT.h"
#include <stdio.h>
#include <stddef.h>


/*                   sharkSslCAList (Ref-CA)

The data from the include file below is a CA (Certificate Authority)
Root Certificate. The CA enables SharkSSL to verify the identity of
the broker. The broker must use a certificate signed with this CA.

The Certification Authority Root Certificate was
converted to 'sharkSslCAList' as follows:
SharkSSLParseCAList CA_RTL_EC_256.pem > CA_RTL_EC_256.h

An introduction to certificate management can be found here:
https://realtimelogic.com/blog/2013/10/Certificate-Management-for-Embedded-Systems
*/

/* Validate (authenticate) the broker's certificate by using one of: */
#ifdef LOCALHOST_TEST
#ifdef USE_RSA
#include "certificates/CA_RTL_RSA.h"
#else
/* Real Time Logic's ECC root cert (signed by us) */
#include "certificates/CA_RTL_EC_256.h"
#endif
#else
/* List of common RSA root certs (public Certificate Authorities) */
#include "CA-list.h"
#endif


/* Used if broker requires authentication. Search for
 * sharkSslECCert_device in the code below.
 *
 */
#ifdef USE_RSA
#include "certificates/device_RSA_2048.h"
#else
#include "certificates/device_EC_256.h"
#endif


static char*
bin2Hex(char* out, const U8 in) 
{
   static const char hexTable[] = { 
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f' };
   out[0] = hexTable[(in) >> 4]; 
   out[1] = hexTable[(in) & 0x0f];
   return out+2;
}

static void
printMsg(const U8* msg, int len)
{
   while(len--)
      xprintf(("%c",*msg++));
}


/****************************************************************************
 **************************-----------------------***************************
 ************************| PLATFORM SPECIFIC CODE |**************************
 **************************-----------------------***************************
 ****************************************************************************/

#if HOST_PLATFORM

/*

  Windows/Linux code for non blocking reading of keyboard input and code
  for fetching a unique ID for the MQTT client.

 */

#ifdef _WIN32
// For calculating unique ID
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")
#endif


/* The following must be adapted to the device/eval-board */

#include <stdio.h>

/* Macro xprintf redirects to this function.
 */
void
_xprintf(const char* fmt, ...)
{
   va_list varg;
   va_start(varg, fmt);
   vprintf(fmt, varg);
   va_end(varg);
}

/* Function pollkb requires non blocking keyboard I/O. The following
 * code sets this up for WIN and UNIX.
 */
#include <ctype.h>
#ifdef _WIN32
#include <conio.h>
#define xkbhit _kbhit
#define xgetch  _getch
#define pause() Sleep(1000)
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <termios.h>

#define pause() sleep(2)

/* UNIX kbhit and getch simulation */
static int
xkbhit()
{
   struct timeval tv = { 0L, 0L };
   fd_set fds;
   struct termios orgTs;
   struct termios asyncTs;
   int set;
   tcgetattr(0, &orgTs);
   memcpy(&asyncTs, &orgTs, sizeof(asyncTs));
   cfmakeraw(&asyncTs);
   asyncTs.c_oflag=orgTs.c_oflag;
   tcsetattr(0, TCSANOW, &asyncTs);
   FD_ZERO(&fds);
   FD_SET(STDIN_FILENO, &fds);
   set = select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
   tcsetattr(0, TCSANOW, &orgTs);
   return set;
}

static int xgetch()
{
   int r;
   unsigned char c;
   if ((r = read(0, &c, sizeof(c))) < 0)
      return r;
   if(c == 3) /* CTRL-C Linux */
      exit(0);
   return c;
}
 

static void
die(const char* fmt, ...)
{
   va_list varg;
   va_start(varg, fmt);
   vprintf(fmt, varg);
   va_end(varg);
   printf("\n");
   exit(1);
}

static void
getMacAddr(U8 macaddr[6], const char* ifname)
{
   char buf[8192] = {0};
   struct ifconf ifc = {0};
   struct ifreq *ifr = NULL;
   int sck = 0;
   int nInterfaces = 0;
   int i = 0;
   struct ifreq *item=0;
   struct sockaddr *addr;
   /* Get a socket handle. */
   sck = socket(PF_INET, SOCK_DGRAM, 0);
   if(sck < 0) 
      die("socket: %s",strerror(errno));
   /* Query available interfaces. */
   ifc.ifc_len = sizeof(buf);
   ifc.ifc_buf = buf;
   if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) 
      die("ioctl(SIOCGIFCONF) %s", strerror(errno));
   /* Iterate through the list of interfaces. */
   ifr = ifc.ifc_req;
   nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
   for(i = 0; i < nInterfaces; i++) 
   {
      unsigned long ipaddr;
      item = &ifr[i];
      addr = &(item->ifr_addr);
      /* Get the IP address*/
      if(ioctl(sck, SIOCGIFADDR, item) < 0) 
      {
         perror("ioctl(OSIOCGIFADDR)");
         continue;
      }
      ipaddr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
      if(0x100007F == ipaddr || 0 == ipaddr)
         continue;
      /* Get the MAC address */
      if(ioctl(sck, SIOCGIFHWADDR, item) < 0) {
         perror("ioctl(SIOCGIFHWADDR)");
         continue;
      }
      break;
   }
   close(sck);   
   if(i == nInterfaces)
      die("Cannot get a MAC address\n");
   memcpy(macaddr, item->ifr_hwaddr.sa_data, 6);
}
#endif /* Endif UNIX/Linux specific code */

/* Platform specific function for non blocking keyboard read.
 */
static int pollkb(void)
{
   if(xkbhit())
   {
      int c = xgetch();
      return c=='\r' ? '\n' : c;
   }
   return 0;
}

/* Fetch the unique ID required by MQTT. We use the MAC address with
   an optional seed value thus making it possible to run more than one
   instance on the same computer.

   buf must be no less than 20 bytes;
 */
#ifndef NO_MAIN
static void
getClientId(char* buf,int argc, char* argv[])
{
   int uuidLen,i;
#ifdef _WIN32
   WSADATA wsaData;
   UUID winid;
   char uuid[8];
   (void)argc;
   (void)argv;
   uuidLen=8;
   /* Windows specific: Start winsock library */
    WSAStartup(MAKEWORD(1,1), &wsaData);
   if(RPC_S_OK == UuidCreateSequential(&winid))
      memcpy(uuid,winid.Data4,8);
   else
      memset(uuid,0,8);
#else
   char uuid[6];
   uuidLen=6;
   getMacAddr((U8*)uuid, argc > 1 ? argv[1] : "eth0");
#endif
   for(i = 0; i < uuidLen ; i++)
      buf=bin2Hex(buf,uuid[i]);
   *buf = 0;
}
#endif

#define initClientId()
#ifdef NO_MAIN
static const char* clientId="FIXME-set-unique-id";
#else
static char clientId[20];
#endif

/*
  Windows: chat-SharkMQTT [id]
  Linux: chat-SharkMQTT [network [id]]
*/
#ifndef NO_MAIN
int
main(int argc, char* argv[])
{
#ifdef _WIN32
   int ix = 1;
#else
   int ix = 2;
#endif
   getClientId(clientId+1,argc,argv);
   if(argc > ix)
      clientId[0] = argv[ix][0];
   else
      clientId[0] = '#';
   mainTask(0);
   return 0;
}
#endif

#else /* HOST_PLATFORM */

static char clientId[2*6+1];

/* Must fetch MAC addr */
extern int getUniqueId(const char** id);
extern int pollkb(void);
#define pause()


static void initClientId(void)
{
   const char* id;
   char* ptr = clientId;
   if(6 == getUniqueId(&id))
   {
      int i;
      for(i = 0; i < 6 ; i++)
         ptr=bin2Hex(ptr,id[i]);
      *ptr = 0;
   }
   else
   {
      xprintf(("getUniqueId != 6\n"));
      baAssert(0);
   }

}

#endif /* HOST_PLATFORM */


/****************************************************************************
 **************************----------------------****************************
 **************************| GENERIC CODE BELOW |****************************
 **************************----------------------****************************
 ****************************************************************************/

/* Keeps connecting until a connection is successful or until a non
   recoverable error occurs. The function returns a SharkSslCon object
   on success. The function returns NULL if a non recoverable error
   occurs.
 */
static SharkSslCon*
connect2broker(SharkMQTT* mqtt, SharkSsl* ssl)
{
   MqttCredentials cred = { MQTT_USERNAME, (const U8*)MQTT_PASSWORD, 0 };
   BaBool cleanSession = TRUE;
   MqttWillMsg wm;
   int canReconnect = TRUE;
   cred.pwdlen=(U16)strlen((char*)cred.password);

   /* Will message is used as a 'user signing off' message (Ref-Will)
    */
   wm.topic = "/goodbye/";
   wm.message = (U8*)clientId;
   wm.msgLen = (U16)strlen(clientId);
   wm.qos = 2;
   wm.retain = FALSE;

   mqtt->timeout = 5000; /* Max 5 sec for connecting */

   while(canReconnect)
   {
      int status;
      /* Secure connection object */
      SharkSslCon* scon = SharkSsl_createCon(ssl);
      if(!scon)
      {
         xprintf(("Cannot allocate SharkSslCon"));
         return 0;
      }

      status = SharkMQTT_connect(mqtt,
                                 scon, /* Secure connection object */
                                 MQTT_BROKER,
                                 MQTT_BROKER_PORT,
                                 clientId, /* Unique ID (MAC address) */
                                 &cred, /* username/paasword */
                                 cleanSession,
                                 &wm); /* Will message */
      if(status < 0)
      {
         switch(status)
         {
            case SMQTTE_ALREADYCON: /* program error: assert */
            case SMQTTE_CONREFUSED:
            case SMQTTE_SERVERNOTTRUSTED:
            case SMQTTE_OVERFLOW:
            case (-SharkSslCon_AlertRecv):
               canReconnect = FALSE;
         }
         switch(status)
         {
            case SMQTTE_ALREADYCON: /* program error */
               xprintf(("Already connected"));
               break;
            case SMQTTE_CONREFUSED:
               xprintf(("Connection refused, ecode: %d",
                        SharkMQTT_connackCode(mqtt)));
               break;
            case SMQTTE_TIMEOUT:
               xprintf(("Connect request timeout"));
               break;
            case SMQTTE_OVERFLOW:
               xprintf(("Shark out buffer must be larger"));
               break;
            case SMQTTE_SERVERNOTTRUSTED:
               switch(SharkMQTT_trustInfo(mqtt))
               {
                  case SharkSslConTrust_NotSSL:
                     xprintf(("SharkSslConTrust_NotSSL"));
                     break;
                  case SharkSslConTrust_None:
                     xprintf(("SharkSslConTrust_None"));
                     break;
                  case SharkSslConTrust_Cert:
                     xprintf(("SharkSslConTrust_Cert"));
                     break;
                  case SharkSslConTrust_Cn: xprintf(("SharkSslConTrust_Cn"));
                     break;
                  default:
                     baAssert(0);
               }
               break;
            case -1:
               xprintf(("Socket error"));
               break;
            case -2:
               xprintf(("Cannot resolve IP address for " MQTT_BROKER ));
               break;
            case -3:
               xprintf(("Cannot connect to " MQTT_BROKER ));
               break;

            case (-SharkSslCon_AlertRecv):
               xprintf(("SharkSslCon_AlertRecv: probably invalid cert "));
               break;

            default:
               xprintf(("Unknown error"));
               canReconnect = FALSE;
         }
         xprintf(("\n"));
         SharkSsl_terminateCon(ssl, scon);
         pause();
      }
      else
      {
         if (status !=
#if SHARKSSL_CHECK_DATE
            SharkSslConTrust_CertCnDate
#else
            SharkSslConTrust_CertCn
#endif
            )
         {
            xprintf(("Security warning: server certificate not trusted!\n"));
            SharkSsl_terminateCon(ssl, scon);
            scon = 0; /* not connected */
         }
         return scon; /* Connected */
      }
   }
   return 0;
}


/** The chat example's main process loop. The function is called after
    function connect2broker establishes a persistent MQTT
    connection. This function does not return unless the persistent
    MQTT connection breaks (on network error).
 */
static void
processLoop(SharkMQTT* mqtt)
{
   U8* buf=0;
   U8* ptr=0;
   U8* start=0;
   int maxLen=0;
   int subAckCounter=0;

   /* Used for consistency check. Not required for any
    * functionality in this demo.
    */
   U16 packetIds[3];

   /* Send a hello message to all other connected chat clients */
   SharkMQTT_publish(mqtt,"/hello/",clientId,strlen(clientId),FALSE,2);

   /* New clients publish one message to the following topic */
   SharkMQTT_subscribe(mqtt,"/hello/",   0, packetIds);
   /* Chat messages are published to the following topic */
   SharkMQTT_subscribe(mqtt,"/chatmsg/", 0, packetIds+1);
   /* MQTT Will messages are published to the following topic */
   SharkMQTT_subscribe(mqtt,"/goodbye/", 0, packetIds+2);

   mqtt->timeout = 50; /* Fast timeout so we can check for keyboard input */

   for(;;) /* Message loop */
   {
      U8* msg;
      int c;
      int len = SharkMQTT_getMessage(mqtt, &msg);
      if(len < 0) /* If a control or error message */
      {
         switch(len)
         {

            /********************** Control messages *********************/

            case SMQTT_TIMEOUT:
               /* Check for keyboard events every 50 millisec */
               while((c=pollkb()) !=0 )
               {  /* New keyboard event */
                  /* Using zero copy publish API */
                  if( ! buf )
                  { /* Start of new message */
                     buf=SharkMQTT_zeroCopyPub(mqtt,"/chatmsg/",2,&maxLen);
                     sprintf((char*)buf,"%s: ",clientId);
                     start = ptr = buf + strlen((char*)buf);
                  }
                  *ptr++ = (U8)c;
                  putchar(c);
                  if(--maxLen == 0 || c == '\n')
                  { /* End of message; on ENTER */
                     int simClose = strncmp("CLOSE\n", (char*)start, 6) == 0;
                     SharkMQTT_publish(mqtt,"/chatmsg/", 0, ptr-buf,FALSE,2);
                     if( simClose )
                     {
                        xprintf(("Simulating network error\n"));
                        se_close(&mqtt->sock);
                     }
                     buf=0;
                  }
               }
               break;

               /* We subscribed to 3 topics in 'mainTask'; thus we get
                  here 3 times.
                */
            case SMQTT_SUBACK:
               /* Not needed: We use this for state consistency check */
               baAssert(subAckCounter < 3);
               baAssert(SMQTT_SUBACK == len);
               baAssert(SharkMQTT_packetId(mqtt) == packetIds[subAckCounter]);
               xprintf(("SUBACK %d\n", packetIds[subAckCounter]));
               subAckCounter++;
               break;

            case SMQTT_UNSUBACK:
               baAssert(0); /* Not used */
               break;

            /*********************** Error Codes ***********************/

            case SMQTTE_TIMEOUT:
               xprintf(("Timeout during read operation\n"));
               return;

            case SMQTTE_PONGTIMEOUT:
               xprintf(("Server PONG timeout\n"));
               return;

            case SMQTTE_PROTOCOL_ERROR:
               xprintf(("Protocol error\n"));
               return;

            case SMQTTE_OVERFLOW:
               xprintf(("Shark out buffer must be larger\n"));
               return;

            default:
               xprintf(("Socket error %d\n",len));
               return;
         }
      }
      else /* received an MQTT PUBLISH message */
      {
         /* Check the topic. We are subscribed to 3 topics */
         const char* topic = SharkMQTT_topic(mqtt);
         if( ! strcmp(topic, "/chatmsg/") )
         {
            /* Ingore messages from 'self' */
            if(strncmp(clientId, (char*)msg, strlen(clientId)))
               printMsg(msg,len);
         }
         else if( ! strcmp(topic, "/hello/") )
         {
            printf(("User "));
            printMsg(msg,len);
            printf((" signing on\n"));
         }
         else if( ! strcmp(topic, "/goodbye/") )
         {   /* MQTT Will message (Ref-Will) */
            printf(("User "));
            printMsg(msg,len);
            printf((" leaving\n"));
         }
      }
   }
}


/*
  The mainTask is the entry function for the chat example program. The
  function creates a SharkSSL instance and sets the X.509 CA
  certificate (for broker authentication) and sets the client
  certificate for client authentication by the broker.

  The function stays in a forever loop, connecting and reconnecting on
  network errors. The loop terminates if function connect2broker
  signals an unrecoverable error.
 */
void
mainTask(SeCtx* ctx)
{
   static SharkSsl sharkSsl;
   static SharkSslCon* scon;
   static SharkMQTT mqtt;
   static U8 mqttBuf[512];
   (void)ctx;
   initClientId();
   SharkSsl_constructor(&sharkSsl,
                        SharkSsl_Client, /* Two options: client or server */
                        0,      /* Not using SSL cache */
                        8000,   /* initial inBuf size: Can grow */
                        8000);   /* outBuf size: Fixed */
   /* Authenticate broker */
   SharkSsl_setCAList(&sharkSsl, sharkSslCAList);

#ifdef LOCALHOST_TEST
   /* Broker is configured to authenticate clients */
#ifdef USE_RSA
   SharkSsl_addCertificate(&sharkSsl, sharkSSL_RTL_device);
#else
   SharkSsl_addCertificate(&sharkSsl, sharkSslECCert_device);
#endif
#endif

   /* It is very important to seed the SharkSSL RNG generator */
   sharkssl_entropy(baGetUnixTime() ^ (ptrdiff_t)&sharkSsl);
   SharkMQTT_constructor(&mqtt, mqttBuf, sizeof(mqttBuf));
   SharkMQTT_setCtx(&mqtt, ctx);  /* Required for non RTOS env. */
   for(;;) /* Connect - reconnect loop */
   {
      if( (scon = connect2broker(&mqtt, &sharkSsl)) == 0 )
      {
         xprintf(("Aborting...\n"));
         break;
      }
      processLoop(&mqtt);
      SharkMQTT_disconnect(&mqtt);
      SharkSsl_terminateCon(&sharkSsl, scon);
   }
   SharkMQTT_destructor(&mqtt);
}
