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
 *   $Id: AWS-MQTT.c 4965 2021-12-17 01:59:19Z wini $
 *
 *   COPYRIGHT:  Real Time Logic LLC, 2018 - 2021
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

 This AWS example is designed for the steps outlined in the following video:
 https://youtu.be/6w9a6y_-T2o

 Follow the exact steps in the video (except running start.sh and the
 python code), download the connect_device_package.zip, unzip, open
 start.sh, and set the macro AWS_IOT_MQTT_HOST below to the hostname
 set in start.sh (the hostname is set with the -e argument).

 Copy Demo_Thing.cert.pem and Demo_Thing.private.key to the directory
 where you will be executing the compiled software. Optionally embed the
 certificate and key by converting the certificate/key combo to a
 SharkSSL certificate, ref:
 https://realtimelogic.com/ba/doc/en/C/shark/md_md_Certificate_Management.html#SharkSSLCertificate

 Download and save the AWS root certificate in the same directory e.g.:
 wget https://www.amazontrust.com/repository/AmazonRootCA1.pem
*/

#include "SharkMQTT.h"


/* Customer specific MQTT HOST. */
#define AWS_IOT_MQTT_HOST  "XXXXXXX.amazonaws.com"

/* MQTT client ID should be unique for every device */
#define AWS_IOT_MQTT_CLIENT_ID         "basicPubSub"
/* You must have a policy for these two topics, which you do if you
 * follow the video instructions: https://youtu.be/6w9a6y_-T2o
*/
#define AWS_TST_TOPIC_1                 "topic_1"
#define AWS_TST_TOPIC_2                 "topic_2"

/* AWS MQTT broker port number. We use port 443 if SharkSSL is
 * compiled with SHARKSSL_ENABLE_ALPN_EXTENSION (enabled by default).
 * See the code below for how this is used. Additional details:
 * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
 */
#if SHARKSSL_ENABLE_ALPN_EXTENSION
#define AWS_IOT_MQTT_PORT              443
#else
#define AWS_IOT_MQTT_PORT              8883
#endif


#if HOST_PLATFORM
#ifndef EMBED_CERTIFICATES
#define EMBED_CERTIFICATES 0
#endif
#else
#ifndef EMBED_CERTIFICATES
#define EMBED_CERTIFICATES 1
#endif
#endif

/* Reading certificates and key from file system */
#if EMBED_CERTIFICATES
/* The signer of the broker's certificate:
   SharkSSLParseCAList AmazonRootCA1.pem > AmazonRootCA1.h
*/
#include "AmazonRootCA1.h"
/* our AWS certificate and private key:
   SharkSSLParseCert Demo_Thing.cert.pem Demo_Thing.private.key >DemoThingCert.h
*/
#include "DemoThingCert.h"
#else
/* Root CA file name : The signer of the broker's certificate */
#define AWS_IOT_ROOT_CA_FILENAME       "AmazonRootCA1.pem"
/* device signed certificate file name (our cert) */
#define AWS_IOT_CERTIFICATE_FILENAME   "Demo_Thing.cert.pem"
/* Device private key filename  (our key) */
#define AWS_IOT_PRIVATE_KEY_FILENAME   "Demo_Thing.private.key"
#endif

#include <stdio.h>
#include <stddef.h>
#include <sys/stat.h>

/****************************************************************************
 **************************-----------------------***************************
 ************************| PLATFORM SPECIFIC CODE |**************************
 **************************-----------------------***************************
 ****************************************************************************/

#if HOST_PLATFORM

/* Macro xprintf redirects to this function.
 */
void _xprintf(const char* fmt, ...)
{
   va_list varg;
   va_start(varg, fmt);
   vprintf(fmt, varg);
   va_end(varg);
}

#ifndef NO_MAIN
int main()
{
#ifdef _WIN32
   WSADATA wsaData;
   /* Windows specific: Start winsock library */
   WSAStartup(MAKEWORD(1,1), &wsaData);
#endif
   mainTask(0);
   return 0;
}
#endif

#endif /* HOST_PLATFORM */

#if EMBED_CERTIFICATES == 0
static char* readFile(const char* filename, U32* bufSize)
{
   char* buf;
   struct stat fstat;
   FILE* fp = fopen(filename, "rb");
   if(!fp || stat(filename, &fstat))
   {
      xprintf(("Cannot open %s.\n"
               "Make sure the file is in the executable directory!\n",
               filename));
      return 0;
   }
   buf = baMalloc(fstat.st_size);
   if(!buf) return 0;
   if(fread(buf, 1, fstat.st_size, fp) == 0) return 0;
   fclose(fp);
   *bufSize=fstat.st_size;
   return buf;
}
#endif


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
   int canReconnect = TRUE;

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
#if (AWS_IOT_MQTT_PORT == 443)
      SharkSslCon_setALPNProtocols(scon, "x-amzn-http-ca,x-amzn-mqtt-ca");
#endif
      status = SharkMQTT_connect(mqtt,
                                 scon, /* Secure connection object */
                                 AWS_IOT_MQTT_HOST,
                                 AWS_IOT_MQTT_PORT,
                                 AWS_IOT_MQTT_CLIENT_ID, /* Unique ID */
                                 0, /* username/paasword */
                                 TRUE, /* Clean session */
                                 0); /* Will message */
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
               xprintf(("Cannot resolve IP address for " AWS_IOT_MQTT_HOST ));
               break;
            case -3:
               xprintf(("Cannot connect to " AWS_IOT_MQTT_HOST ));
               break;

            case (-SharkSslCon_AlertRecv):
               xprintf(("SharkSslCon_AlertRecv: invalid cert or policy"));
               break;

            default:
               xprintf(("Unknown error"));
               canReconnect = FALSE;
         }
         xprintf(("\n"));
         SharkSsl_terminateCon(ssl, scon);
      }
      else
      {
#if (AWS_IOT_MQTT_PORT == 443)
         const char * ALPNProtocol = SharkSslCon_getALPNProtocol(scon);
         if(ALPNProtocol)
         {   
            xprintf(("ALPN protocol accepted: %s\n", ALPNProtocol));
         }
         else
         {
            SharkSsl_terminateCon(ssl, scon);
            scon=0; /* not connected */
         }
#endif
         if(status !=
#if SHARKSSL_CHECK_DATE
            SharkSslConTrust_CertCnDate
#else
            SharkSslConTrust_CertCn
#endif
            )
         {
            /* This error would indicate AWS_IOT_ROOT_CA_FILENAME
            * references incorrect root CA's or this is a man in the
            * middle attack.
             */
            xprintf(("Security warning: server certificate not trusted!\n"));
            SharkSsl_terminateCon(ssl, scon);
            scon=0; /* not connected */
         }
         return scon; /* Connected if != NULL */
      }
   }
   return 0;
}


/* The example's main process loop. The function is called after
   function connect2broker establishes a persistent MQTT
   connection. This function does not return unless the persistent
   MQTT connection breaks (on network error).
*/
static void
processLoop(SharkMQTT* mqtt, SharkSslCon* scon)
{
   int msgCounter=0;

   xprintf(("Subscribing to %s\n", AWS_TST_TOPIC_1));
   SharkMQTT_subscribe(mqtt, AWS_TST_TOPIC_1, 0, 0);

   /* Setting timeout to one second so we can publish every second */
   mqtt->timeout = 1000;

   for(;;) /* Message loop */
   {
      char* msg;
      int len = SharkMQTT_getMessage(mqtt, (U8**)&msg);
      if(len < 0) /* If a control or error message */
      {
         switch(len)
         {

            /********************** Control messages *********************/

            /* We publish to the two topics every time we get a timeout. */
            case SMQTT_TIMEOUT:
               sprintf(msg, "Message %d", ++msgCounter);
               SharkMQTT_publish(mqtt,AWS_TST_TOPIC_1,msg,strlen(msg),FALSE,0);
               SharkMQTT_publish(mqtt,AWS_TST_TOPIC_2,msg,strlen(msg),FALSE,0);
               if (msgCounter == 5)
               {
                  xprintf(("Subscribing to %s\n", AWS_TST_TOPIC_2));
                  SharkMQTT_subscribe(mqtt, AWS_TST_TOPIC_2, 0, 0);
               }
               if (msgCounter == 10)
               {
                  xprintf(("Unsubscribing from %s\n", AWS_TST_TOPIC_1));
                  SharkMQTT_unsubscribe(mqtt, AWS_TST_TOPIC_1, 0);
               }
               break;

            case SMQTT_SUBACK:
               xprintf(("SUBACK %d\n", SharkMQTT_packetId(mqtt)));
               break;

            case SMQTT_UNSUBACK:
               xprintf(("UNSUBACK %d\n", SharkMQTT_packetId(mqtt)));
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

            case -SharkSslCon_AlertRecv:
               if(SharkSslCon_getAlertDescription(scon) == 
                  SHARKSSL_ALERT_CLOSE_NOTIFY)
               {
                  /* Check your "thing" policy if you receive this
                   * message as a result from subscribing or publishing.
                   */
                  xprintf(("Broker wants to close connection\n"));
               }
               else
               {
                  xprintf(("TLS alert %d\n",
                           SharkSslCon_getAlertDescription(scon)));
               }
               return;

            default:
               xprintf(("Socket error %d\n",len));
               return;
         }
      }
      else /* Received an MQTT PUBLISH message */
      {
         xprintf(("REC PUB, topic: %s, data: ", SharkMQTT_topic(mqtt)));
         while(len--)
         {
            xprintf(("%c",*msg++));
         }
         xprintf(("\n"));
      }
   }
}

#if EMBED_CERTIFICATES == 0
static int addAWSCert(SharkSsl* shark)
{
   SharkSslCert sharkCert;
   char* certBuf;
   char* keyBuf;
   U32 bufSize;

   certBuf=readFile(AWS_IOT_CERTIFICATE_FILENAME, &bufSize);
   keyBuf=readFile(AWS_IOT_PRIVATE_KEY_FILENAME, &bufSize);
   if(!certBuf || !keyBuf) return -1;
   if(sharkssl_PEM(certBuf,keyBuf,NULL,&sharkCert))
      return -1;
   baFree(certBuf);
   baFree(keyBuf);
   /*
     You may redesign the code and keep a reference to the
     SharkSslCert object if you design a system using dynamic objects
     i.e. if you later plan on releasing the SharkSSL object and the
     SharkSslCert object. You cannot release the SharkSslCert object
     before releasing the SharkSSL object.
   */
   SharkSsl_addCertificate(shark,sharkCert);
   return 0;
}
#endif

/*
  The mainTask is the entry function for the AWS example. The
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
#if EMBED_CERTIFICATES == 0
   SharkSslCAList caList;
   SharkSslCertStore certStore;
   char* buf;
   U32 bufSize;
#endif
   (void)ctx;

   SharkSsl_constructor(&sharkSsl,
                        SharkSsl_Client, /* Two options: client or server */
                        0,      /* Not using SSL cache */
                        8000,   /* initial inBuf size: Can grow */
                        8000);   /* outBuf size: Fixed */


#if EMBED_CERTIFICATES
   /* SharkSSLParseCAList aws-iot-rootCA.crt > aws-iot-rootCA.h */
   SharkSsl_setCAList(&sharkSsl, sharkSslCAList);
   /* SharkSSLParseCert.exe aws.pem aws.key >aws-certificate.h */
   SharkSsl_addCertificate(&sharkSsl,sharkSslRSACert);
#else
   SharkSslCertStore_constructor(&certStore);
   buf = readFile(AWS_IOT_ROOT_CA_FILENAME, &bufSize);
   if(!buf) return;
   SharkSslCertStore_add(&certStore, buf, bufSize);
   SharkSslCertStore_assemble(&certStore, &caList);
   baFree(buf);
   /* Authenticate broker */
   SharkSsl_setCAList(&sharkSsl, caList);
   /* The AWS Broker requires client authentication */
   if(addAWSCert(&sharkSsl)) return;
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
      processLoop(&mqtt, scon);
      SharkMQTT_disconnect(&mqtt);
      SharkSsl_terminateCon(&sharkSsl, scon);
   }
   SharkMQTT_destructor(&mqtt);
}
