/*
 *     ____             _________                __                _
 *    / __ \___  ____ _/ /_  __(_)___ ___  ___  / /   ____  ____ _(_)____
 *   / /_/ / _ \/ __ `/ / / / / / __ `__ \/ _ \/ /   / __ \/ __ `/ / ___/
 *  / _, _/  __/ /_/ / / / / / / / / / / /  __/ /___/ /_/ / /_/ / / /__
 * /_/ |_|\___/\__,_/_/ /_/ /_/_/ /_/ /_/\___/_____/\____/\__, /_/\___/
 *                                                       /____/
 *
 *                  SMTP example program
 ****************************************************************************
 *
 *   $Id: SMTP.h 4324 2018-11-17 17:13:25Z wini $
 *
 *   COPYRIGHT:  Real Time Logic, 2013 - 2015
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
 ****************************************************************************
 */

#ifndef _SMTP_h
#define _SMTP_h

#include <selib.h>
#include "BufPrint.h"

/** @defgroup SMTP Simple Mail Transfer Protocol
    @ingroup SharkExamples

A minimal secure SMTP client library (SMTPS and STARTTLS).

The SMTP library is delivered as an example program. The library uses
the socket functions in selib.c for secure and non-secure
communication.

A Visual C++ project is provided in build/VC-Win/examples.sln. This
project enables you to quickly test the library on a Windows computer.

Modify one of the two example files: example.c or example.cpp. The
example.cpp source code file uses the C++ wrapper API, thus
simplifying the use of the library.

@{
*/


/** SMTP error codes
 */ 
typedef enum {
   /** OK
    */
   SMTP_NoError=0,
   /** Not an error code: means that the library has started sending data.
    */
   SMTP_DataCommitted,

   /* error codes below */

   /** Hostname does not resolve or the client is unable to connect to server.
    */
   SMTP_ErrHostName,

   /** Cannot create socket
    */
   SMTP_ErrSocketCreate,

   /** Cannot connect.
    */
   SMTP_ErrConnect,

   /** EHLO (Extended SMTP (ESMTP)) required, but not supported by server. 
    */
   SMTP_ErrHELO,

   /** Failed sending MAIL FROM:<%s> BODY=8BITMIME
    */
   SMTP_ErrMAILFROM,

   /** Failed sending the initial DATA message
    */
   SMTP_ErrDATA,

   /** Failed sending RCPT TO:<%s>
    */
   SMTP_ErrRCPTTO,

   /** Socket unexpectedly closed
    */
   SMTP_ErrSocketClosed,

   /** Cannot decode response data
    */
   SMTP_ErrSmtpResponseCode,

   /** Cannot add recipients after data is committed: see #SMTP_DataCommitted
    */
   SMTP_ErrWriteStarted,

   /** Unknown/unsupported server authentication request.
    */
   SMTP_ErrNoAuthSup,

   /** Server requires credentials, but no credentials were provided.
    */
   SMTP_ErrAuth,

   /** #SharkSsl_createCon failed.
    */
   SMTP_ErrSslCon,

   /** Server certificate not trusted. Disable by setting
       serverDomainName to NULL when calling SMTP::SMTP.
    */
   SMTP_ErrCertNotTrusted
} SMTP_ErrCode;



/**
   This class is a minimal SMTP client that takes an email message
   body and passes it on to a SMTP server. Email messages can be used
   to provide status reports or alarm notifications for embedded devices.

   This ANSI C library, is designed as one class with C++ wrapper
   functions in the header file. Please refer to the following article
   for more information on <a href =
   "https://realtimelogic.com/ba/doc/en/C/introduction.html#oo_c">
   Object Oriented programming in C code </a>.

   C++ Example code:

   \code

   SMTP smtp("device1@realtimelogic.com", //const char* from,
             "alarmcentral@realtimelogic.com", //const char* to,
             "Alarm from device 1", //const char* subject,
             "smtp.mandrillapp.com", //const char* smtpServer,
             587, //int port,
             &sharkSsl,
             TRUE, //int startTLS,
             "device1@realtimelogic.com", //const char* username,
             "mandrill-key", //const char* password
             0, //const char* clientDomainName,
             "smtp.mandrillapp.com"); //const char* serverDomainName
   if(smtp.getEcode() == SMTP_NoError)
      if( !smtp.addRecipient("ginfo@realtimelogic.com") )
         if( ! smtp.printf("This email was sent at %d\n", time(0)) )
            if( !smtp.commit() )
               return; //Success.

   SMTP_ErrCode eCode = smtp.getEcode();
   // Handle error.
   \endcode
*/
typedef struct SMTP
{
#ifdef __cplusplus
public:
   /** Initiate the SMTP email message.
       \param from the sender of the email.
       \param to the receiver of this email.
       \param subject email message subject.
       \param smtpServer The name or IP address of the SMTP server.
       \param port the SMTP server port number. Default is 25.
       \param sharkSsl use secure connection, either SMTPS or STARTTLS. 
       \param startTLS use STARTTLS (RFC 3207) if TRUE, otherwise, use SMTPS.
       \param username the username is required by SMTP servers requiring AUTH.
       \param password the password is required by SMTP servers requiring AUTH.
       \param clientDomainName defaults to "localhost" if not set.
       \param serverDomainName must be set to the expected server's
       SSL certificate domain name. The SMTP library will not do any server
       certificate validation if this variable is set to NULL.
       \param ctx for bare metal systems
       \sa SMTP_constructor
   */
   SMTP(const char* from,
        const char* to,
        const char* subject,
        const char* smtpServer,
        int port=25,
        SharkSsl* sharkSsl=0,
        bool startTLS=false,
        const char* username=0,
        const char* password=0,
        const char* clientDomainName=0,
        const char* serverDomainName=0,
        SeCtx* ctx=0);

   /** The destructor automatically commits the email if you do not
       call SMTP::commit
       \sa  SMTP_destructor
   */
   ~SMTP();

   /** Optionally add more recipients to this email.
       This function cannot be called after you call SMTP::write
       or SMTP::printf.
       \sa SMTP_addRecipient
   */
   int addRecipient(const char* to);

   /** Set content-type.
      \param type the content type defaults to "text/plain; charset=utf-8".
       \sa SMTP_setContentType
   */
   void setContentType(const char* type);

   /** Add body text to email.
       \sa SMTP_write
    */
   int write(const char* txt, int len = -1);

   /** Add body text to email.
       \sa SMTP_printf
    */
   int printf(const char* fmt, ...);

   /** Commit (send) email.
       \sa SMTP_commit
    */
   int commit();

   /** Get the error code (#SMTP_ErrCode), if any.
       \sa SMTP::getEmsg
   */
   SMTP_ErrCode getEcode() const { return eCode; }

   /** Returns the SMTP error message if any.
    */
   const char* getEmsg();

   /** Returns true if server supports 8BITMIME. You must make sure
       you do not send messages not in the seven-bit ASCII character
       set if this function returns false.
    */
   bool bit8() { return eightBit?true:false; }

private:

#endif
   BufPrint bp;
   char printBuf[1024];
   
   SOCKET sock;
   SharkSsl* sharkSsl;
   SharkSslCon* sharkSslCon;
   SMTP_ErrCode eCode;
   char writeStarted;

   const char* from;
   const char* to;
   const char* subject;
   const char* clientDomainName;
   const char* serverDomainName;
   const char* contentType;
   U8 isSecure;
   U8 eightBit;
} SMTP;

#ifdef __cplusplus
extern "C" {
#endif

/** Documentation: SMTP::SMTP */
void SMTP_constructor(SMTP* o,
                      const char* from,
                      const char* to,
                      const char* subject,
                      const char* smtpServer,
                      int port,
                      SharkSsl* sharkSsl,
                      int startTLS,
                      const char* username,
                      const char* password,
                      const char* clientDomainName,
                      const char* serverDomainName,
                      SeCtx* ctx);
/** Documentation: SMTP::~SMTP */
void SMTP_destructor(SMTP* o);

/** Documentation: SMTP::addRecipient */
int SMTP_addRecipient(SMTP* o, const char* to);
/** Documentation: SMTP::write */
int SMTP_write(SMTP* o, const char* txt, int len);
/** Documentation: SMTP::printf */
int SMTP_printf(SMTP* o, const char* fmt, ...);
/** Documentation: SMTP::vprintf */
int SMTP_vprintf(SMTP* o, const char* fmt, va_list argList);
/** Documentation: SMTP::commit */
int SMTP_commit(SMTP* o);
/** Documentation: SMTP::getEcode */
#define SMTP_getEcode(o) (o)->eCode
/** Returns the SMTP error message if any. */
const char* SMTP_getEmsg(SMTP* o);
/** Documentation: SMTP::setContentType */
#define SMTP_setContentType(o,type) (o)->contentType=type
/** Returns true if server supports 8BITMIME */
#define SMTP_bit8(o) (o)->eightBit

#ifdef __cplusplus
} 
inline SMTP::SMTP(const char* from,
                  const char* to,
                  const char* subject,
                  const char* smtpServer,
                  int port,
                  SharkSsl* sharkSsl,
                  bool startTLS,
                  const char* username,
                  const char* password,
                  const char* clientDomainName,
                  const char* serverDomainName,
                  SeCtx* ctx) {
   SMTP_constructor(this,from,to,subject,smtpServer,port,sharkSsl,startTLS?1:0,
                    username,password,clientDomainName,serverDomainName,ctx);
}

inline SMTP::~SMTP() {
   SMTP_destructor(this);
}

inline int SMTP::addRecipient(const char* to) {
   return SMTP_addRecipient(this, to);
}

inline void SMTP::setContentType(const char* type) {
   SMTP_setContentType(this,type);
}

inline int SMTP::write(const char* txt, int len) {
   return SMTP_write(this, txt, len);
}

inline int SMTP::printf(const char* fmt, ...) {
   int retVal;
   va_list varg;
   va_start(varg, fmt);  
   retVal = SMTP_vprintf(this, fmt, varg);
   va_end(varg);
   return retVal;
}

inline const char* SMTP::getEmsg() {
   return SMTP_getEmsg(this);
}


inline int SMTP::commit() {
   return SMTP_commit(this);
}
#endif

/** @} */ /* end group SMTP */ 

#endif
