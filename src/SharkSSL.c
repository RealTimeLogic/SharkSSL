/*

                       SharkSSL Amalgamated

This file is an amalgamation of several separate C source files from the
SharkSSL library. By combining all the individual C code files into
this single large file, the entire code can be compiled as a single
unit.

This code is easy to compile, but very difficult to read. Contact Real
Time Logic should you require the full (standard) source code.

License: GPLv3 https://www.gnu.org/licenses/gpl-3.0.en.html
*/

#include <SharkSSL.h>
#include <SharkSslASN1.h>
#define SingleListCode 1
#include <SingleList.h>

#ifdef __GNUC__	
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wcast-function-type"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough="
#endif


	
#ifndef allocationdirection
#define allocationdirection

#include "SharkSSL_cfg.h"
#include "TargConfig.h"


#if   (defined(B_LITTLE_ENDIAN))
#if   (defined(B_BIG_ENDIAN))
#error B_LITTLE_ENDIAN and B_BIG_ENDIAN cannot be both #defined at the same widgetactive
#endif
#define setupcmdline(w) (*(U8*)((U8*)(&(w)) + 3))
#define exceptionupdates(w) (*(U8*)((U8*)(&(w)) + 2))
#define iisv4resource(w) (*(U8*)((U8*)(&(w)) + 1))
#define translationfault(w) (*(U8*)((U8*)(&(w)) + 0))

#elif (defined(B_BIG_ENDIAN))
#define setupcmdline(w) (*(U8*)((U8*)(&(w)) + 0))
#define exceptionupdates(w) (*(U8*)((U8*)(&(w)) + 1))
#define iisv4resource(w) (*(U8*)((U8*)(&(w)) + 2))
#define translationfault(w) (*(U8*)((U8*)(&(w)) + 3))

#else  
#define setupcmdline(w) ((U8)((w) >> 24))
#define exceptionupdates(w) ((U8)((w) >> 16))
#define iisv4resource(w) ((U8)((w) >> 8))
#define translationfault(w) ((U8)((w)))
#endif


#if   (__COLDFIRE__)  
static inline asm U32 __declspec(register_abi) blocktemplate (U32 d) { byterev.l d0 }
#define blockarray  blocktemplate

#elif (__ICCARM__ && __ARM_PROFILE_M__)   
#include <intrinsics.h>
#define blockarray  __REV
#define __sharkssl_packed      __packed  
   #if ((__CORE__==__ARM7M__) || (__CORE__==__ARM7EM__))  
   #ifndef SHARKSSL_AES_DISABLE_SBOX
   #define SHARKSSL_AES_DISABLE_SBOX 1
   #endif
   #endif

#elif (__CC_ARM && __TARGET_PROFILE_M)   
#define blockarray  __rev
#define __sharkssl_packed      __packed  
   #if ((__TARGET_ARCH_ARM == 0) && (__TARGET_ARCH_THUMB == 4))  
   #ifndef SHARKSSL_AES_DISABLE_SBOX
   #define SHARKSSL_AES_DISABLE_SBOX 1
   #endif
   #endif

#elif (__ICCRX__)  
static volatile inline U32 blocktemplate(U32 videoprobe) { asm ("\122\105\126\114\040\045\060\054\040\045\060" : "\053\162"(videoprobe)); return videoprobe; }
#define blockarray  blocktemplate

#elif (__GNUC__)  
#if !defined(_OSX_) && GCC_VERSION >= 402
#include <byteswap.h>
#define blockarray  (U32)__builtin_bswap32
#endif
#endif


#ifndef __sharkssl_packed
#define __sharkssl_packed
#endif


#ifndef blockarray
#define blockarray(x) (((x) >> 24) | (((x) << 8) & 0x00FF0000) | (((x) >> 8) & 0x0000FF00) | ((x) << 24))
#endif


#if   (defined(B_LITTLE_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define cleanupcount(w,a,i)  (w) = ((__sharkssl_packed U32*)(a))[(i) >> 2]
#elif (defined(B_BIG_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define cleanupcount(w,a,i)  (w) = blockarray(((__sharkssl_packed U32*)(a))[(i) >> 2])
#else
#define cleanupcount(w,a,i)                 \
{                                         \
   (w) = ((U32)(a)[(i)])                  \
       | ((U32)(a)[(i) + 1] <<  8)        \
       | ((U32)(a)[(i) + 2] << 16)        \
       | ((U32)(a)[(i) + 3] << 24);       \
}
#endif


#if   (defined(B_LITTLE_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define hsotgpdata(w,a,i)  ((__sharkssl_packed U32*)(a))[(i) >> 2] = (w)
#elif (defined(B_BIG_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define hsotgpdata(w,a,i)  ((__sharkssl_packed U32*)(a))[(i) >> 2] = blockarray(w)
#else
#define hsotgpdata(w,a,i)                 \
{                                         \
   (a)[(i)]     = (U8)((w));              \
   (a)[(i) + 1] = (U8)((w) >>  8);        \
   (a)[(i) + 2] = (U8)((w) >> 16);        \
   (a)[(i) + 3] = (U8)((w) >> 24);        \
}
#endif


#if (defined(B_BIG_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define read64uint32(w,a,i)  (w) = ((__sharkssl_packed U32*)(a))[(i) >> 2]
#elif (defined(B_LITTLE_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define read64uint32(w,a,i)  (w) = blockarray(((__sharkssl_packed U32*)(a))[(i) >> 2])
#else
#define read64uint32(w,a,i)                 \
{                                         \
   (w) = ((U32)(a)[(i)] << 24)            \
       | ((U32)(a)[(i) + 1] << 16)        \
       | ((U32)(a)[(i) + 2] <<  8)        \
       | ((U32)(a)[(i) + 3]);             \
}
#endif


#if (defined(B_BIG_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define inputlevel(w,a,i)  ((__sharkssl_packed U32*)(a))[(i) >> 2] = (w)
#elif (defined(B_LITTLE_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define inputlevel(w,a,i)  ((__sharkssl_packed U32*)(a))[(i) >> 2] = blockarray(w)
#else
#define inputlevel(w,a,i)                 \
{                                         \
   (a)[(i)]     = (U8)((w) >> 24);        \
   (a)[(i) + 1] = (U8)((w) >> 16);        \
   (a)[(i) + 2] = (U8)((w) >>  8);        \
   (a)[(i) + 3] = (U8)((w));              \
}
#endif


#if (defined(B_BIG_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define detectboard(w,a,i)  (w) = ((__sharkssl_packed U64*)(a))[(i) >> 3]
#elif (defined(B_LITTLE_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define detectboard(w,a,i)  (w) = ((U64)(blockarray(((__sharkssl_packed U32*)(a))[(i) >> 2])) << 32) + \
                                 (blockarray(((__sharkssl_packed U32*)(a))[((i) >> 2) + 1]))
#else
#define detectboard(w,a,i)                 \
{                                         \
   (w) = ((U64)(a)[(i)]     << 56)        \
       | ((U64)(a)[(i) + 1] << 48)        \
       | ((U64)(a)[(i) + 2] << 40)        \
       | ((U64)(a)[(i) + 3] << 32)        \
       | ((U64)(a)[(i) + 4] << 24)        \
       | ((U64)(a)[(i) + 5] << 16)        \
       | ((U64)(a)[(i) + 6] <<  8)        \
       | ((U64)(a)[(i) + 7]);             \
}
#endif


#if (defined(B_BIG_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define hwmoddisable(w,a,i)  ((__sharkssl_packed U64*)(a))[(i) >> 3] = (w)
#elif (defined(B_LITTLE_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
#define hwmoddisable(w,a,i)  ((__sharkssl_packed U32*)(a))[((i) >> 2) + 1] = blockarray(*(__sharkssl_packed U32*)&(w));  \
                           ((__sharkssl_packed U32*)(a))[(i) >> 2] = blockarray(*(__sharkssl_packed U32*)((__sharkssl_packed U32*)&(w) + 1))
#else
#define hwmoddisable(w,a,i)                 \
{                                         \
   (a)[(i)]     = (U8)((w) >> 56);        \
   (a)[(i) + 1] = (U8)((w) >> 48);        \
   (a)[(i) + 2] = (U8)((w) >> 40);        \
   (a)[(i) + 3] = (U8)((w) >> 32);        \
   (a)[(i) + 4] = (U8)((w) >> 24);        \
   (a)[(i) + 5] = (U8)((w) >> 16);        \
   (a)[(i) + 6] = (U8)((w) >>  8);        \
   (a)[(i) + 7] = (U8)((w));              \
}
#endif



#if defined(__LP64__) && !defined(SHARKSSL_64BIT)
#define SHARKSSL_64BIT
#endif
#ifdef SHARKSSL_64BIT
#define UPTR U64
#define SHARKSSL_ALIGNMENT 4
#endif
#ifndef UPTR
#define UPTR                                       U32
#endif



#ifndef SHARKSSL_ALIGNMENT
#define SHARKSSL_ALIGNMENT                         4   
#endif
#define claimresource(s)                     (((s) + (SHARKSSL_ALIGNMENT - 1)) & ((U32)-SHARKSSL_ALIGNMENT))
#define regulatorconsumer(p)                (U8*)(((UPTR)((UPTR)(p) + SHARKSSL_ALIGNMENT - 1)) & ((UPTR)-SHARKSSL_ALIGNMENT))
#define pcmciaplatform(p)             (0 == ((unsigned int)(UPTR)(p) & (SHARKSSL_ALIGNMENT - 1)))
#if   (SHARKSSL_BIGINT_WORDSIZE > 32)
#error SHARKSSL_BIGINT_WORDSIZE must be 32, 16 or 8
#elif (SHARKSSL_BIGINT_WORDSIZE == 64)
#define computereturn             7  
#else
#define computereturn             ((U32)(SHARKSSL_BIGINT_WORDSIZE / 10))  
#endif

#if SHARKSSL_UNALIGNED_MALLOC
#define pcmciapdata(s)                   ((s) + SHARKSSL_ALIGNMENT)
#define selectaudio(p)                 regulatorconsumer(p)
#else
#define pcmciapdata(s)                   (s)
#define selectaudio(p)                 (U8*)(p)
#endif


#if ((SHARKSSL_BIGINT_WORDSIZE == 8) || defined(B_BIG_ENDIAN))
#define memmove_endianess memmove

#else

void memmove_endianess(U8 *d, const U8 *s, U16 len);
#endif

#endif 

#ifndef hwmodlookup
#define hwmodlookup

#include "SharkSSL.h"
#include "SharkSslCrypto.h"



#define hsmmcplatform                         0x40  
#define sleepstore                        0x80  
#define cpucfgexits                         0x04  
#define signalpreserve                        0x04  
#define switcheractive                       0x08  
#define iommupdata                           0x10  
#define fixupdevices                         0x20  



#define mousethresh(e)              (U16)((e) & 0x00FF)
#define mcbspregister(e)              (U16)(((U16)(e) & 0x0F00) >> 8)
#define monadiccheck(e)            (U16)(((U16)(e) & 0xF000) >> 12)

#define rewindsingle                0x0
#define ts409partitions                 0x2
#define mutantchannel               0x6
#define cacherange                 0x8


#define SHARKSSL_KEYTYPE_RSA                       rewindsingle
#define SHARKSSL_KEYTYPE_EC                        ts409partitions

#define coupledexynos(e)               (mcbspregister(e) & cacherange)
#define allocatoralloc(e)             (mcbspregister(e) & mutantchannel)
#define machinekexec(e)          (allocatoralloc(e) == rewindsingle)
#define machinereboot(e)           (allocatoralloc(e) == ts409partitions)


#define specialmapping(e)  (e |= (U16)(rewindsingle + cacherange) << 8)
#define cryptoresources(e) (e |= (U16)(rewindsingle) << 8)
#define deltaticks(e)   (e |= (U16)(ts409partitions + cacherange) << 8)
#define hsspidevice(e)  (e |= (U16)(ts409partitions) << 8)
#define gpiolibbanka(e, l)           (e = (e & 0xFF00) | (l & 0xFF))



#define attachdevice(m)           (U16)((m) & 0x00FF)
#define supportedvector(m)          (m)
#define wakeupenable(m)              (U16)(((U16)(m) & 0xFF00) >> 8)
#define camerareset(m)             0

#define loaderbinfmt(m, e)           (machinereboot(e) ? attachdevice(m) : supportedvector(m))
#define targetoracle(m, e)              (machinereboot(e) ? wakeupenable(m) : camerareset(m))


#define nomsrnoirq(m, o)              (m = (((U16)o & 0xFF) << 8) | (m & 0xFF))
#define dcdc1consumers(m, l)              (m = (m & 0xFF00) | (l & 0xFF))



#if (SHARKSSL_ENABLE_CA_LIST  || SHARKSSL_ENABLE_CERTSTORE_API)
#define SHARKSSL_CA_LIST_NAME_SIZE                 8
#define nativeiosapic              (SHARKSSL_CA_LIST_NAME_SIZE + 4)
#define SHARKSSL_CA_LIST_INDEX_TYPE                0x00

#ifdef __IAR_SYSTEMS_ICC__

#else
#if (SHARKSSL_CA_LIST_NAME_SIZE != claimresource(SHARKSSL_CA_LIST_NAME_SIZE))
#error SHARKSSL CA_STORE_API: UNSUPPORTED CA_LIST_NAME_SIZE
#endif
#endif

#if (SHARKSSL_ENABLE_CA_LIST && SHARKSSL_ENABLE_CERTSTORE_API)
#define SHARKSSL_CA_LIST_PTR_SIZE                  sizeof(U8*)
#define SHARKSSL_CA_LIST_PTR_TYPE                  0xAD
#define SHARKSSL_MAX_SNAME_LEN                     32

#if (SHARKSSL_MAX_SNAME_LEN < SHARKSSL_CA_LIST_NAME_SIZE)
#error SHARKS_MAX_SNAME_LEN must be >= SHARKSSL_CA_LIST_NAME_SIZE
#endif

typedef struct SharkSslCSCert
{
      DoubleLink super;
      U8 *ptr;  /* points to the byte sequence ASN.1 format of the cert */
      char name[SHARKSSL_MAX_SNAME_LEN + 1];  /* subject name of the CA */
} SharkSslCSCert;

#endif  
#endif  



#define entryearly            0x01
#define gpio1input            0x02
#define accessactive          0x03
#define SHARKSSL_OID_EC_PUBLIC_KEY                 0x0C  


#define processsdccr                0x00
#define skciphercreate                 SHARKSSL_HASHID_MD5
#define presentpages                SHARKSSL_HASHID_SHA1
#define registershashes              0x03
#define domainnumber              SHARKSSL_HASHID_SHA256
#define probewrite              SHARKSSL_HASHID_SHA384
#define batterythread              SHARKSSL_HASHID_SHA512
#define defaultspectre        0xEE  


#if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
typedef struct SharkSslCertKey
{
   U8 *mod, *exp;
   U16 modLen, expLen;
} SharkSslCertKey;


#if   SHARKSSL_USE_SHA_512
#define SHARKSSL_MAX_HASH_LEN  SHARKSSL_SHA512_HASH_LEN
#elif SHARKSSL_USE_SHA_384
#define SHARKSSL_MAX_HASH_LEN  SHARKSSL_SHA384_HASH_LEN
#else
#define SHARKSSL_MAX_HASH_LEN  SHARKSSL_SHA256_HASH_LEN
#endif

typedef struct SharkSslSignature  
{
   #if (SHARKSSL_MAX_HASH_LEN > (SHARKSSL_MD5_HASH_LEN + SHARKSSL_SHA1_HASH_LEN))
   U8 hash[SHARKSSL_MAX_HASH_LEN];
   #else
   U8 hash[SHARKSSL_MD5_HASH_LEN + SHARKSSL_SHA1_HASH_LEN];
   #endif
   U8 *signature;
   U16 signLen;
   U8  signatureAlgo;
   U8  hashAlgo;
} SharkSslSignature;


typedef struct SharkSslCertParam
{
   SharkSslCertInfo  certInfo;
   SharkSslCertKey   certKey;
   SharkSslSignature signature;
} SharkSslCertParam;


typedef struct SharkSslSignParam  
{
   SharkSslCertKey  *pCertKey;
   SharkSslSignature signature;
} SharkSslSignParam;


#if SHARKSSL_ENABLE_CLONE_CERTINFO
typedef struct SharkSslClonedCertInfo
{
   SharkSslCertInfo ci;
   #if SHARKSSL_ENABLE_SESSION_CACHE
   U8 flags;
   #endif
} SharkSslClonedCertInfo;



#define SHARKSSL_CCINFO_CERT_CLONED  0x01
#define SHARKSSL_CCINFO_CERT_CACHED  0x02
#endif  
#endif  


#if SHARKSSL_ENABLE_DHE_RSA
typedef struct SharkSslDHParam
{
   U8 *p;     /* prime modulus     */
   U8 *g;     /* generator         */
   U8 *Y;     /* Ys/Yc             */
   U8 *r;     /* random secret     */
   U16 pLen;  /* len of p in bytes */
   U16 gLen;  /* len of g in bytes */
} SharkSslDHParam;
#endif


#if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
typedef struct SharkSslECDHParam
{
   U8 *XY;         /* X,Y coordinates */
   U8 *k;          /* random secret   */
   U16 xLen;       /* len of X, Y, k  */
   U16 curveType;  /* curve ID        */
} SharkSslECDHParam;
#endif


#if SHARKSSL_ENABLE_ECDSA
typedef struct SharkSslECDSAParam
{
   U8 *R;          /* R coordinate   */
   U8 *S;          /* S coordinate   */
   U8 *key;        /* key (pub/pri)  */
   U8 *hash;       /* message hash   */
   U16 keyLen;     /* len of key,R,S */
   U16 hashLen;    /* len of hash    */
   U16 curveType;  /* curve ID       */
} SharkSslECDSAParam;
#endif


#if SHARKSSL_ENABLE_RSA
SHARKSSL_API int async3clksrc(const SharkSslCertKey *ck, U8 op, U8 *stackchecker);
int omap3430common(const SharkSslCertKey *disableclock, U16 len, U8 *in, U8 *out, U8 seepromprobe);
int writemessage(const SharkSslCertKey *disableclock, U16 len, U8 *in, U8 *out, U8 seepromprobe);
int clockaccess(const SharkSslCertKey *disableclock, U16 len, U8 *in, U8 *out, U8 seepromprobe);
int handleguest(const SharkSslCertKey *disableclock, U16 len, U8 *in, U8 *out, U8 seepromprobe);
#endif
#if SHARKSSL_ENABLE_DHE_RSA
int  SharkSslDHParam_DH(const SharkSslDHParam*, U8 op, U8*);
#if SHARKSSL_SSL_SERVER_CODE
void SharkSslDHParam_setParam(SharkSslDHParam *dh);
#endif
#endif  
#if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
int  SharkSslECDHParam_ECDH(const SharkSslECDHParam*, U8 op, U8*);
#endif
#if SHARKSSL_ENABLE_ECDSA
int SharkSslECDSAParam_ECDSA(const SharkSslECDSAParam*, U8 op);
U16 relocationchain(SharkSslCertKey *disableclock);
#endif

#if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)

int  checkactions(SharkSslSignParam*);
int  systemcapabilities(const SharkSslSignParam*);

SHARKSSL_API int  spromregister(SharkSslCertParam*, const U8*, U32, U8*);
U8   SharkSslCertDN_equal(const SharkSslCertDN*, const SharkSslCertDN*);
SHARKSSL_API U16 interrupthandler(SharkSslCertKey*, SharkSslCert);
U16  SharkSslCert_vectSize_keyType(const SharkSslCert, U8*);
#if SHARKSSL_ENABLE_CLIENT_AUTH
U8   domainassociate(SharkSslCert, U8*, U16);
#endif
U8   fixupresources(SharkSslCert, U16, U8*);
U16  setupboard(SharkSslCert);
#if SHARKSSL_ENABLE_CLONE_CERTINFO
U8   realnummemory(SharkSslCon *o, SharkSslClonedCertInfo **outCertInfoPtr);
#endif
#if SHARKSSL_USE_ECC
U8   controllerregister(U16 delayusecs);
#endif
#endif


#endif 

#ifndef _SharkSslCon_h
#define _SharkSslCon_h

#define SHARKSSL_LIB 1
#include "SharkSSL.h"



#if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_SSL_CLIENT_CODE)

#define            SharkSsl_isServer(o) (o->role == SharkSsl_Server)
#define            SharkSsl_isClient(o) (o->role == SharkSsl_Client)

#elif SHARKSSL_SSL_SERVER_CODE

#define            SharkSsl_isServer(o) (1)
#define            SharkSsl_isClient(o) (0)

#elif SHARKSSL_SSL_CLIENT_CODE

#define            SharkSsl_isServer(o) (0)
#define            SharkSsl_isClient(o) (1)

#elif ((!SHARKSSL_ENABLE_RSA_API) && (!SHARKSSL_ENABLE_ECDSA_API) && (!SHARKSSL_ENABLE_PEM_API))

#error NEITHER SERVER NOR CLIENT CODE SELECTED
#endif

#define rangealigned   20
#define firstentry                21
#define controllegacy            22
#define polledbutton     23

#define switchessetup       0
#define pciercxcfg070        1
#define trampolinehandler        2
#define parsebootinfo         11
#define startflags 12
#define logicmembank 13
#define configcwfon   14
#define modifygraph  15
#define subtableheaders 16
#define switcherdevice            20
#define loongson3notifier            0xFF

#define ahashchild                0x01
#define systemtable                0x02
#define compatrestart              0x40

#define deviceunregister          0x00FF

#define cminstclear                0


#define firstversion                  0
#define protectionfault          1
#define switchertrace       2
#define pca953xpdata              3
#define mailboxentries               4
#define registerwatchdog               5
#define deviceprobe                6
#define recoverygpiod                 7
#define bootloaderentry                 8
#define callchainkernel                    9
#define registerpwrdms              10
#define edma0resources             11
#define logicpdtorpedo                          12
#define entrypaddr          13
#define moduleflags                     14
#define cpucfgsynthesize                    15
#define clkdmclear  16
#define queuelogical            17
#define pciercxcfg075 18
#define aa64isar1override               35
#define featurespresent           0xFF01


#define spannedpages                   23
#define restoretrace                   24
#define buildmemmap                   25

#define samplingevent             26
#define entrytrampoline             27
#define resumeprepare             28



#define probesystem             0
#define crashsetup      1
#define checkheader      2



#define pchip1present             1
#define targetmemory1             2
#define mcbsp5hwmod                3



#if (!SHARKSSL_ENABLE_RSA)
#if SHARKSSL_ENABLE_DHE_RSA
#error SHARKSSL_ENABLE_RSA must be selected when SHARKSSL_ENABLE_DHE_RSA is enabled
#endif
#if SHARKSSL_ENABLE_ECDHE_RSA
#error SHARKSSL_ENABLE_RSA must be selected when SHARKSSL_ENABLE_ECDHE_RSA is enabled
#endif
#endif


#if SHARKSSL_USE_ECC
#if ((!SHARKSSL_ECC_USE_SECP256R1) && (!SHARKSSL_ECC_USE_SECP384R1) && (!SHARKSSL_ECC_USE_SECP521R1))
#error no elliptic nandflashpartition selected
#endif
#if (SHARKSSL_ECDSA_ONLY_VERIFY && (SHARKSSL_SSL_CLIENT_CODE || SHARKSSL_SSL_SERVER_CODE))
#error SHARKSSL_ECDSA_ONLY_VERIFY must be 0 when SSL/TLS is enabled
#endif
#else
#if SHARKSSL_ENABLE_ECDHE_RSA
#error SHARKSSL_USE_ECC must be selected when SHARKSSL_ENABLE_ECDHE_RSA is enabled
#endif
#if SHARKSSL_ENABLE_ECDHE_ECDSA
#error SHARKSSL_USE_ECC must be selected when SHARKSSL_ENABLE_ECDHE_ECDSA is enabled
#endif

#if (!SHARKSSL_ENABLE_RSA)
#if SHARKSSL_ENABLE_ECDHE_RSA
#error SHARKSSL_ENABLE_RSA must be selected when SHARKSSL_ENABLE_ECDHE_RSA is enabled
#endif
#endif  

#if SHARKSSL_ENABLE_ECDSA
#error SHARKSSL_USE_ECC must be selected when SHARKSSL_ENABLE_ECDSA is enabled
#else
#if SHARKSSL_ENABLE_ECDHE_ECDSA
#error SHARKSSL_ENABLE_ECDSA must be selected when SHARKSSL_ENABLE_ECDHE_ECDSA is enabled
#endif
#endif  
#endif  



#if SHARKSSL_ENABLE_AES_GCM

#if (SHARKSSL_USE_AES_128 && SHARKSSL_USE_SHA_256)
#if SHARKSSL_ENABLE_DHE_RSA
#define branchenable   TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
#endif  
#if SHARKSSL_ENABLE_ECDHE_RSA
#define resumenonboot TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#endif  
#if SHARKSSL_ENABLE_ECDHE_ECDSA
#define enablecharger TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#endif  
#endif  

#if (SHARKSSL_USE_AES_256 && SHARKSSL_USE_SHA_384)
#if SHARKSSL_ENABLE_DHE_RSA
#define quirkslc90e66   TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
#endif  
#if SHARKSSL_ENABLE_ECDHE_RSA
#define mallocalign TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#endif  
#if SHARKSSL_ENABLE_ECDHE_ECDSA
#define mitigationstate TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
#endif  
#endif  

#endif  


#if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
#if SHARKSSL_ENABLE_DHE_RSA
#define nvramgetenv         TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
#endif  
#if SHARKSSL_ENABLE_ECDHE_RSA
#define releasedpages       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
#endif  
#if SHARKSSL_ENABLE_ECDHE_ECDSA
#define kernelrelocation     TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
#endif  
#endif  


#define resourcebtuart                       SHARKSSL_MD5_HASH_LEN  
#define m62332senddata                      SHARKSSL_SHA1_HASH_LEN
#define loongson3cpucfg                    SHARKSSL_SHA256_HASH_LEN
#define gpiocfgdefault                    SHARKSSL_SHA384_HASH_LEN
#define iwmmxtcontext                    SHARKSSL_SHA512_HASH_LEN
#define stateoneshot                  SHARKSSL_POLY1305_HASH_LEN

#define sapicvector              12   
#define SHARKSSL_MAX_FINISHED_MSG_LEN              sapicvector

#define clkctrlmanaged                5    
#define traceentry             4    
#define SHARKSSL_MAX_SESSION_ID_LEN                32   
#define statsstruct                       8    
#define SHARKSSL_RANDOM_LEN                        32   
#define SHARKSSL_MASTER_SECRET_LEN                 48   


#if   SHARKSSL_USE_SHA_512
#define SHARKSSL_MAX_DIGEST_LEN                    iwmmxtcontext
#define SHARKSSL_MAX_DIGEST_BLOCK_LEN              SHARKSSL_SHA512_BLOCK_LEN
#elif SHARKSSL_USE_SHA_384
#define SHARKSSL_MAX_DIGEST_LEN                    gpiocfgdefault
#define SHARKSSL_MAX_DIGEST_BLOCK_LEN              SHARKSSL_SHA384_BLOCK_LEN
#else
#define SHARKSSL_MAX_DIGEST_LEN                    loongson3cpucfg
#define SHARKSSL_MAX_DIGEST_BLOCK_LEN              SHARKSSL_SHA256_BLOCK_LEN
#endif  
#define SHARKSSL_MAX_DIGEST_PAD_LEN                48   
#define gpio2enable                       (16384 + 2048) 
#define prefetchwrite                   SHARKSSL_MAX_BLOCK_LEN

#define ckctlrecalc                16   
#if SHARKSSL_ENABLE_AES_GCM
#define systemcontroller                    statsstruct
#else
#define systemcontroller                    0
#endif

#if   (SHARKSSL_USE_AES_256 || (SHARKSSL_USE_POLY1305 && SHARKSSL_USE_CHACHA20))
#define SHARKSSL_MAX_KEY_LEN                       32   
#elif (SHARKSSL_USE_AES_128)
#define SHARKSSL_MAX_KEY_LEN                       16   
#else
#error At least one cipher must be selected in SharkSSL_cfg.h
#endif

#if   (SHARKSSL_USE_AES_128 || SHARKSSL_USE_AES_256)
#define SHARKSSL_MAX_BLOCK_LEN                     16   
#else
#define SHARKSSL_MAX_BLOCK_LEN                     0    
#endif



#define cachewback                    1024
#define gpio5config                 (statsstruct)



#define SHARKSSL_HS_PARAM_OFFSET                   claimresource(clkctrlmanaged + 1 + \
                                                                       clkctrlmanaged + \
                                                                       SHARKSSL_MAX_BLOCK_LEN + \
                                                                       sapicvector + \
                                                                       SHARKSSL_MAX_DIGEST_LEN + \
                                                                       prefetchwrite)

#define clockgettime32                0x00000001
#define audiosuspend                0x00000002
#define cachematch    0x00000004
#define shutdownlevel               0x00000008
#define timerwritel           0x00000010
#define firstcomponent                  0x00000020
#define switcherregister                  0x00000040
#define stealenabled               0x00000080
#define probedaddress          0x00000100
#define startqueue              0x00000200
#define unregistershash          0x00000400
#define nresetconsumers        0x00000800
#define accountsoftirq              0x00001000
#define serialreset            0x00002000
#define switcheractivation                   0x00004000
#define aarch32ptrace         0x00008000
#define registerbuses      0x00010000
#define skciphersetkey      0x00020000
#define platformdevice        0x00040000
#define createmappings     0x00080000
#define gpiolibmbank               0x00100000
#define devicedriver           0x00200000
#define uprobeabort                    0x00400000
#define symbolnodebug            0x00800000
#define ftracehandler               0x01000000


#define bcm1x80bcm1x55                     0x01
#define boardcompat                       0x02
#define chargerworker                     (bcm1x80bcm1x55 | boardcompat)
#define ptraceregsets                        0x10
#define populatebasepages                        0x20



#define cleandcache                            0x0001
#define irqhandlerfixup                             0x0002
#define cpufreqcallback                            0x0004
#define percpudevid                            0x0008
#define fixupmem32                       0x0010
#define framekernel                           0x0020  
#define suspendenter                        0x0040  
#define compareinterrupt                       0x0080  
#define overcommitmemory                          0x0100
#define ioasicclocksource                         0x0200
#define keypadrelease                         0x0400
#define da9034backlight                        0x0800
#define recoverrange                           0x1000


typedef struct SharkSslBuf
{
   #if SHARKSSL_UNALIGNED_MALLOC
   U8  *mem;     /* where the allocated memory begins in this case */
   #endif
   U8  *buf;     /* where the allocated memory begins */
   U8  *data;    /* where the data begins */
   U16  size;    /* number of bytes in the buffer available to the user */
   U16  dataLen; /* length of the data to be processed */
   U16  temp;
} SharkSslBuf;

void    atomiccmpxchg(SharkSslBuf*, U16);
void    guestconfig5(SharkSslBuf*);
#if (!SHARKSSL_DISABLE_INBUF_EXPANSION)
U8     *othersegments(SharkSslBuf*, U16);
#endif
void    binaryheader(SharkSslBuf*);
#define microresources(o) (!((o)->buf))
#define func3fixup(o) \
   ((o)->buf + gpio5config)
#define serial2platform(o) \
   ((o)->data == func3fixup(o))
#define registerfixed(o) do {\
   (o)->data = func3fixup(o); \
   } while (0)
#if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
#define reportsyscall(pciercxcfg448, src) \
   memcpy((U8*)((pciercxcfg448)->buf), (U8*)((src)->buf), gpio5config)
#endif



typedef int (*SharkSslCon_cipherFunc)(SharkSslCon*, U8, U8*, U16);

typedef struct SharkSslCipherSuite
{
   SharkSslCon_cipherFunc cipherFunc;
   U16 id;
   U16 flags;
   U8  keyLen;
   U8  digestLen;
   U8  hashID;
} SharkSslCipherSuite;

U16 disableclean(SharkSslCipherSuite*);


#if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
typedef struct SharkSslCertParsed
{
   SharkSslCert cert;
   U16 msgLen;   /* certificate message length */
   U8  keyType;
   U8  keyOID;
   U8  signatureAlgo;
   U8  hashAlgo;
   #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI)
   const U8 *commonName;
   U8 *subjectAltNamesPtr;
   U16 subjectAltNamesLen; 
   U8  commonNameLen;      /** length in bytes of the field "commonName" */
   #endif
} SharkSslCertParsed;


typedef struct SharkSslCertList
{
   SingleLink link;
   SharkSslCertParsed certP;
} SharkSslCertList;
#endif  


typedef struct SharkSslHSParam
{
   U8  clientRandom[SHARKSSL_RANDOM_LEN];
   U8  serverRandom[SHARKSSL_RANDOM_LEN];
   U8  masterSecret[SHARKSSL_MASTER_SECRET_LEN];
   U8  sharedSecret[2 * (SHARKSSL_MAX_DIGEST_LEN +
                         SHARKSSL_MAX_KEY_LEN +
                         SHARKSSL_MAX_BLOCK_LEN) + SHARKSSL_MAX_DIGEST_LEN];
   SharkSslSha256Ctx   sha256Ctx;
   #if SHARKSSL_USE_SHA_384
   SharkSslSha384Ctx   sha384Ctx;
   #endif
   #if SHARKSSL_USE_SHA_512
   SharkSslSha384Ctx   sha512Ctx;
   #endif
   #if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
   SharkSslCertParsed *certParsed;  /* the selected cert */
   SharkSslCertKey     certKey;     /* points to cert's key */
   SharkSslCertParam   certParam;   /* peer's cert */
   SharkSslSignParam   signParam;
   #endif
   #if SHARKSSL_ENABLE_DHE_RSA
   SharkSslDHParam     dhParam;
   #endif
   #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
   SharkSslECDHParam   ecdhParam;
   #endif
   SharkSslCipherSuite *cipherSuite;
} SharkSslHSParam;


void    breakpointhandler(SharkSslHSParam*);
void    alignmentldmstm(SharkSslHSParam*);
void    ioremapresource(SharkSslHSParam*, U8*, U16);
int     wakeupvector(SharkSslHSParam*, U8*, U8);
#define hsParam(o) ((SharkSslHSParam*)(func3fixup(&o->outBuf) + SHARKSSL_HS_PARAM_OFFSET))


#if SHARKSSL_ENABLE_SESSION_CACHE
struct SharkSslSession
{
   SharkSslCipherSuite *cipherSuite;
   U32 firstAccess, latestAccess;
   U8  id[SHARKSSL_MAX_SESSION_ID_LEN];
   U8  masterSecret[SHARKSSL_MASTER_SECRET_LEN];
   U16 nUse;
   U8  major_minor, flags;
   #if SHARKSSL_ENABLE_CLONE_CERTINFO
   SharkSslClonedCertInfo *clonedCertInfo;
   #endif
};

#define restarthandler(o,maj,min) ((o)->major_minor == (((maj & 0x0F) << 4) | (min & 0x0F)))
#define batterylevels(o)            (((o)->major_minor & 0xF0) >> 4)
#define hardirqsenabled(o)            ((o)->major_minor & 0x0F)
#define sha224final(o,maj,min) do {           \
   baAssert((maj <= 0x0F) && (min <= 0x0F));                \
   (o)->major_minor = (((maj & 0x0F) << 4) | (min & 0x0F)); \
   } while (0);



#define ecoffaouthdr             0x80


void    counter1clocksource(SharkSslSessionCache*, U16);
void    defaultsdhci0(SharkSslSessionCache*);
#define filtermatch(o)   ThreadMutex_set(&((o)->cacheMutex))
#define helperglobal(o) ThreadMutex_release(&((o)->cacheMutex))
SharkSslSession *sa1111device(SharkSslSessionCache*, SharkSslCon*, U8*, U16);
SharkSslSession *latchgpiochip(SharkSslSessionCache*, SharkSslCon*, U8*, U16);
#endif


struct SharkSslCon   
{
   #if SHARKSSL_MAX_BLOCK_LEN
   #if ((SHARKSSL_MAX_BLOCK_LEN < 16) && (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305))
   U8 rIV[16];
   #else
   U8 rIV[SHARKSSL_MAX_BLOCK_LEN];
   #endif
   #elif (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
   U8 rIV[16];
   #endif
   #if SHARKSSL_MAX_KEY_LEN
   U8 rKey[SHARKSSL_MAX_KEY_LEN];
   #endif

   #if SHARKSSL_MAX_BLOCK_LEN
   #if ((SHARKSSL_MAX_BLOCK_LEN < 16) && ((SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305) || SHARKSSL_ENABLE_AES_GCM))
   U8 wIV[16];
   #else
   U8 wIV[SHARKSSL_MAX_BLOCK_LEN];
   #endif
   #elif  ((SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305) || SHARKSSL_ENABLE_AES_GCM)
   U8 wIV[16];
   #endif
   #if SHARKSSL_MAX_KEY_LEN
   U8 wKey[SHARKSSL_MAX_KEY_LEN];
   #endif

   SharkSsl *sharkSsl;
   SharkSslCipherSuite *rCipherSuite, *wCipherSuite;
   #if SHARKSSL_ENABLE_SESSION_CACHE
   SharkSslSession *session;
   #endif

   void *rCtx, *wCtx;
   #if SHARKSSL_UNALIGNED_MALLOC
   SharkSslCon *mem;
   #endif

   #if SHARKSSL_ENABLE_ALPN_EXTENSION
   const char  *pALPN;
   const char  *rALPN;
   #if SHARKSSL_SSL_SERVER_CODE
   ALPNFunction fALPN;
   #endif
   #endif

   #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
   U8 clientVerifyData[SHARKSSL_MAX_FINISHED_MSG_LEN];
   U8 serverVerifyData[SHARKSSL_MAX_FINISHED_MSG_LEN];
   #endif

   #if ((SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA) && SHARKSSL_ENABLE_CLONE_CERTINFO)
   SharkSslClonedCertInfo *clonedCertInfo;
   #endif

   #if (SHARKSSL_ENABLE_CA_LIST && SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_CLIENT_AUTH && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA))
   SharkSslCAList caListCertReq;
   #endif

   SharkSslBuf inBuf, outBuf;
   #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
   SharkSslBuf tmpBuf;
   #endif

   U32 flags;
   U8 state;
   U8 reqMajor, reqMinor;
   U8 major, minor;
   U8 padLen;
   U8 alertLevel, alertDescr;
   #if ((SHARKSSL_SSL_SERVER_CODE || SHARKSSL_SSL_CLIENT_CODE) && SHARKSSL_ENABLE_SELECT_CIPHERSUITE)
   #if (SHARKSSL_SELECT_CIPHERSUITE_LIST_DEPTH > 0xFF)
   #error SHARKSSL_SELECT_CIPHERSUITE_LIST_DEPTH must be lower than 256
   #endif
   U8 cipherSelection[SHARKSSL_SELECT_CIPHERSUITE_LIST_DEPTH];
   U8 cipherSelCtr;
   #endif

   #if SHARKSSL_ERRORLINE_DEBUG
   int errLine;
   #endif
};


typedef enum
{
  tvp5146routes,
  rodatastart
} SharkSslCon_SendersRole;



#define SharkSsl_createCon2(o, sharkSslCon) do {\
   (o)->nCon++;\
   conditionvalid(sharkSslCon, o);\
} while (0)



void               conditionvalid(SharkSslCon *o, SharkSsl *resetcounters);
void               localenable(SharkSslCon *o);


SharkSslCon_RetVal savedconfig(SharkSslCon*, U8);
SharkSslCon_RetVal securememblock(SharkSslCon*, U8, U8);
#if SHARKSSL_ENABLE_CLONE_CERTINFO
SharkSslCon_RetVal configdword(SharkSslCon*, U8*, U16, U8);
#else
SharkSslCon_RetVal configdword(SharkSslCon*, U8*, U16*, U8);
#endif
SharkSslCon_RetVal kexecprotect(SharkSslCon*, U8*, U16);
U8                *templateentry(SharkSslCon*, U8, U8*, U16);
int                allocalloc(SharkSslCon*, U8*, U16, U8*, U16, U8[32], U8[32]);
int                printsilicon(SharkSslCon*, SharkSslCon_SendersRole, U8*);
int                sanitisependbaser(SharkSslCon *o, SharkSslCon_SendersRole, U8*);
int                writebackscache(SharkSslCon*, U8);
#define            r3000tlbchange(o) claimresource(clkctrlmanaged + ckctlrecalc + systemcontroller)
void               fpemureturn(SharkSslCon*);

#if SHARKSSL_ERRORLINE_DEBUG
#define            debugdestroy(o)      (o)->errLine
#define            resvdexits(o)      (debugdestroy(o) = (int)__LINE__)
#else
#define            debugdestroy(o)      0
#define            resvdexits(o)      
#endif

#if ((SHARKSSL_USE_AES_128 || SHARKSSL_USE_AES_256) && SHARKSSL_ENABLE_AES_GCM)
int  offsetkernel(SharkSslCon*, U8, U8*, U16);
#endif
#if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
int updatecontext(SharkSslCon*, U8, U8*, U16);
#endif

#endif


#ifndef BA_LIB
#define BA_LIB
#endif



#if SHARKSSL_USE_ECC

#endif
#include <string.h>

#define SHARKSSL_DIM_ARR(a)  (sizeof(a)/sizeof(a[0]))

#define _SHARKSSLCON_HS_C_

#ifndef _SharkSslCipher_h
#define _SharkSslCipher_h


#ifdef _SHARKSSLCON_HS_C_

static const SharkSslCipherSuite sharkSslCipherSuiteList[] =
{
   #if SHARKSSL_ENABLE_ECDHE_ECDSA
   
   #if kernelrelocation
   {
   updatecontext,
   kernelrelocation,
   irqhandlerfixup | cleandcache | cpufreqcallback | suspendenter | overcommitmemory,
   32, 
   16, 
   SHARKSSL_HASHID_SHA256
   },
   #endif
   #if mitigationstate
   {
   offsetkernel,
   mitigationstate,
   irqhandlerfixup | cleandcache | cpufreqcallback | framekernel | overcommitmemory | ioasicclocksource,
   32, 
   16, 
   SHARKSSL_HASHID_SHA384
   },
   #endif
   #if enablecharger
   {
   offsetkernel,
   enablecharger,
   irqhandlerfixup | cleandcache | cpufreqcallback | framekernel | overcommitmemory,
   16, 
   16, 
   SHARKSSL_HASHID_SHA256
   },
   #endif
   #endif  

   #if SHARKSSL_ENABLE_RSA
   
   #if releasedpages
   {
   updatecontext,
   releasedpages,
   irqhandlerfixup | cleandcache | percpudevid | suspendenter | overcommitmemory,
   32, 
   16, 
   SHARKSSL_HASHID_SHA256
   },
   #endif
   #if mallocalign
   {
   offsetkernel,
   mallocalign,
   irqhandlerfixup | cleandcache | percpudevid | framekernel | overcommitmemory | ioasicclocksource,
   32, 
   16, 
   SHARKSSL_HASHID_SHA384
   },
   #endif
   #if resumenonboot
   {
   offsetkernel,
   resumenonboot,
   irqhandlerfixup | cleandcache | percpudevid | framekernel | overcommitmemory,
   16, 
   16, 
   SHARKSSL_HASHID_SHA256
   },
   #endif

   
   #if nvramgetenv
   {
   updatecontext,
   nvramgetenv,
   cleandcache | percpudevid | suspendenter | overcommitmemory,
   32, 
   16, 
   SHARKSSL_HASHID_SHA256
   },
   #endif
   #if quirkslc90e66
   {
   offsetkernel,
   quirkslc90e66,
   cleandcache | percpudevid | framekernel | overcommitmemory | ioasicclocksource,
   32, 
   16, 
   SHARKSSL_HASHID_SHA384
   },
   #endif
   #if branchenable
   {
   offsetkernel,
   branchenable,
   cleandcache | percpudevid | framekernel | overcommitmemory,
   16, 
   16, 
   SHARKSSL_HASHID_SHA256
   },
   #endif
   #endif  
};
#endif  

#endif
  
#undef  _SHARKSSLCON_HS_C_


#if ((SHARKSSL_SSL_SERVER_CODE || SHARKSSL_SSL_CLIENT_CODE) && SHARKSSL_ENABLE_SELECT_CIPHERSUITE)
SHARKSSL_API U8 SharkSslCon_selectCiphersuite(SharkSslCon *o, U16 clockmodtable)
{
   baAssert(SHARKSSL_DIM_ARR(sharkSslCipherSuiteList) < 0xFF);

   if ((o) && ((o->state <= pciercxcfg070)
               #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
               || (o->flags & registerbuses)
               #endif
       ))
   {
      if (o->cipherSelCtr < SHARKSSL_SELECT_CIPHERSUITE_LIST_DEPTH)
      {
         
         int i;

         for (i = 0; i < SHARKSSL_DIM_ARR(sharkSslCipherSuiteList); i++)
         {
            if (sharkSslCipherSuiteList[i].id == clockmodtable)
            {
               o->cipherSelection[o->cipherSelCtr++] = (U8)i;
               return 1;  
            }
         }
      }
   }

   return 0;
}


SHARKSSL_API U8 SharkSslCon_clearCiphersuiteSelection(SharkSslCon *o)
{
   if ((o) && ((o->state <= pciercxcfg070)
               #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
               || (o->flags & registerbuses)
               #endif
       ))
   {
      o->cipherSelCtr = 0;
      return 1;  
   }

   return 0;
}
#endif


#if SHARKSSL_ENABLE_ALPN_EXTENSION
#if SHARKSSL_SSL_CLIENT_CODE
U8 SharkSslCon_setALPNProtocols(SharkSslCon* o, const char* iobanktiming)
{
   if (o && (o->state <= pciercxcfg070)
      #if SHARKSSL_SSL_SERVER_CODE
      && (SharkSsl_isClient(o->sharkSsl))
      #endif
      )
   {
      o->pALPN = iobanktiming;
      return 1;  
   }

   return 0;
}


const char * SharkSslCon_getALPNProtocol(SharkSslCon* o)
{
   return o->rALPN;
}
#endif


#if SHARKSSL_SSL_SERVER_CODE
U8 SharkSslCon_setALPNFunction(SharkSslCon* o, ALPNFunction func0fixup, void *writeabort)
{
   if (o && (o->state <= trampolinehandler)
      #if SHARKSSL_SSL_CLIENT_CODE
      && (SharkSsl_isServer(o->sharkSsl))
      #endif
      )
   {
      o->fALPN = func0fixup;
      o->pALPN = (const char*)writeabort;
      o->rALPN = NULL;
      return 1;  
   }

   return 0;
}
#endif
#endif  


#define SHARKSSL_WEIGHT                 U32          
#define trainingneeded   0x00800000L
#define smbuswrite        0x01000000L
#define lcd035q3dg01pdata              0x10000000L
#define clearevent       0x80000000L  
#define coverstate   0x00080000L  

#if SHARKSSL_SSL_SERVER_CODE
#if SHARKSSL_ENABLE_SNI
#include <SharkSslEx.h>
#endif
static int writepmresr(SharkSslCon *o, SHARKSSL_WEIGHT *mfgpt0counter, U8 *registeredevent, U16 len)
{
   SHARKSSL_WEIGHT *p;
   SingleListEnumerator e;
   SingleLink *link;
   SharkSslHSParam *sharkSslHSParam;

#else
static int writepmresr(SharkSslCon *o, U8 *registeredevent, U16 len)
{
#endif

   U16 extId, csLen;

   baAssert(o);
   baAssert(registeredevent);
   #if SHARKSSL_SSL_SERVER_CODE
   sharkSslHSParam = hsParam(o);
   #endif
   #if SHARKSSL_USE_ECC
   baAssert(SHARKSSL_EC_CURVE_ID_SECP256R1 == spannedpages);
   baAssert(SHARKSSL_EC_CURVE_ID_SECP384R1 == restoretrace);
   baAssert(SHARKSSL_EC_CURVE_ID_SECP521R1 == buildmemmap);
   baAssert(SHARKSSL_EC_CURVE_ID_BRAINPOOLP256R1 == samplingevent);
   baAssert(SHARKSSL_EC_CURVE_ID_BRAINPOOLP384R1 == entrytrampoline);
   baAssert(SHARKSSL_EC_CURVE_ID_BRAINPOOLP512R1 == resumeprepare);
   #endif

   while (len >= 2)
   {
      extId  = (U16)(*registeredevent++) << 8;
      extId += *registeredevent++;
      len -= 2;

      if (len < 2)
      {
         return -1;
      }

      csLen  = (U16)(*registeredevent++) << 8;
      csLen += *registeredevent++;
      len -= 2;

      if (len < csLen)
      {
         return -1;
      }

      switch (extId)
      {
         #if SHARKSSL_ENABLE_ALPN_EXTENSION
         case clkdmclear:
            if (csLen)  
            {
               csLen = (U16)(*registeredevent++) << 8;
               csLen += *registeredevent++;
               len -= 2;
               if (csLen > len)
               {
                  return -1;
               }
               #if SHARKSSL_SSL_CLIENT_CODE 
               #if SHARKSSL_SSL_SERVER_CODE
               if (SharkSsl_isClient(o->sharkSsl))
               #endif
               {
                  csLen = *registeredevent++;
                  len--;
                  if (csLen > len)
                  {
                     return -1;
                  }
                  len -= csLen;
                  
                  if (o->pALPN)
                  {
                     
                     U8 *afterhandler = (U8*)baMalloc(csLen + 1);
                     memcpy(afterhandler, registeredevent, csLen);
                     *(afterhandler + csLen) = 0;
                     o->rALPN = strstr(o->pALPN, (const char *)afterhandler);
                     baFree(afterhandler);
                  }
               }
               #if SHARKSSL_SSL_SERVER_CODE 
               else
               #endif
               #endif
               #if SHARKSSL_SSL_SERVER_CODE
               {
                  if (o->fALPN)
                  {
                     o->rALPN = NULL;
                     while ((csLen > 0) && (csLen <= len) && (NULL == o->rALPN))
                     {
                        int ret;
                        U8* afterhandler;
                        extId = *registeredevent;  
                        
                        afterhandler = (U8*)baMalloc(extId + 1);
                        memcpy(afterhandler, registeredevent + 1, extId);
                        *(afterhandler + extId) = 0;
                        ret = o->fALPN(o, (const char*)afterhandler, (void*)o->pALPN);
                        baFree(afterhandler);
                        
                        if (ret)
                        {
                           o->rALPN = (const char*)registeredevent;  
                        }
                        extId++;
                        registeredevent += extId;
                        csLen -= extId;
                        len -= extId;
                     }
                     if ((NULL == o->rALPN) && (0 == o->fALPN(o, NULL, (void*)o->pALPN)))
                     {
                        return -2;  
                     }
                  }
                  len -= csLen;
               }
               #endif
               registeredevent += csLen;
            }
            break;
         #endif

         case featurespresent:
            if (len < 1)
            {
               return -1;
            }
            csLen = *registeredevent++;
            len--;
            if (csLen > len)
            {
               return -1;
            }
            len -= csLen;
            if (!(o->flags & aarch32ptrace))
            {
               o->flags |= aarch32ptrace;
               if (csLen)
               {
                  
                  #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
                  goto _sharkssl_parseext_1;
                  #else
                  return -1;
                  #endif
               }
            }
            else 
            {
               #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
               if (!(o->flags & platformdevice))
               {
                  _sharkssl_parseext_1:
                  if (csLen != sapicvector)
                  {
                     return -1;
                  }
               }
               if (sharkssl_kmemcmp(registeredevent, SharkSsl_isServer(o->sharkSsl) ? o->clientVerifyData : o->serverVerifyData, csLen))
               {
                  return -1;
               }
               registeredevent += csLen;

               #else
               return -1;  

               #endif
            }
            break;

         #if SHARKSSL_USE_ECC
         case edma0resources:
            if ((len < 1)
                #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
                || (o->minor == 0)
                #endif
               )
            {
               return -1;
            }
            csLen = *registeredevent++;
            len--;
            if (csLen > len)
            {
               return -1;
            }
            len -= csLen;
            while ((csLen) && (*registeredevent++ != probesystem))
            {
               csLen--;
            }
            if (0 == csLen)  
            {
               return -1;
            }
            csLen--;
            registeredevent += csLen;
            break;
         #endif  

         #if SHARKSSL_SSL_SERVER_CODE
         #if SHARKSSL_ENABLE_SNI
         case firstversion:
            if (csLen)   
            {
               csLen  = (U16)(*registeredevent++) << 8;
               csLen += *registeredevent++;
               len -= 2;
               if (csLen > len)
               {
                  return -1;
               }
               len -= csLen;

               #if SHARKSSL_SSL_CLIENT_CODE
               
               if (0 == mfgpt0counter)
               {
                  registeredevent += csLen;
                  csLen = 0;
               }
               #endif
            }

            while (csLen)
            {
               if (*registeredevent++)
               {
                  return -1;  
               }
               extId  = (U16)(*registeredevent++) << 8;
               extId += *registeredevent++;
               csLen -= 3;
               if (extId > csLen)
               {
                  return -1;
               }
               
               
               SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
               for (p = mfgpt0counter, link = SingleListEnumerator_getElement(&e);
                     link;
                     link = SingleListEnumerator_nextElement(&e), p++)
               {
                  if (*p) 
                  {
                     if (0 == sharkSubjectSubjectAltCmp((const char*)((SharkSslCertList*)link)->certP.commonName,
                                                        ((SharkSslCertList*)link)->certP.commonNameLen,
                                                        ((SharkSslCertList*)link)->certP.subjectAltNamesPtr,
                                                        ((SharkSslCertList*)link)->certP.subjectAltNamesLen,
                                                        (const char*)registeredevent, extId))
                     {
                        *(SHARKSSL_WEIGHT*)p |= clearevent;
                     }
                  }
               }

               registeredevent += extId;
               csLen -= extId;
            }
            break;
         #endif  

         #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         case registerpwrdms:
            if ((o->flags & startqueue)
                #if SHARKSSL_SSL_CLIENT_CODE  
                || (SharkSsl_isClient(o->sharkSsl))
                #endif
               )
            {
               goto _sharkssl_parseext_default;
            }
            if ((len < 2)
                #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
                || (o->minor == 0)
                #endif
               )
            {
               return -1;
            }
            csLen  = (U16)(*registeredevent++) << 8;
            csLen += *registeredevent++;
            len -= 2;
            if (csLen > len)
            {
               return -1;
            }
            len -= csLen;
            sharkSslHSParam->ecdhParam.xLen = 0;
            while (csLen)
            {
               U8 savedsigmask;

               
               extId  = (U16)(*registeredevent++) << 8;
               extId += *registeredevent++;
               csLen -= 2;

               
               savedsigmask = controllerregister(extId);
               if (savedsigmask)
               {
                  if (0 == sharkSslHSParam->ecdhParam.xLen)
                  {
                     sharkSslHSParam->ecdhParam.xLen = savedsigmask;
                     
                     sharkSslHSParam->ecdhParam.curveType = extId;
                  }

                  
                  SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
                  for (p = mfgpt0counter, link = SingleListEnumerator_getElement(&e);
                       link;
                       link = SingleListEnumerator_nextElement(&e), p++)
                  {
                     if ( (*p)
                          && (((SharkSslCertList*)link)->certP.keyType == compatrestart)  
                          && (((SharkSslCertList*)link)->certP.keyOID == extId))
                     {
                        *(SHARKSSL_WEIGHT*)p |= trainingneeded;
                     }
                  }
               }
            }
            break;
         #endif  

         case entrypaddr:
            #if SHARKSSL_SSL_CLIENT_CODE  
            if (SharkSsl_isClient(o->sharkSsl))
            {
               return -1;
            }
            #endif
            if (o->minor >= 3)  
            {
               if (len < 2)
               {
                  return -1;
               }
               csLen  = (U16)(*registeredevent++) << 8;
               csLen += *registeredevent++;
               len -= 2;
               if ((csLen > len) || (csLen & 0x1))
               {
                  return -1;
               }
               len -= csLen;
               extId = 0;  
               while (csLen)
               {
                  
                  SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
                  for (p = mfgpt0counter, link = SingleListEnumerator_getElement(&e);
                       link;
                       link = SingleListEnumerator_nextElement(&e), p++)
                  {
                     if ((*p) && (!(*p & smbuswrite)))
                     {
                        if ((((SharkSslCertList*)link)->certP.hashAlgo == registeredevent[0]) &&
                            (((SharkSslCertList*)link)->certP.signatureAlgo == registeredevent[1]))
                        {
                           *(SHARKSSL_WEIGHT*)p |= smbuswrite;
                        }
                     }
                  }

                  
                  if (extId < 2)
                  {
                     if ((registeredevent[0] == presentpages) || (registeredevent[0] == domainnumber)
                         #if SHARKSSL_USE_SHA_384
                         || (registeredevent[0] == probewrite)
                         #endif
                         #if SHARKSSL_USE_SHA_512
                         || (registeredevent[0] == batterythread)
                         #endif
                        )
                     {
                        #if SHARKSSL_ENABLE_RSA
                        if ((0 == sharkSslHSParam->signParam.signature.signatureAlgo) && (registeredevent[1] == entryearly))
                        {
                           sharkSslHSParam->signParam.signature.signatureAlgo = registeredevent[0];
                           extId++;
                        }
                        #endif
                        #if SHARKSSL_ENABLE_ECDSA
                        if ((0 == sharkSslHSParam->signParam.signature.hashAlgo) && (registeredevent[1] == accessactive))
                        {
                           sharkSslHSParam->signParam.signature.hashAlgo = registeredevent[0];
                           extId++;
                        }
                        #endif
                     }
                  }
                  registeredevent += 2;
                  csLen -= 2;
               }
               break;
            }
            
         #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
            _sharkssl_parseext_default:
         #endif
         #endif  

         default:  
            len -= csLen;
            registeredevent += csLen;
            break;
      }
   }
   return 0;
}


#if SHARKSSL_SSL_SERVER_CODE

static int SharkSslHSParam_setCert(SharkSslHSParam *s, SharkSslCertParsed **certPtr, U16 cipherSuiteFlags, U8 minor)
{
   (void)minor;
   baAssert(s);
   baAssert(certPtr);
   switch (cipherSuiteFlags & (cleandcache | irqhandlerfixup | cpufreqcallback | percpudevid))
   {
      #if SHARKSSL_ENABLE_RSA
      case percpudevid:  
      #if SHARKSSL_ENABLE_DHE_RSA
      case cleandcache | percpudevid:  
      #endif
      #if SHARKSSL_ENABLE_ECDHE_RSA
      case cleandcache | irqhandlerfixup | percpudevid:  
      #endif
         if (certPtr[0])  
         {
            s->certParsed = certPtr[0];
            return 0;
         }
         break;
      #endif  

      #if SHARKSSL_ENABLE_ECDHE_ECDSA
      case cleandcache | irqhandlerfixup | cpufreqcallback:  
         if (certPtr[2])  
         {
            s->certParsed = certPtr[2];
            return 0;
         }
         break;
      #endif

      default:
         
         break;
   }

   return -1;
}
#endif  


#if SHARKSSL_ENABLE_CLONE_CERTINFO
SharkSslCon_RetVal configdword(SharkSslCon *o,
                                                U8  *registeredevent,
                                                U16  atagsprocfs,
                                                U8   tvp5146pdata)
#else
SharkSslCon_RetVal configdword(SharkSslCon *o,
                                                U8  *registeredevent,
                                                U16 *deviceusbgadget,
                                                U8   tvp5146pdata)
#endif
{
   #if SHARKSSL_SSL_SERVER_CODE
   static const U8 registeraudio[] =
   {
      (U8)(featurespresent >> 8),
      (U8)(featurespresent & 0xFF),
      0x00, 0x01, 0x00
   };
   #endif

   #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
   static const U8 resetsources[] =
   {
      0x00, edma0resources,
      0x00, 0x02, 0x01, probesystem
   };
   #endif
   #if (SHARKSSL_SSL_CLIENT_CODE || (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_CLIENT_AUTH))
   #if (SHARKSSL_ENABLE_ECDSA || SHARKSSL_ENABLE_RSA)
   static const U8 serialwakeup[] =
   {
      #if SHARKSSL_ENABLE_ECDSA
      #if SHARKSSL_USE_SHA_512
      batterythread, accessactive,
      #endif
      #if SHARKSSL_USE_SHA_384
      probewrite, accessactive,
      #endif
      domainnumber, accessactive,
      presentpages,   accessactive,
      #endif  
      #if SHARKSSL_ENABLE_RSA
      #if SHARKSSL_USE_SHA_512
      batterythread, entryearly,
      #endif
      #if SHARKSSL_USE_SHA_384
      probewrite, entryearly,
      #endif
      domainnumber, entryearly,
      #if SHARKSSL_USE_SHA1
      presentpages,   entryearly,
      #endif
      #if SHARKSSL_USE_MD5
      skciphercreate,    entryearly  
      #endif
      #endif  
   };
   #endif
   #if MAX_FRAG_LEN
   static const U8 featureoverride[] =
   {
      (U8)(protectionfault >> 8),
      (U8)(protectionfault & 0xFF),
      0x00, 0x01,
      3  
   };
   #endif
   #endif

   U32  now, crLen;
   U8  *tp, *sp, *tb, *afterhandler;
   SharkSslHSParam *sharkSslHSParam;
   #if ((SHARKSSL_SSL_CLIENT_CODE || SHARKSSL_SSL_SERVER_CODE) && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA))
   SharkSslCertParam *certParam;
   #if (SHARKSSL_SSL_SERVER_CODE || SHARKSSL_ENABLE_CLIENT_AUTH)
   SingleListEnumerator e;
   SingleLink *link;
   #endif
   #endif
   U16  hsDataLen, csLen, hsLen, i;
   #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
   U16  atagsprocfs = *deviceusbgadget;
   #endif
   U8   setupinterface, ics;

   tb = (U8*)0;
   _sharkssl_process_another_hs_record:
   if ((0 == registeredevent) || (*registeredevent != o->state))
   {
      #if SHARKSSL_SSL_CLIENT_CODE
      if (o->flags & probedaddress)
      {
         SharkSslCipherSuite *clockmodtable;

         #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         static const U8 tcpudpmagic[] =
         {
            #if SHARKSSL_ECC_USE_SECP521R1
            0x00, buildmemmap,
            #endif
            #if SHARKSSL_ECC_USE_BRAINPOOLP512R1
            0x00, resumeprepare,
            #endif
            #if SHARKSSL_ECC_USE_SECP384R1
            0x00, restoretrace,
            #endif
            #if SHARKSSL_ECC_USE_BRAINPOOLP384R1
            0x00, entrytrampoline,
            #endif
            #if SHARKSSL_ECC_USE_SECP256R1
            0x00, spannedpages,
            #endif
            #if SHARKSSL_ECC_USE_BRAINPOOLP256R1
            0x00, samplingevent,
            #endif
         };
         #endif

         baAssert(SharkSsl_isClient(o->sharkSsl));
         o->flags &= ~probedaddress;

         baAssert(microresources(&o->outBuf));
         atomiccmpxchg(&o->outBuf, o->sharkSsl->outBufSize);
         if (microresources(&o->outBuf))
         {
            return SharkSslCon_AllocationError;
         }
         sharkSslHSParam = hsParam(o);
         breakpointhandler(sharkSslHSParam);

         baAssert(microresources(&o->inBuf));
         atomiccmpxchg(&o->inBuf, o->sharkSsl->inBufStartSize);
         if (microresources(&o->inBuf))
         {
            return SharkSslCon_AllocationError;
         }

         
         o->major = 0x03;

         #if SHARKSSL_ENABLE_SESSION_CACHE
         
         if (o->session)
         {
            baAssert(batterylevels(o->session) == 3);
            baAssert(hardirqsenabled(o->session) <= 3);
            o->minor = hardirqsenabled(o->session);
         }
         else
         #endif
         o->minor = SHARKSSL_PROTOCOL_TLS_1_2;

         
         #if SHARKSSL_ENABLE_SELECT_CIPHERSUITE
         if (o->cipherSelCtr)
         {
            hsLen = (U16)o->cipherSelCtr;
            csLen = (U16)(hsLen << 1);
         }
         else
         #endif
         {
            hsLen = SHARKSSL_DIM_ARR(sharkSslCipherSuiteList);
            csLen = (U16)(hsLen << 1);
            baAssert(csLen);
         }
         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (o->session)
         {
            csLen += SHARKSSL_MAX_SESSION_ID_LEN;
         }
         #endif

         csLen += 11 + SHARKSSL_RANDOM_LEN;

         #if SHARKSSL_USE_ECC
         hsLen = 0;  
         #endif

         baAssert(SHARKSSL_USE_SHA_256);
         #if (SHARKSSL_ENABLE_ECDSA || SHARKSSL_ENABLE_RSA)
         hsLen += 6 + SHARKSSL_DIM_ARR(serialwakeup);
         #endif

         #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         {
            
            hsLen += 6 + SHARKSSL_DIM_ARR(tcpudpmagic) + SHARKSSL_DIM_ARR(resetsources);  
         }
         #endif  

         #if SHARKSSL_ENABLE_SNI
         {
            
            if (o->padLen && o->rCtx)
            {
               hsLen += 9 + o->padLen;
            }
         }
         #endif

         #if SHARKSSL_ENABLE_ALPN_EXTENSION
         if (o->pALPN)
         {
            hsLen += 7 + (U16)strlen(o->pALPN);
         }
         #endif

         #if (SHARKSSL_USE_ECC || SHARKSSL_ENABLE_SNI || SHARKSSL_ENABLE_ALPN_EXTENSION)
         if (hsLen)
         {
            hsLen += 2;  
         }
         csLen += hsLen;
         #endif

         tp = sp = templateentry(o, controllegacy, o->inBuf.data, csLen);
         csLen -= traceentry;
         *tp++ = pciercxcfg070;
         *tp++ = 0x00;
         *tp++ = (U8)(csLen >> 8);
         *tp++ = (U8)(csLen & 0xFF);
         *tp++ = o->reqMajor = o->major;
         *tp++ = o->reqMinor = o->minor;
         csLen -= (7 + SHARKSSL_RANDOM_LEN);

         #if SHARKSSL_USE_ECC
         csLen -= hsLen;
         #endif

         now = baGetUnixTime();
         *tp++ = (U8)(now >> 24);
         *tp++ = (U8)(now >> 16);
         *tp++ = (U8)(now >> 8);
         *tp++ = (U8)(now & 0xFF);
         
         if (sharkssl_rng(tp, (SHARKSSL_RANDOM_LEN - 4)) < 0)
         {
            resvdexits(o);
            return SharkSslCon_Error;
         }
         tp += (SHARKSSL_RANDOM_LEN - 4);

         
         memcpy(sharkSslHSParam->clientRandom, tp - SHARKSSL_RANDOM_LEN, SHARKSSL_RANDOM_LEN);

         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (o->session)
         {
            *tp++ = SHARKSSL_MAX_SESSION_ID_LEN;
            memcpy(tp, o->session->id, SHARKSSL_MAX_SESSION_ID_LEN);
            tp += SHARKSSL_MAX_SESSION_ID_LEN;
            csLen -= SHARKSSL_MAX_SESSION_ID_LEN;
         }
         else
         #endif
         {
            *tp++ = 0; 
         }

         #if SHARKSSL_ENABLE_SELECT_CIPHERSUITE
         if (o->cipherSelCtr)
         {
            if (csLen)
            {
               *tp++ = (U8)(csLen >> 8);
               *tp++ = (U8)(csLen & 0xFF);
               csLen = 0;
               while (csLen < o->cipherSelCtr)
               {
                  clockmodtable = (SharkSslCipherSuite*)&sharkSslCipherSuiteList[o->cipherSelection[csLen++]];
                  now = clockmodtable->id;
                  *tp++ = (U8)(now >> 8);
                  *tp++ = (U8)(now & 0xFF);
               }
            }
            else
            {
               
               *tp++ = 0x00;
               *tp++ = 0x02;
               *tp++ = 0xFF;
               *tp++ = 0xFF;
            }
         }
         else
         #endif
         {
            *tp++ = (U8)(csLen >> 8);
            *tp++ = (U8)(csLen & 0xFF);
            csLen /= 2;
            clockmodtable = (SharkSslCipherSuite*)&sharkSslCipherSuiteList[0];
            while (csLen)
            {
               csLen--;
               now = clockmodtable->id;
               *tp++ = (U8)(now >> 8);
               *tp++ = (U8)(now & 0xFF);
               clockmodtable++;
            }
         }

         *tp++ = 1; 
         *tp++ = cminstclear;

         #if (SHARKSSL_USE_ECC || SHARKSSL_ENABLE_SNI || SHARKSSL_ENABLE_ALPN_EXTENSION)
         if (hsLen)
         {
            hsLen -= 2;
            *tp++ = (U8)(hsLen >> 8);
            *tp++ = (U8)(hsLen & 0xFF);
         }
         #endif

         #if SHARKSSL_ENABLE_SNI
         {
            if (o->padLen && o->rCtx)
            {
               *tp++ = (U8)(firstversion >> 8);
               *tp++ = (U8)(firstversion & 0xFF);
               csLen = o->padLen + 5;
               hsLen -= csLen + 4;
               *tp++ = (U8)(csLen >> 8);
               *tp++ = (U8)(csLen & 0xFF);
               csLen -= 2;
               *tp++ = (U8)(csLen >> 8);
               *tp++ = (U8)(csLen & 0xFF);
               *tp++ = 0x00;  
               csLen -= 3;
               *tp++ = (U8)(csLen >> 8);
               *tp++ = (U8)(csLen & 0xFF);
               memcpy(tp, o->rCtx, csLen);
               tp += csLen;

               o->rCtx = (void*)0;
               o->padLen = 0;
            }
         }
         #endif

         #if SHARKSSL_ENABLE_ALPN_EXTENSION
         if (o->pALPN)
         {
            *tp++ = (U8)(clkdmclear >> 8);
            *tp++ = (U8)(clkdmclear & 0xFF);
            csLen = (U16)(3 + (U16)strlen(o->pALPN));
            hsLen -= csLen + 4;
            *tp++ = (U8)(csLen >> 8);
            *tp++ = (U8)(csLen & 0xFF);
            csLen -= 2;
            *tp++ = (U8)(csLen >> 8);
            *tp++ = (U8)(csLen & 0xFF);
            tb = (U8*)o->pALPN;
            for (;;)
            {
               csLen = 0;
               tp++;  
               while ((*tb != '\054') && (*tb != 0))
               {
                  csLen++;
                  *tp++ = *tb++;
               }
               *(tp - csLen - 1) = (U8)csLen;   
               if (0 == *tb)
               {
                  break;
               }
               tb++;
            }
         }
         #endif

         #if (SHARKSSL_ENABLE_ECDSA || SHARKSSL_ENABLE_RSA)
         *tp++ = (U8)(entrypaddr >> 8);
         *tp++ = (U8)(entrypaddr & 0xFF);
         csLen = 2 + SHARKSSL_DIM_ARR(serialwakeup);
         hsLen -= csLen + 4;
         *tp++ = (U8)(csLen >> 8);
         *tp++ = (U8)(csLen & 0xFF);
         csLen -= 2;
         *tp++ = (U8)(csLen >> 8);
         *tp++ = (U8)(csLen & 0xFF);
         memcpy(tp, serialwakeup, SHARKSSL_DIM_ARR(serialwakeup));
         tp += SHARKSSL_DIM_ARR(serialwakeup);
         #endif
         #if MAX_FRAG_LEN
         {
            memcpy(tp, featureoverride, SHARKSSL_DIM_ARR(featureoverride));
            tp += SHARKSSL_DIM_ARR(featureoverride);
         }
         #endif  

         #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         
         *tp++ = (U8)(registerpwrdms >> 8);
         *tp++ = (U8)(registerpwrdms & 0xFF);
         csLen = 2 + SHARKSSL_DIM_ARR(tcpudpmagic);
         hsLen -= csLen + 4;
         *tp++ = (U8)(csLen >> 8);
         *tp++ = (U8)(csLen & 0xFF);
         csLen -= 2;
         *tp++ = (U8)(csLen >> 8);
         *tp++ = (U8)(csLen & 0xFF);
         memcpy(tp, tcpudpmagic, SHARKSSL_DIM_ARR(tcpudpmagic));
         tp += SHARKSSL_DIM_ARR(tcpudpmagic);
         memcpy(tp, resetsources, SHARKSSL_DIM_ARR(resetsources));
         tp += SHARKSSL_DIM_ARR(resetsources);
         hsLen -= SHARKSSL_DIM_ARR(resetsources);
         #endif  

         #if (SHARKSSL_USE_ECC || SHARKSSL_ENABLE_SNI || SHARKSSL_ENABLE_ALPN_EXTENSION)
         baAssert(!hsLen);
         #endif
         o->inBuf.temp = (U16)(tp - o->inBuf.data);
         ioremapresource(sharkSslHSParam, sp, (U16)(tp - sp));
         o->state = trampolinehandler;
         return SharkSslCon_Handshake;
      }

      if ( (SharkSsl_isClient(o->sharkSsl)) &&
           (
              0
              #if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
              ||
              ((o->state == configcwfon) && (registeredevent) &&
               (*registeredevent == logicmembank))
              #endif
           )
         )
      {
         o->state = *registeredevent;
      }
      else
      #endif
      #if SHARKSSL_SSL_SERVER_CODE
      if ((o->state == loongson3notifier)
          && (*registeredevent == pciercxcfg070)
          #if SHARKSSL_SSL_CLIENT_CODE
          && (SharkSsl_isServer(o->sharkSsl))
          #endif
         )
      {
         
         baAssert(!(o->flags & audiosuspend));
         #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
         if (o->flags & skciphersetkey)
         {
            o->flags &= ~skciphersetkey;
         }
         else
         #endif
         {
            return securememblock(o, SHARKSSL_ALERT_LEVEL_WARNING, SHARKSSL_ALERT_NO_RENEGOTIATION);
         }
         #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
         o->flags |= platformdevice;
         o->flags &= ~(startqueue | switcheractivation);
         o->state = pciercxcfg070;
         #endif
      }
      else
      #endif
      {
        _sharkssl_hs_alert_illegal_parameter:
        return savedconfig(o, SHARKSSL_ALERT_ILLEGAL_PARAMETER);
      }
   }

   registeredevent++;
   atagsprocfs--;

   if (atagsprocfs < 3)
   {
      goto _sharkssl_hs_alert_illegal_parameter;
   }

   if (tvp5146pdata == 3)
   {
      
      if (*registeredevent++)
      {
         goto _sharkssl_hs_alert_illegal_parameter;
      }

      hsDataLen  = (U16)(*registeredevent++) << 8;
      hsDataLen += (*registeredevent++);
      atagsprocfs -= 3;

      if (atagsprocfs < hsDataLen)
      {
         goto _sharkssl_hs_alert_illegal_parameter;
      }

      atagsprocfs -= hsDataLen;
      tp = registeredevent - traceentry;
      hsLen = hsDataLen + traceentry;
   }
   else
   {
      goto _sharkssl_hs_alert_illegal_parameter;
   }

   baAssert(!microresources(&o->outBuf));
   #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
   if (o->flags & shutdownlevel)
   {
      baAssert(o->flags & platformdevice);
      o->flags &= ~shutdownlevel;
      reportsyscall(&o->tmpBuf, &o->outBuf);
      guestconfig5(&o->outBuf);  
      o->outBuf = o->tmpBuf;
      memset(&o->tmpBuf, 0, sizeof(SharkSslBuf));  
   }
   #endif

   sharkSslHSParam = hsParam(o);
   afterhandler = (U8*)(sharkSslHSParam + 1);

   #if (SHARKSSL_ENABLE_RSA || (SHARKSSL_ENABLE_ECDSA))
   if ((pciercxcfg070 != o->state) &&
       (switcherdevice     != o->state))
   {
      baAssert(0 == monadiccheck(sharkSslHSParam->certParam.certKey.expLen));
      #if SHARKSSL_ENABLE_RSA
      #if (!SHARKSSL_USE_ECC)
      baAssert(machinekexec(sharkSslHSParam->certParam.certKey.expLen));
      #else
      if (machinekexec(sharkSslHSParam->certParam.certKey.expLen))
      #endif
      {
         afterhandler += supportedvector(sharkSslHSParam->certParam.certKey.modLen);
         afterhandler += claimresource(mousethresh(sharkSslHSParam->certParam.certKey.expLen));
      }
      #if SHARKSSL_USE_ECC
      else
      #endif
      #endif  
      #if SHARKSSL_USE_ECC
      if (machinereboot(sharkSslHSParam->certParam.certKey.expLen))
      {
         afterhandler += (U16)(attachdevice(sharkSslHSParam->certParam.certKey.modLen)) * 2;
      }
      #endif
      #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
      if ((sharkSslHSParam->cipherSuite) && (sharkSslHSParam->cipherSuite->flags & cleandcache))
      #endif
      {
         #if SHARKSSL_ENABLE_DHE_RSA
         if (sharkSslHSParam->cipherSuite->flags & percpudevid)
         {
            afterhandler += sharkSslHSParam->dhParam.pLen;  
            #if SHARKSSL_SSL_CLIENT_CODE
            if (SharkSsl_isClient(o->sharkSsl))
            {
               afterhandler += sharkSslHSParam->dhParam.pLen;    
               afterhandler += sharkSslHSParam->dhParam.gLen;    
            }
            #endif  
         }
         #endif  

         #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         if (sharkSslHSParam->cipherSuite->flags & irqhandlerfixup)
         {
            afterhandler += sharkSslHSParam->ecdhParam.xLen;  
            #if SHARKSSL_SSL_CLIENT_CODE
            if (SharkSsl_isClient(o->sharkSsl))
            {
               afterhandler += sharkSslHSParam->ecdhParam.xLen;  
            }
            #endif  
            #if (SHARKSSL_ECC_USE_SECP521R1 && (SHARKSSL_ALIGNMENT >= 4))
            afterhandler = (U8*)regulatorconsumer(afterhandler);
            #endif
         }
        #endif
      }
   }
   #endif

   
   baAssert(pcmciaplatform(afterhandler));

   switch (o->state)
   {
      #if SHARKSSL_SSL_SERVER_CODE
      case pciercxcfg070:
         baAssert(SharkSsl_isServer(o->sharkSsl));
         baAssert(serial2platform(&o->inBuf));
         baAssert(pcmciaplatform(func3fixup(&o->inBuf)));
         baAssert(pcmciaplatform(func3fixup(&o->outBuf)));

         if (hsDataLen < 2)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         o->reqMajor = *registeredevent++;
         o->reqMinor = *registeredevent++;
         hsDataLen -= 2;

         if (o->reqMajor != 3)
         {
            goto _sharkssl_hs_alert_handshake_failure;
         }
         o->major = 3;

         if (o->reqMinor >= 3)
         {
            o->minor = 3;  
         }
         else
         {
            
            _sharkssl_hs_alert_handshake_failure:
            return savedconfig(o, SHARKSSL_ALERT_HANDSHAKE_FAILURE);
         }

         breakpointhandler(sharkSslHSParam);
         ioremapresource(sharkSslHSParam, tp, hsLen);

         
         memset(afterhandler, 0, (4 * (sizeof(SharkSslCertParsed**) + sizeof(SHARKSSL_WEIGHT))));
         afterhandler += (4 * (sizeof(SharkSslCertParsed**) + sizeof(SHARKSSL_WEIGHT)));

         SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
         for (tp = afterhandler, link = SingleListEnumerator_getElement(&e);
              link;
              link = SingleListEnumerator_nextElement(&e), tp += sizeof(SHARKSSL_WEIGHT))
         {
            *(SHARKSSL_WEIGHT*)tp = 0;

            
            #if SHARKSSL_ENABLE_RSA
            if (((SharkSslCertList*)link)->certP.keyType == ahashchild)
            {
               
               *(SHARKSSL_WEIGHT*)tp = trainingneeded + ahashchild;
            }
            #if SHARKSSL_USE_ECC
            else
            #endif
            #endif
            #if SHARKSSL_USE_ECC
            if (((SharkSslCertList*)link)->certP.keyType == compatrestart)
            {
               
               *(SHARKSSL_WEIGHT*)tp = compatrestart +
                                       (((SharkSslCertList*)link)->certP.keyOID) +
                                       (U16)(((SharkSslCertList*)link)->certP.signatureAlgo);
            }
            #endif

            
            {
               if (((SharkSslCertList*)link)->certP.hashAlgo <= presentpages)
               {
                  *(SHARKSSL_WEIGHT*)tp |= smbuswrite;
               }
            }
         }
         baAssert(tp != afterhandler);  
         *(SHARKSSL_WEIGHT*)tp = (SHARKSSL_WEIGHT)-1;  

         baAssert(!(o->flags & startqueue));
         if (hsDataLen < (1 + SHARKSSL_RANDOM_LEN))
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         memcpy(sharkSslHSParam->clientRandom, registeredevent, SHARKSSL_RANDOM_LEN);  
         registeredevent += SHARKSSL_RANDOM_LEN;
         setupinterface = *registeredevent++;
         hsDataLen -= (1 + SHARKSSL_RANDOM_LEN);

         if (setupinterface > 0)
         {
            if ((hsDataLen < setupinterface) || (setupinterface > SHARKSSL_MAX_SESSION_ID_LEN))
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }

            #if SHARKSSL_ENABLE_SESSION_CACHE
            #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
            if (o->flags & platformdevice)
            {
               
               if (o->session)
               {
                  SharkSslSession_release(o->session, o->sharkSsl);
               }
               o->session = (SharkSslSession*)0;
            }
            else
            #endif
            {
               o->session = latchgpiochip(&o->sharkSsl->sessionCache, o, registeredevent, setupinterface);
               if (o->session)
               {
                  o->flags |= startqueue;
               }
            }
            #endif

            registeredevent += setupinterface;
            hsDataLen -= setupinterface;
         }

         
         if (hsDataLen < 2)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         tb = registeredevent;  
         csLen  = (U16)(*registeredevent++) << 8;
         csLen += *registeredevent++;
         hsDataLen -= 2;

         if ((csLen == 0) || (csLen & 0x01) || (hsDataLen < csLen))
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         registeredevent    += csLen;
         hsDataLen -= csLen;

         
         if (hsDataLen < 2)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         setupinterface = *registeredevent++;
         hsDataLen--;

         if ((hsDataLen < setupinterface) || (setupinterface == 0))
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         
         do
         {
            csLen = *registeredevent++;  
            hsDataLen--;
            setupinterface--;
         } while ((setupinterface) && (csLen != cminstclear));

         if (csLen != cminstclear)
         {
            goto _sharkssl_hs_alert_handshake_failure;
         }

         registeredevent += setupinterface;
         hsDataLen -= setupinterface;

         if (hsDataLen)
         {  
            if (hsDataLen < 2)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            csLen  = (U16)(*registeredevent++) << 8;
            csLen += *registeredevent++;
            hsDataLen -= 2;

            if (hsDataLen < csLen)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }

            
            i = (U16)writepmresr(o, (SHARKSSL_WEIGHT*)afterhandler, registeredevent, csLen);
            if (i != 0)
            {
               #if SHARKSSL_ENABLE_ALPN_EXTENSION
               if ((U16)-2 == i)  
               {
                  return savedconfig(o, SHARKSSL_ALERT_NO_APPLICATION_PROTOCOL);
               }
               #endif
               goto _sharkssl_hs_alert_handshake_failure;
            }
            registeredevent += csLen;
            hsDataLen -= csLen;
         }

         #if SHARKSSL_ENABLE_SNI
         
         i = 0;
         tp = afterhandler;
         while (*(SHARKSSL_WEIGHT*)tp != (SHARKSSL_WEIGHT)-1)
         {
            if (*(SHARKSSL_WEIGHT*)tp & clearevent)
            {
               i++;
               break;
            }
            tp += sizeof(SHARKSSL_WEIGHT);
         }
         #endif

         
         tp = afterhandler;
         while (*(SHARKSSL_WEIGHT*)tp != (SHARKSSL_WEIGHT)-1)
         {
            if ( ( (*(SHARKSSL_WEIGHT*)tp)
                     && 
                     (
                     (!(*(SHARKSSL_WEIGHT*)tp & trainingneeded))
                     || ((o->minor >= 3) && (!(*(SHARKSSL_WEIGHT*)tp & smbuswrite)))
                     )
                  )
               #if SHARKSSL_ENABLE_SNI
               ||
                  ((i > 0) && (!(*(SHARKSSL_WEIGHT*)tp & clearevent)))
               #endif
               )

            {

               *(SHARKSSL_WEIGHT*)tp = 0;
            }
            tp += sizeof(SHARKSSL_WEIGHT);
         }

         
         tp = afterhandler;
         afterhandler -= (4 * (sizeof(SharkSslCertParsed**) + sizeof(SHARKSSL_WEIGHT)));

         SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
         for (link = SingleListEnumerator_getElement(&e);
               link;
               link = SingleListEnumerator_nextElement(&e), tp += sizeof(SHARKSSL_WEIGHT))
         {
            #if SHARKSSL_ENABLE_RSA
            if (((SharkSslCertList*)link)->certP.keyType == ahashchild)
            {
               
               if (((SharkSslCertList*)link)->certP.signatureAlgo == entryearly)
               {
                  if ((*(SHARKSSL_WEIGHT*)tp) && (*(SHARKSSL_WEIGHT*)tp > *(SHARKSSL_WEIGHT*)(afterhandler + 4 * sizeof(SharkSslCertParsed**))))
                  {
                     *(SHARKSSL_WEIGHT*)(afterhandler + 4 * sizeof(SharkSslCertParsed**)) = *(SHARKSSL_WEIGHT*)tp;
                     *(SharkSslCertParsed**)afterhandler = &(((SharkSslCertList*)link)->certP);
                  }
               }
            }
            #if (SHARKSSL_ENABLE_ECC || SHARKSSL_ENABLE_ECDSA)
            else
            #endif
            #endif
            #if (SHARKSSL_ENABLE_ECC || SHARKSSL_ENABLE_ECDSA)
            if (((SharkSslCertList*)link)->certP.keyType == compatrestart)
            {
               
               if (((SharkSslCertList*)link)->certP.signatureAlgo == accessactive)
               {
                  if ((*(SHARKSSL_WEIGHT*)tp) && (*(SHARKSSL_WEIGHT*)tp > *(SHARKSSL_WEIGHT*)(afterhandler + 4 * sizeof(SharkSslCertParsed**) + 2 * sizeof(SHARKSSL_WEIGHT))))
                  {
                     *(SHARKSSL_WEIGHT*)(afterhandler + 4 * sizeof(SharkSslCertParsed**) + 2 * sizeof(SHARKSSL_WEIGHT)) = *(SHARKSSL_WEIGHT*)tp;
                     *(SharkSslCertParsed**)(afterhandler + 2 * sizeof(SharkSslCertParsed**)) = &(((SharkSslCertList*)link)->certP);
                  }
               }
            }
            #endif
         }
         baAssert(*(SHARKSSL_WEIGHT*)tp == (SHARKSSL_WEIGHT)-1);  

         
         baAssert(!(sharkSslHSParam->cipherSuite));
         baAssert(SHARKSSL_DIM_ARR(sharkSslCipherSuiteList) < 0xFF);
         ics = 0xFF;
         crLen = 0;  
         #define crLen_FLAG_stream_cipher_found    0x01
         #define crLen_FLAG_RSA_ciphersuite_found  0x02
         #define crLen_FLAG_stream_RSA_found       0x04

         csLen  = (U16)(*tb++) >> 8;
         csLen += *tb++;
         while (csLen)
         {
            i  = (U16)(*tb++) << 8;
            i +=  *tb++;
            csLen -= 2;

            #if SHARKSSL_ENABLE_SESSION_CACHE
            if (o->flags & startqueue)
            {
               baAssert(o->session);
               
               if ((o->session->cipherSuite) && (i == o->session->cipherSuite->id))
               {
                  sharkSslHSParam->cipherSuite = o->session->cipherSuite;
                  break;
               }
            }
            else
            #endif
            {
               if (deviceunregister == i)
               {
                  #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
                  if (o->flags & platformdevice)
                  {
                     goto _sharkssl_hs_alert_handshake_failure;
                  }
                  #endif
                  o->flags |= aarch32ptrace;
               }
               #if SHARKSSL_ENABLE_SELECT_CIPHERSUITE
               else if (o->cipherSelCtr)
               {
                  
                  for (now = 0; now < o->cipherSelCtr; now++)
                  {
                     setupinterface = o->cipherSelection[now];
                     if ( (i == sharkSslCipherSuiteList[setupinterface].id)
                     #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
                           && ((sharkSslHSParam->ecdhParam.xLen) || (!(sharkSslCipherSuiteList[setupinterface].flags & irqhandlerfixup)))
                     #endif
                        )
                     {
                        if ((now < ics) && (0 == SharkSslHSParam_setCert(sharkSslHSParam, (SharkSslCertParsed**)afterhandler, sharkSslCipherSuiteList[setupinterface].flags, o->minor)))
                        {
                           
                           ics = (U8)now;
                        }
                     }
                  }
               }
               #endif
               else
               {
                  for (now = 0; now < SHARKSSL_DIM_ARR(sharkSslCipherSuiteList); now++)
                  {
                     if ( (i == sharkSslCipherSuiteList[now].id)
                     #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
                           && ((sharkSslHSParam->ecdhParam.xLen) || (!(sharkSslCipherSuiteList[now].flags & irqhandlerfixup)))
                     #endif
                        )
                     {
                        
                        #if SHARKSSL_ENABLE_RSA
                        if ((o->flags & uprobeabort) && (sharkSslCipherSuiteList[now].flags & percpudevid))
                        {
                           if ((!(crLen & crLen_FLAG_RSA_ciphersuite_found)) || ((U8)now < ics))
                           {
                              if (0 == SharkSslHSParam_setCert(sharkSslHSParam, (SharkSslCertParsed**)afterhandler, sharkSslCipherSuiteList[now].flags, o->minor))
                              {
                                 crLen |= crLen_FLAG_RSA_ciphersuite_found;
                                 ics = (U8)now;
                              }
                           }
                        }
                        else
                        #endif
                        {
                           if ((now < ics)
                                 #if SHARKSSL_ENABLE_RSA
                                 && (!(crLen & crLen_FLAG_RSA_ciphersuite_found))
                                 #endif
                                 && (0 == SharkSslHSParam_setCert(sharkSslHSParam, (SharkSslCertParsed**)afterhandler, sharkSslCipherSuiteList[now].flags, o->minor))
                              )
                           {
                              ics = (U8)now;
                           }
                        }
                     }
                  }  
               }
            }
         }
         #undef crLen_FLAG_stream_cipher_found
         #undef crLen_FLAG_RSA_ciphersuite_found
         #undef crLen_FLAG_stream_RSA_found

         if (!(sharkSslHSParam->cipherSuite))  
         {
            if (ics == 0xFF)  
            {
               goto _sharkssl_hs_alert_handshake_failure;
            }
            #if SHARKSSL_ENABLE_SELECT_CIPHERSUITE
            if (o->cipherSelCtr)
            {
               sharkSslHSParam->cipherSuite = (SharkSslCipherSuite*)&sharkSslCipherSuiteList[o->cipherSelection[ics]];
            }
            else
            #endif
            {
               sharkSslHSParam->cipherSuite = (SharkSslCipherSuite*)&sharkSslCipherSuiteList[ics];
            }
         }

         
         if (hsDataLen > 0)
         {
            return savedconfig(o, SHARKSSL_ALERT_DECODE_ERROR);
         }

         o->inBuf.temp = 0;

         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (!(o->flags & startqueue))
         {
            o->session = sa1111device(&o->sharkSsl->sessionCache, o, 0, 0);
         }
         #endif

         
         crLen = csLen = 0;  
         if (o->flags & aarch32ptrace)
         {
            #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
            if (o->flags & platformdevice)
            {
               crLen = 1 + 2 * sapicvector;
               
               csLen += 2 + 2 + (U16)crLen; 
            }
            else
            #endif
            {
               csLen += SHARKSSL_DIM_ARR(registeraudio);
            }
         }
         #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         if (sharkSslHSParam->cipherSuite->flags & irqhandlerfixup)
         {
            csLen += SHARKSSL_DIM_ARR(resetsources);
         }
         #endif
         #if SHARKSSL_ENABLE_ALPN_EXTENSION
         if (o->rALPN)
         {
            csLen += *o->rALPN + 7;
            memcpy(afterhandler, o->rALPN, *o->rALPN + 1);
         }
         #endif
         sp = o->inBuf.data + clkctrlmanaged;
         tp = sp + traceentry;
         *tp++ = o->major;
         *tp++ = o->minor;

         now = baGetUnixTime();
         *tp++ = (U8)(now >> 24);
         *tp++ = (U8)(now >> 16);
         *tp++ = (U8)(now >> 8);
         *tp++ = (U8)(now & 0xFF);

         
         if (sharkssl_rng(tp, (SHARKSSL_RANDOM_LEN - 4)) < 0)
         {
            resvdexits(o);
            return SharkSslCon_Error;
         }
         tp += (SHARKSSL_RANDOM_LEN - 4);

         
         memcpy(sharkSslHSParam->serverRandom, tp - SHARKSSL_RANDOM_LEN, SHARKSSL_RANDOM_LEN);

         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (o->session)  
         {
            *tp++ = SHARKSSL_MAX_SESSION_ID_LEN;
            memcpy(tp, o->session->id, SHARKSSL_MAX_SESSION_ID_LEN);
            tp += SHARKSSL_MAX_SESSION_ID_LEN;
         }
         else
         #endif
         {
            *tp++ = 0;
         }

         *tp++ = (U8)(sharkSslHSParam->cipherSuite->id >> 8);
         *tp++ = (U8)(sharkSslHSParam->cipherSuite->id & 0xFF);
         *tp++ = 0; 

         
         if (csLen)
         {
            *tp++ = (csLen >> 8);
            *tp++ = (csLen & 0xFF);
            if (o->flags & aarch32ptrace)
            {
               #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
               if (o->flags & platformdevice)
               {
                  *tp++ = (featurespresent >> 8);
                  *tp++ = (featurespresent & 0xFF);
                  *tp++ = 0x00;
                  *tp++ = crLen & 0xFF;
                  *tp++ = (--crLen) & 0xFF;
                  baAssert((crLen & 1) == 0);
                  crLen >>= 1;
                  memcpy(tp, o->clientVerifyData, crLen);
                  tp+= crLen;
                  memcpy(tp, o->serverVerifyData, crLen);
                  tp+= crLen;
               }
               else
               #endif
               {
                  memcpy(tp, registeraudio, SHARKSSL_DIM_ARR(registeraudio));
                  tp += SHARKSSL_DIM_ARR(registeraudio);
               }
            }
            #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
            if (sharkSslHSParam->cipherSuite->flags & irqhandlerfixup)
            {
               memcpy(tp, resetsources, SHARKSSL_DIM_ARR(resetsources));
               tp += SHARKSSL_DIM_ARR(resetsources);
            }
            #endif
            #if SHARKSSL_ENABLE_ALPN_EXTENSION
            if (o->rALPN)
            {
               *tp++ = (U8)(clkdmclear >> 8);
               *tp++ = (U8)(clkdmclear & 0xFF);
               *tp++ = 0x00;
               *tp++ = *afterhandler + 3;  
               *tp++ = 0x00;
               *tp++ = *afterhandler + 1;  
               memcpy(tp, afterhandler, *afterhandler + 1);
               tp += *afterhandler + 1;
            }
            #endif
         }
         i = (U16)(tp - sp) - traceentry;
         sp[0] = trampolinehandler;
         sp[1] = 0;
         sp[2] = (U8)(i >> 8);
         sp[3] = (U8)(i & 0xFF);
         

         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (o->flags & startqueue)
         {
            
            memcpy(sharkSslHSParam->masterSecret, o->session->masterSecret, SHARKSSL_MASTER_SECRET_LEN);
            
            csLen = disableclean(sharkSslHSParam->cipherSuite);
            if (allocalloc(o, sharkSslHSParam->sharedSecret, csLen,
                                            sharkSslHSParam->masterSecret, SHARKSSL_MASTER_SECRET_LEN,
                                            sharkSslHSParam->serverRandom,
                                            sharkSslHSParam->clientRandom) < 0)
            {
               resvdexits(o);
               return SharkSslCon_Error;
            }

            
            i += traceentry;
            tp = templateentry(o, controllegacy, sp - clkctrlmanaged, i);
            ioremapresource(sharkSslHSParam, tp, i);
            tp += i;

            #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
            baAssert(!(o->flags & platformdevice));
            #endif

            if (sanitisependbaser(o, rodatastart, tp))
            {
               resvdexits(o);
               return SharkSslCon_Error;
            }

            o->state = switcherdevice;
         }
         else  
         #endif
         {
            baAssert(sharkSslHSParam->certParsed);
            
            i = sharkSslHSParam->certParsed->msgLen;
            *tp++ = parsebootinfo;
            *tp++ = 0x00;
            *tp++ = (i >> 8);
            *tp++ = (i & 0xFF);
            if (fixupresources(sharkSslHSParam->certParsed->cert, i, tp))
            {
               resvdexits(o);
               return SharkSslCon_Error;
            }
            tp += i;
            

            
            if (0 == interrupthandler(&(sharkSslHSParam->certKey), sharkSslHSParam->certParsed->cert))
            {
               return SharkSslCon_CertificateError;
            }

            #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
            if (sharkSslHSParam->cipherSuite->flags & cleandcache)
            {
               
               tb = tp;
               tp += traceentry;  
               #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
               if (sharkSslHSParam->cipherSuite->flags & irqhandlerfixup)
               {
                  baAssert(sharkSslHSParam->ecdhParam.curveType);
                  baAssert(sharkSslHSParam->ecdhParam.xLen);
                  sharkSslHSParam->ecdhParam.k = afterhandler;
                  afterhandler += sharkSslHSParam->ecdhParam.xLen;
                  #if (SHARKSSL_ECC_USE_SECP521R1 && (SHARKSSL_ALIGNMENT >= 4))
                  afterhandler = (U8*)regulatorconsumer(afterhandler);
                  #endif
                  csLen = (U16)(sharkSslHSParam->ecdhParam.xLen << 1);
                  baAssert(csLen < 0x00FF);
                  i = 5;  
                  *tp++ = mcbsp5hwmod;
                  *tp++ = (sharkSslHSParam->ecdhParam.curveType >> 8);
                  *tp++ = (sharkSslHSParam->ecdhParam.curveType & 0xFF);
                  *tp++ = (U8)(csLen + 1);
                  *tp++ = SHARKSSL_EC_POINT_UNCOMPRESSED;
                  
                  if ((int)SharkSslCon_AllocationError ==
                      SharkSslECDHParam_ECDH(&(sharkSslHSParam->ecdhParam), signalpreserve, tp))
                  {
                     return SharkSslCon_AllocationError;
                  }
               }
               else
               #endif
               {
                  #if SHARKSSL_ENABLE_DHE_RSA
                  U8 *g;

                  
                  SharkSslDHParam_setParam(&(sharkSslHSParam->dhParam));
                  
                  baAssert(pcmciaplatform(afterhandler));
                  sharkSslHSParam->dhParam.r = afterhandler;
                  csLen = sharkSslHSParam->dhParam.pLen;
                  afterhandler += csLen;
                  i = 6;  
                  *tp++ = (U8)(csLen >> 8);
                  *tp++ = (U8)(csLen & 0xFF);
                  memcpy(tp, sharkSslHSParam->dhParam.p, csLen);
                  tp += csLen;
                  i  += csLen;
                  g = sharkSslHSParam->dhParam.g;
                  crLen = sharkSslHSParam->dhParam.gLen;
                  while ((0 == *g) && (crLen > 1))
                  {
                     g++;
                     crLen--;
                  }
                  *tp++ = (U8)(crLen >> 8);
                  *tp++ = (U8)(crLen & 0xFF);
                  memcpy(tp, g, crLen);
                  tp += (U16)crLen;
                  i  += (U16)crLen;
                  *tp++ = (U8)(csLen >> 8);
                  *tp++ = (U8)(csLen & 0xFF);
                  
                  if ((int)SharkSslCon_AllocationError ==
                      SharkSslDHParam_DH(&(sharkSslHSParam->dhParam), cpucfgexits, tp))
                  {
                     return SharkSslCon_AllocationError;
                  }
                  #else
                  return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
                  #endif
               }
               tp += csLen;
               i  += csLen;
               
               baAssert(pcmciaplatform(afterhandler));
               memcpy(afterhandler, sharkSslHSParam->clientRandom, SHARKSSL_RANDOM_LEN);
               memcpy(afterhandler + SHARKSSL_RANDOM_LEN, sharkSslHSParam->serverRandom, SHARKSSL_RANDOM_LEN);
               memcpy(afterhandler + (2 * SHARKSSL_RANDOM_LEN), (tp - i), i);
               i += (2 * SHARKSSL_RANDOM_LEN);

               sharkSslHSParam->signParam.pCertKey = &(sharkSslHSParam->certKey);  

               
               #if SHARKSSL_ENABLE_RSA
               if (machinekexec(sharkSslHSParam->signParam.pCertKey->expLen))
               {
                  sharkSslHSParam->signParam.signature.hashAlgo = sharkSslHSParam->signParam.signature.signatureAlgo;
                  sharkSslHSParam->signParam.signature.signatureAlgo = entryearly;
               }
               #endif
               #if SHARKSSL_ENABLE_ECDSA
               if (machinereboot(sharkSslHSParam->signParam.pCertKey->expLen))
               {
                  sharkSslHSParam->signParam.signature.signatureAlgo = accessactive;
               }
               #endif
               if (!(sharkSslHSParam->signParam.signature.hashAlgo))
               {
                  sharkSslHSParam->signParam.signature.hashAlgo = presentpages;
               }

               
               if (sharkssl_hash(sharkSslHSParam->signParam.signature.hash, afterhandler, i, sharkSslHSParam->signParam.signature.hashAlgo))
               {
                  return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
               }

               *tp++ = sharkSslHSParam->signParam.signature.hashAlgo;
               *tp++ = sharkSslHSParam->signParam.signature.signatureAlgo;

               sharkSslHSParam->signParam.signature.signature = tp + 2;  
               if (checkactions(&(sharkSslHSParam->signParam)) < 0)
               {
                  return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
               }
               *tp++ = (sharkSslHSParam->signParam.signature.signLen >> 8);
               *tp++ = (sharkSslHSParam->signParam.signature.signLen & 0xFF);
               tp += sharkSslHSParam->signParam.signature.signLen;

               i = (U16)(tp - tb) - traceentry;
               tb[0] = startflags;
               tb[1]= 0;
               tb[2] = (U8)(i >> 8);
               tb[3] = (U8)(i & 0xFF);
               
            }
            #endif

            #if (SHARKSSL_ENABLE_CLIENT_AUTH && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA))
            if (o->flags & unregistershash)
            {
               
               tb = tp;
               tp += traceentry;  
               ics = 0;
               #if SHARKSSL_ENABLE_RSA
               tp[++ics] = ahashchild;
               #endif
               #if SHARKSSL_ENABLE_ECDSA
               {
                  tp[++ics] = compatrestart;
               }
               #endif
               *tp++ = ics;  
               tp += ics;
               *tp++ = (U8)(SHARKSSL_DIM_ARR(serialwakeup) >> 8);
               *tp++ = (U8)(SHARKSSL_DIM_ARR(serialwakeup) & 0xFF);
               memcpy(tp, serialwakeup, SHARKSSL_DIM_ARR(serialwakeup));
               tp += SHARKSSL_DIM_ARR(serialwakeup);
               #if SHARKSSL_ENABLE_CA_LIST
               if (o->caListCertReq)
               {
                  SharkSslCert pCert;
                  U8 *cp;

                  #if SHARKSSL_ENABLE_CERTSTORE_API
                  baAssert(SHARKSSL_CA_LIST_PTR_SIZE == claimresource(SHARKSSL_CA_LIST_PTR_SIZE));
                  #endif
                  if ((o->caListCertReq[0] != SHARKSSL_CA_LIST_INDEX_TYPE)
                        #if SHARKSSL_ENABLE_CERTSTORE_API
                        && (o->caListCertReq[0] != SHARKSSL_CA_LIST_PTR_TYPE)
                        #endif
                     )
                  {
                     return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
                  }
                  now = ((U16)(o->caListCertReq[2]) << 8) + o->caListCertReq[3];
                  if (0 == now)  
                  {
                     goto _sharkssl_empty_CA_DN;
                  }
                  csLen = 2;  
                  cp = (U8*)&(o->caListCertReq[4]);
                  while (now--)
                  {
                     int ret;
                     U16 installidmap;
                     #if SHARKSSL_ENABLE_CERTSTORE_API
                     if (o->caListCertReq[0] == SHARKSSL_CA_LIST_PTR_TYPE)
                     {
                        pCert = *(SharkSslCert*)&cp[SHARKSSL_CA_LIST_NAME_SIZE];
                        cp += SHARKSSL_CA_LIST_NAME_SIZE + SHARKSSL_CA_LIST_PTR_SIZE;  
                     }
                     else
                     #endif
                     {
                        crLen  = (U32)cp[SHARKSSL_CA_LIST_NAME_SIZE+0] << 24;
                        crLen += (U32)cp[SHARKSSL_CA_LIST_NAME_SIZE+1] << 16;
                        crLen += (U16)cp[SHARKSSL_CA_LIST_NAME_SIZE+2] << 8;
                        crLen +=      cp[SHARKSSL_CA_LIST_NAME_SIZE+3];
                        pCert  = (SharkSslCert)&(o->caListCertReq[crLen]);
                        cp    += nativeiosapic;  
                     }
                     
                     ret = spromregister(0, (U8*)pCert, (U32)-2, (U8*)&installidmap);
                     if (ret > 0)
                     {
                        pCert += (U32)ret;
                        tp[csLen++] = (U8)(installidmap >> 8);
                        tp[csLen++] = (U8)(installidmap & 0xFF);
                        memcpy(tp + csLen, pCert, installidmap);
                        csLen += installidmap;
                     }
                  }
                  
                  csLen -= 2;
                  *tp++ = (csLen >> 8);
                  *tp++ = (csLen & 0xFF);
                  tp += csLen;
               }
               else
               #endif
               {
                  #if SHARKSSL_ENABLE_CA_LIST
                  _sharkssl_empty_CA_DN:
                  #endif
                  *tp++ = 0;  
                  *tp++ = 0;
               }
               i = (U16)(tp - tb) - traceentry;
               tb[0] = logicmembank;
               tb[1]= 0;
               tb[2] = (U8)(i >> 8);
               tb[3] = (U8)(i & 0xFF);
               
            }
            else
            {
               o->flags &= ~unregistershash;
            }
            #endif  

            if (o->flags & unregistershash)
            {
               o->state = parsebootinfo;
            }
            else
            {
               o->state = subtableheaders;
            }

            
            *tp++ = configcwfon;
            *tp++ = 0x00;
            *tp++ = 0x00;
            *tp++ = 0x00;
            i = (U16)(tp - sp);
            templateentry(o, controllegacy, sp - clkctrlmanaged, i);
            ioremapresource(sharkSslHSParam, sp, i);
            
         }

         o->inBuf.temp += (U16)(tp - o->inBuf.data);

         #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
         if (o->flags & platformdevice)
         {
            
            o->tmpBuf = o->outBuf;
            csLen = claimresource(r3000tlbchange(o) + o->inBuf.temp);
            atomiccmpxchg(&o->outBuf, csLen);
            if (microresources(&o->outBuf))
            {
               return SharkSslCon_AllocationError;
            }
            reportsyscall(&o->outBuf, &o->tmpBuf);
            memcpy(func3fixup(&o->outBuf), sp - clkctrlmanaged, o->inBuf.temp);

            if (writebackscache(o, ptraceregsets) < 0)
            {
               resvdexits(o);
               return SharkSslCon_Error;
            }
            o->inBuf.temp = o->outBuf.dataLen;
            o->flags |= (createmappings | shutdownlevel);
         }
         #endif
         #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
         *deviceusbgadget = 0;
         #endif
         return SharkSslCon_Handshake;

      case subtableheaders:
         ioremapresource(sharkSslHSParam, registeredevent - traceentry, hsLen);
         #if SHARKSSL_USE_ECC
         if (!(sharkSslHSParam->cipherSuite->flags & irqhandlerfixup))
         #endif
         {
            if (hsDataLen < 2)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            csLen  = (U16)(*registeredevent++ << 8);
            csLen += *registeredevent++;
            hsDataLen -= 2;
            if ((csLen != hsDataLen) || (csLen == 0))
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
         }

         ics = 0;  
         #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         if (sharkSslHSParam->cipherSuite->flags & (cleandcache | irqhandlerfixup))
         {
            #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
            if (sharkSslHSParam->cipherSuite->flags & irqhandlerfixup)
            {
               if (hsDataLen < 2)
               {
                  goto _sharkssl_hs_alert_illegal_parameter;
               }
               csLen = (*registeredevent++);
               hsDataLen--;
               if (*registeredevent++ != SHARKSSL_EC_POINT_UNCOMPRESSED)
               {
                  goto _sharkssl_hs_alert_illegal_parameter;
               }
               hsDataLen--;
               csLen--;
               i = sharkSslHSParam->ecdhParam.xLen;
               if ((hsDataLen < csLen) || (csLen != (U16)(i << 1)))
               {
                  goto _sharkssl_hs_alert_illegal_parameter;
               }
               sharkSslHSParam->ecdhParam.XY = registeredevent;      
               if ((int)SharkSslCon_AllocationError ==
                   SharkSslECDHParam_ECDH(&(sharkSslHSParam->ecdhParam), switcheractive, afterhandler))
               {
                  return SharkSslCon_AllocationError;
               }

               tb = afterhandler;
               tp = tb + claimresource(i);
            }
            else
            #endif
            {
               #if SHARKSSL_ENABLE_DHE_RSA
               csLen = sharkSslHSParam->dhParam.pLen;
               baAssert(csLen > 2);
               if (hsDataLen != csLen)
               {
                  if (hsDataLen != (csLen - 1))
                  {
                     if (hsDataLen != (csLen - 2))
                     {
                        goto _sharkssl_hs_alert_illegal_parameter;
                     }
                     
                     registeredevent--;
                     *registeredevent = 0;
                  }
                  
                  registeredevent--;
                  *registeredevent = 0;
               }
               
               sharkSslHSParam->dhParam.Y = registeredevent;
               
               if ((int)SharkSslCon_AllocationError ==
                   SharkSslDHParam_DH(&(sharkSslHSParam->dhParam), switcheractive, afterhandler))
               {
                  return SharkSslCon_AllocationError;
               }

               tb = afterhandler;
               tp = tb + csLen;
               while ((0 == *tb) && (csLen))  
               {
                  csLen--;
                  tb++;
                  *registeredevent++ = 0;  
               }
               i = csLen;
               #else
               return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
               #endif
            }
         }
         else
         #endif
         {
            #if SHARKSSL_ENABLE_RSA
            int ret;
            csLen = supportedvector(sharkSslHSParam->certKey.modLen);
            if (hsDataLen != csLen)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }

            ret = (int)writemessage(&(sharkSslHSParam->certKey), csLen, registeredevent, registeredevent, SHARKSSL_RSA_PKCS1_PADDING);

            
            if (sharkssl_rng(afterhandler, SHARKSSL_MASTER_SECRET_LEN) < 0)
            {
               goto _sharkssl_hs_clear_premaster;
            }

            
            ret = (int)((ret != SHARKSSL_MASTER_SECRET_LEN) & 1);
            tb = registeredevent + (ret * (int)(afterhandler - registeredevent));

            tb[0] = o->major;

            
            ret  = (int)((tb[1] != o->reqMinor) & 1) * (int)((tb[1] != o->minor) & 1);
            tb[1] = (U8)(tb[1] + (U8)(ret * (U8)(o->reqMinor - tb[1])));

            ics = 0;
            i   = SHARKSSL_MASTER_SECRET_LEN;
            tp  = afterhandler + i;
            #else
            csLen = i = 0;
            #endif
         }

         
         if (allocalloc(o, sharkSslHSParam->masterSecret, SHARKSSL_MASTER_SECRET_LEN,
                                          tb, i, 
                                          sharkSslHSParam->clientRandom,
                                          sharkSslHSParam->serverRandom) < 0)
         {
            ics = 1;
         }

         
         i = disableclean(sharkSslHSParam->cipherSuite);
         if (allocalloc(o, sharkSslHSParam->sharedSecret, i,
                                         sharkSslHSParam->masterSecret, SHARKSSL_MASTER_SECRET_LEN,
                                         sharkSslHSParam->serverRandom,
                                         sharkSslHSParam->clientRandom) < 0)
         {
            ics = 1;
         }

         #if SHARKSSL_ENABLE_RSA
          _sharkssl_hs_clear_premaster:
         #endif
         memset(registeredevent, 0, csLen);  
         registeredevent += csLen;

         if (ics > 0)
         {
            resvdexits(o);
            return SharkSslCon_Error;
         }

         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (o->session)
         {
            
            filtermatch(&o->sharkSsl->sessionCache);
            memcpy(o->session->masterSecret, sharkSslHSParam->masterSecret, SHARKSSL_MASTER_SECRET_LEN);
            helperglobal(&o->sharkSsl->sessionCache);
         }
         #endif
         if (o->flags & unregistershash)
         {
            o->state = modifygraph;
         }
         else
         {
            o->state = switcherdevice;
         }

         if (atagsprocfs)
         {
            goto _sharkssl_process_another_hs_record;
         }
         o->inBuf.temp = 0;
         #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
         *deviceusbgadget = 0;
         #endif
         return SharkSslCon_Handshake;

      #if SHARKSSL_ENABLE_CLIENT_AUTH
      case modifygraph:
         tp = registeredevent - traceentry;
         if (hsDataLen < 2)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         {
            if ( (hsDataLen < 2)
                  ||
                  ((*registeredevent != presentpages) && (*registeredevent != domainnumber)
                  #if SHARKSSL_USE_SHA_384
                  && (*registeredevent != probewrite)
                  #endif
                  #if SHARKSSL_USE_SHA_512
                  && (*registeredevent != batterythread)
                  #endif
                  ) )
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            sharkSslHSParam->signParam.signature.hashAlgo = *registeredevent++;

            if (1
                #if SHARKSSL_ENABLE_RSA
                && (*registeredevent != entryearly)
                #endif
                #if SHARKSSL_ENABLE_ECDSA
                && (*registeredevent != accessactive)
                #endif
                )
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            sharkSslHSParam->signParam.signature.signatureAlgo = *registeredevent++;
            hsDataLen -= 2;
         }

         csLen  = (*registeredevent++ << 8);
         csLen += *registeredevent++;
         hsDataLen -= 2;
         if (csLen != hsDataLen)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         if (wakeupvector(sharkSslHSParam, sharkSslHSParam->signParam.signature.hash, sharkSslHSParam->signParam.signature.hashAlgo) < 0)
         {
            return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
         }
         ioremapresource(sharkSslHSParam, tp, hsLen);

         sharkSslHSParam->signParam.signature.signature = registeredevent;
         sharkSslHSParam->signParam.signature.signLen = hsDataLen;
         sharkSslHSParam->signParam.pCertKey = &(sharkSslHSParam->certParam.certKey);  
         if (systemcapabilities(&(sharkSslHSParam->signParam)) < 0)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         registeredevent += hsDataLen;
         o->state = switcherdevice;

         if (atagsprocfs)
         {
            goto _sharkssl_process_another_hs_record;
         }
         o->inBuf.temp = 0;
         #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
         *deviceusbgadget = 0;
         #endif
         return SharkSslCon_Handshake;
      #endif  
      #endif  

      #if SHARKSSL_SSL_CLIENT_CODE
      case trampolinehandler:
         #if !SHARKSSL_ENABLE_SNI
         baAssert(serial2platform(&o->inBuf));
         #endif
         baAssert(pcmciaplatform(func3fixup(&o->inBuf)));
         baAssert(pcmciaplatform(func3fixup(&o->outBuf)));

         if (hsDataLen < 2)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         o->major = *registeredevent++; 
         o->minor = *registeredevent++;
         hsDataLen -= 2;

         if ((o->major < 3) || (o->major > o->reqMajor) || (o->minor > o->reqMinor))
         {
            #if SHARKSSL_SSL_SERVER_CODE
            goto _sharkssl_hs_alert_handshake_failure;
            #else
            _sharkssl_hs_alert_handshake_failure:
            return savedconfig(o, SHARKSSL_ALERT_HANDSHAKE_FAILURE);
            #endif
         }

         if (hsDataLen < (1 + SHARKSSL_RANDOM_LEN)) 
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         memcpy(sharkSslHSParam->serverRandom, registeredevent, SHARKSSL_RANDOM_LEN);
         registeredevent += SHARKSSL_RANDOM_LEN;

         setupinterface = *registeredevent++;
         hsDataLen -= (1 + SHARKSSL_RANDOM_LEN);

         if ((hsDataLen < setupinterface) || (setupinterface > SHARKSSL_MAX_SESSION_ID_LEN))
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         sp = registeredevent; 
         registeredevent += setupinterface;
         hsDataLen -= setupinterface;

         
         if (hsDataLen < 2)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         
         csLen  = (U16)(*registeredevent++) << 8;
         csLen += *registeredevent++;
         hsDataLen -= 2;

         ics = SHARKSSL_DIM_ARR(sharkSslCipherSuiteList);
         while (ics--)
         {
            if (csLen == sharkSslCipherSuiteList[ics].id)
            {
               sharkSslHSParam->cipherSuite = (SharkSslCipherSuite*)&sharkSslCipherSuiteList[ics];
               break;
            }
         }

         if (!(sharkSslHSParam->cipherSuite))
         {
            goto _sharkssl_hs_alert_handshake_failure;
         }

         if ((hsDataLen < 1) || (*registeredevent++ != 0))
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         hsDataLen--;

         
         if (hsDataLen)
         {
            if (hsDataLen < 2)
            {
               goto _sharkssl_hs_alert_decode_error;
            }

            
            csLen  = (U16)(*registeredevent++) << 8;
            csLen += *registeredevent++;
            hsDataLen -= 2;
            if (hsDataLen != csLen)
            {
               goto _sharkssl_hs_alert_decode_error;
            }

            #if SHARKSSL_SSL_SERVER_CODE
            if (writepmresr(o, 0, registeredevent, csLen))
            #else
            if (writepmresr(o, registeredevent, csLen))
            #endif
            {
               goto _sharkssl_hs_alert_decode_error;
            }

            registeredevent += csLen;
            hsDataLen -= csLen;
         }

         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (setupinterface)  
         {
            o->flags |= gpiolibmbank;
            if (o->session)
            {
               SharkSslSession *s = latchgpiochip(&o->sharkSsl->sessionCache, o, sp, setupinterface);
               if (s)
               {
                  
                  o->session = s;  
                  o->flags |= startqueue;
               }
               else
               {
                  goto _sharkssl_hs_session_new;
               }
            }
            else
            {
               _sharkssl_hs_session_new:  
               o->session = sa1111device(&o->sharkSsl->sessionCache, o, sp, setupinterface);
            }
         }
         else if (o->session)  
         {
            o->session = 0;
         }
         #endif

         ioremapresource(sharkSslHSParam, tp, hsLen);

         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (o->flags & startqueue)
         {
            memcpy(sharkSslHSParam->masterSecret, o->session->masterSecret, SHARKSSL_MASTER_SECRET_LEN);
            
            csLen = disableclean(sharkSslHSParam->cipherSuite);
            if (allocalloc(o, sharkSslHSParam->sharedSecret, csLen,
                                            sharkSslHSParam->masterSecret, SHARKSSL_MASTER_SECRET_LEN,
                                            sharkSslHSParam->serverRandom,
                                            sharkSslHSParam->clientRandom) < 0)
            {
               resvdexits(o);
               return SharkSslCon_Error;
            }

            o->state = switcherdevice;
         }
         else
         #endif
         {
            o->state = parsebootinfo;
         }

         if (atagsprocfs)
         {
            goto _sharkssl_process_another_hs_record;
         }
         o->inBuf.temp = 0;
         #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
         *deviceusbgadget = 0;
         #endif
         return SharkSslCon_Handshake;

      #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
      case startflags:
         baAssert(sharkSslHSParam->cipherSuite->flags & cleandcache);
         sp = NULL;  
         #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         if (sharkSslHSParam->cipherSuite->flags & irqhandlerfixup)
         {
            if (hsDataLen < 5)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            
            if (*registeredevent++ != mcbsp5hwmod)
            {
               goto _sharkssl_hs_alert_decode_error;
            }
            hsDataLen--;
            csLen  = (U16)(*registeredevent++) << 8;
            csLen += (*registeredevent++);
            hsDataLen -= 2;
            sharkSslHSParam->ecdhParam.curveType = csLen;  
            
            i = controllerregister(csLen);
            csLen = (*registeredevent++);
            hsDataLen--;
            if ((0 == i) || (*registeredevent++ != SHARKSSL_EC_POINT_UNCOMPRESSED))
            {
               goto _sharkssl_hs_alert_decode_error;
            }
            hsDataLen--;
            csLen--;
            if ((hsDataLen < csLen) || (csLen != (U16)(i << 1)))
            {
               goto _sharkssl_hs_alert_decode_error;
            }
            sharkSslHSParam->ecdhParam.xLen = i;
            
            memcpy(afterhandler, registeredevent, csLen);
            sharkSslHSParam->ecdhParam.XY = afterhandler;      
            hsDataLen -= csLen;
            afterhandler += csLen;
            registeredevent += csLen;
            sp = registeredevent;
         }
         else
         #endif
         {
            #if SHARKSSL_ENABLE_DHE_RSA
            if (hsDataLen < 2)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            csLen  = (U16)(*registeredevent++) << 8;
            csLen += (*registeredevent++);
            hsDataLen -= 2;
            baAssert(sharkSslHSParam->cipherSuite->flags & cleandcache);
            
            if ((hsDataLen < csLen) || (csLen & 0x03) || (csLen == 0))
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            sharkSslHSParam->dhParam.pLen = csLen;
            
            baAssert(((unsigned int)(UPTR)afterhandler & 0x03) == 0);
            memcpy(afterhandler, registeredevent, csLen);
            sharkSslHSParam->dhParam.p = afterhandler;
            registeredevent += csLen;
            afterhandler += csLen;
            hsDataLen -= csLen;

            if (hsDataLen < 2)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            csLen  = (U16)(*registeredevent++) << 8;
            csLen += (*registeredevent++);
            hsDataLen -= 2;
            if ((hsDataLen < csLen) || (csLen == 0))
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            sharkSslHSParam->dhParam.g = afterhandler;
            i = csLen;
            while (csLen & 0x03)
            {
               *afterhandler++ = 0;
               csLen++;
            }
            sharkSslHSParam->dhParam.gLen = csLen;
            memcpy(afterhandler, registeredevent, i);
            registeredevent += i;
            afterhandler += i;
            hsDataLen -= i;

            if (hsDataLen < 2)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            csLen  = (U16)(*registeredevent++) << 8;
            csLen += (*registeredevent++);
            hsDataLen -= 2;
            if (hsDataLen < csLen)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }

            sharkSslHSParam->dhParam.Y = afterhandler;  
            
            if (csLen != sharkSslHSParam->dhParam.pLen)
            {
               if ((csLen == 0) || (csLen > sharkSslHSParam->dhParam.pLen))
               {
                  goto _sharkssl_hs_alert_illegal_parameter;
               }
               i = sharkSslHSParam->dhParam.pLen - csLen;
               
               while (i--)
               {
                  *afterhandler++ = 0;
               }
            }
            
            memcpy(afterhandler, registeredevent, csLen);
            registeredevent += csLen;
            afterhandler += csLen;
            hsDataLen -= csLen;
            sp = registeredevent;
            #else
            return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
            #endif  
         }

         #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         
         {
            if ( (hsDataLen < 2)
                  ||
                  ((*registeredevent != presentpages) && (*registeredevent != domainnumber)
                  #if SHARKSSL_USE_SHA_384
                  && (*registeredevent != probewrite)
                  #endif
                  #if SHARKSSL_USE_SHA_512
                  && (*registeredevent != batterythread)
                  #endif
                  ) )
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            sharkSslHSParam->signParam.signature.hashAlgo = *registeredevent++;
            sharkSslHSParam->signParam.signature.signatureAlgo = *registeredevent++;
            if (
                  #if SHARKSSL_ENABLE_RSA
                  (sharkSslHSParam->signParam.signature.signatureAlgo != entryearly)
                  #if (SHARKSSL_ENABLE_ECDSA)
                  &&
                  #endif
                  #endif
                  #if (SHARKSSL_ENABLE_ECDSA)
                  (sharkSslHSParam->signParam.signature.signatureAlgo != accessactive)
                  #endif
               )
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            hsDataLen -= 2;
         }

         if (hsDataLen < 2)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         csLen  = (U16)(*registeredevent++) << 8;
         csLen += (*registeredevent++);
         hsDataLen -= 2;
         
         if (hsDataLen != csLen)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         #endif

         ioremapresource(sharkSslHSParam, tp, hsLen);

         #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         
         csLen = (U16)(sp - tp) - traceentry;
         memcpy(afterhandler, sharkSslHSParam->clientRandom, SHARKSSL_RANDOM_LEN);
         memcpy(afterhandler + SHARKSSL_RANDOM_LEN, sharkSslHSParam->serverRandom, SHARKSSL_RANDOM_LEN);
         memcpy(afterhandler + (2 * SHARKSSL_RANDOM_LEN), tp + traceentry, csLen);
         csLen += (2 * SHARKSSL_RANDOM_LEN);

         #if SHARKSSL_ENABLE_RSA
         if (machinekexec(sharkSslHSParam->certParam.certKey.expLen))
         {
            sharkSslHSParam->signParam.signature.signatureAlgo = entryearly;
         }
         #endif
         #if (SHARKSSL_ENABLE_ECDSA)
         if (machinereboot(sharkSslHSParam->certParam.certKey.expLen))
         {
            sharkSslHSParam->signParam.signature.signatureAlgo = accessactive;
         }
         #endif

         if (sharkssl_hash(sharkSslHSParam->signParam.signature.hash, afterhandler, csLen, sharkSslHSParam->signParam.signature.hashAlgo))
         {
            return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
         }

         sharkSslHSParam->signParam.signature.signature = registeredevent;
         sharkSslHSParam->signParam.signature.signLen   = hsDataLen;
         sharkSslHSParam->signParam.pCertKey = &(sharkSslHSParam->certParam.certKey);  

         
         if (systemcapabilities(&(sharkSslHSParam->signParam)) < 0)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         registeredevent += hsDataLen;  
         #else
         registeredevent += csLen;
         #endif

         o->state = configcwfon;
         if (atagsprocfs)
         {
            goto _sharkssl_process_another_hs_record;
         }
         o->inBuf.temp = 0;
         #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
         *deviceusbgadget = 0;
         #endif
         return SharkSslCon_Handshake;
      #endif  

      #if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
      case logicmembank:
         if (hsDataLen < 4)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         i = 0;
         csLen = *registeredevent++;
         hsDataLen--;
         if (hsDataLen < csLen)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         #if SHARKSSL_ENABLE_CLIENT_AUTH
         
         baAssert(0 == (ahashchild & compatrestart & systemtable));
         baAssert(0 == (ahashchild & (ahashchild - 1)));
         baAssert(0 == (systemtable & (systemtable - 1)));
         baAssert(0 == (compatrestart & (compatrestart - 1)));
         while (csLen--)
         {
            if ( 0
                 #if SHARKSSL_ENABLE_RSA
                 || (ahashchild == *registeredevent)
                 #endif
                 #if SHARKSSL_ENABLE_ECDSA
                 || (compatrestart == *registeredevent)
                 #endif
               )
            {
               i |= *registeredevent;
            }
            registeredevent++;
            hsDataLen--;
         }

         
         SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
         for (tb = (U8*)afterhandler, link = SingleListEnumerator_getElement(&e);
              link;
              link = SingleListEnumerator_nextElement(&e), tb += sizeof(SHARKSSL_WEIGHT))
         {
            *(SHARKSSL_WEIGHT*)tb = (SHARKSSL_WEIGHT)((((SharkSslCertList*)link)->certP.keyType & (U8)i) ? ((SharkSslCertList*)link)->certP.keyType : 0);
         }
         *(SHARKSSL_WEIGHT*)tb = (SHARKSSL_WEIGHT)-1;  

         
         #else
         registeredevent += csLen;
         hsDataLen -= csLen;
         #endif  
         sharkSslHSParam->signParam.signature.signatureAlgo = sharkSslHSParam->signParam.signature.hashAlgo = 0;

         {
            
            if (hsDataLen < 2)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }
            csLen  = (U16)(*registeredevent++) << 8;
            csLen += *registeredevent++;
            hsDataLen -= 2;

            if ((hsDataLen < csLen) || (csLen & 1))
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }

            hsDataLen -= csLen;
            #if SHARKSSL_ENABLE_CLIENT_AUTH
            i = 0;
            while (csLen)
            {
               
               SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
               for (tb = (U8*)afterhandler, link = SingleListEnumerator_getElement(&e);
                    link;
                    link = SingleListEnumerator_nextElement(&e), tb += sizeof(SHARKSSL_WEIGHT))
               {
                  
                  if ((*(SHARKSSL_WEIGHT*)tb) && (*(SHARKSSL_WEIGHT*)tb < smbuswrite))
                  {
                     if ((((SharkSslCertList*)link)->certP.hashAlgo == registeredevent[0]) &&
                         (((SharkSslCertList*)link)->certP.signatureAlgo == registeredevent[1]))
                     {
                        
                        *(SHARKSSL_WEIGHT*)tb += (smbuswrite + (((SharkSslCertList*)link)->certP.keyOID) + csLen);
                     }
                  }
               }

               if (i < 2)
               {
                  if ((registeredevent[0] == presentpages) || (registeredevent[0] == domainnumber)
                      #if SHARKSSL_USE_SHA_384
                      || (registeredevent[0] == probewrite)
                      #endif
                      #if SHARKSSL_USE_SHA_512
                      || (registeredevent[0] == batterythread)
                      #endif
                     )
                  {
                     #if SHARKSSL_ENABLE_RSA
                     if ((0 == sharkSslHSParam->signParam.signature.signatureAlgo) && (registeredevent[1] == entryearly))
                     {
                        sharkSslHSParam->signParam.signature.signatureAlgo = registeredevent[0];
                        i++;
                     }
                     #endif

                     #if SHARKSSL_ENABLE_ECDSA
                     if ((0 == sharkSslHSParam->signParam.signature.hashAlgo) && (registeredevent[1] == accessactive))
                     {
                        sharkSslHSParam->signParam.signature.hashAlgo = registeredevent[0];
                        i++;
                     }
                     #endif
                  }
               }

               registeredevent += 2;
               csLen -= 2;
            }

            
            tb = (U8*)afterhandler;
            while (*(SHARKSSL_WEIGHT*)tb != (SHARKSSL_WEIGHT)-1)
            {
               if (*(SHARKSSL_WEIGHT*)tb < smbuswrite)
               {
                  *(SHARKSSL_WEIGHT*)tb = 0;
               }
               tb += sizeof(SHARKSSL_WEIGHT);
            }
            #else
            registeredevent += csLen;
            #endif  
         }

         
         if (hsDataLen < 2)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         csLen  = (U16)(*registeredevent++) << 8;
         csLen += *registeredevent++;
         hsDataLen -= 2;
         if (hsDataLen != csLen)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }
         hsDataLen = 0;
         #if SHARKSSL_ENABLE_CLIENT_AUTH
         if (csLen)  
         {
            while (csLen)
            {
               if (csLen < 2)
               {
                  goto _sharkssl_hs_alert_illegal_parameter;
               }
               i  = (U16)(*registeredevent++) << 8;
               i += *registeredevent++;
               csLen -= 2;
               if (i > csLen)
               {
                  goto _sharkssl_hs_alert_illegal_parameter;
               }

               SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
               for (tb = (U8*)afterhandler, link = SingleListEnumerator_getElement(&e);
                    link;
                    link = SingleListEnumerator_nextElement(&e), tb += sizeof(SHARKSSL_WEIGHT))
               {
                  
                  if ((*(SHARKSSL_WEIGHT*)tb) && (*(SHARKSSL_WEIGHT*)tb < lcd035q3dg01pdata))
                  {
                     
                     if (domainassociate(((SharkSslCertList*)link)->certP.cert, registeredevent, i))
                     {
                        *(SHARKSSL_WEIGHT*)tb += lcd035q3dg01pdata;
                     }
                  }
               }
               registeredevent += i;
               csLen -= i;
            }

            
            tb = (U8*)afterhandler;
            while (*(SHARKSSL_WEIGHT*)tb != (SHARKSSL_WEIGHT)-1)
            {
               if (*(SHARKSSL_WEIGHT*)tb < lcd035q3dg01pdata)
               {
                  *(SHARKSSL_WEIGHT*)tb = 0;
               }
               tb += sizeof(SHARKSSL_WEIGHT);
            }
         }
         #else
         registeredevent += csLen;
         #endif  

         sharkSslHSParam->certParsed = NULL;

         #if SHARKSSL_ENABLE_CLIENT_AUTH
         
         now = 0;
         SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
         for (tb = (U8*)afterhandler, link = SingleListEnumerator_getElement(&e);
              link;
              link = SingleListEnumerator_nextElement(&e), tb += sizeof(SHARKSSL_WEIGHT))
         {
            if (*(SHARKSSL_WEIGHT*)tb > now)
            {
               now = (U32)(*(SHARKSSL_WEIGHT*)tb);
               sharkSslHSParam->certParsed = &(((SharkSslCertList*)link)->certP);
            }
         }
         baAssert(*(SHARKSSL_WEIGHT*)tb == (SHARKSSL_WEIGHT)-1);

         
         if (now)
         {
            #if SHARKSSL_ENABLE_RSA
            if (sharkSslHSParam->certParsed->keyType == ahashchild)
            {
               sharkSslHSParam->signParam.signature.hashAlgo = sharkSslHSParam->signParam.signature.signatureAlgo;
               sharkSslHSParam->signParam.signature.signatureAlgo = entryearly;
            }
            #if (SHARKSSL_ENABLE_ECDSA)
            else
            #endif
            #endif
            #if (SHARKSSL_ENABLE_ECDSA)
            if (sharkSslHSParam->certParsed->keyType == compatrestart)
            {
               sharkSslHSParam->signParam.signature.signatureAlgo = accessactive;
            }
            #endif

            if ((0 == sharkSslHSParam->signParam.signature.hashAlgo) || (0 == sharkSslHSParam->signParam.signature.signatureAlgo))
            {
               sharkSslHSParam->certParsed = NULL;  
            }
         }
         #endif  

         ioremapresource(sharkSslHSParam, tp, hsLen);
         o->flags |= (unregistershash + nresetconsumers);
         o->state = configcwfon;
         if (atagsprocfs)
         {
            goto _sharkssl_process_another_hs_record;
         }
         o->inBuf.temp = 0;
         #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
         *deviceusbgadget = 0;
         #endif
         return SharkSslCon_Handshake;
      #endif

      case configcwfon:
         if (hsDataLen != 0)
         {
            _sharkssl_hs_alert_decode_error:
            return savedconfig(o, SHARKSSL_ALERT_DECODE_ERROR);
         }

         ioremapresource(sharkSslHSParam, tp, hsLen);
         o->state = switcherdevice;

         
         registerfixed(&o->inBuf);
         tp = o->inBuf.data;
         #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         if (sharkSslHSParam->cipherSuite->flags & (cleandcache | irqhandlerfixup))
         {
            #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
            if (sharkSslHSParam->cipherSuite->flags & irqhandlerfixup)
            {
               csLen = (U16)(sharkSslHSParam->ecdhParam.xLen << 1) + 2 + 4;
            }
            else
            #endif
            {
               #if SHARKSSL_ENABLE_DHE_RSA
               csLen = sharkSslHSParam->dhParam.pLen + 6;
               #else
               return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
               #endif
            }
         }
         else
         #endif
         {
            csLen = 6;
            #if SHARKSSL_ENABLE_RSA
            {
               baAssert(sharkSslHSParam->cipherSuite->flags & percpudevid);
               csLen += supportedvector(sharkSslHSParam->certParam.certKey.modLen);
            }
            #else
            goto _sharkssl_hs_alert_handshake_failure;
            #endif
         }
         #if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
         if (o->flags & unregistershash)
         {
            #if SHARKSSL_ENABLE_CLIENT_AUTH
            if (sharkSslHSParam->certParsed)
            {
               i = sharkSslHSParam->certParsed->msgLen;
               baAssert(i > 0);  
               i += traceentry;
               baAssert(i < 16384);

               
               if (0 == interrupthandler(&(sharkSslHSParam->certKey), sharkSslHSParam->certParsed->cert))
               {
                  return SharkSslCon_CertificateError;
               }
            }
            else
            #endif
            {
               o->flags &= ~unregistershash;
               i = traceentry + 3;
            }
            tp = sp = templateentry(o, controllegacy, tp, csLen + i);
            
            i -= traceentry;
            *tp++ = parsebootinfo;
            *tp++ = 0x00;
            *tp++ = (i >> 8);
            *tp++ = (i & 0xFF);
            #if SHARKSSL_ENABLE_CLIENT_AUTH
            if (sharkSslHSParam->certParsed)
            {
               if (fixupresources(sharkSslHSParam->certParsed->cert, i, tp))
               {
                  resvdexits(o);
                  return SharkSslCon_Error;
               }
            }
            else
            #endif
            {
               if (fixupresources((U8*)0, i, tp))
               {
                  resvdexits(o);
                  return SharkSslCon_Error;
               }
            }
            tp += i;
            
         }
         else
         #endif
         {
            tp = sp = templateentry(o, controllegacy, tp, csLen);
         }

         
         csLen -= traceentry;
         *tp++ = subtableheaders;
         *tp++ = 0x00;
         *tp++ = csLen >> 8;
         *tp++ = csLen & 0xFF;
         #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         if (sharkSslHSParam->cipherSuite->flags & irqhandlerfixup)
         {
            baAssert(csLen < 0x0100);
            csLen--;  
            *tp++ = csLen & 0xFF;
            *tp++ = SHARKSSL_EC_POINT_UNCOMPRESSED;
            csLen--;
            baAssert(csLen == (U16)(sharkSslHSParam->ecdhParam.xLen << 1));
         }
         else
         #endif
         {
            csLen -= 2; 
            *tp++ = csLen >> 8;
            *tp++ = csLen & 0xFF;
         }

         #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
         if (sharkSslHSParam->cipherSuite->flags & (cleandcache | irqhandlerfixup))
         {
            #if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
            if (sharkSslHSParam->cipherSuite->flags & irqhandlerfixup)
            {
               if ((int)SharkSslCon_AllocationError ==
                     SharkSslECDHParam_ECDH(&(sharkSslHSParam->ecdhParam), (signalpreserve + switcheractive), tp))
               {
                  return SharkSslCon_AllocationError;
               }

               
               tp += csLen;
               tb  = tp;
               baAssert((csLen & 1) == 0);
               csLen >>= 1;
            }
            else
            #endif
            {
               #if SHARKSSL_ENABLE_DHE_RSA
               
               baAssert(pcmciaplatform(afterhandler));
               sharkSslHSParam->dhParam.r = afterhandler;

               
               if ((int)SharkSslCon_AllocationError ==
                   SharkSslDHParam_DH(&(sharkSslHSParam->dhParam), (cpucfgexits + switcheractive), tp))
               {
                  return SharkSslCon_AllocationError;
               }

               
               tp += csLen;
               tb  = tp;
               while ((0 == *tb) && (csLen > 0))
               {
                  tb++;
                  csLen--;
               }
               #endif  
            }
            if (allocalloc(o, sharkSslHSParam->masterSecret, SHARKSSL_MASTER_SECRET_LEN,
                                            tb, csLen, 
                                            sharkSslHSParam->clientRandom,
                                            sharkSslHSParam->serverRandom) < 0)
            {
               resvdexits(o);
               return SharkSslCon_Error;
            }
         }
         else
         #endif  
         {
            #if SHARKSSL_ENABLE_RSA
            csLen = SHARKSSL_MASTER_SECRET_LEN;
            if (sharkssl_rng(tp, csLen) < 0)
            {
               resvdexits(o);
               return SharkSslCon_Error;
            }
            tp[0] = o->reqMajor; 
            tp[1] = o->reqMinor; 

            
            if (allocalloc(o, sharkSslHSParam->masterSecret, SHARKSSL_MASTER_SECRET_LEN,
                                            tp, csLen, 
                                            sharkSslHSParam->clientRandom,
                                            sharkSslHSParam->serverRandom) < 0)
            {
               resvdexits(o);
               return SharkSslCon_Error;
            }
            #else
            goto _sharkssl_hs_alert_handshake_failure;
            #endif

            #if SHARKSSL_ENABLE_RSA
            
            {
               int ret = (int)omap3430common(&(sharkSslHSParam->certParam.certKey), csLen, tp, tp, SHARKSSL_RSA_PKCS1_PADDING);
               if (ret < 0)
               {
                  resvdexits(o);
                  return SharkSslCon_Error;
               }
               csLen = (U16)ret;
               tp += csLen;
            }
            #endif
         }

         csLen = disableclean(sharkSslHSParam->cipherSuite);
         if (allocalloc(o, sharkSslHSParam->sharedSecret, csLen,
                                         sharkSslHSParam->masterSecret, SHARKSSL_MASTER_SECRET_LEN,
                                         sharkSslHSParam->serverRandom,
                                         sharkSslHSParam->clientRandom) < 0)
         {
            resvdexits(o);
            return SharkSslCon_Error;
         }

         
         ioremapresource(sharkSslHSParam, sp, (U16)(tp - sp));

         #if ((SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA) && SHARKSSL_ENABLE_CLIENT_AUTH)
         if (o->flags & unregistershash)
         {
            o->flags &= ~unregistershash;
            
            csLen = traceentry + 2;  
            csLen += 2;  

            
            sharkSslHSParam->signParam.signature.signature = (tp + clkctrlmanaged + csLen);  

            if (wakeupvector(sharkSslHSParam, sharkSslHSParam->signParam.signature.hash, sharkSslHSParam->signParam.signature.hashAlgo) < 0)
            {
               return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
            }

            sharkSslHSParam->signParam.pCertKey = &(sharkSslHSParam->certKey);  
            if (checkactions(&(sharkSslHSParam->signParam)) < 0)
            {
               return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
            }

            
            i = sharkSslHSParam->signParam.signature.signLen + csLen;
            sp = tp = templateentry(o, controllegacy, tp, i);
            i -= traceentry;
            *tp++ = modifygraph;
            *tp++ = 0;
            *tp++ = i >> 8;
            *tp++ = i & 0xFF;
            *tp++ = sharkSslHSParam->signParam.signature.hashAlgo;
            *tp++ = sharkSslHSParam->signParam.signature.signatureAlgo;
            i -= 2;
            i -= 2;
            *tp++ = i >> 8;
            *tp++ = i & 0xFF;
            tp += i;  
            
            ioremapresource(sharkSslHSParam, sp, (U16)(tp - sp));
         }
         #else
         baAssert(!(o->flags & unregistershash));
         #endif

         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (o->session)
         {
            
            filtermatch(&o->sharkSsl->sessionCache);
            memcpy(o->session->masterSecret, sharkSslHSParam->masterSecret, SHARKSSL_MASTER_SECRET_LEN);
            helperglobal(&o->sharkSsl->sessionCache);
         }
         #endif

         o->inBuf.temp = (U16)(tp - o->inBuf.data);
         if (sanitisependbaser(o, tvp5146routes, tp))
         {
            resvdexits(o);
            return SharkSslCon_Error;
         }

         if (atagsprocfs)
         {
            goto _sharkssl_process_another_hs_record;
         }
         #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
         *deviceusbgadget = 0;
         #endif
         return SharkSslCon_Handshake;
      #endif  

      #if ((SHARKSSL_SSL_CLIENT_CODE && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)) || \
           (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_CLIENT_AUTH))
      case parsebootinfo:
         if (hsDataLen < 3)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         crLen  = (U32)(*registeredevent++) << 16;
         crLen += (U16)(*registeredevent++) << 8;
         crLen += *registeredevent++;
         hsDataLen -= 3;

         if (crLen == 0)
         {
            
            if (SharkSsl_isServer(o->sharkSsl))
            {
               o->flags &= ~unregistershash;
               o->flags |=  serialreset;
            }
            else
            {
               _sharkssl_hs_alert_bad_certificate:
               return savedconfig(o, SHARKSSL_ALERT_BAD_CERTIFICATE);
            }
         }
         else if (hsDataLen < 3)
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         
         ioremapresource(sharkSslHSParam, tp, hsLen);

         ics = 0; 
         certParam = &(sharkSslHSParam->certParam);
         while (crLen > 0)
         {
            
            now  = (U32)(*registeredevent++) << 16;
            now += (U16)(*registeredevent++) << 8;
            now += *registeredevent++;
            hsDataLen -= 3;

            if (hsDataLen < now)
            {
               goto _sharkssl_hs_alert_illegal_parameter;
            }

            
            if (spromregister(certParam, registeredevent, now, 0) < 0)
            {
               return savedconfig(o, SHARKSSL_ALERT_UNSUPPORTED_CERTIFICATE);
            }

            if (0 == ics)
            {
               ics++;
               
               #if SHARKSSL_USE_ECC
               if (machinereboot(certParam->certKey.expLen))
               {
                  baAssert(0 == mousethresh(certParam->certKey.expLen));
                  baAssert(sharkSslHSParam->cipherSuite);
                  i = (U16)(attachdevice(certParam->certKey.modLen)) * 2;
                  memcpy(afterhandler, certParam->certKey.mod, i);
                  certParam->certKey.mod = afterhandler;
                  afterhandler += i;
               }
               #if SHARKSSL_ENABLE_RSA
               else
               #endif
               #endif
               #if SHARKSSL_ENABLE_RSA
               {
                  baAssert(machinekexec(certParam->certKey.expLen));
                  memcpy(afterhandler, certParam->certKey.mod, supportedvector(certParam->certKey.modLen));
                  certParam->certKey.mod = afterhandler;
                  afterhandler += supportedvector(certParam->certKey.modLen);
                  memcpy(afterhandler, certParam->certKey.exp, mousethresh(certParam->certKey.expLen));
                  certParam->certKey.exp = afterhandler;
                  afterhandler += claimresource(mousethresh(certParam->certKey.expLen));
               }
               #endif
            }

            hsDataLen -= (U16)now;
            registeredevent += (U16)now;
            crLen -= (now + 3);

            if (crLen) 
            {
               certParam->certInfo.parent = (SharkSslCertInfo*)afterhandler;
               certParam = (SharkSslCertParam*)afterhandler;
               memset(certParam, 0, sizeof(SharkSslCertParam));
               afterhandler += claimresource(sizeof(SharkSslCertParam));
            }
         }

         if (!(o->flags & serialreset))
         {
            #if SHARKSSL_ENABLE_CA_LIST
            ics = 1;
            #endif
            certParam = &(sharkSslHSParam->certParam);
            while (certParam)
            {
                
               if (certParam->certInfo.parent != 0)
               {
                  if (0 == SharkSslCertDN_equal(&(certParam->certInfo.issuer),
                     &((SharkSslCertParam*)(certParam->certInfo.parent))->certInfo.subject))
                  {
                     goto _sharkssl_hs_alert_bad_certificate;
                  }
               #if SHARKSSL_ENABLE_CA_LIST
               }

               
               if (o->sharkSsl->caList)
               {
                  #if SHARKSSL_ENABLE_CERTSTORE_API
                  baAssert(SHARKSSL_CA_LIST_PTR_SIZE == claimresource(SHARKSSL_CA_LIST_PTR_SIZE));
                  csLen = nativeiosapic;
                  if (o->sharkSsl->caList[0] == SHARKSSL_CA_LIST_PTR_TYPE)
                  {
                     csLen = SHARKSSL_CA_LIST_NAME_SIZE + SHARKSSL_CA_LIST_PTR_SIZE;
                  }
                  else
                  #endif
                  if (o->sharkSsl->caList[0] != SHARKSSL_CA_LIST_INDEX_TYPE)
                  {
                     return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
                  }
                  tp = (U8*)&(o->sharkSsl->caList[2]);
                  now = (U16)(*tp++) << 8;
                  now += *tp++;
                  if (0 == now)  
                  {
                     break;
                  }
                  now--;
                  #if SHARKSSL_ENABLE_CERTSTORE_API
                  now *= csLen;
                  #else
                  now *= nativeiosapic;
                  #endif

                  
                  sp = afterhandler;
                  afterhandler += SHARKSSL_CA_LIST_NAME_SIZE;

                  
                  i = 0;
                  if ((certParam->certInfo.issuer.commonName) && (certParam->certInfo.issuer.commonNameLen))
                  {
                     i = certParam->certInfo.issuer.commonNameLen;
                     memcpy(sp, certParam->certInfo.issuer.commonName, SHARKSSL_CA_LIST_NAME_SIZE);
                  }
                  else if ((certParam->certInfo.issuer.organization) && (certParam->certInfo.issuer.organizationLen))
                  {
                     i = certParam->certInfo.issuer.organizationLen;
                     memcpy(sp, certParam->certInfo.issuer.organization, SHARKSSL_CA_LIST_NAME_SIZE);
                  }
                  
                  if (i >= SHARKSSL_CA_LIST_NAME_SIZE)
                  {
                     i = SHARKSSL_CA_LIST_NAME_SIZE;
                  }
                  if (i == 0)
                  {
                     return savedconfig(o, SHARKSSL_ALERT_UNSUPPORTED_CERTIFICATE);
                  }

                  
                  memset(afterhandler, 0, sizeof(SharkSslCertParam));

                  
                  tp += now;
                  while ((*tp != *sp) && (now > 0))
                  {
                     #if SHARKSSL_ENABLE_CERTSTORE_API
                     tp  -= csLen;
                     now -= csLen;
                     #else
                     tp  -= nativeiosapic;
                     now -= nativeiosapic;
                     #endif
                  }

                  
                  while (*tp == *sp)
                  {
                     if (0 == sharkssl_kmemcmp(tp, sp, i))
                     {
                        #if SHARKSSL_ENABLE_CERTSTORE_API
                        if (o->sharkSsl->caList[0] == SHARKSSL_CA_LIST_PTR_TYPE)
                        {
                           tb = *(U8**)&tp[SHARKSSL_CA_LIST_NAME_SIZE];
                        }
                        else
                        #endif
                        {
                           crLen  = (U32)tp[SHARKSSL_CA_LIST_NAME_SIZE+0] << 24;
                           crLen += (U32)tp[SHARKSSL_CA_LIST_NAME_SIZE+1] << 16;
                           crLen += (U16)tp[SHARKSSL_CA_LIST_NAME_SIZE+2] << 8;
                           crLen +=      tp[SHARKSSL_CA_LIST_NAME_SIZE+3];
                           #if SHARKSSL_ENABLE_CERTSTORE_API
                           tb = (U8*)&(o->sharkSsl->caList[crLen]);
                           #endif
                        }
                        #if SHARKSSL_ENABLE_CERTSTORE_API
                        if (!(spromregister((SharkSslCertParam*)afterhandler, tb, (U32)-1,
                                                            (afterhandler + claimresource(sizeof(SharkSslCertParam)))) < 0))
                        #else
                        if (!(spromregister((SharkSslCertParam*)afterhandler, (U8*)&(o->sharkSsl->caList[crLen]), (U32)-1,
                                                            (afterhandler + claimresource(sizeof(SharkSslCertParam)))) < 0))
                        #endif
                        {
                           if ((((SharkSslCertParam*)afterhandler)->certInfo.version < 2) || (((SharkSslCertParam*)afterhandler)->certInfo.CAflag))
                           {
                              if (SharkSslCertDN_equal(&(((SharkSslCertParam*)afterhandler)->certInfo.subject), &(certParam->certInfo.issuer)))
                              {
                                 if (SharkSslCertDN_equal(&(certParam->certInfo.issuer), &(certParam->certInfo.subject)))
                                 {
                                    
                                    if (0 == sharkssl_kmemcmp(((SharkSslCertParam*)afterhandler)->signature.signature,
                                                               certParam->signature.signature,
                                                               certParam->signature.signLen))
                                    {
                                       o->flags |= switcheractivation;
                                       break;
                                    }
                                    
                                 }
                                 else
                                 {
                                    
                                    if (0
                                          #if SHARKSSL_ENABLE_RSA
                                          || ((certParam->signature.signatureAlgo == entryearly) &&
                                             machinekexec(((SharkSslCertParam*)afterhandler)->certKey.expLen))
                                          #endif
                                          #if SHARKSSL_ENABLE_ECDSA
                                          || ((certParam->signature.signatureAlgo == accessactive) &&
                                             machinereboot(((SharkSslCertParam*)afterhandler)->certKey.expLen))
                                          #endif
                                       )
                                    {
                                       certParam->certInfo.parent = (SharkSslCertInfo*)afterhandler;
                                       ics = 0;
                                       goto _sharkssl_verify_cert_signature;
                                    }
                                 }
                              }
                           }
                        }
                     }
                     if (0 == now)
                     {
                        break;
                     }
                     #if SHARKSSL_ENABLE_CERTSTORE_API
                     tp  -= csLen;
                     now -= csLen;
                     #else
                     tp  -= nativeiosapic;
                     now -= nativeiosapic;
                     #endif
                  }
               }

               
               if (certParam->certInfo.parent != 0)
               {
                  _sharkssl_verify_cert_signature:
               #endif
                  
                  if (((certParam->certInfo.parent)->version == 2) && !((certParam->certInfo.parent)->CAflag))
                  {
                     goto _sharkssl_hs_alert_bad_certificate;
                  }

                  
                  sharkSslHSParam->signParam.pCertKey  = &(((SharkSslCertParam*)certParam->certInfo.parent)->certKey);
                  
                  memcpy(&(sharkSslHSParam->signParam.signature), &(certParam->signature), sizeof(SharkSslSignature));
                  if (systemcapabilities(&(sharkSslHSParam->signParam)) < 0)
                  {
                     goto _sharkssl_hs_alert_bad_certificate;
                  }

                  #if SHARKSSL_ENABLE_CA_LIST
                  if (ics == 0)  
                  {
                     o->flags |= switcheractivation;
                     break;
                  }
                  #endif
               }

               certParam = (SharkSslCertParam*)certParam->certInfo.parent;
            }
         }

         #if SHARKSSL_ENABLE_CLONE_CERTINFO
         baAssert((void*)0 == o->clonedCertInfo);
         
         if (realnummemory(o, &o->clonedCertInfo))
         {
            #if SHARKSSL_ENABLE_SESSION_CACHE
            if (o->session)
            {
               
               filtermatch(&o->sharkSsl->sessionCache);
               baAssert((void*)0 == o->session->clonedCertInfo);
               o->session->clonedCertInfo = o->clonedCertInfo;
               o->clonedCertInfo->flags |= SHARKSSL_CCINFO_CERT_CACHED;
               #if SHARKSSL_ENABLE_CA_LIST
               if (o->flags & switcheractivation)
               {
                  o->session->flags |= ecoffaouthdr;
               }
               #endif
               helperglobal(&o->sharkSsl->sessionCache);
            }
            #endif  
         }
         #endif  

         #if SHARKSSL_SSL_CLIENT_CODE
         if (SharkSsl_isClient(o->sharkSsl))
         {
            #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
            if (sharkSslHSParam->cipherSuite->flags & cleandcache)
            {
               o->state = startflags;
            }
            else
            #endif
            {
               o->state = configcwfon;
            }
         }
         #if SHARKSSL_SSL_SERVER_CODE
         else
         #endif
         #endif
         #if SHARKSSL_SSL_SERVER_CODE
         {
            o->state = subtableheaders;
         }
         #endif

         #if SHARKSSL_ENABLE_CLONE_CERTINFO
         if (atagsprocfs)
         {
            goto _sharkssl_process_another_hs_record;
         }
         o->inBuf.temp = 0;
         return SharkSslCon_Handshake;
         #else
         if (atagsprocfs)
         {
            
            templateentry(o, controllegacy,
                                       registeredevent - clkctrlmanaged, atagsprocfs);
            atagsprocfs += clkctrlmanaged;
            #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
            if (o->rCipherSuite)
            {
               o->flags |= symbolnodebug;
            }
            #endif
         }
         o->inBuf.temp = 0;
         *deviceusbgadget = atagsprocfs;
         return SharkSslCon_Certificate;
         #endif
      #endif

      case switcherdevice:
         if (!(o->flags & cachematch))
         {
            return savedconfig(o, SHARKSSL_ALERT_UNEXPECTED_MESSAGE);
         }
         o->flags &= ~cachematch;

         csLen = sapicvector;

         if ((atagsprocfs) || (hsDataLen != csLen))
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         
         registerfixed(&o->outBuf);

         
         if (printsilicon(o,
                SharkSsl_isClient(o->sharkSsl) ? rodatastart : tvp5146routes,
                o->outBuf.data) < 0)
         {
            resvdexits(o);
            return SharkSslCon_Error;
         }
         if (sharkssl_kmemcmp(registeredevent, o->outBuf.data, csLen))
         {
            goto _sharkssl_hs_alert_illegal_parameter;
         }

         #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
         memcpy(SharkSsl_isServer(o->sharkSsl) ? o->clientVerifyData : o->serverVerifyData, registeredevent, csLen);
         #if (SHARKSSL_ENABLE_ALPN_EXTENSION) && (SHARKSSL_SSL_CLIENT_CODE)
         #if SHARKSSL_SSL_SERVER_CODE
         if (SharkSsl_isClient(o->sharkSsl))
         #endif
         {
            o->pALPN = NULL;  
         }
         #endif
         #endif

         o->state = loongson3notifier;
         #if SHARKSSL_ENABLE_AES_GCM
         
         o->flags |= devicedriver;
         #endif
         
         o->flags &= ~unregistershash;

         o->inBuf.temp = 0;

         if (((SharkSsl_isServer(o->sharkSsl)) && (!(o->flags & startqueue)))
             ||
             ((SharkSsl_isClient(o->sharkSsl)) && ((o->flags & startqueue))))
         {
            ioremapresource(sharkSslHSParam, registeredevent - traceentry, hsDataLen + traceentry);
            if (sanitisependbaser(o, SharkSsl_isServer(o->sharkSsl) ? rodatastart : tvp5146routes, (U8*)0))
            {
               resvdexits(o);
               return SharkSslCon_Error;
            }
         }

         #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
         o->flags &= ~platformdevice;
         #endif
         alignmentldmstm(sharkSslHSParam);
         #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
         *deviceusbgadget = 0;
         #endif
         return SharkSslCon_Handshake;

      default:
         return savedconfig(o, SHARKSSL_ALERT_UNEXPECTED_MESSAGE);
   }
}

#ifndef _shtype_t_h
#define _shtype_t_h

#include "SharkSSL.h"


#ifndef SHARKSSL_BIGINT_WORDSIZE
#error UNDEFINED SHARKSSL_BIGINT_WORDSIZE 
#endif

#ifndef SHARKSSL_BIGINT_EXP_SLIDING_WINDOW_K
#error UNDEFINED SHARKSSL_BIGINT_EXP_SLIDING_WINDOW_K
#endif

#ifndef SHARKSSL_BIGINT_MULT_LOOP_UNROLL
#error UNDEFINED SHARKSSL_BIGINT_MULT_LOOP_UNROLL
#endif

#define SHARKSSL_ECC_USE_NIST       (SHARKSSL_ECC_USE_SECP256R1 || SHARKSSL_ECC_USE_SECP384R1 || SHARKSSL_ECC_USE_SECP521R1)
#define SHARKSSL_ECC_USE_BRAINPOOL  (SHARKSSL_ECC_USE_BRAINPOOLP256R1 || SHARKSSL_ECC_USE_BRAINPOOLP384R1 || SHARKSSL_ECC_USE_BRAINPOOLP512R1)



#if   (SHARKSSL_BIGINT_WORDSIZE == 8)
typedef U8  shtype_tWord;
typedef S8  shtype_tWordS;
typedef U16 shtype_tDoubleWord;
typedef S16 shtype_tDoubleWordS;
#elif (SHARKSSL_BIGINT_WORDSIZE == 16)
typedef U16 shtype_tWord;
typedef S16 shtype_tWordS;
typedef U32 shtype_tDoubleWord;
typedef S32 shtype_tDoubleWordS;
#elif (SHARKSSL_BIGINT_WORDSIZE == 32)
typedef U32 shtype_tWord;
typedef S32 shtype_tWordS;
typedef U64 shtype_tDoubleWord;
typedef S64 shtype_tDoubleWordS;
#else
#error SHARKSSL_BIGINT_WORDSIZE should be 8, 16 or 32
#endif



#if (((shtype_tDoubleWordS)-1LL >> SHARKSSL_BIGINT_WORDSIZE) & (1LL << SHARKSSL_BIGINT_WORDSIZE))  
#define anatopdisconnect(a) (a >>= SHARKSSL_BIGINT_WORDSIZE);  
#else
#define anatopdisconnect(a) do {                                                                            \
   if (a < 0)                                                                                            \
   {                                                                                                     \
      a = ((shtype_tDoubleWord)-1LL ^ (shtype_tWord)-1L) | (a >> SHARKSSL_BIGINT_WORDSIZE);  \
   }                                                                                                     \
   else                                                                                                  \
   {                                                                                                     \
      a >>= SHARKSSL_BIGINT_WORDSIZE;                                                                    \
   }                                                                                                     \
} while (0)
#endif



typedef struct shtype_t
{
   shtype_tWord *mem, *beg;
   U16  len;
} shtype_t;


#define SHARKSSL__M (SHARKSSL_BIGINT_WORDSIZE / 8)


#ifdef __cplusplus
extern "\103" {
#endif


#if (SHARKSSL_ENABLE_RSA || (SHARKSSL_USE_ECC && SHARKSSL_ECC_USE_BRAINPOOL))
shtype_tWord remapcfgspace(const shtype_t *mod);
void envdatamcheck(shtype_t *injectexception, const shtype_t *mod, shtype_tWord *afterhandler);

#if SHARKSSL_OPTIMIZED_BIGINT_ASM
extern
#endif
void writebytes(const shtype_t *o1, const shtype_t *o2,
                           shtype_t *deltadevices,   const shtype_t *mod,
                           shtype_tWord mu);
#endif

#define onenandpartitions(o,enablekernel,d) \
        traceaddress(o, (U16)((enablekernel)/SHARKSSL_BIGINT_WORDSIZE),(void*)(d))

#define consoledevice(o)     ((o)->beg)

#define publishdevices(o) ((o)->len)

#define pulsewidth(o)      (publishdevices(o) * SHARKSSL__M)

#define cachestride(o)           (!((o)->beg[(o)->len - 1] & 0x1))
        
void    deviceparse(const shtype_t *o);

void    blastscache(shtype_t *o);

void    traceaddress(shtype_t *o, U16 writepmresrn, void *alloccontroller);

void    unassignedvector(const shtype_t *src, shtype_t *pciercxcfg448);

shtype_tWord resolverelocs(shtype_t *o1, const shtype_t *o2);

shtype_tWord updatepmull(shtype_t *o1, const shtype_t *o2);

void    setupsdhci1(shtype_t *o1, const shtype_t *o2,
                              const shtype_t *mod);

void    keypaddevice(shtype_t *o1, const shtype_t *o2,
                              const shtype_t *mod);

U8      timerwrite(const shtype_t *o1, const shtype_t *o2);

void    hotplugpgtable(const shtype_t *o1, const shtype_t *o2, 
                            shtype_t *deltadevices);

int     suspendfinish(shtype_t *injectexception, const shtype_t *mod);

int     chunkmutex(const shtype_t *validconfig, shtype_t *exp,
                              const shtype_t *mod,  shtype_t *res,
                              U8 countersvalid);

void    ioswabwdefault(shtype_t *u, const shtype_t *mod,
                                  shtype_tWord *afterhandler);

void    backlightpdata(shtype_t *o);

#if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
int     iommumapping(shtype_t *o, const shtype_t *mod);
#endif

#if SHARKSSL_ENABLE_ECDSA
U8      eventtimeout(shtype_t *o);
#endif

#if (SHARKSSL_ENABLE_RSA && SHARKSSL_ENABLE_RSAKEY_CREATE)
int     aemifdevice(shtype_t *o);
int     translateaddress(const shtype_t *o1, const shtype_t *o2,
                           shtype_t *deltadevices);

#endif

#ifdef __cplusplus
}
#endif


#endif 

#ifndef _SharkSslECC_h
#define _SharkSslECC_h


#include <SharkSslASN1.h>


#if SHARKSSL_USE_ECC
typedef struct  
{
   shtype_t x, y;
} SharkSslECPoint;

typedef struct           
{                                                        
   shtype_t  prime;                /* prime */
   shtype_t  order;                /* order */
   SharkSslECPoint G;               /* base point */
   #if SHARKSSL_ECC_USE_BRAINPOOL
   shtype_t  a;              /* parameter a */
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   shtype_t  b;              /* parameter b */
   #endif
   U16 bits;     /* the size of the prime in bits */
} SharkSslECCurve;


#define SHARKSSL_SECP256R1_POINTLEN        32
#define SHARKSSL_SECP384R1_POINTLEN        48
#define SHARKSSL_SECP521R1_POINTLEN        66
#define SHARKSSL_BRAINPOOLP256R1_POINTLEN  32
#define SHARKSSL_BRAINPOOLP384R1_POINTLEN  48
#define SHARKSSL_BRAINPOOLP512R1_POINTLEN  64

#ifdef __cplusplus
extern "\103" {
#endif


void    clearerrors(SharkSslECCurve *o, U16 rightsvalid);

int     initialdomain(SharkSslECCurve *o, SharkSslECPoint *p);

#if (!SHARKSSL_ECDSA_ONLY_VERIFY)
int     unregisterskciphers(SharkSslECCurve *o, shtype_t *k, 
                                 SharkSslECPoint *deltadevices);
#endif

#if SHARKSSL_ENABLE_ECDSA
int     directalloc(SharkSslECCurve *S, shtype_t *d, 
                                  SharkSslECCurve *T, shtype_t *e, 
                                  SharkSslECPoint *deltadevices);
#endif

#define receivebroadcast(o,w,a,b) \
        traceaddress(&((o)->x),(w),(a)); traceaddress(&((o)->y),(w),(b))

#define updatefrequency(o,t,a,b) \
        onenandpartitions(&((o)->x),(t),(a)); onenandpartitions(&((o)->y),(t),(b))

#define mipidplatform(s,d) \
        unassignedvector(&((s)->x), &((d)->x)); unassignedvector(&((s)->y), &((d)->y))

#ifdef __cplusplus
}
#endif

#endif  
#endif 



#ifndef BA_LIB
#define BA_LIB
#endif
#include "SharkSslASN1.h"
#include <string.h>


#if (((SHARKSSL_SSL_CLIENT_CODE || SHARKSSL_SSL_SERVER_CODE) && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)) ||  \
     (SHARKSSL_ENABLE_CERTSTORE_API) || (SHARKSSL_ENABLE_PEM_API) || \
     (SHARKSSL_ENABLE_CSR_CREATION) || (SHARKSSL_ENABLE_CSR_SIGNING) || \
     (SHARKSSL_USE_ECC && SHARKSSL_ENABLE_ECDSA && SHARKSSL_ENABLE_ECDSA_API))

int SharkSslParseASN1_getLength(SharkSslParseASN1 *o)
{
   int len;

   if (o->len < 1)
   {
      return -1;
   }

   len = *(o->ptr);

   o->len--;
   o->ptr++;

   if (len & 0x80)
   {
      U32 spi4000initialize = 0;

      len &= 0x7F;
      
      if (len > 4)
      {
         return -1;
      }

      while ((o->len) && (len--))
      {
         spi4000initialize <<= 8;
         spi4000initialize |= *(o->ptr++);
         o->len--;
      }

      len = (int)spi4000initialize;
   }

   if (o->len < (U32)len)
   {
      return -1;
   }

   return len;
}


int SharkSslParseASN1_getSetSeq(SharkSslParseASN1 *o, U8 iotiminggetbank)
{
   if ((o->len < 1) || (*(o->ptr) != iotiminggetbank))
   {
      return -1;
   }
   o->ptr++;
   o->len--;
   return SharkSslParseASN1_getLength(o);
}


int SharkSslParseASN1_getType(SharkSslParseASN1 *o, U8 modifyauxcoreboot0)
{
   int l; 

   if ((l = SharkSslParseASN1_getSetSeq(o, modifyauxcoreboot0)) < 0)
   {
      return -1;
   }
   o->datalen = (U32)l;

   if (SHARKSSL_ASN1_INTEGER == modifyauxcoreboot0)  
   {
      if (*(o->ptr) == 0x00) 
      {
         if (o->datalen > 1)  
         {
            o->datalen--;
            o->len--;
            o->ptr++;
            #if SHARKSSL_ASN1_BER_STRICT  
            if ((*(o->ptr)) < 0x80)
            {
               return -1;  
            }
            #endif
         }
      }
      #if SHARKSSL_ASN1_BER_STRICT
      else if (*(o->ptr) >= 0x80)
      {
         return -1;  
      }
      #endif
   }

   o->dataptr = o->ptr;
   o->ptr += o->datalen;
   o->len -= o->datalen;

   if ((SHARKSSL_ASN1_OID == modifyauxcoreboot0) && (o->len) && (SHARKSSL_ASN1_NULL == *(o->ptr)))
   {
      
       o->ptr++;
       o->len--;
       if (SharkSslParseASN1_getLength(o) != 0)
       {
          return -1;
       }
   }

   return 0;
}


int SharkSslParseASN1_getContextSpecific(SharkSslParseASN1 *o, U8 *tag)
{
   int l;

   if ((o->len < 1) || (!(*(o->ptr) & SHARKSSL_ASN1_CONTEXT_SPECIFIC)))
   {
      return -1;
   }

   *tag = (*(o->ptr) & ~SHARKSSL_ASN1_CONTEXT_SPECIFIC);

   o->ptr++;
   o->len--;
   if (((l = SharkSslParseASN1_getLength(o)) < 0) || ((U32)l > o->len))
   {
      return -1;
   }
   o->datalen = (U32)l;
   o->dataptr = o->ptr;
   o->ptr += o->datalen;
   o->len -= o->datalen;

   return 0;
}




const U8 sharkssl_oid_CN[3]                      = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_ATTRTYPE, SHARKSSL_OID_JIIT_DS_ATTRTYPE_CN};
const U8 sharkssl_oid_serial[3]                  = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_ATTRTYPE, SHARKSSL_OID_JIIT_DS_ATTRTYPE_SERIAL};
const U8 sharkssl_oid_country[3]                 = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_ATTRTYPE, SHARKSSL_OID_JIIT_DS_ATTRTYPE_COUNTRY};
const U8 sharkssl_oid_locality[3]                = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_ATTRTYPE, SHARKSSL_OID_JIIT_DS_ATTRTYPE_LOCALITY};
const U8 sharkssl_oid_province[3]                = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_ATTRTYPE, SHARKSSL_OID_JIIT_DS_ATTRTYPE_PROVINCE};
const U8 sharkssl_oid_organization[3]            = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_ATTRTYPE, SHARKSSL_OID_JIIT_DS_ATTRTYPE_ORGANIZATION};
const U8 sharkssl_oid_unit[3]                    = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_ATTRTYPE, SHARKSSL_OID_JIIT_DS_ATTRTYPE_UNIT};

const U8 sharkssl_oid_emailAddress[9]            = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01};
const U8 sharkssl_oid_csr_ext_req[9]             = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E};
const U8 sharkssl_oid_signedData[9]              = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};

const U8 sharkssl_oid_ns_cert_type[9]            = {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x01};
const U8 sharkssl_oid_key_usage[3]               = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_CERTEXT, SHARKSSL_OID_JIIT_DS_CERTEXT_KEYUSAGE};
const U8 sharkssl_oid_san[3]                     = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_CERTEXT, SHARKSSL_OID_JIIT_DS_CERTEXT_SUBJALTNAMES};
const U8 sharkssl_oid_basic_constraints[3]       = {SHARKSSL_OID_JIIT_DS, SHARKSSL_OID_JIIT_DS_CERTEXT, SHARKSSL_OID_JIIT_DS_CERTEXT_BASICCONSTRAINTS};

#if SHARKSSL_ENABLE_RSA
const U8 sharkssl_oid_rsaEncryption[9]           = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
const U8 sharkssl_oid_md2withRSAEncryption[9]    = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02};
#if SHARKSSL_USE_MD5
const U8 sharkssl_oid_md5withRSAEncryption[9]    = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04};
#endif

const U8 sharkssl_oid_sha1withRSAEncryption[9]   = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05};
#if SHARKSSL_USE_SHA_256
const U8 sharkssl_oid_sha256withRSAEncryption[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
#endif
#if SHARKSSL_USE_SHA_384
const U8 sharkssl_oid_sha384withRSAEncryption[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};
#endif
#if SHARKSSL_USE_SHA_512
const U8 sharkssl_oid_sha512withRSAEncryption[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D};
#endif
#endif

#if SHARKSSL_USE_MD5
const U8 sharkssl_oid_md5[8]                     = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05};
#endif
#if SHARKSSL_USE_SHA1
const U8 sharkssl_oid_sha1[5]                    = {0x2B, 0x0E, 0x03, 0x02, 0x1A};
#endif
#if SHARKSSL_USE_SHA_256
const U8 sharkssl_oid_sha256[9]                  = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
#endif
#if SHARKSSL_USE_SHA_384
const U8 sharkssl_oid_sha384[9]                  = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
#endif
#if SHARKSSL_USE_SHA_512
const U8 sharkssl_oid_sha512[9]                  = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
#endif

#if SHARKSSL_USE_ECC


const U8 sharkssl_oid_ecPublicKey[7]             = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};

#if SHARKSSL_ECC_USE_SECP256R1

const U8 sharkssl_oid_prime256v1[8]              = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
#endif

#if SHARKSSL_ECC_USE_SECP384R1
const U8 sharkssl_oid_secp384r1[5]               = {0x2B, 0x81, 0x04, 0x00, 0x22};
#endif
#if SHARKSSL_ECC_USE_SECP521R1
const U8 sharkssl_oid_secp521r1[5]               = {0x2B, 0x81, 0x04, 0x00, 0x23};
#endif
#if SHARKSSL_ECC_USE_BRAINPOOLP256R1

const U8 sharkssl_oid_brainpoolP256r1[9]         = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
#endif
#if SHARKSSL_ECC_USE_BRAINPOOLP384R1

const U8 sharkssl_oid_brainpoolP384r1[9]         = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B};
#endif
#if SHARKSSL_ECC_USE_BRAINPOOLP512R1

const U8 sharkssl_oid_brainpoolP512r1[9]         = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D};
#endif
#endif  

#if SHARKSSL_ENABLE_ECDSA

#if SHARKSSL_USE_SHA1
const U8 sharkssl_oid_ecdsaWithSHA1[7]           = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01};
#endif
#if SHARKSSL_USE_SHA_256
const U8 sharkssl_oid_ecdsaWithSHA256[8]         = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
#endif
#if SHARKSSL_USE_SHA_384
const U8 sharkssl_oid_ecdsaWithSHA384[8]         = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
#endif
#if SHARKSSL_USE_SHA_512
const U8 sharkssl_oid_ecdsaWithSHA512[8]         = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};
#endif
#endif

#if SHARKSSL_ENABLE_ENCRYPTED_PKCS8_SUPPORT

const U8 sharkssl_oid_pkcs5PBES2[9]              = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D};
const U8 sharkssl_oid_pkcs5PBKDF2[9]             = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C}; 
#if SHARKSSL_USE_SHA_256

const U8 sharkssl_oid_HMACWithSHA256[8]          = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09};
#endif
#if (SHARKSSL_USE_AES_128 && SHARKSSL_ENABLE_AES_CBC)

const U8 sharkssl_oid_aes128cbc[9]               = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02};
#endif
#if (SHARKSSL_USE_AES_256 && SHARKSSL_ENABLE_AES_CBC)

const U8 sharkssl_oid_aes256cbc[9]               = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A};
#endif
#endif



SHARKSSL_API void SharkSslASN1Create_constructor(SharkSslASN1Create *o, U8 *buf, int lsdc2format)
{
   o->start = buf;
   o->end = o->ptr = (buf + lsdc2format);
}


SHARKSSL_API int SharkSslASN1Create_length(SharkSslASN1Create *o, int len)
{
   if (len < 0x80)
   {
      if ((o->ptr - o->start) < 1)
      {
         return -1;
      }
      *--o->ptr = (U8)len;
   }
   else if (len <= 0xFF)
   {
      if ((o->ptr - o->start) < 2)
      {
         return -1;
      }
      *--o->ptr = (U8)len;
      *--o->ptr = 0x81;
   }
   else
   {
      if (((o->ptr - o->start) < 3) || (len > 0xFFFF))
      {
         return -1;
      }

      
      *--o->ptr = (U8)len; 
      *--o->ptr = (U8)((U16)len >> 8);
      *--o->ptr = 0x82;
   }
   return 0;
}


int SharkSslASN1Create_tag(SharkSslASN1Create *o, U8 modifyauxcoreboot0)
{
   if ((o->ptr - o->start) < 1)
   {
      return -1;
   }
   *--o->ptr = modifyauxcoreboot0;
   return 0;
}



int SharkSslASN1Create_int(SharkSslASN1Create *o, const U8 *unlockrescan, int len)
{
   U8 *ref = o->ptr;
   if ((len < 0) || (len >= 0x8000) || ((o->ptr - o->start) < (len + 3)))
   {
      return -1;
   }
   if (len > 0)
   {
      o->ptr -= len;
      memmove(o->ptr, unlockrescan, len);
      
      while ((0x00 == *o->ptr) && (len > 1))
      {
         o->ptr++;
         len--;
      }
      if (*o->ptr >= 0x80)
      {
         *--o->ptr = 0x00;
      }
   }
   return
      SharkSslASN1Create_length(o, (int)(ref - o->ptr)) ||
      SharkSslASN1Create_tag(o, SHARKSSL_ASN1_INTEGER);
}

#if (SHARKSSL_ENABLE_CSR_CREATION || SHARKSSL_ENABLE_CSR_SIGNING || SHARKSSL_ENABLE_ASN1_KEY_CREATION)
int SharkSslASN1Create_oid(SharkSslASN1Create *o, const U8 *oid, int fieldvalue)
{
   return
      SharkSslASN1Create_raw(o, oid, fieldvalue) ||
      SharkSslASN1Create_length(o, fieldvalue) ||
      SharkSslASN1Create_tag(o, SHARKSSL_ASN1_OID);
} 


int SharkSslASN1Create_raw(SharkSslASN1Create *o, const void *alloccontroller, int icachealiases)
{
   if ((o->ptr - o->start) < icachealiases)
   {
      return -1;
   }
   o->ptr -= icachealiases;
   memcpy(o->ptr, alloccontroller, icachealiases);
   return 0;
}
#endif


#if (SHARKSSL_ENABLE_CSR_CREATION || SHARKSSL_ENABLE_CSR_SIGNING)
static int countusable(SharkSslASN1Create *o, const U8 *gpio1config, int len)
{
   return
      SharkSslASN1Create_raw(o, gpio1config, len) ||
      SharkSslASN1Create_length(o, len) ||
      SharkSslASN1Create_printableString(o);
}


static int supportsstage2(SharkSslASN1Create *o, const U8 *gpio1config, int len)
{
   return
      SharkSslASN1Create_raw(o, gpio1config, len) ||
      SharkSslASN1Create_length(o, len) ||
      SharkSslASN1Create_IA5String(o);
}


int SharkSslASN1Create_email(SharkSslASN1Create *o, const U8 *oid, int fieldvalue, const U8 *blockoffset, int detachdevice)
{
   U8 *ref = o->ptr;
   return 
      supportsstage2(o, blockoffset, detachdevice) ||
      SharkSslASN1Create_oid(o, oid, fieldvalue) ||
      SharkSslASN1Create_length(o, (int)(ref - o->ptr)) ||
      SharkSslASN1Create_sequence(o) ||
      SharkSslASN1Create_length(o, (int)(ref - o->ptr)) ||
      SharkSslASN1Create_set(o);
}

int SharkSslASN1Create_name(SharkSslASN1Create *o, const U8 *oid, int fieldvalue, const U8 *gpio1config, int alignresource)
{
   U8 *ref = o->ptr;
   return 
      countusable(o, gpio1config, alignresource) ||
      SharkSslASN1Create_oid(o, oid, fieldvalue) ||
      SharkSslASN1Create_length(o, (int)(ref - o->ptr)) ||
      SharkSslASN1Create_sequence(o) ||
      SharkSslASN1Create_length(o, (int)(ref - o->ptr)) ||
      SharkSslASN1Create_set(o);
}
#endif


#if (SHARKSSL_ENABLE_CSR_SIGNING)
int SharkSslASN1Create_boolean(SharkSslASN1Create *o, U8 dm9000device)
{
   if ((o->ptr - o->start) < 3)
   {
      return -1;
   }
   *--o->ptr = (dm9000device ? 0xFF : 0x00);
   return
      SharkSslASN1Create_length(o, 1) ||
      SharkSslASN1Create_tag(o, SHARKSSL_ASN1_BOOLEAN);
}
#endif
#endif


#ifndef BA_LIB
#define BA_LIB
#endif





#if SHARKSSL_USE_ECC

#endif
#include <string.h>

#define SHARKSSL_DIM_ARR(a)  (sizeof(a)/sizeof(a[0]))


#if ((SHARKSSL_BIGINT_WORDSIZE != 8) && !defined(B_BIG_ENDIAN))

void memmove_endianess(U8 *d, const U8 *s, U16 len)
{
   #ifndef B_LITTLE_ENDIAN
   static const U16 devicebluetooth = 0xFF00;

   if (0 == (*(U8*)&devicebluetooth))  
   {
   #endif
      baAssert(0 == (len & (U16)computereturn));
      len /= (SHARKSSL_BIGINT_WORDSIZE / 8);

      #if ((!defined(SHARKSSL_UNALIGNED_ACCESS)) || (!(SHARKSSL_UNALIGNED_ACCESS)))
      if (0 == ((unsigned int)(UPTR)d & computereturn)) 
      #endif
      {
         __sharkssl_packed shtype_tWord *da = (shtype_tWord*)d;

         #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
         #if ((!defined(SHARKSSL_UNALIGNED_ACCESS)) || (!(SHARKSSL_UNALIGNED_ACCESS)))
         if (0 == ((unsigned int)(UPTR)s & computereturn)) 
         #endif
         {
            while (len--)
            {
               *da++ = (shtype_tWord)blockarray(*(__sharkssl_packed shtype_tWord*)s);
               s += 4;
            }
         }
         #if ((!defined(SHARKSSL_UNALIGNED_ACCESS)) || (!(SHARKSSL_UNALIGNED_ACCESS)))
         else
         {
            while (len--)
            {
               *da++ = (shtype_tWord)((((shtype_tWord)(s[0])) << 24) +
                                            (((shtype_tWord)(s[1])) << 16) +
                                            (((shtype_tWord)(s[2])) << 8) +  s[3]);
               s += 4;
            }
         }
         #endif
         #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
         while (len--)
         {
            *da++ = (shtype_tWord)((((shtype_tWord)(s[0])) << 8) + s[1]);
            s += 2;
         }
         #endif
      }
      #if ((!defined(SHARKSSL_UNALIGNED_ACCESS)) || (!(SHARKSSL_UNALIGNED_ACCESS)))
      else  
      {
         while (len--)
         {
            #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
            U8 b[4];
            b[0] = s[0];
            b[1] = s[1];
            b[2] = s[2];
            b[3] = s[3];

            *d++ = b[3];
            *d++ = b[2];
            *d++ = b[1];
            *d++ = b[0];
            s += 4;
            #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
            U8 b[2];
            b[0] = s[0];
            b[1] = s[1];

            *d++ = b[1];
            *d++ = b[0];
            s += 2;
            #endif
         }
      }
      #endif
   #ifndef B_LITTLE_ENDIAN
   }
   else
   {
      memmove(d, s, len);
   }
   #endif
}
#endif 


#if SHARKSSL_ENABLE_RSA
int async3clksrc(const SharkSslCertKey *ck, U8 op, U8 *stackchecker)
{
   U16 p_len, e_len, icachealiases;
   #if (SHARKSSL_BIGINT_WORDSIZE > 8)
   U16 prctlreset;
   #endif
   U8 *afterhandler, *temporaryentry, *ckexp, *ckmod;
   shtype_t in, mod, exp, u;

   baAssert(ck);

   if (!(machinekexec(ck->expLen)))  
   {
      return (int)SharkSslCon_AllocationError;  
   }

   p_len = supportedvector(ck->modLen);
   e_len = mousethresh(ck->expLen);
   #if (SHARKSSL_BIGINT_WORDSIZE > 8)
   prctlreset = claimresource(e_len);
   #endif
   ckmod = ck->mod;
   ckexp = ck->exp;

   #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_SSL_SERVER_CODE || SHARKSSL_ENABLE_RSA_API || \
        (SHARKSSL_SSL_CLIENT_CODE && SHARKSSL_ENABLE_CLIENT_AUTH))
   baAssert((op == sleepstore) || (op == hsmmcplatform));
   if (op == hsmmcplatform)
   #else
   baAssert(op == hsmmcplatform);
   #endif
   {
      
      icachealiases   = p_len;
      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      icachealiases  += p_len;     
      icachealiases  += prctlreset;     
      #if (!(defined(B_BIG_ENDIAN)) || !(SHARKSSL_UNALIGNED_ACCESS))
      icachealiases  += p_len;
      #endif
      #endif
      afterhandler = (U8*)baMalloc(pcmciapdata(icachealiases));
      if (afterhandler == (void*)0)
      {
         return (int)SharkSslCon_AllocationError;
      }
      temporaryentry = (U8*)selectaudio(afterhandler);
      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      memmove_endianess(temporaryentry, stackchecker, p_len);
      onenandpartitions(&in, (p_len * 8), temporaryentry);
      temporaryentry += p_len;
      prctlreset -= e_len;
      memset(temporaryentry, 0, prctlreset);
      memcpy(temporaryentry + prctlreset, ckexp, e_len);
      e_len += prctlreset;
      memmove_endianess(temporaryentry, temporaryentry, e_len);
      ckexp = temporaryentry;
      temporaryentry += e_len;
      #if (!(defined(B_BIG_ENDIAN)) || !(SHARKSSL_UNALIGNED_ACCESS))
      memmove_endianess(temporaryentry, ckmod, p_len);
      ckmod = temporaryentry;
      temporaryentry += p_len;
      #endif
      #else
      onenandpartitions(&in, (p_len * 8), stackchecker);
      #endif
      onenandpartitions(&exp, (e_len * 8), ckexp);
      onenandpartitions(&mod, (p_len * 8), ckmod);
      onenandpartitions(&u, (p_len * 8), temporaryentry);
      chunkmutex(&in, &exp, &mod, &u, 1);
      #if (SHARKSSL_BIGINT_WORDSIZE == 8)
      if (pulsewidth(&u) < p_len)
      {
         baAssert(pulsewidth(&u) == (p_len - 1));
         *stackchecker++ = 0;
         p_len--;
      }
      #endif
      memmove_endianess(stackchecker, (U8*)consoledevice(&u), p_len);
      baFree(afterhandler);
   }

   #if (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_SSL_SERVER_CODE || SHARKSSL_ENABLE_RSA_API || \
        (SHARKSSL_SSL_CLIENT_CODE && SHARKSSL_ENABLE_CLIENT_AUTH))
   else  
   {
      
      U16 redistregion;
      shtype_t q, m1, m2, h;
      shtype_t r;

      if (coupledexynos(ck->expLen))  
      {
         return (int)SharkSslCon_AllocationError;  
      }

      ckmod += p_len;
      redistregion = p_len;
      p_len >>= 1;
      icachealiases   = redistregion;
      icachealiases  += (icachealiases * 2); 
      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      icachealiases  += redistregion;     
      icachealiases  += prctlreset;      
      #if (!(defined(B_BIG_ENDIAN)) || !(SHARKSSL_UNALIGNED_ACCESS))
      icachealiases  += p_len;
      icachealiases  += (p_len * 4);
      #endif
      #endif
      if (e_len)
      {
         icachealiases += redistregion;     
         icachealiases += 2 * redistregion;
      }
      afterhandler = (U8*)baMalloc(pcmciapdata(icachealiases));
      if (afterhandler == (void*)0)
      {
         return (int)SharkSslCon_AllocationError;
      }
      temporaryentry = (U8*)selectaudio(afterhandler);
      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      memmove_endianess(temporaryentry, stackchecker, redistregion);
      onenandpartitions(&in, redistregion * 8, temporaryentry);
      temporaryentry += redistregion;
      if (ckexp == (void*)0)
      {
         baAssert(e_len == 0);
         e_len = 0;  
      }
      else
      {
         prctlreset -= e_len;
         memset(temporaryentry, 0, prctlreset);
         memcpy(temporaryentry + prctlreset, ckexp, e_len);
         e_len += prctlreset;
         memmove_endianess(temporaryentry, temporaryentry, e_len);
         ckexp = temporaryentry;
         temporaryentry += e_len;
      }
      #if (!(defined(B_BIG_ENDIAN)) || !(SHARKSSL_UNALIGNED_ACCESS))
      memmove_endianess(temporaryentry, ckmod, (U16)(2 * redistregion + p_len));
      ckmod = temporaryentry;
      temporaryentry += 2 * redistregion + p_len;
      #endif
      #else
      onenandpartitions(&in, redistregion * 8, stackchecker);
      #endif
      onenandpartitions(&m1, redistregion * 8, temporaryentry);
      temporaryentry += redistregion;
      onenandpartitions(&m2, redistregion * 8, temporaryentry);
      temporaryentry += redistregion;
      onenandpartitions(&h,  redistregion * 8, temporaryentry);

      if (e_len)  
      {
         temporaryentry += redistregion;
         
         memmove_endianess((U8*)consoledevice(&m1), ck->mod, redistregion);
         
         sharkssl_rng(temporaryentry, redistregion);
         onenandpartitions(&r, redistregion * 8, temporaryentry);
         temporaryentry += redistregion;
         
         onenandpartitions(&exp, e_len * 8, ckexp);
         chunkmutex(&r, &exp, &m1, &m2, 1); 
         
         onenandpartitions(&u,  redistregion * 2 * 8, temporaryentry);
         hotplugpgtable(&m2, &in, &u);
         suspendfinish(&u, &m1);
         unassignedvector(&u, &in);
      }

      
      onenandpartitions(&mod, p_len * 8, &(ckmod[p_len]));     
      onenandpartitions(&exp, p_len * 8, &(ckmod[3 * p_len])); 
      chunkmutex(&in, &exp, &mod, &m2, 0); 

      
      onenandpartitions(&mod, p_len * 8, &(ckmod[0]));         
      onenandpartitions(&exp, p_len * 8, &(ckmod[2 * p_len])); 
      chunkmutex(&in, &exp, &mod, &m1, 0); 

      onenandpartitions(&u,   p_len * 8, &(ckmod[4 * p_len])); 
      onenandpartitions(&q,   p_len * 8, &(ckmod[p_len]));     

      
      keypaddevice(&m1, &m2, &mod);
      hotplugpgtable(&u, &m1, &h);
      suspendfinish(&h, &mod); 
      hotplugpgtable(&h, &q, &in);
      resolverelocs(&in, &m2);
      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      if (!e_len)
      {
         memmove_endianess(stackchecker, (U8*)consoledevice(&in), redistregion);
      }
      #endif

      if (e_len)
      {
         #if 0  
         
         onenandpartitions(&q, p_len * 8, &(ckmod[p_len])); 
         onenandpartitions(&u, p_len * 8, &(ckmod[0]));     
         hotplugpgtable(&q, &u, &m1);
         #else
         
         onenandpartitions(&m1, redistregion * 8, consoledevice(&m1));
         memmove_endianess((U8*)consoledevice(&m1), ck->mod, redistregion);
         #endif
         
         iommumapping(&r, &m1);
         
         onenandpartitions(&u,  redistregion * 2 * 8, temporaryentry);
         hotplugpgtable(&r, &in, &u);
         
         suspendfinish(&u, &m1);
         #if (SHARKSSL_BIGINT_WORDSIZE == 8)
         baAssert(pulsewidth(&u) == redistregion);
         #endif
         memmove_endianess(stackchecker, (U8*)consoledevice(&u), redistregion);
      }

      baFree(afterhandler);
   }
   #endif

   return 0;
}
#endif  


#if SHARKSSL_ENABLE_DHE_RSA
int SharkSslDHParam_DH(const SharkSslDHParam *dh, U8 op, U8 *out)
{
   shtype_t validconfig, mod, exp, res;
   U8 *afterhandler, *dhexp, *dhmod;
   #if (SHARKSSL_BIGINT_WORDSIZE > 8)
   U8 *temporaryentry;
   #endif
   U16 p_len, g_len, icachealiases;

   baAssert(dh);
   baAssert(op & (cpucfgexits | switcheractive));

   g_len = dh->gLen;
   p_len = dh->pLen;
   dhmod = dh->p;
   dhexp = dh->r;

   
   icachealiases   = p_len;  
   #if (SHARKSSL_BIGINT_WORDSIZE > 8)
   icachealiases  += p_len;
   #if (!(defined(B_BIG_ENDIAN)) || !(SHARKSSL_UNALIGNED_ACCESS))
   icachealiases  += (p_len * 2);
   #endif
   #endif
   afterhandler = (U8*)baMalloc(pcmciapdata(icachealiases));
   if (afterhandler == (void*)0)
   {
      return (int)SharkSslCon_AllocationError;
   }

   if (op & cpucfgexits)
   {
      
      baAssert(0 == (p_len & 0x3));
      if ((dhexp == (void*)0) || (sharkssl_rng(dhexp, p_len) < 0))
      {
         return (int)SharkSslCon_AllocationError;
      }
   }

   #if (SHARKSSL_BIGINT_WORDSIZE > 8)
   temporaryentry = (U8*)selectaudio(afterhandler + p_len);
   #if (!(defined(B_BIG_ENDIAN)) || !(SHARKSSL_UNALIGNED_ACCESS))
   memmove_endianess(temporaryentry, dhexp, p_len);
   dhexp = temporaryentry;
   temporaryentry += p_len;
   memmove_endianess(temporaryentry, dhmod, p_len);
   dhmod = temporaryentry;
   temporaryentry += p_len;
   #endif
   #endif

   onenandpartitions(&exp, (p_len * 8), dhexp);
   onenandpartitions(&mod, (p_len * 8), dhmod);
   #if ((SHARKSSL_BIGINT_WORDSIZE > 8) && SHARKSSL_UNALIGNED_MALLOC)
   onenandpartitions(&res, (p_len * 8), (temporaryentry - 3 * p_len));
   #else
   onenandpartitions(&res, (p_len * 8), afterhandler);
   #endif

   if (op & cpucfgexits)
   {
      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      memmove_endianess(temporaryentry, dh->g, g_len);
      onenandpartitions(&validconfig, (g_len * 8), temporaryentry);
      #else
      onenandpartitions(&validconfig, (g_len * 8), dh->g);
      #endif
      chunkmutex(&validconfig, &exp, &mod, &res, 0);
      
      memmove_endianess(out, (U8*)consoledevice(&res), p_len);
      out += p_len;  
   }

   if (op & switcheractive)
   {
      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      memmove_endianess(temporaryentry, dh->Y, p_len);
      onenandpartitions(&validconfig, (p_len * 8), temporaryentry);
      #else
      onenandpartitions(&validconfig, (p_len * 8), dh->Y);
      #endif
      chunkmutex(&validconfig, &exp, &mod, &res, 0);
      
      memmove_endianess(out, (U8*)consoledevice(&res), p_len);
   }

   baFree(afterhandler);
   return 0;
}


#if SHARKSSL_SSL_SERVER_CODE
void SharkSslDHParam_setParam(SharkSslDHParam *dh)
{
   

   static const U8 wm97xxirqen[256] =
   {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
      0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
      0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
      0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
      0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
      0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
      0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
      0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
      0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
      0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
      0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
      0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
      0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
      0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
      0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
      0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
      0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
      0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
      0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
      0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
      0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
      0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
      0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
      0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
      0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
      0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
      0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
      0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
      0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
      0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
   };

   static const U8 g[4] = {0, 0, 0, 2};

   dh->p    = (U8*)wm97xxirqen;
   dh->pLen = SHARKSSL_DIM_ARR(wm97xxirqen);

   dh->g    = (U8*)g;
   dh->gLen = SHARKSSL_DIM_ARR(g);
}
#endif  
#endif  


#if (SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA)
int SharkSslECDHParam_ECDH(const SharkSslECDHParam *configvdcdc2, U8 op, U8 *out)
{
   shtype_t secret;
   SharkSslECCurve nandflashpartition;
   SharkSslECPoint point, keypoint;
   U8 *afterhandler, *temporaryentry, *xy, *k;
   U16 x_len, x_lenr, x_lenk, icachealiases;

   baAssert(configvdcdc2);
   baAssert(op & (signalpreserve | switcheractive));

   xy = configvdcdc2->XY;
   x_len  = configvdcdc2->xLen;         
   baAssert(x_len);

   
   x_lenr = (x_len + computereturn) & ~computereturn;

   
   clearerrors(&nandflashpartition, configvdcdc2->curveType);
   if (0 == nandflashpartition.bits)  
   {
      return (int)SharkSslCon_AllocationError;
   }

   
   x_lenk = (x_len + 3) & ~0x3;
   baAssert(x_lenk >= x_lenr);

   icachealiases  = x_lenk;  
   #if (SHARKSSL_BIGINT_WORDSIZE > 8)
   icachealiases += x_lenk;  
   #endif
   icachealiases += (U16)(x_lenr * 2);  
   #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
   if (x_len != x_lenr)
   {
      icachealiases += (U16)(x_lenr * 2);  
   }
   #endif
   if (op & switcheractive)
   {
      icachealiases += (x_lenr * 2);  
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      if (x_len != x_lenr)
      {
         icachealiases += x_lenr;  
      }
      #endif
   }
   afterhandler = (U8*)baMalloc(pcmciapdata(icachealiases));
   if ((afterhandler == (void*)0) || (0 == nandflashpartition.bits))
   {
      return (int)SharkSslCon_AllocationError;
   }
   temporaryentry = (U8*)selectaudio(afterhandler);

   if (op & signalpreserve)
   {
      
      k = temporaryentry;
      sharkssl_rng(k, x_lenk);
      k[x_lenk - x_len] |= 0x01;  

      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      #if SHARKSSL_ECC_USE_SECP521R1
      
      if (x_lenr > x_len)
      {
         memset(k, 0, x_lenr - x_len);
      }
      #endif
      temporaryentry += x_lenk;
      memmove_endianess(temporaryentry, k, x_lenk);
      k = temporaryentry;
      #endif
      #if ((SHARKSSL_BIGINT_WORDSIZE < 32) && (SHARKSSL_ECC_USE_SECP521R1))
      k += (x_lenk - x_lenr);
      #endif

      
      onenandpartitions(&secret, (U16)(x_lenr * 8), k);

      
      *(consoledevice(&(secret))) &= *(consoledevice(&(nandflashpartition.prime)));
      if (timerwrite(&secret, &nandflashpartition.prime))
      {
         updatepmull(&secret, &nandflashpartition.prime);
         baAssert(!(timerwrite(&secret, &nandflashpartition.prime)));
      }

      
      if (!(op & switcheractive))
      {
         if (configvdcdc2->k == (void*)0)
         {
            baFree(afterhandler);
            return (int)SharkSslCon_AllocationError;
         }
         #if (SHARKSSL_BIGINT_WORDSIZE > 8)
         memmove_endianess(temporaryentry - x_lenk, temporaryentry, x_lenk);
         memcpy(configvdcdc2->k, temporaryentry - x_len, x_len);
         #else
         memcpy(configvdcdc2->k, k, x_len);
         #endif
      }

      temporaryentry += x_lenk;
      baAssert(pcmciaplatform(temporaryentry));
      updatefrequency(&point, x_lenr * 8, temporaryentry, temporaryentry + x_lenr);
      unregisterskciphers(&nandflashpartition, &secret, &point);
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      if (x_len != x_lenr)
      {
         temporaryentry += (U16)(x_lenr * 2);
         memmove_endianess(temporaryentry, (U8*)consoledevice(&(point.x)), x_lenr);
         temporaryentry += x_lenr;
         memmove_endianess(temporaryentry, (U8*)consoledevice(&(point.y)), x_lenr);
         memcpy(out, temporaryentry - x_len, x_len);
         out  += x_len;
         temporaryentry += x_lenr;
         memcpy(out, temporaryentry - x_len, x_len);
         out  += x_len;
         temporaryentry -= (U16)(x_lenr * 4);
      }
      else
      #endif
      {
         memmove_endianess(out, (U8*)consoledevice(&(point.x)), x_len);
         out += x_len;
         memmove_endianess(out, (U8*)consoledevice(&(point.y)), x_len);
         out += x_len;
      }
   }
   else if (op & switcheractive)
   {
      if (configvdcdc2->k == (void*)0)
      {
         return (int)SharkSslCon_AllocationError;
      }
      
      k = temporaryentry;
      if (x_lenr > x_len)
      {
         memset(k, 0, x_lenr - x_len);
         temporaryentry += (x_lenr - x_len);
      }
      memcpy(temporaryentry, configvdcdc2->k, x_len);
      temporaryentry += x_len;
      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      memmove_endianess(temporaryentry, k, x_lenr);
      k = temporaryentry;
      temporaryentry += x_lenr;
      #endif
      onenandpartitions(&secret, x_lenr * 8, k);
   }

   if (op & switcheractive)
   {
      if (xy == (void*)0)
      {
         baFree(afterhandler);
         return (int)SharkSslCon_AllocationError;
      }
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      if (x_len != x_lenr)
      {
         icachealiases = x_lenr - x_len;
         memset(temporaryentry, 0, icachealiases);
         memcpy(temporaryentry + icachealiases, xy, x_len);
         temporaryentry += x_lenr;
         memset(temporaryentry, 0, icachealiases);
         memcpy(temporaryentry + icachealiases, xy + x_len, x_len);
         temporaryentry += x_lenr;
         icachealiases = (U16)(x_lenr * 2);
         memmove_endianess(temporaryentry, temporaryentry - icachealiases, icachealiases);
      }
      else
      #endif
      {
         memmove_endianess(temporaryentry, xy, x_len * 2);
      }
      updatefrequency(&point, x_lenr * 8, temporaryentry, temporaryentry + x_lenr);
      if (initialdomain(&nandflashpartition, &point))
      {
         baFree(afterhandler);
         return (int)SharkSslCon_AllocationError;
      }
      temporaryentry += (U16)(x_lenr * 2);
      updatefrequency(&keypoint, x_lenr * 8, temporaryentry, temporaryentry + x_lenr);
      unregisterskciphers(&nandflashpartition, &secret, &keypoint);
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      if (x_len != x_lenr)
      {
         temporaryentry += (U16)(x_lenr * 2);
         memmove_endianess(temporaryentry, (U8*)consoledevice(&(keypoint.x)), x_lenr);
         memcpy(out, temporaryentry + x_lenr - x_len, x_len);
      }
      else
      #endif
      {
         memmove_endianess(out, (U8*)consoledevice(&(keypoint.x)), x_len);
      }
   }

   baFree(afterhandler);
   return 0;
}
#endif


#if SHARKSSL_ENABLE_ECDSA
int SharkSslECDSAParam_ECDSA(const SharkSslECDSAParam *audioshutdown, U8 op)
{
   shtype_t e, w, u1, u2, R, S;
   #if (!SHARKSSL_ECDSA_ONLY_VERIFY)
   shtype_t K, dA;
   #endif
   SharkSslECCurve G, T;
   SharkSslECPoint point, Qa;
   U8 *afterhandler, *temporaryentry, *r, *s, *h, *k;
   U16 k_len, k_lenr, k_lenk, h_len, icachealiases;
   int offsetarray = 1;

   baAssert(audioshutdown);
   #if SHARKSSL_ECDSA_ONLY_VERIFY
   baAssert(op == fixupdevices);
   #else
   baAssert((op == iommupdata) || (op == fixupdevices));
   #endif

   r = audioshutdown->R;
   s = audioshutdown->S;
   k = audioshutdown->key;
   h = audioshutdown->hash;
   k_len = audioshutdown->keyLen;         
   h_len = audioshutdown->hashLen;
   baAssert((k_len) && (h_len));
   baAssert(0 == (h_len & 0x3));  
   baAssert(h_len <= 64);         

   
   k_lenr = (k_len + computereturn) & ~computereturn;

   if (h_len > k_lenr)
   {
      h_len = k_lenr;
   }

   
   k_lenk = (k_len + 3) & ~0x3;

   
   clearerrors(&G, audioshutdown->curveType);
   if (0 == G.bits)  
   {
      return offsetarray;
   }

   icachealiases  = (U16)((k_lenr << 2) + (k_lenr << 1));     
   icachealiases += k_lenk;                                   
   #if (SHARKSSL_BIGINT_WORDSIZE > 32)
   icachealiases += 4;  
   #else
   baAssert(k_lenk >= k_lenr);
   #endif

   #if (SHARKSSL_BIGINT_WORDSIZE > 8)
   icachealiases += h_len;                                    
   #if (!SHARKSSL_ECDSA_ONLY_VERIFY)
   if (op & iommupdata)
   {
      icachealiases += k_lenr;                                
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      icachealiases += k_lenr;                                
      #endif
   }
   else
   #endif
   if (op & fixupdevices)
   {
      icachealiases += (U16)(k_lenr << 2);                    
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      icachealiases += (U16)(k_lenr << 2);                    
      #endif
   }
   #endif  

   afterhandler = (U8*)baMalloc(pcmciapdata(icachealiases));
   if ((afterhandler == (void*)0) || (0 == G.bits))
   {
      return (int)SharkSslCon_AllocationError;
   }
   temporaryentry = (U8*)selectaudio(afterhandler);

   onenandpartitions(&u1, (k_lenr * 2 * 8), temporaryentry);
   temporaryentry += (U16)(k_lenr << 1);
   onenandpartitions(&u2, (k_lenr * 2 * 8), temporaryentry);
   temporaryentry += (U16)(k_lenr << 1);
   updatefrequency(&point, (k_lenr * 8), temporaryentry, temporaryentry + k_lenr);
   temporaryentry += (U16)(k_lenr << 1);

   #if (SHARKSSL_BIGINT_WORDSIZE > 8)
   memmove_endianess(temporaryentry, h, h_len);
   h = temporaryentry;
   temporaryentry += h_len;
   #endif
   onenandpartitions(&e, (h_len * 8), h);

   #if (!SHARKSSL_ECDSA_ONLY_VERIFY)
   if (op & iommupdata)
   {
      U8 cnt = 0;

      _SharkSslECDSAParam_ECDSA_rng:
      sharkssl_rng(temporaryentry, k_lenk);
      temporaryentry[k_lenk - k_len] |= 0x01;  

      #if SHARKSSL_ECC_USE_SECP521R1
      
      if (k_lenk > k_len)
      {
         memset(temporaryentry, 0, k_lenk - k_len);
      }
      #endif

      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      memmove_endianess((U8*)consoledevice(&u1), temporaryentry, k_lenk);
      memcpy(temporaryentry, (U8*)consoledevice(&u1), k_lenk);
      #endif
      onenandpartitions(&K, (k_lenk * 8), temporaryentry);
      suspendfinish(&K, &G.order);
      blastscache(&K);
      baAssert(pulsewidth(&K) <= k_lenr);
      temporaryentry += k_lenk;

      if (unregisterskciphers(&G, &K, &point))
      {
         goto _SharkSslECDSAParam_ECDSA_end;
      }

      suspendfinish(&point.x, &G.order);
      if (eventtimeout(&point.x))
      {
         if (++cnt & 0x8)  
         {
            goto _SharkSslECDSAParam_ECDSA_end;
         }
         goto _SharkSslECDSAParam_ECDSA_rng;
      }

      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      if (k_len != k_lenr)
      {
         icachealiases = k_lenr - k_len;
         memset(temporaryentry, 0, icachealiases);
         memcpy(temporaryentry + icachealiases, k, k_len);
         temporaryentry += k_lenr;
         memmove_endianess(temporaryentry, temporaryentry - k_lenr, k_lenr);
      }
      else
      #endif
      {
         memmove_endianess(temporaryentry, k, k_lenr);
      }
      onenandpartitions(&dA, (k_lenr * 8), temporaryentry);
      #else  
      onenandpartitions(&dA, (k_lenr * 8), k);
      #endif
      hotplugpgtable(&dA, &point.x, &u1);
      suspendfinish(&u1, &G.order);
      setupsdhci1(&u1, &e, &G.order);
      iommumapping(&K, &G.order);
      hotplugpgtable(&K, &u1, &u2);
      suspendfinish(&u2, &G.order);
      if (eventtimeout(&u2))
      {
         if (++cnt & 0x8)  
         {
            goto _SharkSslECDSAParam_ECDSA_end;
         }
         goto _SharkSslECDSAParam_ECDSA_rng;
      }
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      if (k_len != k_lenr)
      {
         temporaryentry = (U8*)consoledevice(&(point.y));
         memmove_endianess(temporaryentry, (U8*)consoledevice(&(point.x)), k_lenr);
         memcpy(r, temporaryentry + k_lenr - k_len, k_len);
         memmove_endianess(temporaryentry, (U8*)consoledevice(&u2), k_lenr);
         memcpy(s, temporaryentry + k_lenr - k_len, k_len);
      }
      else
      #endif
      {
         memmove_endianess(r, (U8*)consoledevice(&(point.x)), k_len);
         memmove_endianess(s, (U8*)consoledevice(&u2), k_len);
      }
      offsetarray = 0;
   }

   else
   #endif
   if (op & fixupdevices)
   {
      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      if (k_len != k_lenr)
      {
         icachealiases = k_lenr - k_len;
         memset(temporaryentry, 0, icachealiases);
         memcpy(temporaryentry + icachealiases, r, k_len);
         r = temporaryentry;
         temporaryentry += k_lenr;
         memset(temporaryentry, 0, icachealiases);
         memcpy(temporaryentry + icachealiases, s, k_len);
         s = temporaryentry;
         temporaryentry += k_lenr;
      }
      #endif
      memmove_endianess(temporaryentry, r, k_lenr);
      r = temporaryentry;
      temporaryentry += k_lenr;
      memmove_endianess(temporaryentry, s, k_lenr);
      s = temporaryentry;
      temporaryentry += k_lenr;
      #endif

      onenandpartitions(&R, (k_lenr * 8), r);
      onenandpartitions(&S, (k_lenr * 8), s);
      onenandpartitions(&w, (k_lenr * 8), temporaryentry);
      temporaryentry += k_lenr;

      #if (SHARKSSL_BIGINT_WORDSIZE > 8)
      
      #if ((SHARKSSL_BIGINT_WORDSIZE > 16) && (SHARKSSL_ECC_USE_SECP521R1))
      if (k_len != k_lenr)
      {
         icachealiases = k_lenr - k_len;
         memset(temporaryentry, 0, icachealiases);
         memcpy(temporaryentry + icachealiases, k, k_len);
         temporaryentry += k_lenr;
         memset(temporaryentry, 0, icachealiases);
         memcpy(temporaryentry + icachealiases, k + k_len, k_len);
         temporaryentry += k_lenr;
         icachealiases = (U16)(k_lenr << 1);
         memmove_endianess(temporaryentry, temporaryentry - icachealiases, icachealiases);
      }
      else
      #endif
      {
         memmove_endianess(temporaryentry, k, (U16)(k_lenr << 1));
      }
      updatefrequency(&Qa, (k_lenr * 8), temporaryentry, temporaryentry + k_lenr);
      #else  
      updatefrequency(&Qa, (k_lenr * 8), k, k + k_lenr);
      #endif

      
      if ((eventtimeout(&R)) || (eventtimeout(&S)) ||
          (timerwrite(&R, &G.order) || timerwrite(&S, &G.order)))
      {
         goto _SharkSslECDSAParam_ECDSA_end;
      }

      clearerrors(&T, audioshutdown->curveType);
      if ((0 == T.bits) || (initialdomain(&T, &Qa)))
      {
         goto _SharkSslECDSAParam_ECDSA_end;
      }

      unassignedvector(&S, &w);
      iommumapping(&w, &G.order);
      hotplugpgtable(&w, &e, &u1);
      suspendfinish(&u1, &G.order);
      hotplugpgtable(&w, &R, &u2);
      suspendfinish(&u2, &G.order);
      if (directalloc(&G, &u1, &T, &u2, &point))
      {
         goto _SharkSslECDSAParam_ECDSA_end;
      }
      keypaddevice(&point.x, &R, &G.order);

      
      if (eventtimeout(&point.x))
      {
         offsetarray = 0;  
      }
   }

   _SharkSslECDSAParam_ECDSA_end:
   baFree(afterhandler);
   return offsetarray;
}
#endif  


#if (SHARKSSL_ENABLE_RSA && SHARKSSL_ENABLE_RSAKEY_CREATE)
SHARKSSL_API int SharkSslRSAKey_create(SharkSslRSAKey *mcbspplatform, U16 blake2bupdate)
{
   static const U8 patchimm64[4] = {0x00, 0x01, 0x00, 0x01};  
   
   static const shtype_tWord one = 1;
   shtype_t P, Q, N, H, G, E, DP, DQ, QP, ONE;
   U8 *afterhandler, *p;
   int i, sffsdrnandflash = 0;
   U16 writeuncached = (blake2bupdate >> 1);

   *mcbspplatform = NULL;

   
   if (blake2bupdate & ((SHARKSSL_BIGINT_WORDSIZE << 1) - 1))
   {
      return -1;
   }

   p = afterhandler = (U8*)baMalloc((sizeof(patchimm64)/sizeof(patchimm64[0])) + (blake2bupdate >> 4) + (blake2bupdate >> 2) + (blake2bupdate >> 1));
   if (afterhandler == (void*)0)
   {
      return -2;
   }

   onenandpartitions(&ONE, SHARKSSL_BIGINT_WORDSIZE, &one);
   onenandpartitions(&P, writeuncached, p);
   p += (writeuncached >> 3);
   onenandpartitions(&Q, writeuncached, p);
   p += (writeuncached >> 3);
   onenandpartitions(&DP, writeuncached * 2, p);
   p += (writeuncached >> 2);
   onenandpartitions(&DQ, writeuncached * 2, p);
   p += (writeuncached >> 2);
   onenandpartitions(&QP, writeuncached, p);
   p += (writeuncached >> 3);
   onenandpartitions(&N, writeuncached * 2, p);
   p += (writeuncached >> 2);
   onenandpartitions(&H, writeuncached * 2, p);
   p += (writeuncached >> 2);
   onenandpartitions(&E, sizeof(patchimm64)*8, p);
   memmove_endianess(p, (const U8*)&patchimm64, (sizeof(patchimm64)/sizeof(patchimm64[0])));
   p += (sizeof(patchimm64)/sizeof(patchimm64[0]));
   onenandpartitions(&G, writeuncached * 2, p);

   for (;;)
   {
      if ( !sffsdrnandflash )
      {
         sffsdrnandflash = aemifdevice(&P);
      }

      if ( !sffsdrnandflash )
      {
         sffsdrnandflash = aemifdevice(&Q);
      }

      if ( sffsdrnandflash )
      {
         break;
      }

      if (timerwrite(&P, &Q))  
      {
         if (timerwrite(&Q, &P)) 
         {
            continue;
         }
      }
      else  
      {
         shtype_tWord *mem2, *beg2;

         
         beg2 = P.beg;
         mem2 = P.mem;
         P.beg = Q.beg;
         P.mem = Q.mem;
         Q.beg = beg2;
         Q.mem = mem2;

         P.len += Q.len;
         Q.len  = P.len - Q.len;
         P.len -= Q.len;
      }

      hotplugpgtable(&P, &Q, &N);
      if (0 == (N.beg[0] & (shtype_tWord)(1 << (SHARKSSL_BIGINT_WORDSIZE - 1))))
      {
         continue;
      }

      updatepmull(&P, &ONE);
      updatepmull(&Q, &ONE);
      
      hotplugpgtable(&P, &Q, &H);

      
      sffsdrnandflash = translateaddress(&H, &E, &G);
      if (sffsdrnandflash)
      {
         break;
      }

      if (timerwrite(&G, &ONE) && timerwrite(&ONE, &G))  
      {
         break;
      }
   }

   if ( !sffsdrnandflash )
   {
      
      unassignedvector(&E, &G);
      iommumapping(&G, &H);  
      unassignedvector(&G, &DP);
      unassignedvector(&G, &DQ);
      suspendfinish(&DP, &P);
      suspendfinish(&DQ, &Q);

      resolverelocs(&P, &ONE);
      resolverelocs(&Q, &ONE);
      unassignedvector(&Q, &QP);
      iommumapping(&QP, &P);

      writeuncached >>= 2;
      i = sizeof(patchimm64)/sizeof(patchimm64[0]);
      sffsdrnandflash = 8 + i + (writeuncached >> 1) + (writeuncached) + (writeuncached << 1);
      p = (U8*)baMalloc(sffsdrnandflash);
      if (p == (void*)0)
      {
         sffsdrnandflash = -2;
      }
      else
      {
         *mcbspplatform = p;
         p[0] = 0x30;
         p[1] = 0x82;
         p[2] = 0x00;
         p[3] = 0x00;
         p[4] = 0x00;
         p[5] = (U8)i;
         p[6] = (U8)(writeuncached >> 8);
         p[7] = (U8)writeuncached;
         p += 8;
         while (i--)
         {
            *(p + i) = patchimm64[i];
         }
         p += sizeof(patchimm64)/sizeof(patchimm64[0]);
         memmove_endianess(p, (U8*)consoledevice(&N), writeuncached);
         p += writeuncached;
         writeuncached >>= 1;
         memmove_endianess(p, (U8*)consoledevice(&P), writeuncached);
         p += writeuncached;
         memmove_endianess(p, (U8*)consoledevice(&Q), writeuncached);
         p += writeuncached;
         memmove_endianess(p, (U8*)consoledevice(&DP), writeuncached);
         p += writeuncached;
         memmove_endianess(p, (U8*)consoledevice(&DQ), writeuncached);
         p += writeuncached;
         memmove_endianess(p, (U8*)consoledevice(&QP), writeuncached);
      }
   }

   baFree(afterhandler);
   return sffsdrnandflash;
}


SHARKSSL_API U8 *SharkSslRSAKey_getPublic(SharkSslRSAKey mcbspplatform)
{
   SharkSslCertKey disableclock;

   if (interrupthandler(&disableclock, (SharkSslCert)mcbspplatform))
   {
      return disableclock.mod;
   }

   return NULL;
}
#endif  

#ifndef BA_LIB
#define BA_LIB
#endif

#include "SharkSslCrypto.h"

#include <string.h>

#define SHARKSSL_DIM_ARR(a)  (sizeof(a)/sizeof(a[0]))


#if (SHARKSSL_SSL_CLIENT_CODE || SHARKSSL_SSL_SERVER_CODE || SHARKSSL_ENABLE_RSA || \
    (SHARKSSL_ENABLE_ECDSA && (!SHARKSSL_ECDSA_ONLY_VERIFY)))
#if (SHARKSSL_USE_RNG_TINYMT)

#define TINYMT32_INIT_MAT1 0xA5A6A7A8
#define TINYMT32_INIT_MAT2 0x12345678
#define TINYMT32_INIT_TMAT 0x55555555



#define branchdelay      127
#define backlightpower       1
#define contiguousreserve       10
#define aemifpdata       8
#define unmaptable      (U32)0x7FFFFFFFL
#define firstnonsched       (1.0f / 4294967296.0f)

#define kernelinstr           8
#define framecreation           8



typedef struct SharkSslRngCtx
{
    U32 status[4];
    U32 mat1;
    U32 mat2;
    U32 tmat;
    ThreadMutexBase mutex;
} SharkSslRngCtx;

static SharkSslRngCtx sharkSslRngCtx;


static void SharkSslRngCtx_next_state(void)
{
    U32 x, y;

    y = sharkSslRngCtx.status[3];
    x = (sharkSslRngCtx.status[0] & unmaptable)	^ sharkSslRngCtx.status[1]	^ sharkSslRngCtx.status[2];
    x ^= (x << backlightpower);
    y ^= (y >> backlightpower) ^ x;
    sharkSslRngCtx.status[0] = sharkSslRngCtx.status[1];
    sharkSslRngCtx.status[1] = sharkSslRngCtx.status[2];
    sharkSslRngCtx.status[2] = x ^ (y << contiguousreserve);
    sharkSslRngCtx.status[3] = y;
    sharkSslRngCtx.status[1] ^= (U32)(0L -((U32)(y & 1))) & sharkSslRngCtx.mat1;
    sharkSslRngCtx.status[2] ^= (U32)(0L -((U32)(y & 1))) & sharkSslRngCtx.mat2;
}


static U32 classdevregister(void)
{
    U32 t0, t1;

    SharkSslRngCtx_next_state();

    t0 = sharkSslRngCtx.status[3];
    t1 = sharkSslRngCtx.status[0] + (sharkSslRngCtx.status[2] >> aemifpdata);
    t0 ^= t1;
    t0 ^= (U32)(0L -((U32)(t1 & 1))) & sharkSslRngCtx.tmat;
    return t0;
}


static void SharkSslRngCtx_init2(void)
{
   U8 i;

   for (i = 1; i < kernelinstr; i++)
   {
      sharkSslRngCtx.status[i & 3] ^= i + (U32)(1812433253L) * (sharkSslRngCtx.status[(i - 1) & 3] ^ (sharkSslRngCtx.status[(i - 1) & 3] >> 30));
   }

   
   if ((sharkSslRngCtx.status[0] & unmaptable) == 0 &&
        sharkSslRngCtx.status[1] == 0 &&
        sharkSslRngCtx.status[2] == 0 &&
        sharkSslRngCtx.status[3] == 0)
   {
      sharkSslRngCtx.status[0] = '\124';
      sharkSslRngCtx.status[1] = '\111';
      sharkSslRngCtx.status[2] = '\116';
      sharkSslRngCtx.status[3] = '\131';
   }

   for (i = 0; i < framecreation; i++)
   {
	   SharkSslRngCtx_next_state();
   }
}



static void enablecounter(U32 suspendblock)
{
   sharkSslRngCtx.status[0] = suspendblock;
   sharkSslRngCtx.status[1] = sharkSslRngCtx.mat1;
   sharkSslRngCtx.status[2] = sharkSslRngCtx.mat2;
   sharkSslRngCtx.status[3] = sharkSslRngCtx.tmat;

   SharkSslRngCtx_init2();
}


static void registerclkdms(U32 suspendblock)
{
   sharkSslRngCtx.mat1 = sharkSslRngCtx.mat2;
   sharkSslRngCtx.mat2 = sharkSslRngCtx.tmat;
   sharkSslRngCtx.tmat = suspendblock;

   SharkSslRngCtx_init2();
}
#undef framecreation
#undef kernelinstr
#undef branchdelay
#undef backlightpower
#undef contiguousreserve
#undef aemifpdata
#undef unmaptable
#undef firstnonsched


SHARKSSL_API int sharkssl_entropy(U32 deviceuevent)
{
   if (0 == sharkSslRngCtx.mat1)  
   {
      U8 i;

      #if SHARKSSL_RNG_MULTITHREADED
      ThreadMutex_constructor(&(sharkSslRngCtx.mutex));
      ThreadMutex_set(&(sharkSslRngCtx.mutex));
      #endif
      sharkSslRngCtx.mat1 = TINYMT32_INIT_MAT1;
      sharkSslRngCtx.mat2 = TINYMT32_INIT_MAT2;
      sharkSslRngCtx.tmat = TINYMT32_INIT_TMAT;
      enablecounter(deviceuevent);
      for (i = (U8)(classdevregister() & 0x7F); i > 0; i--)
      {
         registerclkdms(classdevregister());
      }
   }
   else
   {
      #if SHARKSSL_RNG_MULTITHREADED
      ThreadMutex_set(&(sharkSslRngCtx.mutex));
      #endif
   }
   registerclkdms(deviceuevent);
   #if SHARKSSL_RNG_MULTITHREADED
   ThreadMutex_release(&(sharkSslRngCtx.mutex));
   #endif
   return 0;
}
#undef TINYMT32_INIT_MAT1
#undef TINYMT32_INIT_MAT2
#undef TINYMT32_INIT_TMAT

#elif (SHARKSSL_USE_RNG_FORTUNA && SHARKSSL_USE_AES_256 && SHARKSSL_USE_SHA_256)



typedef struct SharkSslRngCtx
{
    U8 key[SHARKSSL_SHA256_HASH_LEN];
    U8 ctr[16];  /* AES_256_BLOCK_LEN */
    U8 blk[16];  /* AES_256_BLOCK_LEN */
    U32 cursor;
    #if SHARKSSL_RNG_MULTITHREADED
    ThreadMutexBase mutex;
    #endif
} SharkSslRngCtx;

static SharkSslRngCtx sharkSslRngCtx;  


static void SharkSslRngCtx_inc_ctr(void)
{
   register U8 i = 0;
   while (0 == ++sharkSslRngCtx.ctr[i])
   {
      i = (i + 1) & 0xF;  
   }
}


static U32 SharkSslRngCtx_is_ctr_notzero(void)
{
   register U8 *p = &sharkSslRngCtx.ctr[0];
   register U32 i = 16;

   while (i--)
   {
      if (*p++)
      {
         return 1;
      }
   }
   return 0;
}


static void SharkSslRngCtx_generate_block(void)
{
   
   if (SharkSslRngCtx_is_ctr_notzero())
   {
      SharkSslAesCtx registermcasp;

      SharkSslAesCtx_constructor(&registermcasp, SharkSslAesCtx_Encrypt, sharkSslRngCtx.key, SHARKSSL_DIM_ARR(sharkSslRngCtx.key));
      SharkSslAesCtx_encrypt(&registermcasp, sharkSslRngCtx.ctr, sharkSslRngCtx.blk);
      SharkSslAesCtx_destructor(&registermcasp);
      sharkSslRngCtx.cursor = SHARKSSL_DIM_ARR(sharkSslRngCtx.blk);
      SharkSslRngCtx_inc_ctr();
   }
}


SHARKSSL_API int sharkssl_entropy(U32 deviceuevent)
{
   U8 suspendblock[4];
   SharkSslSha256Ctx registermcasp;

   inputlevel(deviceuevent, suspendblock, 0);
   SharkSslSha256Ctx_constructor(&registermcasp);
   #if SHARKSSL_RNG_MULTITHREADED
   if (!(SharkSslRngCtx_is_ctr_notzero()))  
   {
      ThreadMutex_constructor(&(sharkSslRngCtx.mutex));
   }
   ThreadMutex_set(&(sharkSslRngCtx.mutex));
   #endif
   SharkSslSha256Ctx_append(&registermcasp, sharkSslRngCtx.key, SHARKSSL_SHA256_HASH_LEN);
   SharkSslSha256Ctx_append(&registermcasp, suspendblock, SHARKSSL_DIM_ARR(suspendblock));
   SharkSslSha256Ctx_finish(&registermcasp, sharkSslRngCtx.key);
   SharkSslRngCtx_inc_ctr();
   #if SHARKSSL_RNG_MULTITHREADED
   ThreadMutex_release(&(sharkSslRngCtx.mutex));
   #endif
   return 0;
}


SHARKSSL_API int sharkssl_rng(U8 *ptr, U16 len)
{
   baAssert(ptr);
   baAssert((len) && (0 == (len & 0x3)));
   baAssert(len < (1 << 20));

   #if SHARKSSL_RNG_MULTITHREADED
   ThreadMutex_set(&(sharkSslRngCtx.mutex));
   #endif
   while (len >= 16)
   {
      SharkSslRngCtx_generate_block();  
      memcpy(ptr, &sharkSslRngCtx.blk[0], 16);
      sharkSslRngCtx.cursor = 0;  
      ptr += 16;
      len -= 16;
   }
   while (len)
   {
      register U32 r;
      if (0 == sharkSslRngCtx.cursor)
      {
         SharkSslRngCtx_generate_block();  
      }
      sharkSslRngCtx.cursor -= 4;
      r = (*(__sharkssl_packed U32*)&sharkSslRngCtx.blk[sharkSslRngCtx.cursor]);
      #ifndef B_LITTLE_ENDIAN
      inputlevel(r, ptr, 0);
      #else
      hsotgpdata(r, ptr, 0);
      #endif
      ptr += 4;
      len -= 4;
   }
   SharkSslRngCtx_generate_block();  
   memcpy(&sharkSslRngCtx.key[0],  &sharkSslRngCtx.blk[0], 16);
   
   SharkSslRngCtx_generate_block();
   memcpy(&sharkSslRngCtx.key[16], &sharkSslRngCtx.blk[0], 16);
   
   sharkSslRngCtx.cursor = 0;
   #if SHARKSSL_RNG_MULTITHREADED
   ThreadMutex_release(&(sharkSslRngCtx.mutex));
   #endif
   return 0;
}


#else  

typedef struct SharkSslRngCtx
{
   U32 randrsl[256];
   U32 randmem[256];
   U32 randa;
   U32 randb;
   U32 randc;
   U8  randcnt;
   U8  entropyIndex;
   #if SHARKSSL_RNG_MULTITHREADED
   ThreadMutexBase mutex;
   U8 mutexinit;
   #endif
} SharkSslRngCtx;


static SharkSslRngCtx  sharkSslRngCtx;


#define dcachedirty(mm,x) ((mm)[((x)>>2)&0xFF])
#define devicebuild(totalpages,a,b,mm,m,m2,r,x)  \
{                                     \
  x = *m;                             \
  a = ((a)^(totalpages)) + *(m2++);          \
  *(m++) = y = dcachedirty(mm,x) + (a) + (b); \
  *(r++) = b = dcachedirty(mm,(y)>>8) + (x);  \
}


static void doublefuito(void)
{
   register U32 a, b, x, y, *m, *mm, *m2, *r, *mend;

   mm = sharkSslRngCtx.randmem;
   r  = sharkSslRngCtx.randrsl;
   a  = sharkSslRngCtx.randa;
   b  = sharkSslRngCtx.randb + (++sharkSslRngCtx.randc);

   for (m = mm, mend = m2 = m + 128; m < mend; )
   {
      devicebuild( a<<13, a, b, mm, m, m2, r, x);
      devicebuild( a>>6 , a, b, mm, m, m2, r, x);
      devicebuild( a<<2 , a, b, mm, m, m2, r, x);
      devicebuild( a>>16, a, b, mm, m, m2, r, x);
   }

   for (m2 = mm; m2<mend; )
   {
      devicebuild( a<<13, a, b, mm, m, m2, r, x);
      devicebuild( a>>6 , a, b, mm, m, m2, r, x);
      devicebuild( a<<2 , a, b, mm, m, m2, r, x);
      devicebuild( a>>16, a, b, mm, m, m2, r, x);
   }

   sharkSslRngCtx.randb = b;
   sharkSslRngCtx.randa = a;
}


#define totalpages(a,b,c,d,e,f,g,h) \
{ \
   a^=b<<11; d+=a; b+=c; \
   b^=c>>2;  e+=b; c+=d; \
   c^=d<<8;  f+=c; d+=e; \
   d^=e>>16; g+=d; e+=f; \
   e^=f<<10; h+=e; f+=g; \
   f^=g>>4;  a+=f; g+=h; \
   g^=h<<8;  b+=g; h+=a; \
   h^=a>>9;  c+=h; a+=b; \
}


static void eventoverflow(void)
{
   U16 i;
   U32 a , b, c, d, e, f, g, h, *m, *r;

   sharkSslRngCtx.randa = sharkSslRngCtx.randb = sharkSslRngCtx.randc = 0;
   m = sharkSslRngCtx.randmem;
   r = sharkSslRngCtx.randrsl;
   a = b = c = d = e = f = g = h = 0x9e3779b9;

   for (i=0; i<4; ++i)          
   {
      totalpages(a,b,c,d,e,f,g,h);
   }

   
   for (i=0; i<256; i+=8)
   {
      a+=r[i  ]; b+=r[i+1]; c+=r[i+2]; d+=r[i+3];
      e+=r[i+4]; f+=r[i+5]; g+=r[i+6]; h+=r[i+7];
      totalpages(a,b,c,d,e,f,g,h);
      m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
      m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
   }

   
   for (i=0; i<256; i+=8)
   {
       a+=m[i  ]; b+=m[i+1]; c+=m[i+2]; d+=m[i+3];
       e+=m[i+4]; f+=m[i+5]; g+=m[i+6]; h+=m[i+7];
       totalpages(a,b,c,d,e,f,g,h);
       m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
       m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
   }

   doublefuito();
}


static U32 classdevregister(void)
{
   register U32 doublefcmpz;

   if ((sharkSslRngCtx.randcnt & 0xFF) == 0)
   {
      doublefuito();
   }
   doublefcmpz = sharkSslRngCtx.randrsl[(--sharkSslRngCtx.randcnt) & 0xFF];

   return doublefcmpz;
}


#undef totalpages
#undef devicebuild
#undef dcachedirty


SHARKSSL_API int sharkssl_entropy(U32 deviceuevent)
{
   #if SHARKSSL_RNG_MULTITHREADED
   if (!sharkSslRngCtx.mutexinit)
   {
      ThreadMutex_constructor(&(sharkSslRngCtx.mutex));
      ThreadMutex_set(&(sharkSslRngCtx.mutex));
      sharkSslRngCtx.mutexinit++;
   }
   else
   {
      ThreadMutex_set(&(sharkSslRngCtx.mutex));
   }
   #endif
   sharkSslRngCtx.randrsl[(sharkSslRngCtx.entropyIndex++) & 0xFF] = deviceuevent;
   eventoverflow();
   #if SHARKSSL_RNG_MULTITHREADED
   ThreadMutex_release(&(sharkSslRngCtx.mutex));
   #endif
   return 0;
}

#endif


#if (SHARKSSL_USE_RNG_TINYMT || (!SHARKSSL_USE_RNG_FORTUNA))
SHARKSSL_API int sharkssl_rng(U8 *ptr, U16 len)
{
   baAssert(ptr);
   baAssert((len) && (0 == (len & 0x3)));

   #if SHARKSSL_RNG_MULTITHREADED
   ThreadMutex_set(&(sharkSslRngCtx.mutex));
   #endif
   while (len)
   {
      register U32 r = classdevregister();
      #ifndef B_LITTLE_ENDIAN
      inputlevel(r, ptr, 0);
      #else
      hsotgpdata(r, ptr, 0);
      #endif
      ptr += 4;
      len -= 4;
   }
   #if SHARKSSL_RNG_MULTITHREADED
   ThreadMutex_release(&(sharkSslRngCtx.mutex));
   #endif
   return 0;
}
#endif
#endif  


#if (SHARKSSL_USE_MD5 || SHARKSSL_USE_SHA1 || SHARKSSL_USE_SHA_256 || SHARKSSL_USE_SHA_384 || SHARKSSL_USE_SHA_512)
#if (SHARKSSL_USE_SHA_384 || SHARKSSL_USE_SHA_512)
static const U8 prusspdata[128] =
#else
static const U8 prusspdata[64] =
#endif
{
   0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#if (SHARKSSL_USE_SHA_384 || SHARKSSL_USE_SHA_512)
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#endif
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
#endif


#if SHARKSSL_USE_MD5

#if SHARKSSL_MD5_SMALL_FOOTPRINT
static const U32 unregisterclient[64] =
{
   0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
   0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
   0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
   0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
   0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
   0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
   0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
   0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
   0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
   0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
   0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
   0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
   0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
   0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
   0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
   0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};

static const U8 keypadresources[64] =
{
   7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
   5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
   4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
   6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static const U8 writefeature[64] =
{
   0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
   1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
   5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
   0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9
};
#endif


#ifndef B_LITTLE_ENDIAN
static void kexecalloc(SharkSslMd5Ctx *registermcasp, const U8 alloccontroller[64])
#else
static void kexecalloc(SharkSslMd5Ctx *registermcasp, U32 countshift[16])
#endif
{
   U32 a, b, c, d;
   #if SHARKSSL_MD5_SMALL_FOOTPRINT
   const U32 *p;
   unsigned int i;
   #endif

   #ifndef B_LITTLE_ENDIAN
   U32 countshift[16];

   #if SHARKSSL_MD5_SMALL_FOOTPRINT
   for (i = 0; !(i & 16); i++)
   {
      cleanupcount(countshift[i], alloccontroller, (i << 2));
   }
   #else
   cleanupcount(countshift[0],  alloccontroller,  0);
   cleanupcount(countshift[1],  alloccontroller,  4);
   cleanupcount(countshift[2],  alloccontroller,  8);
   cleanupcount(countshift[3],  alloccontroller, 12);
   cleanupcount(countshift[4],  alloccontroller, 16);
   cleanupcount(countshift[5],  alloccontroller, 20);
   cleanupcount(countshift[6],  alloccontroller, 24);
   cleanupcount(countshift[7],  alloccontroller, 28);
   cleanupcount(countshift[8],  alloccontroller, 32);
   cleanupcount(countshift[9],  alloccontroller, 36);
   cleanupcount(countshift[10], alloccontroller, 40);
   cleanupcount(countshift[11], alloccontroller, 44);
   cleanupcount(countshift[12], alloccontroller, 48);
   cleanupcount(countshift[13], alloccontroller, 52);
   cleanupcount(countshift[14], alloccontroller, 56);
   cleanupcount(countshift[15], alloccontroller, 60);
   #endif
   #endif

   #define invalidcontext(x,n) ((U32)((U32)x << n) | ((U32)x >> (32 - n)))

   #define F(x,y,z) ((x & (y ^ z)) ^ z)  
   #define G(x,y,z) ((z & (x ^ y)) ^ y)  
   #define H(x,y,z) (x ^ y ^ z)
   #define I(x,y,z) (y ^ (x | ~z))

   a = registermcasp->state[0];
   b = registermcasp->state[1];
   c = registermcasp->state[2];
   d = registermcasp->state[3];

   #if SHARKSSL_MD5_SMALL_FOOTPRINT
   p = &unregisterclient[0];

   for (i = 0; (0 == (i & 0x40)); i++)
   {
      U32 e;

      a += countshift[writefeature[i]] + *p++;
      switch (i & 0x30)
      {
         case 0x00:
            a += F(b,c,d);
            break;

         case 0x10:
            a += G(b,c,d);
            break;

         case 0x20:
            a += H(b,c,d);
            break;

         default:
            a += I(b,c,d);
            break;
      }
      a = invalidcontext(a, keypadresources[i]);
      e = b;
      b += a;
      a = d;
      d = c;
      c = e;
   }

   #else  
   #define class3disable(A, B, C, D, X, S, K) { A += F(B,C,D) + X + K; A = invalidcontext(A,S) + B; }
   #define privilegefault(A, B, C, D, X, S, K) { A += G(B,C,D) + X + K; A = invalidcontext(A,S) + B; }
   #define alternativesapplied(A, B, C, D, X, S, K) { A += H(B,C,D) + X + K; A = invalidcontext(A,S) + B; }
   #define hsmmc3resource(A, B, C, D, X, S, K) { A += I(B,C,D) + X + K; A = invalidcontext(A,S) + B; }

   class3disable(a, b, c, d, countshift[0],   7, 0xD76AA478);
   class3disable(d, a, b, c, countshift[1],  12, 0xE8C7B756);
   class3disable(c, d, a, b, countshift[2],  17, 0x242070DB);
   class3disable(b, c, d, a, countshift[3],  22, 0xC1BDCEEE);
   class3disable(a, b, c, d, countshift[4],   7, 0xF57C0FAF);
   class3disable(d, a, b, c, countshift[5],  12, 0x4787C62A);
   class3disable(c, d, a, b, countshift[6],  17, 0xA8304613);
   class3disable(b, c, d, a, countshift[7],  22, 0xFD469501);
   class3disable(a, b, c, d, countshift[8],   7, 0x698098D8);
   class3disable(d, a, b, c, countshift[9],  12, 0x8B44F7AF);
   class3disable(c, d, a, b, countshift[10], 17, 0xFFFF5BB1);
   class3disable(b, c, d, a, countshift[11], 22, 0x895CD7BE);
   class3disable(a, b, c, d, countshift[12],  7, 0x6B901122);
   class3disable(d, a, b, c, countshift[13], 12, 0xFD987193);
   class3disable(c, d, a, b, countshift[14], 17, 0xA679438E);
   class3disable(b, c, d, a, countshift[15], 22, 0x49B40821);

   privilegefault(a, b, c, d, countshift[1],   5, 0xF61E2562);
   privilegefault(d, a, b, c, countshift[6],   9, 0xC040B340);
   privilegefault(c, d, a, b, countshift[11], 14, 0x265E5A51);
   privilegefault(b, c, d, a, countshift[0],  20, 0xE9B6C7AA);
   privilegefault(a, b, c, d, countshift[5],   5, 0xD62F105D);
   privilegefault(d, a, b, c, countshift[10],  9, 0x02441453);
   privilegefault(c, d, a, b, countshift[15], 14, 0xD8A1E681);
   privilegefault(b, c, d, a, countshift[4],  20, 0xE7D3FBC8);
   privilegefault(a, b, c, d, countshift[9],   5, 0x21E1CDE6);
   privilegefault(d, a, b, c, countshift[14],  9, 0xC33707D6);
   privilegefault(c, d, a, b, countshift[3],  14, 0xF4D50D87);
   privilegefault(b, c, d, a, countshift[8],  20, 0x455A14ED);
   privilegefault(a, b, c, d, countshift[13],  5, 0xA9E3E905);
   privilegefault(d, a, b, c, countshift[2],   9, 0xFCEFA3F8);
   privilegefault(c, d, a, b, countshift[7],  14, 0x676F02D9);
   privilegefault(b, c, d, a, countshift[12], 20, 0x8D2A4C8A);

   alternativesapplied(a, b, c, d, countshift[5],   4, 0xFFFA3942);
   alternativesapplied(d, a, b, c, countshift[8],  11, 0x8771F681);
   alternativesapplied(c, d, a, b, countshift[11], 16, 0x6D9D6122);
   alternativesapplied(b, c, d, a, countshift[14], 23, 0xFDE5380C);
   alternativesapplied(a, b, c, d, countshift[1],   4, 0xA4BEEA44);
   alternativesapplied(d, a, b, c, countshift[4],  11, 0x4BDECFA9);
   alternativesapplied(c, d, a, b, countshift[7],  16, 0xF6BB4B60);
   alternativesapplied(b, c, d, a, countshift[10], 23, 0xBEBFBC70);
   alternativesapplied(a, b, c, d, countshift[13],  4, 0x289B7EC6);
   alternativesapplied(d, a, b, c, countshift[0],  11, 0xEAA127FA);
   alternativesapplied(c, d, a, b, countshift[3],  16, 0xD4EF3085);
   alternativesapplied(b, c, d, a, countshift[6],  23, 0x04881D05);
   alternativesapplied(a, b, c, d, countshift[9],   4, 0xD9D4D039);
   alternativesapplied(d, a, b, c, countshift[12], 11, 0xE6DB99E5);
   alternativesapplied(c, d, a, b, countshift[15], 16, 0x1FA27CF8);
   alternativesapplied(b, c, d, a, countshift[2],  23, 0xC4AC5665);

   hsmmc3resource(a, b, c, d, countshift[0],   6, 0xF4292244);
   hsmmc3resource(d, a, b, c, countshift[7],  10, 0x432AFF97);
   hsmmc3resource(c, d, a, b, countshift[14], 15, 0xAB9423A7);
   hsmmc3resource(b, c, d, a, countshift[5],  21, 0xFC93A039);
   hsmmc3resource(a, b, c, d, countshift[12],  6, 0x655B59C3);
   hsmmc3resource(d, a, b, c, countshift[3],  10, 0x8F0CCC92);
   hsmmc3resource(c, d, a, b, countshift[10], 15, 0xFFEFF47D);
   hsmmc3resource(b, c, d, a, countshift[1],  21, 0x85845DD1);
   hsmmc3resource(a, b, c, d, countshift[8],   6, 0x6FA87E4F);
   hsmmc3resource(d, a, b, c, countshift[15], 10, 0xFE2CE6E0);
   hsmmc3resource(c, d, a, b, countshift[6],  15, 0xA3014314);
   hsmmc3resource(b, c, d, a, countshift[13], 21, 0x4E0811A1);
   hsmmc3resource(a, b, c, d, countshift[4],   6, 0xF7537E82);
   hsmmc3resource(d, a, b, c, countshift[11], 10, 0xBD3AF235);
   hsmmc3resource(c, d, a, b, countshift[2],  15, 0x2AD7D2BB);
   hsmmc3resource(b, c, d, a, countshift[9],  21, 0xEB86D391);

   #undef hsmmc3resource
   #undef alternativesapplied
   #undef privilegefault
   #undef class3disable
   #endif

   registermcasp->state[0] += a;
   registermcasp->state[1] += b;
   registermcasp->state[2] += c;
   registermcasp->state[3] += d;


   #undef I
   #undef H
   #undef G
   #undef F

   #undef invalidcontext
}


SHARKSSL_API void SharkSslMd5Ctx_constructor(SharkSslMd5Ctx *registermcasp)
{
   baAssert(((unsigned int)(UPTR)(registermcasp->buffer) & (sizeof(int)-1)) == 0);

   registermcasp->total[0] = 0;
   registermcasp->total[1] = 0;

   registermcasp->state[0] = 0x67452301;
   registermcasp->state[1] = 0xEFCDAB89;
   registermcasp->state[2] = 0x98BADCFE;
   registermcasp->state[3] = 0x10325476;
}


SHARKSSL_API void SharkSslMd5Ctx_append(SharkSslMd5Ctx *registermcasp, const U8 *in, U32 len)
{
   unsigned int dm9000platdata, pxa300evalboard;

   dm9000platdata = (unsigned int)(registermcasp->total[0]) & 0x3F;
   pxa300evalboard = 64 - dm9000platdata;

   registermcasp->total[0] += len;
   if (registermcasp->total[0] < len)
   {
      registermcasp->total[1]++;
   }

   if((dm9000platdata) && (len >= pxa300evalboard))
   {
      memcpy((registermcasp->buffer + dm9000platdata), in, pxa300evalboard);
      #ifndef B_LITTLE_ENDIAN
      kexecalloc(registermcasp, registermcasp->buffer);
      #else
      kexecalloc(registermcasp, (U32*)(registermcasp->buffer));
      #endif
      len -= pxa300evalboard;
      in  += pxa300evalboard;
      dm9000platdata = 0;
   }

   while (len >= 64)
   {
      #ifndef B_LITTLE_ENDIAN
      kexecalloc(registermcasp, in);
      #else
      memcpy(registermcasp->buffer, in, 64);
      kexecalloc(registermcasp, (U32*)(registermcasp->buffer));
      #endif
      len -= 64;
      in  += 64;
   }

   if (len)
   {
      memcpy((registermcasp->buffer + dm9000platdata), in, len);
   }
}


SHARKSSL_API void SharkSslMd5Ctx_finish(SharkSslMd5Ctx *registermcasp, U8 secondaryentry[SHARKSSL_MD5_HASH_LEN])
{
   U32 timerenable, dummywrites;
   U32 timer0start, checkcontext;
   U8  usbgadgetresource[8];

   timer0start = (registermcasp->total[0] >> 29) | (registermcasp->total[1] <<  3);
   checkcontext  = (registermcasp->total[0] <<  3);

   hsotgpdata(checkcontext,  usbgadgetresource, 0);
   hsotgpdata(timer0start, usbgadgetresource, 4);

   timerenable = registermcasp->total[0] & 0x3F;
   dummywrites = (timerenable < 56) ? (56 - timerenable) : (120 - timerenable);

   SharkSslMd5Ctx_append(registermcasp, (U8*)prusspdata, dummywrites);
   SharkSslMd5Ctx_append(registermcasp, usbgadgetresource, 8);

   hsotgpdata(registermcasp->state[0], secondaryentry,  0);
   hsotgpdata(registermcasp->state[1], secondaryentry,  4);
   hsotgpdata(registermcasp->state[2], secondaryentry,  8);
   hsotgpdata(registermcasp->state[3], secondaryentry, 12);
}


SHARKSSL_API int sharkssl_md5(const U8* alloccontroller, U16 len, U8 *secondaryentry)
{
   #if SHARKSSL_CRYPTO_USE_HEAP
   SharkSslMd5Ctx *hctx = (SharkSslMd5Ctx *)baMalloc(claimresource(sizeof(SharkSslMd5Ctx)));
   baAssert(hctx);
   if (!hctx)
   {
      return -1;
   }
   #else
   SharkSslMd5Ctx registermcasp;
   #define hctx &registermcasp
   #endif

   baAssert(alloccontroller);
   baAssert(secondaryentry);

   SharkSslMd5Ctx_constructor(hctx);
   SharkSslMd5Ctx_append(hctx, alloccontroller, len);
   SharkSslMd5Ctx_finish(hctx, secondaryentry);

   #if SHARKSSL_CRYPTO_USE_HEAP
   baFree(hctx);
   #else
   #undef hctx
   #endif
   return 0;
}
#endif


#if SHARKSSL_USE_SHA1

#ifndef B_BIG_ENDIAN
static void SharkSslSha1Ctx_process(SharkSslSha1Ctx *registermcasp, const U8 alloccontroller[64])
#else
static void SharkSslSha1Ctx_process(SharkSslSha1Ctx *registermcasp, U32 countshift[16])
#endif
{
   U32 a, b, c, d, e, brightnesslimit;
   #if SHARKSSL_SHA1_SMALL_FOOTPRINT
   unsigned int i;
   #endif
   #ifndef B_BIG_ENDIAN
   U32 countshift[16];

   #if SHARKSSL_SHA1_SMALL_FOOTPRINT
   for (i = 0; !(i & 16); i++)
   {
      read64uint32(countshift[i], alloccontroller, (i << 2));
   }
   #else
   read64uint32(countshift[0],  alloccontroller,  0);
   read64uint32(countshift[1],  alloccontroller,  4);
   read64uint32(countshift[2],  alloccontroller,  8);
   read64uint32(countshift[3],  alloccontroller, 12);
   read64uint32(countshift[4],  alloccontroller, 16);
   read64uint32(countshift[5],  alloccontroller, 20);
   read64uint32(countshift[6],  alloccontroller, 24);
   read64uint32(countshift[7],  alloccontroller, 28);
   read64uint32(countshift[8],  alloccontroller, 32);
   read64uint32(countshift[9],  alloccontroller, 36);
   read64uint32(countshift[10], alloccontroller, 40);
   read64uint32(countshift[11], alloccontroller, 44);
   read64uint32(countshift[12], alloccontroller, 48);
   read64uint32(countshift[13], alloccontroller, 52);
   read64uint32(countshift[14], alloccontroller, 56);
   read64uint32(countshift[15], alloccontroller, 60);
   #endif
   #endif

   #define invalidcontext(x,n) ((U32)((U32)x << n) | ((U32)x >> (32 - n)))

   #define pwdowninverted(x,y,z) ((x & (y ^ z)) ^ z)  
   #define configparse(x,y,z) (x ^ y ^ z)
   #define emulationhandler(x,y,z) ((x & y) | ((x | y) & z))
   #define es3plushwmod(x,y,z) (x ^ y ^ z)

   #define serial0pdata 0x5A827999
   #define registerrproc 0x6ED9EBA1
   #define powergpiod 0x8F1BBCDC
   #define allockernel 0xCA62C1D6

   a = registermcasp->state[0];
   b = registermcasp->state[1];
   c = registermcasp->state[2];
   d = registermcasp->state[3];
   e = registermcasp->state[4];

   #if SHARKSSL_SHA1_SMALL_FOOTPRINT
   for (i = 0; i < 80; i++)
   {
      if (i >= 16)
      {
         brightnesslimit = countshift[i & 0xF] ^ countshift[(i + 2) & 0xF] ^ countshift[(i + 8) & 0xF] ^ countshift[(i + 13) & 0xF];
         countshift[i & 0xF] = brightnesslimit = invalidcontext(brightnesslimit, 1);
      }
      brightnesslimit = countshift[i & 0xF];
      brightnesslimit += e + invalidcontext(a, 5);
      if (i < 20)
      {
         brightnesslimit += pwdowninverted(b,c,d) + serial0pdata;
      }
      else if (i < 40)
      {
         brightnesslimit += configparse(b,c,d) + registerrproc;
      }
      else if (i < 60)
      {
         brightnesslimit += emulationhandler(b,c,d) + powergpiod;
      }
      else
      {
         brightnesslimit += es3plushwmod(b,c,d) + allockernel;
      }
      e = d;
      d = c;
      c = invalidcontext(b, 30);
      b = a;
      a = brightnesslimit;
   }

   #else  
                                   e += (countshift[0]                ) + invalidcontext(a,5) + pwdowninverted(b,c,d) + serial0pdata; b = invalidcontext(b,30);
                                   d += (countshift[1]                ) + invalidcontext(e,5) + pwdowninverted(a,b,c) + serial0pdata; a = invalidcontext(a,30);
                                   c += (countshift[2]                ) + invalidcontext(d,5) + pwdowninverted(e,a,b) + serial0pdata; e = invalidcontext(e,30);
                                   b += (countshift[3]                ) + invalidcontext(c,5) + pwdowninverted(d,e,a) + serial0pdata; d = invalidcontext(d,30);
                                   a += (countshift[4]                ) + invalidcontext(b,5) + pwdowninverted(c,d,e) + serial0pdata; c = invalidcontext(c,30);

                                   e += (countshift[5]                ) + invalidcontext(a,5) + pwdowninverted(b,c,d) + serial0pdata; b = invalidcontext(b,30);
                                   d += (countshift[6]                ) + invalidcontext(e,5) + pwdowninverted(a,b,c) + serial0pdata; a = invalidcontext(a,30);
                                   c += (countshift[7]                ) + invalidcontext(d,5) + pwdowninverted(e,a,b) + serial0pdata; e = invalidcontext(e,30);
                                   b += (countshift[8]                ) + invalidcontext(c,5) + pwdowninverted(d,e,a) + serial0pdata; d = invalidcontext(d,30);
                                   a += (countshift[9]                ) + invalidcontext(b,5) + pwdowninverted(c,d,e) + serial0pdata; c = invalidcontext(c,30);

                                   e += (countshift[10]               ) + invalidcontext(a,5) + pwdowninverted(b,c,d) + serial0pdata; b = invalidcontext(b,30);
                                   d += (countshift[11]               ) + invalidcontext(e,5) + pwdowninverted(a,b,c) + serial0pdata; a = invalidcontext(a,30);
                                   c += (countshift[12]               ) + invalidcontext(d,5) + pwdowninverted(e,a,b) + serial0pdata; e = invalidcontext(e,30);
                                   b += (countshift[13]               ) + invalidcontext(c,5) + pwdowninverted(d,e,a) + serial0pdata; d = invalidcontext(d,30);
                                   a += (countshift[14]               ) + invalidcontext(b,5) + pwdowninverted(c,d,e) + serial0pdata; c = invalidcontext(c,30);

                                   e += (countshift[15]               ) + invalidcontext(a,5) + pwdowninverted(b,c,d) + serial0pdata; b = invalidcontext(b,30);
   brightnesslimit = countshift[13]^countshift[8] ^countshift[2] ^countshift[0];  d += (countshift[0]  = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + pwdowninverted(a,b,c) + serial0pdata; a = invalidcontext(a,30);
   brightnesslimit = countshift[14]^countshift[9] ^countshift[3] ^countshift[1];  c += (countshift[1]  = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + pwdowninverted(e,a,b) + serial0pdata; e = invalidcontext(e,30);
   brightnesslimit = countshift[15]^countshift[10]^countshift[4] ^countshift[2];  b += (countshift[2]  = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + pwdowninverted(d,e,a) + serial0pdata; d = invalidcontext(d,30);
   brightnesslimit = countshift[0] ^countshift[11]^countshift[5] ^countshift[3];  a += (countshift[3]  = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + pwdowninverted(c,d,e) + serial0pdata; c = invalidcontext(c,30);

   brightnesslimit = countshift[1] ^countshift[12]^countshift[6] ^countshift[4];  e += (countshift[4]  = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + configparse(b,c,d) + registerrproc; b = invalidcontext(b,30);
   brightnesslimit = countshift[2] ^countshift[13]^countshift[7] ^countshift[5];  d += (countshift[5]  = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + configparse(a,b,c) + registerrproc; a = invalidcontext(a,30);
   brightnesslimit = countshift[3] ^countshift[14]^countshift[8] ^countshift[6];  c += (countshift[6]  = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + configparse(e,a,b) + registerrproc; e = invalidcontext(e,30);
   brightnesslimit = countshift[4] ^countshift[15]^countshift[9] ^countshift[7];  b += (countshift[7]  = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + configparse(d,e,a) + registerrproc; d = invalidcontext(d,30);
   brightnesslimit = countshift[5] ^countshift[0] ^countshift[10]^countshift[8];  a += (countshift[8]  = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + configparse(c,d,e) + registerrproc; c = invalidcontext(c,30);

   brightnesslimit = countshift[6] ^countshift[1] ^countshift[11]^countshift[9];  e += (countshift[9]  = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + configparse(b,c,d) + registerrproc; b = invalidcontext(b,30);
   brightnesslimit = countshift[7] ^countshift[2] ^countshift[12]^countshift[10]; d += (countshift[10] = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + configparse(a,b,c) + registerrproc; a = invalidcontext(a,30);
   brightnesslimit = countshift[8] ^countshift[3] ^countshift[13]^countshift[11]; c += (countshift[11] = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + configparse(e,a,b) + registerrproc; e = invalidcontext(e,30);
   brightnesslimit = countshift[9] ^countshift[4] ^countshift[14]^countshift[12]; b += (countshift[12] = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + configparse(d,e,a) + registerrproc; d = invalidcontext(d,30);
   brightnesslimit = countshift[10]^countshift[5] ^countshift[15]^countshift[13]; a += (countshift[13] = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + configparse(c,d,e) + registerrproc; c = invalidcontext(c,30);

   brightnesslimit = countshift[11]^countshift[6] ^countshift[0] ^countshift[14]; e += (countshift[14] = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + configparse(b,c,d) + registerrproc; b = invalidcontext(b,30);
   brightnesslimit = countshift[12]^countshift[7] ^countshift[1] ^countshift[15]; d += (countshift[15] = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + configparse(a,b,c) + registerrproc; a = invalidcontext(a,30);
   brightnesslimit = countshift[13]^countshift[8] ^countshift[2] ^countshift[0];  c += (countshift[0]  = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + configparse(e,a,b) + registerrproc; e = invalidcontext(e,30);
   brightnesslimit = countshift[14]^countshift[9] ^countshift[3] ^countshift[1];  b += (countshift[1]  = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + configparse(d,e,a) + registerrproc; d = invalidcontext(d,30);
   brightnesslimit = countshift[15]^countshift[10]^countshift[4] ^countshift[2];  a += (countshift[2]  = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + configparse(c,d,e) + registerrproc; c = invalidcontext(c,30);

   brightnesslimit = countshift[0] ^countshift[11]^countshift[5] ^countshift[3];  e += (countshift[3]  = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + configparse(b,c,d) + registerrproc; b = invalidcontext(b,30);
   brightnesslimit = countshift[1] ^countshift[12]^countshift[6] ^countshift[4];  d += (countshift[4]  = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + configparse(a,b,c) + registerrproc; a = invalidcontext(a,30);
   brightnesslimit = countshift[2] ^countshift[13]^countshift[7] ^countshift[5];  c += (countshift[5]  = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + configparse(e,a,b) + registerrproc; e = invalidcontext(e,30);
   brightnesslimit = countshift[3] ^countshift[14]^countshift[8] ^countshift[6];  b += (countshift[6]  = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + configparse(d,e,a) + registerrproc; d = invalidcontext(d,30);
   brightnesslimit = countshift[4] ^countshift[15]^countshift[9] ^countshift[7];  a += (countshift[7]  = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + configparse(c,d,e) + registerrproc; c = invalidcontext(c,30);

   brightnesslimit = countshift[5] ^countshift[0] ^countshift[10]^countshift[8];  e += (countshift[8]  = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + emulationhandler(b,c,d) + powergpiod; b = invalidcontext(b,30);
   brightnesslimit = countshift[6] ^countshift[1] ^countshift[11]^countshift[9];  d += (countshift[9]  = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + emulationhandler(a,b,c) + powergpiod; a = invalidcontext(a,30);
   brightnesslimit = countshift[7] ^countshift[2] ^countshift[12]^countshift[10]; c += (countshift[10] = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + emulationhandler(e,a,b) + powergpiod; e = invalidcontext(e,30);
   brightnesslimit = countshift[8] ^countshift[3] ^countshift[13]^countshift[11]; b += (countshift[11] = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + emulationhandler(d,e,a) + powergpiod; d = invalidcontext(d,30);
   brightnesslimit = countshift[9] ^countshift[4] ^countshift[14]^countshift[12]; a += (countshift[12] = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + emulationhandler(c,d,e) + powergpiod; c = invalidcontext(c,30);

   brightnesslimit = countshift[10]^countshift[5] ^countshift[15]^countshift[13]; e += (countshift[13] = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + emulationhandler(b,c,d) + powergpiod; b = invalidcontext(b,30);
   brightnesslimit = countshift[11]^countshift[6] ^countshift[0] ^countshift[14]; d += (countshift[14] = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + emulationhandler(a,b,c) + powergpiod; a = invalidcontext(a,30);
   brightnesslimit = countshift[12]^countshift[7] ^countshift[1] ^countshift[15]; c += (countshift[15] = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + emulationhandler(e,a,b) + powergpiod; e = invalidcontext(e,30);
   brightnesslimit = countshift[13]^countshift[8] ^countshift[2] ^countshift[0];  b += (countshift[0]  = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + emulationhandler(d,e,a) + powergpiod; d = invalidcontext(d,30);
   brightnesslimit = countshift[14]^countshift[9] ^countshift[3] ^countshift[1];  a += (countshift[1]  = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + emulationhandler(c,d,e) + powergpiod; c = invalidcontext(c,30);

   brightnesslimit = countshift[15]^countshift[10]^countshift[4] ^countshift[2];  e += (countshift[2]  = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + emulationhandler(b,c,d) + powergpiod; b = invalidcontext(b,30);
   brightnesslimit = countshift[0] ^countshift[11]^countshift[5] ^countshift[3];  d += (countshift[3]  = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + emulationhandler(a,b,c) + powergpiod; a = invalidcontext(a,30);
   brightnesslimit = countshift[1] ^countshift[12]^countshift[6] ^countshift[4];  c += (countshift[4]  = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + emulationhandler(e,a,b) + powergpiod; e = invalidcontext(e,30);
   brightnesslimit = countshift[2] ^countshift[13]^countshift[7] ^countshift[5];  b += (countshift[5]  = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + emulationhandler(d,e,a) + powergpiod; d = invalidcontext(d,30);
   brightnesslimit = countshift[3] ^countshift[14]^countshift[8] ^countshift[6];  a += (countshift[6]  = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + emulationhandler(c,d,e) + powergpiod; c = invalidcontext(c,30);

   brightnesslimit = countshift[4] ^countshift[15]^countshift[9] ^countshift[7];  e += (countshift[7]  = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + emulationhandler(b,c,d) + powergpiod; b = invalidcontext(b,30);
   brightnesslimit = countshift[5] ^countshift[0] ^countshift[10]^countshift[8];  d += (countshift[8]  = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + emulationhandler(a,b,c) + powergpiod; a = invalidcontext(a,30);
   brightnesslimit = countshift[6] ^countshift[1] ^countshift[11]^countshift[9];  c += (countshift[9]  = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + emulationhandler(e,a,b) + powergpiod; e = invalidcontext(e,30);
   brightnesslimit = countshift[7] ^countshift[2] ^countshift[12]^countshift[10]; b += (countshift[10] = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + emulationhandler(d,e,a) + powergpiod; d = invalidcontext(d,30);
   brightnesslimit = countshift[8] ^countshift[3] ^countshift[13]^countshift[11]; a += (countshift[11] = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + emulationhandler(c,d,e) + powergpiod; c = invalidcontext(c,30);

   brightnesslimit = countshift[9] ^countshift[4] ^countshift[14]^countshift[12]; e += (countshift[12] = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + es3plushwmod(b,c,d) + allockernel; b = invalidcontext(b,30);
   brightnesslimit = countshift[10]^countshift[5] ^countshift[15]^countshift[13]; d += (countshift[13] = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + es3plushwmod(a,b,c) + allockernel; a = invalidcontext(a,30);
   brightnesslimit = countshift[11]^countshift[6] ^countshift[0] ^countshift[14]; c += (countshift[14] = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + es3plushwmod(e,a,b) + allockernel; e = invalidcontext(e,30);
   brightnesslimit = countshift[12]^countshift[7] ^countshift[1] ^countshift[15]; b += (countshift[15] = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + es3plushwmod(d,e,a) + allockernel; d = invalidcontext(d,30);
   brightnesslimit = countshift[13]^countshift[8] ^countshift[2] ^countshift[0];  a += (countshift[0]  = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + es3plushwmod(c,d,e) + allockernel; c = invalidcontext(c,30);

   brightnesslimit = countshift[14]^countshift[9] ^countshift[3] ^countshift[1];  e += (countshift[1]  = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + es3plushwmod(b,c,d) + allockernel; b = invalidcontext(b,30);
   brightnesslimit = countshift[15]^countshift[10]^countshift[4] ^countshift[2];  d += (countshift[2]  = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + es3plushwmod(a,b,c) + allockernel; a = invalidcontext(a,30);
   brightnesslimit = countshift[0] ^countshift[11]^countshift[5] ^countshift[3];  c += (countshift[3]  = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + es3plushwmod(e,a,b) + allockernel; e = invalidcontext(e,30);
   brightnesslimit = countshift[1] ^countshift[12]^countshift[6] ^countshift[4];  b += (countshift[4]  = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + es3plushwmod(d,e,a) + allockernel; d = invalidcontext(d,30);
   brightnesslimit = countshift[2] ^countshift[13]^countshift[7] ^countshift[5];  a += (countshift[5]  = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + es3plushwmod(c,d,e) + allockernel; c = invalidcontext(c,30);

   brightnesslimit = countshift[3] ^countshift[14]^countshift[8] ^countshift[6];  e += (countshift[6]  = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + es3plushwmod(b,c,d) + allockernel; b = invalidcontext(b,30);
   brightnesslimit = countshift[4] ^countshift[15]^countshift[9] ^countshift[7];  d += (countshift[7]  = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + es3plushwmod(a,b,c) + allockernel; a = invalidcontext(a,30);
   brightnesslimit = countshift[5] ^countshift[0] ^countshift[10]^countshift[8];  c += (countshift[8]  = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + es3plushwmod(e,a,b) + allockernel; e = invalidcontext(e,30);
   brightnesslimit = countshift[6] ^countshift[1] ^countshift[11]^countshift[9];  b += (countshift[9]  = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + es3plushwmod(d,e,a) + allockernel; d = invalidcontext(d,30);
   brightnesslimit = countshift[7] ^countshift[2] ^countshift[12]^countshift[10]; a += (countshift[10] = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + es3plushwmod(c,d,e) + allockernel; c = invalidcontext(c,30);

   brightnesslimit = countshift[8] ^countshift[3] ^countshift[13]^countshift[11]; e += (countshift[11] = invalidcontext(brightnesslimit,1)) + invalidcontext(a,5) + es3plushwmod(b,c,d) + allockernel; b = invalidcontext(b,30);
   brightnesslimit = countshift[9] ^countshift[4] ^countshift[14]^countshift[12]; d += (countshift[12] = invalidcontext(brightnesslimit,1)) + invalidcontext(e,5) + es3plushwmod(a,b,c) + allockernel; a = invalidcontext(a,30);
   brightnesslimit = countshift[10]^countshift[5] ^countshift[15]^countshift[13]; c += (countshift[13] = invalidcontext(brightnesslimit,1)) + invalidcontext(d,5) + es3plushwmod(e,a,b) + allockernel; e = invalidcontext(e,30);
   brightnesslimit = countshift[11]^countshift[6] ^countshift[0] ^countshift[14]; b += (countshift[14] = invalidcontext(brightnesslimit,1)) + invalidcontext(c,5) + es3plushwmod(d,e,a) + allockernel; d = invalidcontext(d,30);
   brightnesslimit = countshift[12]^countshift[7] ^countshift[1] ^countshift[15]; a += (countshift[15] = invalidcontext(brightnesslimit,1)) + invalidcontext(b,5) + es3plushwmod(c,d,e) + allockernel; c = invalidcontext(c,30);
   #endif

   registermcasp->state[0] += a;
   registermcasp->state[1] += b;
   registermcasp->state[2] += c;
   registermcasp->state[3] += d;
   registermcasp->state[4] += e;

   #undef allockernel
   #undef powergpiod
   #undef registerrproc
   #undef serial0pdata

   #undef es3plushwmod
   #undef emulationhandler
   #undef configparse
   #undef pwdowninverted

   #undef invalidcontext
}


SHARKSSL_API void SharkSslSha1Ctx_constructor(SharkSslSha1Ctx *registermcasp)
{
   baAssert(((unsigned int)(UPTR)(registermcasp->buffer) & (sizeof(int)-1)) == 0);

   registermcasp->total[0] = 0;
   registermcasp->total[1] = 0;

   registermcasp->state[0] = 0x67452301;
   registermcasp->state[1] = 0xEFCDAB89;
   registermcasp->state[2] = 0x98BADCFE;
   registermcasp->state[3] = 0x10325476;
   registermcasp->state[4] = 0xC3D2E1F0;
}


SHARKSSL_API void SharkSslSha1Ctx_append(SharkSslSha1Ctx *registermcasp, const U8 *in, U32 len)
{
   unsigned int dm9000platdata, pxa300evalboard;

   dm9000platdata = (unsigned int)(registermcasp->total[0]) & 0x3F;
   pxa300evalboard = 64 - dm9000platdata;

   registermcasp->total[0] += len;
   if (registermcasp->total[0] < len)
   {
      registermcasp->total[1]++;
   }

   if((dm9000platdata) && (len >= pxa300evalboard))
   {
      memcpy((registermcasp->buffer + dm9000platdata), in, pxa300evalboard);
      #ifndef B_BIG_ENDIAN
      SharkSslSha1Ctx_process(registermcasp, registermcasp->buffer);
      #else
      SharkSslSha1Ctx_process(registermcasp, (U32*)(registermcasp->buffer));
      #endif
      len -= pxa300evalboard;
      in  += pxa300evalboard;
      dm9000platdata = 0;
   }

   while (len >= 64)
   {
      #ifndef B_BIG_ENDIAN
      SharkSslSha1Ctx_process(registermcasp, in);
      #else
      memcpy(registermcasp->buffer, in, 64);
      SharkSslSha1Ctx_process(registermcasp, (U32*)(registermcasp->buffer));
      #endif
      len -= 64;
      in  += 64;
   }

   if (len)
   {
      memcpy((registermcasp->buffer + dm9000platdata), in, len);
   }
}


SHARKSSL_API void SharkSslSha1Ctx_finish(SharkSslSha1Ctx *registermcasp, U8 secondaryentry[SHARKSSL_SHA1_HASH_LEN])
{
   U32 timerenable, dummywrites;
   U32 timer0start, checkcontext;
   U8  usbgadgetresource[8];

   timer0start = (registermcasp->total[0] >> 29) | (registermcasp->total[1] <<  3);
   checkcontext  = (registermcasp->total[0] <<  3);

   inputlevel(timer0start, usbgadgetresource, 0);
   inputlevel(checkcontext,  usbgadgetresource, 4);

   timerenable = registermcasp->total[0] & 0x3F;
   dummywrites = (timerenable < 56) ? (56 - timerenable) : (120 - timerenable);

   SharkSslSha1Ctx_append(registermcasp, (U8*)prusspdata, dummywrites);
   SharkSslSha1Ctx_append(registermcasp, usbgadgetresource, 8);

   inputlevel(registermcasp->state[0], secondaryentry,  0);
   inputlevel(registermcasp->state[1], secondaryentry,  4);
   inputlevel(registermcasp->state[2], secondaryentry,  8);
   inputlevel(registermcasp->state[3], secondaryentry, 12);
   inputlevel(registermcasp->state[4], secondaryentry, 16);
}


SHARKSSL_API int sharkssl_sha1(const U8 *alloccontroller, U16 len, U8 *secondaryentry)
{
   #if SHARKSSL_CRYPTO_USE_HEAP
   SharkSslSha1Ctx *hctx = (SharkSslSha1Ctx *)baMalloc(claimresource(sizeof(SharkSslSha1Ctx)));
   baAssert(hctx);
   if (!hctx)
   {
      return -1;
   }

   #else
   SharkSslSha1Ctx registermcasp;
   #define hctx &registermcasp
   #endif

   baAssert(alloccontroller);
   baAssert(secondaryentry);

   SharkSslSha1Ctx_constructor(hctx);
   SharkSslSha1Ctx_append(hctx, alloccontroller, len);
   SharkSslSha1Ctx_finish(hctx, secondaryentry);

   #if SHARKSSL_CRYPTO_USE_HEAP
   baFree(hctx);
   #else
   #undef hctx
   #endif
   return 0;
}
#endif


#if SHARKSSL_USE_SHA_256

static const U32 callchainentry[64] =
{
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
   0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
   0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
   0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


#ifndef B_BIG_ENDIAN
static void SharkSslSha256Ctx_process(SharkSslSha256Ctx *registermcasp, const U8 alloccontroller[64])
#else
static void SharkSslSha256Ctx_process(SharkSslSha256Ctx *registermcasp, U32 countshift[16])
#endif
{
   U32 a, b, c, d, e, f, g, h, T1, T2;
   #if SHARKSSL_SHA256_SMALL_FOOTPRINT
   unsigned int i;
   #else
   const U32 *p;
   #endif
   #ifndef B_BIG_ENDIAN
   U32 countshift[16];

   #if SHARKSSL_SHA256_SMALL_FOOTPRINT
   for (i = 0; !(i & 16); i++)
   {
      read64uint32(countshift[i], alloccontroller, (i << 2));
   }
   #else
   read64uint32(countshift[0],  alloccontroller,  0);
   read64uint32(countshift[1],  alloccontroller,  4);
   read64uint32(countshift[2],  alloccontroller,  8);
   read64uint32(countshift[3],  alloccontroller, 12);
   read64uint32(countshift[4],  alloccontroller, 16);
   read64uint32(countshift[5],  alloccontroller, 20);
   read64uint32(countshift[6],  alloccontroller, 24);
   read64uint32(countshift[7],  alloccontroller, 28);
   read64uint32(countshift[8],  alloccontroller, 32);
   read64uint32(countshift[9],  alloccontroller, 36);
   read64uint32(countshift[10], alloccontroller, 40);
   read64uint32(countshift[11], alloccontroller, 44);
   read64uint32(countshift[12], alloccontroller, 48);
   read64uint32(countshift[13], alloccontroller, 52);
   read64uint32(countshift[14], alloccontroller, 56);
   read64uint32(countshift[15], alloccontroller, 60);
   #endif
   #endif

   #define invalidcontext(x,n)  ((U32)((U32)x << n) | ((U32)x >> (32 - n)))
   #define SHR(x,n)   ((U32)((U32)x >> n))
   #define CH(x,y,z)  ((x & (y ^ z)) ^ z)
   #define MAJ(x,y,z) ((x & y) | ((x | y) & z))
   #define injectundefined(x)  (invalidcontext(x, 30) ^ invalidcontext(x, 19) ^ invalidcontext(x, 10))
   #define clearhighpage(x)  (invalidcontext(x, 26) ^ invalidcontext(x, 21) ^ invalidcontext(x, 7))
   #define joystickdisable(x)  (invalidcontext(x, 25) ^ invalidcontext(x, 14) ^ SHR(x, 3))
   #define sm501resources(x)  (invalidcontext(x, 15) ^ invalidcontext(x, 13) ^ SHR(x, 10))

   a = registermcasp->state[0];
   b = registermcasp->state[1];
   c = registermcasp->state[2];
   d = registermcasp->state[3];
   e = registermcasp->state[4];
   f = registermcasp->state[5];
   g = registermcasp->state[6];
   h = registermcasp->state[7];

   #if SHARKSSL_SHA256_SMALL_FOOTPRINT
   for (i = 0; (0 == (i & 0x40)); i++)
   {
      if (i >= 16)
      {
         T1 = countshift[(i + 1) & 0xF];
         T1 = joystickdisable(T1);
         T2 = countshift[(i + 14) & 0xF];
         T2 = sm501resources(T2);
         countshift[i & 0xF] += (countshift[(i + 9) & 0xF] + T1 + T2);
      }
      T1 = countshift[i & 0xF];
      T1 += callchainentry[i] + h + CH(e,f,g) + clearhighpage(e);
      T2 = MAJ(a,b,c) + injectundefined(a);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
   }

   #else  
   #define mismatchedcache(i,a,b,c,d,e,f,g,h) do {  \
      T1 = clearhighpage(e);  \
      T2 = CH(e,f,g);  \
      h += countshift[(i) & 0xF] + T1 + T2 + (*p++); \
      d += h;  \
      T1 = injectundefined(a);  \
      T2 = MAJ(a,b,c);  \
      h += T1 + T2;  \
   } while (0)

   #define machinetable(i,a,b,c,d,e,f,g,h) do {  \
      T1 = countshift[((i) + 1) & 0xF];  \
      T1 = joystickdisable(T1);  \
      T2 = countshift[((i) + 14) & 0xF];  \
      T2 = sm501resources(T2);  \
      countshift[(i) & 0xF] += (countshift[((i) + 9) & 0xF] + T1 + T2);  \
      mismatchedcache(i,a,b,c,d,e,f,g,h);  \
   } while (0)

   p = &callchainentry[0];

   mismatchedcache( 0,a,b,c,d,e,f,g,h);
   mismatchedcache( 1,h,a,b,c,d,e,f,g);
   mismatchedcache( 2,g,h,a,b,c,d,e,f);
   mismatchedcache( 3,f,g,h,a,b,c,d,e);
   mismatchedcache( 4,e,f,g,h,a,b,c,d);
   mismatchedcache( 5,d,e,f,g,h,a,b,c);
   mismatchedcache( 6,c,d,e,f,g,h,a,b);
   mismatchedcache( 7,b,c,d,e,f,g,h,a);
   mismatchedcache( 8,a,b,c,d,e,f,g,h);
   mismatchedcache( 9,h,a,b,c,d,e,f,g);
   mismatchedcache(10,g,h,a,b,c,d,e,f);
   mismatchedcache(11,f,g,h,a,b,c,d,e);
   mismatchedcache(12,e,f,g,h,a,b,c,d);
   mismatchedcache(13,d,e,f,g,h,a,b,c);
   mismatchedcache(14,c,d,e,f,g,h,a,b);
   mismatchedcache(15,b,c,d,e,f,g,h,a);

   while (p < &callchainentry[63])  
   {
      machinetable( 0,a,b,c,d,e,f,g,h);
      machinetable( 1,h,a,b,c,d,e,f,g);
      machinetable( 2,g,h,a,b,c,d,e,f);
      machinetable( 3,f,g,h,a,b,c,d,e);
      machinetable( 4,e,f,g,h,a,b,c,d);
      machinetable( 5,d,e,f,g,h,a,b,c);
      machinetable( 6,c,d,e,f,g,h,a,b);
      machinetable( 7,b,c,d,e,f,g,h,a);
      machinetable( 8,a,b,c,d,e,f,g,h);
      machinetable( 9,h,a,b,c,d,e,f,g);
      machinetable(10,g,h,a,b,c,d,e,f);
      machinetable(11,f,g,h,a,b,c,d,e);
      machinetable(12,e,f,g,h,a,b,c,d);
      machinetable(13,d,e,f,g,h,a,b,c);
      machinetable(14,c,d,e,f,g,h,a,b);
      machinetable(15,b,c,d,e,f,g,h,a);
   }

   #undef mismatchedcache
   #undef machinetable
   #endif

   registermcasp->state[0] += a;
   registermcasp->state[1] += b;
   registermcasp->state[2] += c;
   registermcasp->state[3] += d;
   registermcasp->state[4] += e;
   registermcasp->state[5] += f;
   registermcasp->state[6] += g;
   registermcasp->state[7] += h;

   #undef sm501resources
   #undef joystickdisable
   #undef injectundefined
   #undef clearhighpage
   #undef MAJ
   #undef CH
   #undef SHR
   #undef invalidcontext
}


SHARKSSL_API void SharkSslSha256Ctx_constructor(SharkSslSha256Ctx *registermcasp)
{
   baAssert(((unsigned int)(UPTR)(registermcasp->buffer) & (sizeof(int)-1)) == 0);

   registermcasp->total[0] = 0;
   registermcasp->total[1] = 0;

   registermcasp->state[0] = 0x6A09E667;
   registermcasp->state[1] = 0xBB67AE85;
   registermcasp->state[2] = 0x3C6EF372;
   registermcasp->state[3] = 0xA54FF53A;
   registermcasp->state[4] = 0x510E527F;
   registermcasp->state[5] = 0x9B05688C;
   registermcasp->state[6] = 0x1F83D9AB;
   registermcasp->state[7] = 0x5BE0CD19;
}


SHARKSSL_API void SharkSslSha256Ctx_append(SharkSslSha256Ctx *registermcasp, const U8 *in, U32 len)
{
   unsigned int dm9000platdata, pxa300evalboard;

   dm9000platdata = (unsigned int)(registermcasp->total[0]) & 0x3F;
   pxa300evalboard = 64 - dm9000platdata;

   registermcasp->total[0] += len;
   if (registermcasp->total[0] < len)
   {
      registermcasp->total[1]++;
   }

   if((dm9000platdata) && (len >= pxa300evalboard))
   {
      memcpy((registermcasp->buffer + dm9000platdata), in, pxa300evalboard);
      #ifndef B_BIG_ENDIAN
      SharkSslSha256Ctx_process(registermcasp, registermcasp->buffer);
      #else
      SharkSslSha256Ctx_process(registermcasp, (U32*)(registermcasp->buffer));
      #endif
      len -= pxa300evalboard;
      in  += pxa300evalboard;
      dm9000platdata = 0;
   }

   while (len >= 64)
   {
      #ifndef B_BIG_ENDIAN
      SharkSslSha256Ctx_process(registermcasp, in);
      #else
      memcpy(registermcasp->buffer, in, 64);
      SharkSslSha256Ctx_process(registermcasp, (U32*)(registermcasp->buffer));
      #endif
      len -= 64;
      in  += 64;
   }

   if (len)
   {
      memcpy((registermcasp->buffer + dm9000platdata), in, len);
   }
}


SHARKSSL_API void SharkSslSha256Ctx_finish(SharkSslSha256Ctx *registermcasp, U8 secondaryentry[SHARKSSL_SHA256_HASH_LEN])
{
   U32 timerenable, dummywrites;
   U32 timer0start, checkcontext;
   U8  usbgadgetresource[8];

   timer0start = (registermcasp->total[0] >> 29) | (registermcasp->total[1] <<  3);
   checkcontext  = (registermcasp->total[0] <<  3);

   inputlevel(timer0start, usbgadgetresource, 0);
   inputlevel(checkcontext,  usbgadgetresource, 4);

   timerenable = registermcasp->total[0] & 0x3F;
   dummywrites = (timerenable < 56) ? (56 - timerenable) : (120 - timerenable);

   SharkSslSha256Ctx_append(registermcasp, (U8*)prusspdata, dummywrites);
   SharkSslSha256Ctx_append(registermcasp, usbgadgetresource, 8);

   inputlevel(registermcasp->state[0], secondaryentry,  0);
   inputlevel(registermcasp->state[1], secondaryentry,  4);
   inputlevel(registermcasp->state[2], secondaryentry,  8);
   inputlevel(registermcasp->state[3], secondaryentry, 12);
   inputlevel(registermcasp->state[4], secondaryentry, 16);
   inputlevel(registermcasp->state[5], secondaryentry, 20);
   inputlevel(registermcasp->state[6], secondaryentry, 24);
   inputlevel(registermcasp->state[7], secondaryentry, 28);
}


SHARKSSL_API int sharkssl_sha256(const U8 *alloccontroller, U16 len, U8 *secondaryentry)
{
   #if SHARKSSL_CRYPTO_USE_HEAP
   SharkSslSha256Ctx *hctx = (SharkSslSha256Ctx *)baMalloc(claimresource(sizeof(SharkSslSha256Ctx)));
   baAssert(hctx);
   if (!hctx)
   {
      return -1;
   }
   #else
   SharkSslSha256Ctx registermcasp;
   #define hctx &registermcasp
   #endif

   baAssert(alloccontroller);
   baAssert(secondaryentry);

   SharkSslSha256Ctx_constructor(hctx);
   SharkSslSha256Ctx_append(hctx, alloccontroller, len);
   SharkSslSha256Ctx_finish(hctx, secondaryentry);

   #if SHARKSSL_CRYPTO_USE_HEAP
   baFree(hctx);
   #else
   #undef hctx
   #endif
   return 0;
}
#endif


#if (SHARKSSL_USE_SHA_384 || SHARKSSL_USE_SHA_512)

static const U64 pxa270income[80] =
{
   0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
   0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
   0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
   0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
   0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
   0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
   0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
   0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
   0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
   0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
   0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
   0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
   0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
   0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
   0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
   0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
   0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
   0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
   0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
   0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};


static U64 injectundefined(U64 *x)
{
   U32 x1, x2, r1, r2;

   x1 = (U32)(*x >> 32);
   x2 = (U32)*x;
   r1 = (x1 >> 28) ^ (x1 << 30) ^ (x1 << 25) ^ (x2 << 4) ^ (x2 >> 2) ^ (x2 >> 7);
   r2 = (x2 >> 28) ^ (x2 << 30) ^ (x2 << 25) ^ (x1 << 4) ^ (x1 >> 2) ^ (x1 >> 7);

   return ((U64)r1 << 32) | r2;
}


static U64 clearhighpage(U64 *x)
{
   U32 x1, x2, r1, r2;

   x1 = (U32)(*x >> 32);
   x2 = (U32)*x;
   r1 = (x1 >> 14) ^ (x1 >> 18) ^ (x1 << 23) ^ (x2 << 18) ^ (x2 << 14) ^ (x2 >> 9);
   r2 = (x2 >> 14) ^ (x2 >> 18) ^ (x2 << 23) ^ (x1 << 18) ^ (x1 << 14) ^ (x1 >> 9);

   return ((U64)r1 << 32) | r2;
}


static U64 joystickdisable(U64 *x)
{
   U32 x1, x2, r1, r2;

   x1 = (U32)(*x >> 32);
   x2 = (U32)*x;
   r1 = (x1 >> 1) ^ (x1 >> 8) ^ (x1 >> 7) ^ (x2 << 31) ^ (x2 << 24);
   r2 = (x2 >> 1) ^ (x2 >> 8) ^ (x2 >> 7) ^ (x1 << 31) ^ (x1 << 24) ^ (x1 << 25);

   return ((U64)r1 << 32) | r2;
}


static U64 sm501resources(U64 *x)
{
   U32 x1, x2, r1, r2;

   x1 = (U32)(*x >> 32);
   x2 = (U32)*x;
   r1 = (x1 >> 19) ^ (x1 << 3) ^ (x1 >> 6) ^ (x2 << 13) ^ (x2 >> 29);
   r2 = (x2 >> 19) ^ (x2 << 3) ^ (x2 >> 6) ^ (x1 << 13) ^ (x1 >> 29) ^ (x1 << 26);

   return ((U64)r1 << 32) | r2;
}


#ifndef B_BIG_ENDIAN
static void pcimtresource(SharkSslSha384Ctx *registermcasp, const U8 alloccontroller[128])
#else
static void pcimtresource(SharkSslSha384Ctx *registermcasp, U64 countshift[16])
#endif
{
   U64 a, b, c, d, e, f, g, h, T1, T2;
   unsigned int i;
   #ifndef B_BIG_ENDIAN
   U64 countshift[16];

   detectboard(countshift[0],  alloccontroller,   0);
   detectboard(countshift[1],  alloccontroller,   8);
   detectboard(countshift[2],  alloccontroller,  16);
   detectboard(countshift[3],  alloccontroller,  24);
   detectboard(countshift[4],  alloccontroller,  32);
   detectboard(countshift[5],  alloccontroller,  40);
   detectboard(countshift[6],  alloccontroller,  48);
   detectboard(countshift[7],  alloccontroller,  56);
   detectboard(countshift[8],  alloccontroller,  64);
   detectboard(countshift[9],  alloccontroller,  72);
   detectboard(countshift[10], alloccontroller,  80);
   detectboard(countshift[11], alloccontroller,  88);
   detectboard(countshift[12], alloccontroller,  96);
   detectboard(countshift[13], alloccontroller, 104);
   detectboard(countshift[14], alloccontroller, 112);
   detectboard(countshift[15], alloccontroller, 120);
   #endif

   #define CH(x,y,z)  ((x & (y ^ z)) ^ z)
   #define MAJ(x,y,z) ((x & y) | ((x | y) & z))

   a = registermcasp->state[0];
   b = registermcasp->state[1];
   c = registermcasp->state[2];
   d = registermcasp->state[3];
   e = registermcasp->state[4];
   f = registermcasp->state[5];
   g = registermcasp->state[6];
   h = registermcasp->state[7];

   for (i = 0; i < 80; i++)
   {
      if (i >= 16)
      {
         countshift[i & 0xF] += countshift[(i + 9) & 0xF] + joystickdisable(&countshift[(i + 1) & 0xF]) + sm501resources(&countshift[(i + 14) & 0xF]);
      }
      T1 = countshift[i & 0xF] + pxa270income[i] + h + CH(e,f,g) + clearhighpage(&e);
      T2 = MAJ(a,b,c) + injectundefined(&a);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
   }

   registermcasp->state[0] += a;
   registermcasp->state[1] += b;
   registermcasp->state[2] += c;
   registermcasp->state[3] += d;
   registermcasp->state[4] += e;
   registermcasp->state[5] += f;
   registermcasp->state[6] += g;
   registermcasp->state[7] += h;

   #undef MAJ
   #undef CH
}
#endif  


#if SHARKSSL_USE_SHA_384
SHARKSSL_API void SharkSslSha384Ctx_constructor(SharkSslSha384Ctx *registermcasp)
{
   baAssert(((unsigned int)(UPTR)(registermcasp->buffer) & (sizeof(int)-1)) == 0);

   registermcasp->total[0] = 0;
   registermcasp->total[1] = 0;
   registermcasp->total[2] = 0;
   registermcasp->total[3] = 0;

   registermcasp->state[0] = 0xCBBB9D5DC1059ED8ULL;
   registermcasp->state[1] = 0x629A292A367CD507ULL;
   registermcasp->state[2] = 0x9159015A3070DD17ULL;
   registermcasp->state[3] = 0x152FECD8F70E5939ULL;
   registermcasp->state[4] = 0x67332667FFC00B31ULL;
   registermcasp->state[5] = 0x8EB44A8768581511ULL;
   registermcasp->state[6] = 0xDB0C2E0D64F98FA7ULL;
   registermcasp->state[7] = 0x47B5481DBEFA4FA4ULL;
}
#endif


#if SHARKSSL_USE_SHA_512
SHARKSSL_API void SharkSslSha512Ctx_constructor(SharkSslSha512Ctx *registermcasp)
{
   baAssert(((unsigned int)(UPTR)(registermcasp->buffer) & (sizeof(int)-1)) == 0);

   registermcasp->total[0] = 0;
   registermcasp->total[1] = 0;
   registermcasp->total[2] = 0;
   registermcasp->total[3] = 0;

   registermcasp->state[0] = 0x6A09E667F3BCC908ULL;
   registermcasp->state[1] = 0xBB67AE8584CAA73BULL;
   registermcasp->state[2] = 0x3C6EF372FE94F82BULL;
   registermcasp->state[3] = 0xA54FF53A5F1D36F1ULL;
   registermcasp->state[4] = 0x510E527FADE682D1ULL;
   registermcasp->state[5] = 0x9B05688C2B3E6C1FULL;
   registermcasp->state[6] = 0x1F83D9ABFB41BD6BULL;
   registermcasp->state[7] = 0x5BE0CD19137E2179ULL;
}
#endif


#if (SHARKSSL_USE_SHA_384 || SHARKSSL_USE_SHA_512)
SHARKSSL_API void SharkSslSha384Ctx_append(SharkSslSha384Ctx *registermcasp, const U8 *in, U32 len)
{
   unsigned int dm9000platdata, pxa300evalboard;

   dm9000platdata = (unsigned int)(registermcasp->total[0]) & 0x7F;
   pxa300evalboard = 128 - dm9000platdata;

   registermcasp->total[0] += len;
   if (registermcasp->total[0] < len)
   {
      if (0 == ++registermcasp->total[1])
      {
         if (0 == ++registermcasp->total[2])
         {
            ++registermcasp->total[3];
         }
      }
   }

   if((dm9000platdata) && (len >= pxa300evalboard))
   {
      memcpy((registermcasp->buffer + dm9000platdata), in, pxa300evalboard);
      #ifndef B_BIG_ENDIAN
      pcimtresource(registermcasp, registermcasp->buffer);
      #else
      pcimtresource(registermcasp, (U64*)(registermcasp->buffer));
      #endif
      len -= pxa300evalboard;
      in  += pxa300evalboard;
      dm9000platdata = 0;
   }

   while (len >= 128)
   {
      #ifndef B_BIG_ENDIAN
      pcimtresource(registermcasp, in);
      #else
      memcpy(registermcasp->buffer, in, 128);
      pcimtresource(registermcasp, (U64*)(registermcasp->buffer));
      #endif
      len -= 128;
      in  += 128;
   }

   if (len)
   {
      memcpy((registermcasp->buffer + dm9000platdata), in, len);
   }
}


SHARKSSL_API void SharkSslSha384Ctx_finish(SharkSslSha384Ctx *registermcasp, U8 secondaryentry[SHARKSSL_SHA384_HASH_LEN])
{
   U32 timerenable, dummywrites;
   U32 enablekernel[4];
   U8  usbgadgetresource[16];

   enablekernel[3] = (registermcasp->total[0] << 3);
   enablekernel[2] = (registermcasp->total[1] << 3) | (registermcasp->total[0] >> 29);
   enablekernel[1] = (registermcasp->total[2] << 3) | (registermcasp->total[1] >> 29);
   enablekernel[0] = (registermcasp->total[3] << 3) | (registermcasp->total[2] >> 29);

   inputlevel(enablekernel[0], usbgadgetresource, 0);
   inputlevel(enablekernel[1], usbgadgetresource, 4);
   inputlevel(enablekernel[2], usbgadgetresource, 8);
   inputlevel(enablekernel[3], usbgadgetresource, 12);

   timerenable = registermcasp->total[0] & 0x7F;
   dummywrites = (timerenable < 112) ? (112 - timerenable) : (240 - timerenable);

   SharkSslSha384Ctx_append(registermcasp, (U8*)prusspdata, dummywrites);
   SharkSslSha384Ctx_append(registermcasp, usbgadgetresource, 16);

   hwmoddisable(registermcasp->state[0], secondaryentry,  0);
   hwmoddisable(registermcasp->state[1], secondaryentry,  8);
   hwmoddisable(registermcasp->state[2], secondaryentry, 16);
   hwmoddisable(registermcasp->state[3], secondaryentry, 24);
   hwmoddisable(registermcasp->state[4], secondaryentry, 32);
   hwmoddisable(registermcasp->state[5], secondaryentry, 40);
}
#endif


#if SHARKSSL_USE_SHA_384
SHARKSSL_API int sharkssl_sha384(const U8 *alloccontroller, U16 len, U8 *secondaryentry)
{
   #if SHARKSSL_CRYPTO_USE_HEAP
   SharkSslSha384Ctx *hctx = (SharkSslSha384Ctx *)baMalloc(claimresource(sizeof(SharkSslSha384Ctx)));
   baAssert(hctx);
   if (!hctx)
   {
      return -1;
   }
   #else
   SharkSslSha384Ctx registermcasp;
   #define hctx &registermcasp
   #endif

   baAssert(alloccontroller);
   baAssert(secondaryentry);

   SharkSslSha384Ctx_constructor(hctx);
   SharkSslSha384Ctx_append(hctx, alloccontroller, len);
   SharkSslSha384Ctx_finish(hctx, secondaryentry);

   #if SHARKSSL_CRYPTO_USE_HEAP
   baFree(hctx);
   #else
   #undef hctx
   #endif
   return 0;
}
#endif


#if SHARKSSL_USE_SHA_512
SHARKSSL_API void SharkSslSha512Ctx_finish(SharkSslSha512Ctx *registermcasp, U8 secondaryentry[SHARKSSL_SHA512_HASH_LEN])
{
   baAssert(sizeof(SharkSslSha512Ctx) == sizeof(SharkSslSha384Ctx));
   SharkSslSha384Ctx_finish((SharkSslSha384Ctx*)registermcasp, secondaryentry);
   hwmoddisable(registermcasp->state[6], secondaryentry, 48);
   hwmoddisable(registermcasp->state[7], secondaryentry, 56);
}


SHARKSSL_API int sharkssl_sha512(const U8 *alloccontroller, U16 len, U8 *secondaryentry)
{
   #if SHARKSSL_CRYPTO_USE_HEAP
   SharkSslSha512Ctx *hctx = (SharkSslSha512Ctx *)baMalloc(claimresource(sizeof(SharkSslSha512Ctx)));
   baAssert(hctx);
   if (!hctx)
   {
      return -1;
   }
   #else
   SharkSslSha512Ctx registermcasp;
   #define hctx &registermcasp
   #endif

   baAssert(alloccontroller);
   baAssert(secondaryentry);

   SharkSslSha512Ctx_constructor(hctx);
   SharkSslSha512Ctx_append(hctx, alloccontroller, len);
   SharkSslSha512Ctx_finish(hctx, secondaryentry);

   #if SHARKSSL_CRYPTO_USE_HEAP
   baFree(hctx);
   #else
   #undef hctx
   #endif
   return 0;
}
#endif


static U16 prminstglobal(U8 configwrite)
{
   baAssert(SHARKSSL_SHA512_BLOCK_LEN == SHARKSSL_SHA384_BLOCK_LEN);
   baAssert(SHARKSSL_SHA256_BLOCK_LEN == SHARKSSL_MD5_BLOCK_LEN);
   baAssert(SHARKSSL_SHA1_BLOCK_LEN == SHARKSSL_MD5_BLOCK_LEN);

   switch (configwrite)
   {
      #if (SHARKSSL_USE_SHA_512 || SHARKSSL_USE_SHA_384)
      #if SHARKSSL_USE_SHA_512
      case SHARKSSL_HASHID_SHA512:
      #endif
      #if SHARKSSL_USE_SHA_384
      case SHARKSSL_HASHID_SHA384:
      #endif
         return SHARKSSL_SHA384_BLOCK_LEN;
      #endif

      #if (SHARKSSL_USE_SHA_256 || SHARKSSL_USE_SHA1 || SHARKSSL_USE_MD5)
      #if SHARKSSL_USE_SHA_256
      case SHARKSSL_HASHID_SHA256:
      #endif
      #if SHARKSSL_USE_SHA1
      case SHARKSSL_HASHID_SHA1:
      #endif
      #if SHARKSSL_USE_MD5
      case SHARKSSL_HASHID_MD5:
      #endif
         return SHARKSSL_MD5_BLOCK_LEN;
      #endif

      default:
         break;
   }

   return 0;
}


U16 sharkssl_getHashLen(U8 configwrite)
{
   switch (configwrite)
   {
      #if SHARKSSL_USE_SHA_512
      case SHARKSSL_HASHID_SHA512:
         return SHARKSSL_SHA512_HASH_LEN;
      #endif

      #if SHARKSSL_USE_SHA_384
      case SHARKSSL_HASHID_SHA384:
         return SHARKSSL_SHA384_HASH_LEN;
      #endif

      #if SHARKSSL_USE_SHA_256
      case SHARKSSL_HASHID_SHA256:
         return SHARKSSL_SHA256_HASH_LEN;
      #endif

      #if SHARKSSL_USE_SHA1
      case SHARKSSL_HASHID_SHA1:
         return SHARKSSL_SHA1_HASH_LEN;
      #endif

      #if SHARKSSL_USE_MD5
      case SHARKSSL_HASHID_MD5:
         return SHARKSSL_MD5_HASH_LEN;
      #endif

      default:
         break;
   }

   return 0;
}


int sharkssl_hash(U8 *secondaryentry, U8 *alloccontroller, U16 len, U8 configwrite)
{
   if (alloccontroller && secondaryentry)
   {
      switch (configwrite)
      {
         #if SHARKSSL_USE_SHA_512
         case SHARKSSL_HASHID_SHA512:
            return sharkssl_sha512(alloccontroller, len, secondaryentry);
         #endif

         #if SHARKSSL_USE_SHA_384
         case SHARKSSL_HASHID_SHA384:
            return sharkssl_sha384(alloccontroller, len, secondaryentry);
         #endif

         #if SHARKSSL_USE_SHA_256
         case SHARKSSL_HASHID_SHA256:
            return sharkssl_sha256(alloccontroller, len, secondaryentry);
         #endif

         #if SHARKSSL_USE_SHA1
         case SHARKSSL_HASHID_SHA1:
            return sharkssl_sha1(alloccontroller, len, secondaryentry);
         #endif

         #if SHARKSSL_USE_MD5
         case SHARKSSL_HASHID_MD5:
            return sharkssl_md5(alloccontroller, len, secondaryentry);
         #endif

         default:
            break;
      }
   }

   return -1;
}


#if (SHARKSSL_USE_SHA_512 || SHARKSSL_USE_SHA_384 || SHARKSSL_USE_SHA_256 || SHARKSSL_USE_SHA1 || SHARKSSL_USE_MD5)
SHARKSSL_API void  SharkSslHMACCtx_constructor(SharkSslHMACCtx *registermcasp, U8 configwrite, const U8 *sourcerouting, U16 creategroup)
{
   U16 usb11device = prminstglobal(configwrite);
   baAssert(0 == (usb11device & 0x03));

   registermcasp->hashID = 0;  
   if (usb11device)
   {
      U8 *k;
      U16 l4 = (usb11device >> 2);

      memset(registermcasp->key, 0, usb11device);
      if (creategroup <= usb11device)
      {
         memcpy(registermcasp->key, sourcerouting, creategroup);
      }
      else
      {
         
         sharkssl_hash((U8*)&(registermcasp->key), (U8*)sourcerouting, creategroup, configwrite);
         creategroup = sharkssl_getHashLen(configwrite);
         baAssert(creategroup);
      }

      k = registermcasp->key;
      while (l4--)
      {
         *(k++) ^= 0x36;
         *(k++) ^= 0x36;
         *(k++) ^= 0x36;
         *(k++) ^= 0x36;
      }

      registermcasp->hashID = configwrite;
      switch (configwrite)
      {
         #if SHARKSSL_USE_SHA_512
         case SHARKSSL_HASHID_SHA512:
            SharkSslSha512Ctx_constructor(&(registermcasp->hashCtx.sha512Ctx));
            SharkSslSha512Ctx_append(&(registermcasp->hashCtx.sha512Ctx), (U8*)&(registermcasp->key), usb11device);
            break;
         #endif

         #if SHARKSSL_USE_SHA_384
         case SHARKSSL_HASHID_SHA384:
            SharkSslSha384Ctx_constructor(&(registermcasp->hashCtx.sha384Ctx));
            SharkSslSha384Ctx_append(&(registermcasp->hashCtx.sha384Ctx), (U8*)&(registermcasp->key), usb11device);
            break;
         #endif

         #if SHARKSSL_USE_SHA_256
         case SHARKSSL_HASHID_SHA256:
            SharkSslSha256Ctx_constructor(&(registermcasp->hashCtx.sha256Ctx));
            SharkSslSha256Ctx_append(&(registermcasp->hashCtx.sha256Ctx), (U8*)&(registermcasp->key), usb11device);
            break;
         #endif

         #if SHARKSSL_USE_SHA1
         case SHARKSSL_HASHID_SHA1:
            SharkSslSha1Ctx_constructor(&(registermcasp->hashCtx.sha1Ctx));
            SharkSslSha1Ctx_append(&(registermcasp->hashCtx.sha1Ctx), (U8*)&(registermcasp->key), usb11device);
            break;
         #endif

         #if SHARKSSL_USE_MD5
         case SHARKSSL_HASHID_MD5:
            SharkSslMd5Ctx_constructor(&(registermcasp->hashCtx.md5Ctx));
            SharkSslMd5Ctx_append(&(registermcasp->hashCtx.md5Ctx), (U8*)&(registermcasp->key), usb11device);
            break;
         #endif

         default:
            break;
      }
   }
}


SHARKSSL_API void  SharkSslHMACCtx_append(SharkSslHMACCtx *registermcasp, const U8 *alloccontroller, U32 len)
{
   switch (registermcasp->hashID)
   {
      #if SHARKSSL_USE_SHA_512
      case SHARKSSL_HASHID_SHA512:
         SharkSslSha512Ctx_append(&(registermcasp->hashCtx.sha512Ctx), alloccontroller, len);
         break;
      #endif

      #if SHARKSSL_USE_SHA_384
      case SHARKSSL_HASHID_SHA384:
         SharkSslSha384Ctx_append(&(registermcasp->hashCtx.sha384Ctx), alloccontroller, len);
         break;
      #endif

      #if SHARKSSL_USE_SHA_256
      case SHARKSSL_HASHID_SHA256:
         SharkSslSha256Ctx_append(&(registermcasp->hashCtx.sha256Ctx), alloccontroller, len);
         break;
      #endif

      #if SHARKSSL_USE_SHA1
      case SHARKSSL_HASHID_SHA1:
         SharkSslSha1Ctx_append(&(registermcasp->hashCtx.sha1Ctx), alloccontroller, len);
         break;
      #endif

      #if SHARKSSL_USE_MD5
      case SHARKSSL_HASHID_MD5:
         SharkSslMd5Ctx_append(&(registermcasp->hashCtx.md5Ctx), alloccontroller, len);
         break;
      #endif

      default:
         break;
   }
}


SHARKSSL_API void  SharkSslHMACCtx_finish(SharkSslHMACCtx *registermcasp, U8 *cfconresource)
{
   U16 usb11device = prminstglobal(registermcasp->hashID);

   if (usb11device)
   {
      U8 *k;
      U16 l4, ftraceupdate;

      k = registermcasp->key;
      l4 = (usb11device >> 2);
      while (l4--)
      {
         *(k++) ^= (0x36 ^ 0x5C);  
         *(k++) ^= (0x36 ^ 0x5C);
         *(k++) ^= (0x36 ^ 0x5C);
         *(k++) ^= (0x36 ^ 0x5C);
      }

      ftraceupdate = sharkssl_getHashLen(registermcasp->hashID);
      switch (registermcasp->hashID)  
      {
         #if SHARKSSL_USE_SHA_512
         case SHARKSSL_HASHID_SHA512:
            SharkSslSha512Ctx_finish(&(registermcasp->hashCtx.sha512Ctx), cfconresource);
            SharkSslSha512Ctx_constructor(&(registermcasp->hashCtx.sha512Ctx));
            SharkSslSha512Ctx_append(&(registermcasp->hashCtx.sha512Ctx), (U8*)&(registermcasp->key), usb11device);
            SharkSslSha512Ctx_append(&(registermcasp->hashCtx.sha512Ctx), cfconresource, ftraceupdate);
            SharkSslSha512Ctx_finish(&(registermcasp->hashCtx.sha512Ctx), cfconresource);
            break;
         #endif

         #if SHARKSSL_USE_SHA_384
         case SHARKSSL_HASHID_SHA384:
            SharkSslSha384Ctx_finish(&(registermcasp->hashCtx.sha384Ctx), cfconresource);
            SharkSslSha384Ctx_constructor(&(registermcasp->hashCtx.sha384Ctx));
            SharkSslSha384Ctx_append(&(registermcasp->hashCtx.sha384Ctx), (U8*)&(registermcasp->key), usb11device);
            SharkSslSha384Ctx_append(&(registermcasp->hashCtx.sha384Ctx), cfconresource, ftraceupdate);
            SharkSslSha384Ctx_finish(&(registermcasp->hashCtx.sha384Ctx), cfconresource);
            break;
         #endif

         #if SHARKSSL_USE_SHA_256
         case SHARKSSL_HASHID_SHA256:
            SharkSslSha256Ctx_finish(&(registermcasp->hashCtx.sha256Ctx), cfconresource);
            SharkSslSha256Ctx_constructor(&(registermcasp->hashCtx.sha256Ctx));
            SharkSslSha256Ctx_append(&(registermcasp->hashCtx.sha256Ctx), (U8*)&(registermcasp->key), usb11device);
            SharkSslSha256Ctx_append(&(registermcasp->hashCtx.sha256Ctx), cfconresource, ftraceupdate);
            SharkSslSha256Ctx_finish(&(registermcasp->hashCtx.sha256Ctx), cfconresource);
            break;
         #endif

         #if SHARKSSL_USE_SHA1
         case SHARKSSL_HASHID_SHA1:
            SharkSslSha1Ctx_finish(&(registermcasp->hashCtx.sha1Ctx), cfconresource);
            SharkSslSha1Ctx_constructor(&(registermcasp->hashCtx.sha1Ctx));
            SharkSslSha1Ctx_append(&(registermcasp->hashCtx.sha1Ctx), (U8*)&(registermcasp->key), usb11device);
            SharkSslSha1Ctx_append(&(registermcasp->hashCtx.sha1Ctx), cfconresource, ftraceupdate);
            SharkSslSha1Ctx_finish(&(registermcasp->hashCtx.sha1Ctx), cfconresource);
            break;
         #endif

         #if SHARKSSL_USE_MD5
         case SHARKSSL_HASHID_MD5:
            SharkSslMd5Ctx_finish(&(registermcasp->hashCtx.md5Ctx), cfconresource);
            SharkSslMd5Ctx_constructor(&(registermcasp->hashCtx.md5Ctx));
            SharkSslMd5Ctx_append(&(registermcasp->hashCtx.md5Ctx), (U8*)&(registermcasp->key), usb11device);
            SharkSslMd5Ctx_append(&(registermcasp->hashCtx.md5Ctx), cfconresource, ftraceupdate);
            SharkSslMd5Ctx_finish(&(registermcasp->hashCtx.md5Ctx), cfconresource);
            break;
         #endif

         default:
            break;
      }
   }
}


SHARKSSL_API int sharkssl_HMAC(const U8 configwrite, const U8 *alloccontroller, U16 len, const U8 *sourcerouting, U16 creategroup, U8 *secondaryentry)
{
   #if SHARKSSL_CRYPTO_USE_HEAP
   SharkSslHMACCtx *hctx = (SharkSslHMACCtx *)baMalloc(claimresource(sizeof(SharkSslHMACCtx)));
   baAssert(hctx);
   if (!hctx)
   {
      return -1;
   }
   #else
   SharkSslHMACCtx registermcasp;
   #define hctx &registermcasp
   #endif

   baAssert(alloccontroller);
   baAssert(sourcerouting);
   baAssert(creategroup);
   baAssert(secondaryentry);

   SharkSslHMACCtx_constructor(hctx, configwrite, sourcerouting, creategroup);
   SharkSslHMACCtx_append(hctx, alloccontroller, len);
   SharkSslHMACCtx_finish(hctx, secondaryentry);

   #if SHARKSSL_CRYPTO_USE_HEAP
   baFree(hctx);
   #else
   #undef hctx
   #endif
   return 0;
}
#endif


#if SHARKSSL_USE_POLY1305

#if SHARKSSL_OPTIMIZED_POLY1305_ASM
extern
#else
static
#endif
void SharkSslPoly1305Ctx_process(SharkSslPoly1305Ctx *registermcasp, const U8 *msg, U32 acsnhadvnh)
#if SHARKSSL_OPTIMIZED_POLY1305_ASM
;
#else
{
   U64 d;
   U32 t[8], r[5];
   U32 sha256export = registermcasp->flag;

   r[0] = registermcasp->r[0];
   r[1] = registermcasp->r[1];
   r[2] = registermcasp->r[2];
   r[3] = registermcasp->r[3];
   r[4] = registermcasp->r[4];

   baAssert(0 == (acsnhadvnh & 0xF));
   while (acsnhadvnh > 0)
   {
      cleanupcount(t[0], msg, 0);
      cleanupcount(t[1], msg, 4);
      cleanupcount(t[2], msg, 8);
      cleanupcount(t[3], msg, 12);

      r[0] += t[0];
      d = (U64)(r[0] < t[0]);
      d += (U64)r[1] + t[1];
      r[1] = (U32)d; d >>= 32;
      d += (U64)r[2] + t[2];
      r[2] = (U32)d; d >>= 32;
      d += (U64)r[3] + t[3];
      r[3] = (U32)d; d >>= 32;
      d += (U64)r[4] + sha256export;
      r[4] = (U32)d;

      
      d = (U64)r[0] * registermcasp->key[0];
      t[0] = (U32)d; d >>= 32;

      d += (U64)r[0] * registermcasp->key[1];
      d += (U64)r[1] * registermcasp->key[0];
      t[1] = (U32)d; d >>= 32;

      d += (U64)r[0] * registermcasp->key[2];
      d += (U64)r[1] * registermcasp->key[1];
      d += (U64)r[2] * registermcasp->key[0];
      t[2] = (U32)d; d >>= 32;

      d += (U64)r[0] * registermcasp->key[3];
      d += (U64)r[1] * registermcasp->key[2];
      d += (U64)r[2] * registermcasp->key[1];
      d += (U64)r[3] * registermcasp->key[0];
      t[3] = (U32)d; d >>= 32;

      d += (U64)r[1] * registermcasp->key[3];
      d += (U64)r[2] * registermcasp->key[2];
      d += (U64)r[3] * registermcasp->key[1];
      d += (U32)((U8)r[4] * registermcasp->key[0]);  
      t[4] = (U32)d; d >>= 32;

      d += (U64)r[2] * registermcasp->key[3];
      d += (U64)r[3] * registermcasp->key[2];
      d += (U32)((U8)r[4] * registermcasp->key[1]);
      t[5] = (U32)d; d >>= 32;

      d += (U64)r[3] * registermcasp->key[3];
      d += (U32)((U8)r[4] * registermcasp->key[2]);
      t[6] = (U32)d;
      t[7] = (U32)(d >> 32) + (U32)((U8)r[4] * registermcasp->key[3]);

      d = (U64)t[0] + (t[4] & ~0x3) + ((t[4] >> 2) | (t[5] << 30)) + ((U64)(t[5] & 0x3) << 32);
      r[0] = (U32)d; d >>= 32;
      d += (U64)t[1] + (t[5] & ~0x3) + ((t[5] >> 2) | (t[6] << 30)) + ((U64)(t[6] & 0x3) << 32);
      r[1] = (U32)d; d >>= 32;
      d += (U64)t[2] + (t[6] & ~0x3) + ((t[6] >> 2) | (t[7] << 30)) + ((U64)(t[7] & 0x3) << 32);
      r[2] = (U32)d; d >>= 32;
      d += (U64)t[3] + (t[7] & ~0x3) + (t[7] >> 2);
      r[3] = (U32)d;
      r[4] = (U32)(d >> 32) + (t[4] & 0x03);

      msg += 16;
      acsnhadvnh -= 16;
   }

   registermcasp->r[0] = r[0];
   registermcasp->r[1] = r[1];
   registermcasp->r[2] = r[2];
   registermcasp->r[3] = r[3];
   registermcasp->r[4] = r[4];
}
#endif


SHARKSSL_API void SharkSslPoly1305Ctx_constructor(SharkSslPoly1305Ctx *registermcasp, const U8 sourcerouting[32])
{
   baAssert(((unsigned int)(UPTR)registermcasp & (sizeof(int)-1)) == 0);

   cleanupcount(registermcasp->key[0],   sourcerouting, 0);
   cleanupcount(registermcasp->key[1],   sourcerouting, 4);
   cleanupcount(registermcasp->key[2],   sourcerouting, 8);
   cleanupcount(registermcasp->key[3],   sourcerouting, 12);
   cleanupcount(registermcasp->nonce[0], sourcerouting, 16);
   cleanupcount(registermcasp->nonce[1], sourcerouting, 20);
   cleanupcount(registermcasp->nonce[2], sourcerouting, 24);
   cleanupcount(registermcasp->nonce[3], sourcerouting, 28);

   
   registermcasp->key[0] &= 0x0FFFFFFF;
   registermcasp->key[1] &= 0x0FFFFFFC;
   registermcasp->key[2] &= 0x0FFFFFFC;
   registermcasp->key[3] &= 0x0FFFFFFC;

   registermcasp->r[0] = 0;
   registermcasp->r[1] = 0;
   registermcasp->r[2] = 0;
   registermcasp->r[3] = 0;
   registermcasp->r[4] = 0;
   registermcasp->blen = 0;
   registermcasp->flag = 1;
}


SHARKSSL_API void SharkSslPoly1305Ctx_append(SharkSslPoly1305Ctx *registermcasp, const U8 *in, U32 len)
{
   U32 pxa300evalboard = 16 - registermcasp->blen;

   if((registermcasp->blen) && (len >= pxa300evalboard))
   {
      memcpy((registermcasp->buffer + registermcasp->blen), in, pxa300evalboard);
      SharkSslPoly1305Ctx_process(registermcasp, registermcasp->buffer, 16);
      len -= pxa300evalboard;
      in  += pxa300evalboard;
      registermcasp->blen = 0;
   }

   if (len > 0xF)
   {
      pxa300evalboard = (len & ~0xF);
      SharkSslPoly1305Ctx_process(registermcasp, in, pxa300evalboard);
      in += pxa300evalboard;
      len &= 0xF;
   }

   if (len)  
   {
      memcpy((registermcasp->buffer + registermcasp->blen), in, len);
      registermcasp->blen += (U8)len;
   }
}


SHARKSSL_API void SharkSslPoly1305Ctx_finish(SharkSslPoly1305Ctx *registermcasp, U8 secondaryentry[SHARKSSL_POLY1305_HASH_LEN])
{
   U64 d;

   if (registermcasp->blen)
   {
      registermcasp->flag = 0;
      registermcasp->buffer[registermcasp->blen++] = 0x01;
      while (registermcasp->blen < 16)
      {
         registermcasp->buffer[registermcasp->blen++] = 0x00;
      }
      SharkSslPoly1305Ctx_process(registermcasp, &registermcasp->buffer[0], 16);
   }

   
   d = (U64)registermcasp->r[0] + registermcasp->nonce[0] + (registermcasp->r[4] & ~3) + (registermcasp->r[4] >> 2);
   hsotgpdata((U32)d, secondaryentry, 0);
   d >>= 32;
   d += (U64)registermcasp->r[1] + registermcasp->nonce[1];
   hsotgpdata((U32)d, secondaryentry, 4);
   d >>= 32;
   d += (U64)registermcasp->r[2] + registermcasp->nonce[2];
   hsotgpdata((U32)d, secondaryentry, 8);
   d >>= 32;
   d += (U64)registermcasp->r[3] + registermcasp->nonce[3];
   hsotgpdata((U32)d, secondaryentry, 12);

   memset(registermcasp, 0, sizeof(SharkSslPoly1305Ctx));
}


SHARKSSL_API int sharkssl_poly1305(const U8 *alloccontroller, U16 len, U8 *secondaryentry, const U8 sourcerouting[32])
{
   #if SHARKSSL_CRYPTO_USE_HEAP
   SharkSslPoly1305Ctx *hctx = (SharkSslPoly1305Ctx *)baMalloc(claimresource(sizeof(SharkSslPoly1305Ctx)));
   baAssert(hctx);
   if (!hctx)
   {
      return -1;
   }
   #else
   SharkSslPoly1305Ctx registermcasp;
   #define hctx &registermcasp
   #endif

   baAssert(alloccontroller);
   baAssert(len);
   baAssert(secondaryentry);
   baAssert(sourcerouting);

   SharkSslPoly1305Ctx_constructor(hctx, sourcerouting);
   SharkSslPoly1305Ctx_append(hctx, alloccontroller, len);
   SharkSslPoly1305Ctx_finish(hctx, secondaryentry);

   #if SHARKSSL_CRYPTO_USE_HEAP
   baFree(hctx);
   #else
   #undef hctx
   #endif
   return 0;
}
#endif


#if SHARKSSL_USE_CHACHA20

#if SHARKSSL_OPTIMIZED_CHACHA_ASM
extern
#else
#define invalidcontext(x,n) ((U32)((U32)x << n) | ((U32)x >> (32 - n)))
#define disablecharger(a,b,c,d) \
  state[a] = registermcasp->state[a] + registermcasp->state[b]; \
  state[d] = invalidcontext((registermcasp->state[d] ^ state[a]), 16); \
  state[c] = registermcasp->state[c] + state[d]; \
  state[b] = invalidcontext((registermcasp->state[b] ^ state[c]), 12); \
  state[a] += state[b]; \
  state[d] = invalidcontext((state[d] ^ state[a]), 8);  \
  state[c] += state[d]; \
  state[b] = invalidcontext((state[b] ^ state[c]), 7);

#define firstdevice(a,b,c,d) \
  state[a] += state[b]; \
  state[d] = invalidcontext((state[d] ^ state[a]), 16); \
  state[c] += state[d]; \
  state[b] = invalidcontext((state[b] ^ state[c]), 12); \
  state[a] += state[b]; \
  state[d] = invalidcontext((state[d] ^ state[a]), 8);  \
  state[c] += state[d]; \
  state[b] = invalidcontext((state[b] ^ state[c]), 7);

#define ptracesethbpregs(a,b,c,d) \
  state[a] += state[b]; \
  state[d] = invalidcontext((state[d] ^ state[a]), 16); \
  state[c] += state[d]; \
  state[b] = invalidcontext((state[b] ^ state[c]), 12); \
  t = state[a] + state[b]; \
  state[a] = t + registermcasp->state[a]; \
  t = invalidcontext((state[d] ^ t), 8);  \
  state[d] = t + registermcasp->state[d]; \
  t += state[c]; \
  state[c] = t + registermcasp->state[c]; \
  t = invalidcontext((state[b] ^ t), 7); \
  state[b] = t + registermcasp->state[b];
#endif
SHARKSSL_API void SharkSslChaChaCtx_crypt(SharkSslChaChaCtx *registermcasp, const U8 *updatecause, U8 *enablehazard, U32 len)
#if SHARKSSL_OPTIMIZED_CHACHA_ASM
;
#else
{
   U32 state[16];
   int i;

   while (len > 0)
   {
      #if SHARKSSL_CHACHA_SMALL_FOOTPRINT
      memcpy(state, registermcasp->state, 64);
      for (i = 10; i > 0; i--)
      {
         firstdevice(0, 4, 8,12)
         firstdevice(1, 5, 9,13)
         firstdevice(2, 6,10,14)
         firstdevice(3, 7,11,15)
         firstdevice(0, 5,10,15)
         firstdevice(1, 6,11,12)
         firstdevice(2, 7, 8,13)
         firstdevice(3, 4, 9,14)
      }
      #else
      disablecharger(0, 4, 8,12)
      disablecharger(1, 5, 9,13)
      disablecharger(2, 6,10,14)
      disablecharger(3, 7,11,15)
      for (i = 9; i > 0; i--)
      {
         firstdevice(0, 5,10,15)
         firstdevice(1, 6,11,12)
         firstdevice(2, 7, 8,13)
         firstdevice(3, 4, 9,14)
         firstdevice(0, 4, 8,12)
         firstdevice(1, 5, 9,13)
         firstdevice(2, 6,10,14)
         firstdevice(3, 7,11,15)
      }
      {
         U32 t;
         ptracesethbpregs(0, 5,10,15)
         ptracesethbpregs(1, 6,11,12)
         ptracesethbpregs(2, 7, 8,13)
         ptracesethbpregs(3, 4, 9,14)
      }
      #endif

      i = 0;
      #if (!(SHARKSSL_UNALIGNED_ACCESS) && !(SHARKSSL_CHACHA_SMALL_FOOTPRINT))
      if (0 == ((unsigned int)(UPTR)updatecause & 3))  
      #endif
      #if (SHARKSSL_UNALIGNED_ACCESS || !(SHARKSSL_CHACHA_SMALL_FOOTPRINT))
      {
         if (len < 64)
         {
            while (len >= 4)
            {
               #ifdef B_LITTLE_ENDIAN
               #if SHARKSSL_CHACHA_SMALL_FOOTPRINT
               hsotgpdata((state[i] + registermcasp->state[i]) ^ (*(__sharkssl_packed U32*)updatecause), enablehazard, 0);
               #else
               hsotgpdata(state[i] ^ (*(__sharkssl_packed U32*)updatecause), enablehazard, 0);
               #endif

               #elif defined(B_BIG_ENDIAN)
               #if SHARKSSL_CHACHA_SMALL_FOOTPRINT
               hsotgpdata((state[i] + registermcasp->state[i]) ^ blockarray(*(__sharkssl_packed U32*)updatecause), enablehazard, 0);
               #else
               hsotgpdata(state[i] ^ blockarray(*(__sharkssl_packed U32*)updatecause), enablehazard, 0);
               #endif

               #else
               #error #define either B_LITTLE_ENDIAN or B_BIG_ENDIAN
               #endif
               i++;
               enablehazard += 4;
               updatecause += 4;
               len -= 4;
            }

            if (len > 0)  
            {
               #if SHARKSSL_CHACHA_SMALL_FOOTPRINT
               state[i] += registermcasp->state[i];
               #endif
               *enablehazard++ = (U8)(state[i]) ^ *updatecause++;
               if (len >= 2)
               {
                  *enablehazard++ = (U8)(state[i] >> 8) ^ *updatecause++;
                  if (len >= 3)
                  {
                     *enablehazard++ = (U8)(state[i] >> 16) ^ *updatecause++;
                  }
               }
               len = 0;
            }
         }
         else
         {
            #ifdef B_LITTLE_ENDIAN
            #if SHARKSSL_CHACHA_SMALL_FOOTPRINT
            hsotgpdata((state[0]  + registermcasp->state[0])  ^ ((__sharkssl_packed U32*)updatecause)[0],  enablehazard, 0);
            hsotgpdata((state[1]  + registermcasp->state[1])  ^ ((__sharkssl_packed U32*)updatecause)[1],  enablehazard, 4);
            hsotgpdata((state[2]  + registermcasp->state[2])  ^ ((__sharkssl_packed U32*)updatecause)[2],  enablehazard, 8);
            hsotgpdata((state[3]  + registermcasp->state[3])  ^ ((__sharkssl_packed U32*)updatecause)[3],  enablehazard, 12);
            hsotgpdata((state[4]  + registermcasp->state[4])  ^ ((__sharkssl_packed U32*)updatecause)[4],  enablehazard, 16);
            hsotgpdata((state[5]  + registermcasp->state[5])  ^ ((__sharkssl_packed U32*)updatecause)[5],  enablehazard, 20);
            hsotgpdata((state[6]  + registermcasp->state[6])  ^ ((__sharkssl_packed U32*)updatecause)[6],  enablehazard, 24);
            hsotgpdata((state[7]  + registermcasp->state[7])  ^ ((__sharkssl_packed U32*)updatecause)[7],  enablehazard, 28);
            hsotgpdata((state[8]  + registermcasp->state[8])  ^ ((__sharkssl_packed U32*)updatecause)[8],  enablehazard, 32);
            hsotgpdata((state[9]  + registermcasp->state[9])  ^ ((__sharkssl_packed U32*)updatecause)[9],  enablehazard, 36);
            hsotgpdata((state[10] + registermcasp->state[10]) ^ ((__sharkssl_packed U32*)updatecause)[10], enablehazard, 40);
            hsotgpdata((state[11] + registermcasp->state[11]) ^ ((__sharkssl_packed U32*)updatecause)[11], enablehazard, 44);
            hsotgpdata((state[12] + registermcasp->state[12]) ^ ((__sharkssl_packed U32*)updatecause)[12], enablehazard, 48);
            hsotgpdata((state[13] + registermcasp->state[13]) ^ ((__sharkssl_packed U32*)updatecause)[13], enablehazard, 52);
            hsotgpdata((state[14] + registermcasp->state[14]) ^ ((__sharkssl_packed U32*)updatecause)[14], enablehazard, 56);
            hsotgpdata((state[15] + registermcasp->state[15]) ^ ((__sharkssl_packed U32*)updatecause)[15], enablehazard, 60);
            #else
            hsotgpdata(state[0]  ^ ((__sharkssl_packed U32*)updatecause)[0],  enablehazard, 0);
            hsotgpdata(state[1]  ^ ((__sharkssl_packed U32*)updatecause)[1],  enablehazard, 4);
            hsotgpdata(state[2]  ^ ((__sharkssl_packed U32*)updatecause)[2],  enablehazard, 8);
            hsotgpdata(state[3]  ^ ((__sharkssl_packed U32*)updatecause)[3],  enablehazard, 12);
            hsotgpdata(state[4]  ^ ((__sharkssl_packed U32*)updatecause)[4],  enablehazard, 16);
            hsotgpdata(state[5]  ^ ((__sharkssl_packed U32*)updatecause)[5],  enablehazard, 20);
            hsotgpdata(state[6]  ^ ((__sharkssl_packed U32*)updatecause)[6],  enablehazard, 24);
            hsotgpdata(state[7]  ^ ((__sharkssl_packed U32*)updatecause)[7],  enablehazard, 28);
            hsotgpdata(state[8]  ^ ((__sharkssl_packed U32*)updatecause)[8],  enablehazard, 32);
            hsotgpdata(state[9]  ^ ((__sharkssl_packed U32*)updatecause)[9],  enablehazard, 36);
            hsotgpdata(state[10] ^ ((__sharkssl_packed U32*)updatecause)[10], enablehazard, 40);
            hsotgpdata(state[11] ^ ((__sharkssl_packed U32*)updatecause)[11], enablehazard, 44);
            hsotgpdata(state[12] ^ ((__sharkssl_packed U32*)updatecause)[12], enablehazard, 48);
            hsotgpdata(state[13] ^ ((__sharkssl_packed U32*)updatecause)[13], enablehazard, 52);
            hsotgpdata(state[14] ^ ((__sharkssl_packed U32*)updatecause)[14], enablehazard, 56);
            hsotgpdata(state[15] ^ ((__sharkssl_packed U32*)updatecause)[15], enablehazard, 60);
            #endif

            #elif defined(B_BIG_ENDIAN)
            #if SHARKSSL_CHACHA_SMALL_FOOTPRINT
            hsotgpdata((state[0]  + registermcasp->state[0])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[0]),  enablehazard, 0);
            hsotgpdata((state[1]  + registermcasp->state[1])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[1]),  enablehazard, 4);
            hsotgpdata((state[2]  + registermcasp->state[2])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[2]),  enablehazard, 8);
            hsotgpdata((state[3]  + registermcasp->state[3])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[3]),  enablehazard, 12);
            hsotgpdata((state[4]  + registermcasp->state[4])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[4]),  enablehazard, 16);
            hsotgpdata((state[5]  + registermcasp->state[5])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[5]),  enablehazard, 20);
            hsotgpdata((state[6]  + registermcasp->state[6])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[6]),  enablehazard, 24);
            hsotgpdata((state[7]  + registermcasp->state[7])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[7]),  enablehazard, 28);
            hsotgpdata((state[8]  + registermcasp->state[8])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[8]),  enablehazard, 32);
            hsotgpdata((state[9]  + registermcasp->state[9])  ^ blockarray(((__sharkssl_packed U32*)updatecause)[9]),  enablehazard, 36);
            hsotgpdata((state[10] + registermcasp->state[10]) ^ blockarray(((__sharkssl_packed U32*)updatecause)[10]), enablehazard, 40);
            hsotgpdata((state[11] + registermcasp->state[11]) ^ blockarray(((__sharkssl_packed U32*)updatecause)[11]), enablehazard, 44);
            hsotgpdata((state[12] + registermcasp->state[12]) ^ blockarray(((__sharkssl_packed U32*)updatecause)[12]), enablehazard, 48);
            hsotgpdata((state[13] + registermcasp->state[13]) ^ blockarray(((__sharkssl_packed U32*)updatecause)[13]), enablehazard, 52);
            hsotgpdata((state[14] + registermcasp->state[14]) ^ blockarray(((__sharkssl_packed U32*)updatecause)[14]), enablehazard, 56);
            hsotgpdata((state[15] + registermcasp->state[15]) ^ blockarray(((__sharkssl_packed U32*)updatecause)[15]), enablehazard, 60);
            #else
            hsotgpdata(state[0]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[0]),  enablehazard, 0);
            hsotgpdata(state[1]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[1]),  enablehazard, 4);
            hsotgpdata(state[2]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[2]),  enablehazard, 8);
            hsotgpdata(state[3]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[3]),  enablehazard, 12);
            hsotgpdata(state[4]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[4]),  enablehazard, 16);
            hsotgpdata(state[5]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[5]),  enablehazard, 20);
            hsotgpdata(state[6]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[6]),  enablehazard, 24);
            hsotgpdata(state[7]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[7]),  enablehazard, 28);
            hsotgpdata(state[8]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[8]),  enablehazard, 32);
            hsotgpdata(state[9]  ^ blockarray(((__sharkssl_packed U32*)updatecause)[9]),  enablehazard, 36);
            hsotgpdata(state[10] ^ blockarray(((__sharkssl_packed U32*)updatecause)[10]), enablehazard, 40);
            hsotgpdata(state[11] ^ blockarray(((__sharkssl_packed U32*)updatecause)[11]), enablehazard, 44);
            hsotgpdata(state[12] ^ blockarray(((__sharkssl_packed U32*)updatecause)[12]), enablehazard, 48);
            hsotgpdata(state[13] ^ blockarray(((__sharkssl_packed U32*)updatecause)[13]), enablehazard, 52);
            hsotgpdata(state[14] ^ blockarray(((__sharkssl_packed U32*)updatecause)[14]), enablehazard, 56);
            hsotgpdata(state[15] ^ blockarray(((__sharkssl_packed U32*)updatecause)[15]), enablehazard, 60);
            #endif

            #endif
            len -= 64;
            enablehazard += 64;
            updatecause += 64;
         }
      }
      #endif
      #if (!(SHARKSSL_UNALIGNED_ACCESS))
      #if (!(SHARKSSL_CHACHA_SMALL_FOOTPRINT))
      else
      #endif
      {
         while (!(i & 0x10) && (len > 0))
         {
            U32 st;
            #if SHARKSSL_CHACHA_SMALL_FOOTPRINT
            state[i] += registermcasp->state[i];
            #endif
            st = state[i];
            *enablehazard++ = (U8)(st) ^ *updatecause++;
            if (--len)
            {
               *enablehazard++ = (U8)(st >> 8) ^ *updatecause++;
               if (--len)
               {
                  *enablehazard++ = (U8)(st >> 16) ^ *updatecause++;
                  if (--len)
                  {
                     *enablehazard++ = (U8)(st >> 24) ^ *updatecause++;
                     len--;
                     i++;
                  }
               }
            }
         }
      }
      #endif  

      if (0 == (++registermcasp->state[12]))
      {
         registermcasp->state[13]++;
         
      }
   }
}
#undef ptracesethbpregs
#undef firstdevice
#undef disablecharger
#undef invalidcontext
#endif


SHARKSSL_API void SharkSslChaChaCtx_constructor(SharkSslChaChaCtx *registermcasp, const U8 *sourcerouting, U8 creategroup)
{
   static const char mcbsp1hwmod[] = "\145\170\160\141\156\144\040\063\062\055\142\171\164\145\040\153";
   static const char tau[] = "\145\170\160\141\156\144\040\061\066\055\142\171\164\145\040\153";
   const char *write64uint32;

   cleanupcount(registermcasp->state[4], sourcerouting, 0);
   cleanupcount(registermcasp->state[5], sourcerouting, 4);
   cleanupcount(registermcasp->state[6], sourcerouting, 8);
   cleanupcount(registermcasp->state[7], sourcerouting, 12);

   if (creategroup == 32)
   { 
      sourcerouting += 16;
      write64uint32 = mcbsp1hwmod;
   }
   else
   { 
      write64uint32 = tau;
   }
   cleanupcount(registermcasp->state[8],  sourcerouting, 0);
   cleanupcount(registermcasp->state[9],  sourcerouting, 4);
   cleanupcount(registermcasp->state[10], sourcerouting, 8);
   cleanupcount(registermcasp->state[11], sourcerouting, 12);

   cleanupcount(registermcasp->state[0], write64uint32, 0);
   cleanupcount(registermcasp->state[1], write64uint32, 4);
   cleanupcount(registermcasp->state[2], write64uint32, 8);
   cleanupcount(registermcasp->state[3], write64uint32, 12);
}


SHARKSSL_API void SharkSslChaChaCtx_setIV(SharkSslChaChaCtx *registermcasp, const U8 IV[12])
{
  registermcasp->state[12] = 0;
  cleanupcount(registermcasp->state[13], IV, 0);
  cleanupcount(registermcasp->state[14], IV, 4);
  cleanupcount(registermcasp->state[15], IV, 8);
}
#endif


#if (SHARKSSL_SSL_CLIENT_CODE || SHARKSSL_SSL_SERVER_CODE || SHARKSSL_ENABLE_AES_GCM || SHARKSSL_ENABLE_PEM_API)

SHARKSSL_API int sharkssl_kmemcmp(const void *a, const void *b, U32 n)
{
   U8 cmp = 0;
   #if SHARKSSL_UNALIGNED_ACCESS
   const U8  *p8a, *p8b;
   __sharkssl_packed const U32 *exceptionlevel = (const U32*)a;
   __sharkssl_packed const U32 *movinandinserted = (const U32*)b;
   U32 dointvecminmax = 0;

   while (n >= 4)
   {
      dointvecminmax |= (*exceptionlevel++ ^ *movinandinserted++);
      n -= 4;
   }

   
   dointvecminmax = (dointvecminmax & 0xFFFF) | (dointvecminmax >> 16);
   cmp   = (U8)dointvecminmax  | (U8)(dointvecminmax >> 8);

   p8a = (U8*)exceptionlevel;
   p8b = (U8*)movinandinserted;
   #else

   U8 *p8a = (U8*)a;
   U8 *p8b = (U8*)b;
   #endif

   while (n--)
   {
      cmp |= (*p8a++ ^ *p8b++);
   }

   return (int)cmp;
}
#endif


#if (SHARKSSL_USE_AES_256 || SHARKSSL_USE_AES_192 || SHARKSSL_USE_AES_128)

#if SHARKSSL_AES_TABLES_IN_RAM
static U32 alloczeroed[256];
static U32 domainalways[256];
static U32 timeoutshift[10];
#if (!SHARKSSL_AES_DISABLE_SBOX)
static U8 class3configure[256];
#endif
#if (!SHARKSSL_DISABLE_AES_ECB_DECRYPT)
static U8 powerpdata[256];
#endif
#endif

#if (!SHARKSSL_AES_DISABLE_SBOX)
#if SHARKSSL_AES_TABLES_IN_RAM
static const U8 singlefuito[256] =
#else
static const U8 class3configure[256] =
#endif
{
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
   0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
   0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
   0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
   0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
   0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
   0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
   0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
   0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
   0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
   0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
   0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
   0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
   0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
   0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
   0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
   0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
#endif

#if (!SHARKSSL_DISABLE_AES_ECB_DECRYPT)
#if SHARKSSL_AES_TABLES_IN_RAM
static const U8 spinboxhwmod[256] =
#else
static const U8 powerpdata[256] =
#endif
{
   0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
   0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
   0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
   0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
   0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
   0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
   0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
   0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
   0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
   0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
   0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
   0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
   0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
   0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
   0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
   0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
   0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
   0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
   0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
   0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
   0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
   0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
   0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
   0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
   0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
   0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
   0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
   0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
   0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
   0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
   0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
   0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};
#endif

#if SHARKSSL_AES_TABLES_IN_RAM
static const U32 timerevtstrm[256] =
#else
static const U32 alloczeroed[256] =
#endif
{
   0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d,
   0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554,
   0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d,
   0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a,
   0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87,
   0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b,
   0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea,
   0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b,
   0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a,
   0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f,
   0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108,
   0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f,
   0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e,
   0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5,
   0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d,
   0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f,
   0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e,
   0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb,
   0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce,
   0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497,
   0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c,
   0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed,
   0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b,
   0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a,
   0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16,
   0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594,
   0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81,
   0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3,
   0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a,
   0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504,
   0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163,
   0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d,
   0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f,
   0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739,
   0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47,
   0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395,
   0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f,
   0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883,
   0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c,
   0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76,
   0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e,
   0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4,
   0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6,
   0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b,
   0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7,
   0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0,
   0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25,
   0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818,
   0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72,
   0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651,
   0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21,
   0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85,
   0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa,
   0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12,
   0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0,
   0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9,
   0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133,
   0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7,
   0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920,
   0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a,
   0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17,
   0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8,
   0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11,
   0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a
};

#if (!SHARKSSL_DISABLE_AES_ECB_DECRYPT)
#if SHARKSSL_AES_TABLES_IN_RAM
static const U32 thumb32break[256] =
#else
static const U32 domainalways[256] =
#endif
{
   0x51f4a750, 0x7e416553, 0x1a17a4c3, 0x3a275e96,
   0x3bab6bcb, 0x1f9d45f1, 0xacfa58ab, 0x4be30393,
   0x2030fa55, 0xad766df6, 0x88cc7691, 0xf5024c25,
   0x4fe5d7fc, 0xc52acbd7, 0x26354480, 0xb562a38f,
   0xdeb15a49, 0x25ba1b67, 0x45ea0e98, 0x5dfec0e1,
   0xc32f7502, 0x814cf012, 0x8d4697a3, 0x6bd3f9c6,
   0x038f5fe7, 0x15929c95, 0xbf6d7aeb, 0x955259da,
   0xd4be832d, 0x587421d3, 0x49e06929, 0x8ec9c844,
   0x75c2896a, 0xf48e7978, 0x99583e6b, 0x27b971dd,
   0xbee14fb6, 0xf088ad17, 0xc920ac66, 0x7dce3ab4,
   0x63df4a18, 0xe51a3182, 0x97513360, 0x62537f45,
   0xb16477e0, 0xbb6bae84, 0xfe81a01c, 0xf9082b94,
   0x70486858, 0x8f45fd19, 0x94de6c87, 0x527bf8b7,
   0xab73d323, 0x724b02e2, 0xe31f8f57, 0x6655ab2a,
   0xb2eb2807, 0x2fb5c203, 0x86c57b9a, 0xd33708a5,
   0x302887f2, 0x23bfa5b2, 0x02036aba, 0xed16825c,
   0x8acf1c2b, 0xa779b492, 0xf307f2f0, 0x4e69e2a1,
   0x65daf4cd, 0x0605bed5, 0xd134621f, 0xc4a6fe8a,
   0x342e539d, 0xa2f355a0, 0x058ae132, 0xa4f6eb75,
   0x0b83ec39, 0x4060efaa, 0x5e719f06, 0xbd6e1051,
   0x3e218af9, 0x96dd063d, 0xdd3e05ae, 0x4de6bd46,
   0x91548db5, 0x71c45d05, 0x0406d46f, 0x605015ff,
   0x1998fb24, 0xd6bde997, 0x894043cc, 0x67d99e77,
   0xb0e842bd, 0x07898b88, 0xe7195b38, 0x79c8eedb,
   0xa17c0a47, 0x7c420fe9, 0xf8841ec9, 0x00000000,
   0x09808683, 0x322bed48, 0x1e1170ac, 0x6c5a724e,
   0xfd0efffb, 0x0f853856, 0x3daed51e, 0x362d3927,
   0x0a0fd964, 0x685ca621, 0x9b5b54d1, 0x24362e3a,
   0x0c0a67b1, 0x9357e70f, 0xb4ee96d2, 0x1b9b919e,
   0x80c0c54f, 0x61dc20a2, 0x5a774b69, 0x1c121a16,
   0xe293ba0a, 0xc0a02ae5, 0x3c22e043, 0x121b171d,
   0x0e090d0b, 0xf28bc7ad, 0x2db6a8b9, 0x141ea9c8,
   0x57f11985, 0xaf75074c, 0xee99ddbb, 0xa37f60fd,
   0xf701269f, 0x5c72f5bc, 0x44663bc5, 0x5bfb7e34,
   0x8b432976, 0xcb23c6dc, 0xb6edfc68, 0xb8e4f163,
   0xd731dcca, 0x42638510, 0x13972240, 0x84c61120,
   0x854a247d, 0xd2bb3df8, 0xaef93211, 0xc729a16d,
   0x1d9e2f4b, 0xdcb230f3, 0x0d8652ec, 0x77c1e3d0,
   0x2bb3166c, 0xa970b999, 0x119448fa, 0x47e96422,
   0xa8fc8cc4, 0xa0f03f1a, 0x567d2cd8, 0x223390ef,
   0x87494ec7, 0xd938d1c1, 0x8ccaa2fe, 0x98d40b36,
   0xa6f581cf, 0xa57ade28, 0xdab78e26, 0x3fadbfa4,
   0x2c3a9de4, 0x5078920d, 0x6a5fcc9b, 0x547e4662,
   0xf68d13c2, 0x90d8b8e8, 0x2e39f75e, 0x82c3aff5,
   0x9f5d80be, 0x69d0937c, 0x6fd52da9, 0xcf2512b3,
   0xc8ac993b, 0x10187da7, 0xe89c636e, 0xdb3bbb7b,
   0xcd267809, 0x6e5918f4, 0xec9ab701, 0x834f9aa8,
   0xe6956e65, 0xaaffe67e, 0x21bccf08, 0xef15e8e6,
   0xbae79bd9, 0x4a6f36ce, 0xea9f09d4, 0x29b07cd6,
   0x31a4b2af, 0x2a3f2331, 0xc6a59430, 0x35a266c0,
   0x744ebc37, 0xfc82caa6, 0xe090d0b0, 0x33a7d815,
   0xf104984a, 0x41ecdaf7, 0x7fcd500e, 0x1791f62f,
   0x764dd68d, 0x43efb04d, 0xccaa4d54, 0xe49604df,
   0x9ed1b5e3, 0x4c6a881b, 0xc12c1fb8, 0x4665517f,
   0x9d5eea04, 0x018c355d, 0xfa877473, 0xfb0b412e,
   0xb3671d5a, 0x92dbd252, 0xe9105633, 0x6dd64713,
   0x9ad7618c, 0x37a10c7a, 0x59f8148e, 0xeb133c89,
   0xcea927ee, 0xb761c935, 0xe11ce5ed, 0x7a47b13c,
   0x9cd2df59, 0x55f2733f, 0x1814ce79, 0x73c737bf,
   0x53f7cdea, 0x5ffdaa5b, 0xdf3d6f14, 0x7844db86,
   0xcaaff381, 0xb968c43e, 0x3824342c, 0xc2a3405f,
   0x161dc372, 0xbce2250c, 0x283c498b, 0xff0d9541,
   0x39a80171, 0x080cb3de, 0xd8b4e49c, 0x6456c190,
   0x7bcb8461, 0xd532b670, 0x486c5c74, 0xd0b85742
};
#endif

#if SHARKSSL_AES_TABLES_IN_RAM
static const U32 enterlowpower[10] =
#else
static const U32 timeoutshift[10] =
#endif
{
   0x01000000, 0x02000000, 0x04000000, 0x08000000,
   0x10000000, 0x20000000, 0x40000000, 0x80000000,
   0x1B000000, 0x36000000
};

#define mcspidevice(a, n) (((a) >> n) | ((a) << (32 - n)))


SHARKSSL_API void SharkSslAesCtx_constructor(SharkSslAesCtx *registermcasp,
                                             SharkSslAesCtx_Type rightsvalid,
                                             const U8 *sourcerouting, U8 creategroup)
{
   U32 *countshift, brightnesslimit;
   U16 i;
   #if (!SHARKSSL_DISABLE_AES_ECB_DECRYPT)
   U16 j;
   #endif

   baAssert(registermcasp);
   baAssert(sourcerouting);
   #if (SHARKSSL_USE_AES_256)
   #if (SHARKSSL_USE_AES_192)
   #if (SHARKSSL_USE_AES_128)
   baAssert((creategroup == 32) || (creategroup == 24) || (creategroup == 16));
   #else  
   baAssert((creategroup == 32) || (creategroup == 24));
   #endif
   #else  
   #if (SHARKSSL_USE_AES_128)
   baAssert((creategroup == 32) || (creategroup == 16));
   #else  
   baAssert(creategroup == 32);
   #endif
   #endif
   #else  
   #if (SHARKSSL_USE_AES_192)
   #if (SHARKSSL_USE_AES_128)
   baAssert((creategroup == 24) || (creategroup == 16));
   #else  
   baAssert((creategroup == 24));
   #endif
   #else
   baAssert((SHARKSSL_USE_AES_128) && (creategroup == 16));
   #endif
   #endif

   #if (!SHARKSSL_DISABLE_AES_ECB_DECRYPT)
   baAssert((rightsvalid == SharkSslAesCtx_Decrypt) || (rightsvalid == SharkSslAesCtx_Encrypt));
   #else
   baAssert(rightsvalid == SharkSslAesCtx_Decrypt);
   #endif

   #if SHARKSSL_AES_TABLES_IN_RAM
   if (!alloczeroed[0])
   {
      memcpy(alloczeroed, timerevtstrm, sizeof(timerevtstrm));
      memcpy(domainalways, thumb32break, sizeof(thumb32break));
      memcpy(timeoutshift, enterlowpower, sizeof(enterlowpower));
      #if (!SHARKSSL_AES_DISABLE_SBOX)
      memcpy(class3configure, singlefuito, sizeof(singlefuito));
      #endif
      #if (!SHARKSSL_DISABLE_AES_ECB_DECRYPT)
      memcpy(powerpdata, spinboxhwmod, sizeof(spinboxhwmod));
      #endif
   }
   #endif

   countshift = registermcasp->key;
   read64uint32(countshift[0], sourcerouting, 0);
   read64uint32(countshift[1], sourcerouting, 4);
   read64uint32(countshift[2], sourcerouting, 8);
   read64uint32(countshift[3], sourcerouting, 12);

   switch (creategroup)
   {
      #if (SHARKSSL_USE_AES_128)
      case 16:
         registermcasp->nr = 10;
         for (i = 0; i < 10; i++, countshift += 4)
         {
            brightnesslimit = countshift[3];
            #if SHARKSSL_AES_DISABLE_SBOX
            brightnesslimit  = ((alloczeroed[exceptionupdates(brightnesslimit)] << 8) & 0xFF000000) |
                     (alloczeroed[iisv4resource(brightnesslimit)]       & 0x00FF0000) |
                     (alloczeroed[translationfault(brightnesslimit)]       & 0x0000FF00) |
                    ((alloczeroed[setupcmdline(brightnesslimit)] >> 8) & 0x000000FF);
            #else
            brightnesslimit  = ((U32)class3configure[exceptionupdates(brightnesslimit)] << 24) |
                    ((U32)class3configure[iisv4resource(brightnesslimit)] << 16) |
                    ((U32)class3configure[translationfault(brightnesslimit)] <<  8) |
                    ((U32)class3configure[setupcmdline(brightnesslimit)]      );
            #endif
            countshift[4] = brightnesslimit ^ countshift[0] ^ timeoutshift[i];
            countshift[5] = countshift[1] ^ countshift[4];
            countshift[6] = countshift[2] ^ countshift[5];
            countshift[7] = countshift[3] ^ countshift[6];
         }
         break;
      #endif

      #if (SHARKSSL_USE_AES_192)
      case 24:
         read64uint32(countshift[4], sourcerouting, 16);
         read64uint32(countshift[5], sourcerouting, 20);
         registermcasp->nr = 12;
         for (i = 0; i < 8; i++, countshift += 6)
         {
            brightnesslimit  = countshift[5];
            #if SHARKSSL_AES_DISABLE_SBOX
            brightnesslimit  = ((alloczeroed[exceptionupdates(brightnesslimit)] << 8) & 0xFF000000) |
                     (alloczeroed[iisv4resource(brightnesslimit)]       & 0x00FF0000) |
                     (alloczeroed[translationfault(brightnesslimit)]       & 0x0000FF00) |
                    ((alloczeroed[setupcmdline(brightnesslimit)] >> 8) & 0x000000FF);
            #else
            brightnesslimit  = ((U32)class3configure[exceptionupdates(brightnesslimit)] << 24) |
                    ((U32)class3configure[iisv4resource(brightnesslimit)] << 16) |
                    ((U32)class3configure[translationfault(brightnesslimit)] <<  8) |
                    ((U32)class3configure[setupcmdline(brightnesslimit)]      );
            #endif
            countshift[6]  = brightnesslimit ^ countshift[0] ^ timeoutshift[i];
            countshift[7]  = countshift[1] ^ countshift[6];
            countshift[8]  = countshift[2] ^ countshift[7];
            countshift[9]  = countshift[3] ^ countshift[8];
            if (i < 7)
            {
               countshift[10] = countshift[4] ^ countshift[9];
               countshift[11] = countshift[5] ^ countshift[10];
            }
         }
         break;
      #endif

      #if (SHARKSSL_USE_AES_256)
      case 32:
         read64uint32(countshift[4], sourcerouting, 16);
         read64uint32(countshift[5], sourcerouting, 20);
         read64uint32(countshift[6], sourcerouting, 24);
         read64uint32(countshift[7], sourcerouting, 28);
         registermcasp->nr = 14;
         for (i = 0; i < 7; i++, countshift += 8)
         {
            brightnesslimit  = countshift[7];
            #if SHARKSSL_AES_DISABLE_SBOX
            brightnesslimit  = ((alloczeroed[exceptionupdates(brightnesslimit)] << 8) & 0xFF000000) |
                     (alloczeroed[iisv4resource(brightnesslimit)]       & 0x00FF0000) |
                     (alloczeroed[translationfault(brightnesslimit)]       & 0x0000FF00) |
                    ((alloczeroed[setupcmdline(brightnesslimit)] >> 8) & 0x000000FF);
            #else
            brightnesslimit  = ((U32)class3configure[exceptionupdates(brightnesslimit)] << 24) |
                    ((U32)class3configure[iisv4resource(brightnesslimit)] << 16) |
                    ((U32)class3configure[translationfault(brightnesslimit)] <<  8) |
                    ((U32)class3configure[setupcmdline(brightnesslimit)]      );
            #endif
            countshift[8]  = brightnesslimit ^ countshift[0] ^ timeoutshift[i];
            countshift[9]  = countshift[1] ^ countshift[8];
            countshift[10] = countshift[2] ^ countshift[9];
            countshift[11] = countshift[3] ^ countshift[10];

            if (i < 6)
            {
               brightnesslimit  = countshift[11];
               #if SHARKSSL_AES_DISABLE_SBOX
               brightnesslimit  = ((alloczeroed[setupcmdline(brightnesslimit)] << 8) & 0xFF000000) |
                        (alloczeroed[exceptionupdates(brightnesslimit)]       & 0x00FF0000) |
                        (alloczeroed[iisv4resource(brightnesslimit)]       & 0x0000FF00) |
                       ((alloczeroed[translationfault(brightnesslimit)] >> 8) & 0x000000FF);
               #else
               brightnesslimit  = ((U32)class3configure[setupcmdline(brightnesslimit)] << 24) |
                       ((U32)class3configure[exceptionupdates(brightnesslimit)] << 16) |
                       ((U32)class3configure[iisv4resource(brightnesslimit)] <<  8) |
                       ((U32)class3configure[translationfault(brightnesslimit)]      );
               #endif
               countshift[12] = brightnesslimit ^ countshift[4];
               countshift[13] = countshift[5] ^ countshift[12];
               countshift[14] = countshift[6] ^ countshift[13];
               countshift[15] = countshift[7] ^ countshift[14];
            }
         }
         break;
      #endif

      default:
         baAssert(0); 
         break;
   }

   #if (!SHARKSSL_DISABLE_AES_ECB_DECRYPT)
   if (rightsvalid == SharkSslAesCtx_Decrypt)
   {
      countshift += 4;

      for (i = 1; i < registermcasp->nr; i++)
      {
         countshift -= 8;

         for (j = 4; j > 0; j--)
         {
            brightnesslimit = *countshift;
            #if SHARKSSL_AES_DISABLE_SBOX
            *countshift++ =      domainalways[(U8)(alloczeroed[setupcmdline(brightnesslimit)] >> 8)]      ^
                   mcspidevice(domainalways[(U8)(alloczeroed[exceptionupdates(brightnesslimit)] >> 8)], 8)  ^
                   mcspidevice(domainalways[(U8)(alloczeroed[iisv4resource(brightnesslimit)] >> 8)], 16) ^
                   mcspidevice(domainalways[(U8)(alloczeroed[translationfault(brightnesslimit)] >> 8)], 24);
            #else
            *countshift++ =      domainalways[class3configure[setupcmdline(brightnesslimit)]]      ^
                   mcspidevice(domainalways[class3configure[exceptionupdates(brightnesslimit)]], 8)  ^
                   mcspidevice(domainalways[class3configure[iisv4resource(brightnesslimit)]], 16) ^
                   mcspidevice(domainalways[class3configure[translationfault(brightnesslimit)]], 24);
            #endif
         }
      }
   }
   #endif

   #if ((!SHARKSSL_AES_SMALL_FOOTPRINT) && SHARKSSL_AES_CIPHER_LOOP_UNROLL)
   registermcasp->nr >>= 1;
   #endif
   registermcasp->nr--;
}


#define AES_ENC_ROUND(s, t, k, mixtable)  do {              \
   k += 4;                                                  \
   t[0] = k[0] ^       mixtable[setupcmdline(s[0])]      ^      \
                  mcspidevice(mixtable[exceptionupdates(s[1])], 8)  ^      \
                  mcspidevice(mixtable[iisv4resource(s[2])], 16) ^      \
                  mcspidevice(mixtable[translationfault(s[3])], 24);       \
   t[1] = k[1] ^       mixtable[setupcmdline(s[1])]      ^      \
                  mcspidevice(mixtable[exceptionupdates(s[2])], 8)  ^      \
                  mcspidevice(mixtable[iisv4resource(s[3])], 16) ^      \
                  mcspidevice(mixtable[translationfault(s[0])], 24);       \
   t[2] = k[2] ^       mixtable[setupcmdline(s[2])]      ^      \
                  mcspidevice(mixtable[exceptionupdates(s[3])], 8)  ^      \
                  mcspidevice(mixtable[iisv4resource(s[0])], 16) ^      \
                  mcspidevice(mixtable[translationfault(s[1])], 24);       \
   t[3] = k[3] ^       mixtable[setupcmdline(s[3])]      ^      \
                  mcspidevice(mixtable[exceptionupdates(s[0])], 8)  ^      \
                  mcspidevice(mixtable[iisv4resource(s[1])], 16) ^      \
                  mcspidevice(mixtable[translationfault(s[2])], 24);       \
} while (0);

#if SHARKSSL_AES_DISABLE_SBOX
#define AES_ENC_FINAL_ROUND(out, s, k, sbox) do {           \
   k += 4;                                                  \
   out[0]  = (U8)((setupcmdline(k[0])) ^ ((U8)(sbox[setupcmdline(s[0])] >> 8))); \
   out[1]  = (U8)((exceptionupdates(k[0])) ^ ((U8)(sbox[exceptionupdates(s[1])] >> 8))); \
   out[2]  = (U8)((iisv4resource(k[0])) ^ ((U8)(sbox[iisv4resource(s[2])] >> 8))); \
   out[3]  = (U8)((translationfault(k[0])) ^ ((U8)(sbox[translationfault(s[3])] >> 8))); \
   out[4]  = (U8)((setupcmdline(k[1])) ^ ((U8)(sbox[setupcmdline(s[1])] >> 8))); \
   out[5]  = (U8)((exceptionupdates(k[1])) ^ ((U8)(sbox[exceptionupdates(s[2])] >> 8))); \
   out[6]  = (U8)((iisv4resource(k[1])) ^ ((U8)(sbox[iisv4resource(s[3])] >> 8))); \
   out[7]  = (U8)((translationfault(k[1])) ^ ((U8)(sbox[translationfault(s[0])] >> 8))); \
   out[8]  = (U8)((setupcmdline(k[2])) ^ ((U8)(sbox[setupcmdline(s[2])] >> 8))); \
   out[9]  = (U8)((exceptionupdates(k[2])) ^ ((U8)(sbox[exceptionupdates(s[3])] >> 8))); \
   out[10] = (U8)((iisv4resource(k[2])) ^ ((U8)(sbox[iisv4resource(s[0])] >> 8))); \
   out[11] = (U8)((translationfault(k[2])) ^ ((U8)(sbox[translationfault(s[1])] >> 8))); \
   out[12] = (U8)((setupcmdline(k[3])) ^ ((U8)(sbox[setupcmdline(s[3])] >> 8))); \
   out[13] = (U8)((exceptionupdates(k[3])) ^ ((U8)(sbox[exceptionupdates(s[0])] >> 8))); \
   out[14] = (U8)((iisv4resource(k[3])) ^ ((U8)(sbox[iisv4resource(s[1])] >> 8))); \
   out[15] = (U8)((translationfault(k[3])) ^ ((U8)(sbox[translationfault(s[2])] >> 8))); \
} while (0);
#else
#define AES_ENC_FINAL_ROUND(out, s, k, sbox) do {           \
   k += 4;                                                  \
   out[0]  = (U8)((setupcmdline(k[0])) ^ sbox[setupcmdline(s[0])]); \
   out[1]  = (U8)((exceptionupdates(k[0])) ^ sbox[exceptionupdates(s[1])]); \
   out[2]  = (U8)((iisv4resource(k[0])) ^ sbox[iisv4resource(s[2])]); \
   out[3]  = (U8)((translationfault(k[0])) ^ sbox[translationfault(s[3])]); \
   out[4]  = (U8)((setupcmdline(k[1])) ^ sbox[setupcmdline(s[1])]); \
   out[5]  = (U8)((exceptionupdates(k[1])) ^ sbox[exceptionupdates(s[2])]); \
   out[6]  = (U8)((iisv4resource(k[1])) ^ sbox[iisv4resource(s[3])]); \
   out[7]  = (U8)((translationfault(k[1])) ^ sbox[translationfault(s[0])]); \
   out[8]  = (U8)((setupcmdline(k[2])) ^ sbox[setupcmdline(s[2])]); \
   out[9]  = (U8)((exceptionupdates(k[2])) ^ sbox[exceptionupdates(s[3])]); \
   out[10] = (U8)((iisv4resource(k[2])) ^ sbox[iisv4resource(s[0])]); \
   out[11] = (U8)((translationfault(k[2])) ^ sbox[translationfault(s[1])]); \
   out[12] = (U8)((setupcmdline(k[3])) ^ sbox[setupcmdline(s[3])]); \
   out[13] = (U8)((exceptionupdates(k[3])) ^ sbox[exceptionupdates(s[0])]); \
   out[14] = (U8)((iisv4resource(k[3])) ^ sbox[iisv4resource(s[1])]); \
   out[15] = (U8)((translationfault(k[3])) ^ sbox[translationfault(s[2])]); \
} while (0);
#endif


SHARKSSL_API void SharkSslAesCtx_encrypt(SharkSslAesCtx *registermcasp, U8 updatecause[16], U8 enablehazard[16])
{
   U32 *K, S[4], T[4];
   U16  i;
   #if SHARKSSL_AES_SMALL_FOOTPRINT
   U16 j, z, y;
   #endif

   baAssert(registermcasp->nr > 0);
   i = registermcasp->nr;
   K = registermcasp->key;

   read64uint32(S[0], updatecause,  0); S[0] ^= K[0];
   read64uint32(S[1], updatecause,  4); S[1] ^= K[1];
   read64uint32(S[2], updatecause,  8); S[2] ^= K[2];
   read64uint32(S[3], updatecause, 12); S[3] ^= K[3];

   #if SHARKSSL_AES_SMALL_FOOTPRINT
   K += 4;
   do
   {
      for (j = 0; !(j & 4); j++)
      {
         T[j] = *K++;
         for (z = 0, y = 0; !(z & 4); z++, y += 8)
         {
            U32 r = alloczeroed[(U8)(S[(j + z) & 3] >> (24 - y))];
            T[j] ^= mcspidevice(r, y);
         }
      }

      S[0] = T[0]; S[1] = T[1]; S[2] = T[2]; S[3] = T[3];
   } while (--i);

   i = 0;
   for (j = 0; !(j & 4); j++)
   {
      for (z = 0, y = 24; !(z & 4); z++, y -= 8)
      {
         #if SHARKSSL_AES_DISABLE_SBOX
         enablehazard[i++] = (U8)((K[j] >> y) ^ (U8)(alloczeroed[(U8)(T[(j + z) & 3] >> y)] >> 8));
         #else
         enablehazard[i++] = (U8)((K[j] >> y) ^ class3configure[(U8)(T[(j + z) & 3] >> y)]);
         #endif
      }
   }

   #else
   #if SHARKSSL_AES_CIPHER_LOOP_UNROLL
   AES_ENC_ROUND(S, T, K, alloczeroed);
   #endif
   do
   {
      #if SHARKSSL_AES_CIPHER_LOOP_UNROLL
      AES_ENC_ROUND(T, S, K, alloczeroed);
      AES_ENC_ROUND(S, T, K, alloczeroed);

      #else
      AES_ENC_ROUND(S, T, K, alloczeroed);
      S[0] = T[0]; S[1] = T[1]; S[2] = T[2]; S[3] = T[3];

      #endif

   } while (--i);

   #if SHARKSSL_AES_DISABLE_SBOX
   AES_ENC_FINAL_ROUND(enablehazard, T, K, alloczeroed);
   #else
   AES_ENC_FINAL_ROUND(enablehazard, T, K, class3configure);
   #endif
   #endif
}


#undef AES_ENC_ROUND
#undef AES_ENC_FINAL_ROUND

#if (!SHARKSSL_DISABLE_AES_ECB_DECRYPT)
#define AES_DEC_ROUND(s, t, k, mixtable)  do {              \
   k -= 4;                                                  \
   t[0] = k[0] ^       mixtable[setupcmdline(s[0])]      ^      \
                  mcspidevice(mixtable[exceptionupdates(s[3])], 8)  ^      \
                  mcspidevice(mixtable[iisv4resource(s[2])], 16) ^      \
                  mcspidevice(mixtable[translationfault(s[1])], 24);       \
   t[1] = k[1] ^       mixtable[setupcmdline(s[1])]      ^      \
                  mcspidevice(mixtable[exceptionupdates(s[0])], 8)  ^      \
                  mcspidevice(mixtable[iisv4resource(s[3])], 16) ^      \
                  mcspidevice(mixtable[translationfault(s[2])], 24);       \
   t[2] = k[2] ^       mixtable[setupcmdline(s[2])]      ^      \
                  mcspidevice(mixtable[exceptionupdates(s[1])], 8)  ^      \
                  mcspidevice(mixtable[iisv4resource(s[0])], 16) ^      \
                  mcspidevice(mixtable[translationfault(s[3])], 24);       \
   t[3] = k[3] ^       mixtable[setupcmdline(s[3])]      ^      \
                  mcspidevice(mixtable[exceptionupdates(s[2])], 8)  ^      \
                  mcspidevice(mixtable[iisv4resource(s[1])], 16) ^      \
                  mcspidevice(mixtable[translationfault(s[0])], 24);       \
} while (0);


#define AES_DEC_FINAL_ROUND(out, s, k, sbox) do {           \
   k -= 4;                                                  \
   out[0]  = (U8)((setupcmdline(k[0])) ^ sbox[setupcmdline(s[0])]); \
   out[1]  = (U8)((exceptionupdates(k[0])) ^ sbox[exceptionupdates(s[3])]); \
   out[2]  = (U8)((iisv4resource(k[0])) ^ sbox[iisv4resource(s[2])]); \
   out[3]  = (U8)((translationfault(k[0])) ^ sbox[translationfault(s[1])]); \
   out[4]  = (U8)((setupcmdline(k[1])) ^ sbox[setupcmdline(s[1])]); \
   out[5]  = (U8)((exceptionupdates(k[1])) ^ sbox[exceptionupdates(s[0])]); \
   out[6]  = (U8)((iisv4resource(k[1])) ^ sbox[iisv4resource(s[3])]); \
   out[7]  = (U8)((translationfault(k[1])) ^ sbox[translationfault(s[2])]); \
   out[8]  = (U8)((setupcmdline(k[2])) ^ sbox[setupcmdline(s[2])]); \
   out[9]  = (U8)((exceptionupdates(k[2])) ^ sbox[exceptionupdates(s[1])]); \
   out[10] = (U8)((iisv4resource(k[2])) ^ sbox[iisv4resource(s[0])]); \
   out[11] = (U8)((translationfault(k[2])) ^ sbox[translationfault(s[3])]); \
   out[12] = (U8)((setupcmdline(k[3])) ^ sbox[setupcmdline(s[3])]); \
   out[13] = (U8)((exceptionupdates(k[3])) ^ sbox[exceptionupdates(s[2])]); \
   out[14] = (U8)((iisv4resource(k[3])) ^ sbox[iisv4resource(s[1])]); \
   out[15] = (U8)((translationfault(k[3])) ^ sbox[translationfault(s[0])]); \
} while (0);


SHARKSSL_API void SharkSslAesCtx_decrypt(SharkSslAesCtx *registermcasp, const U8 updatecause[16], U8 enablehazard[16])
{
   U32 *K, S[4], T[4];
   U16  i;
   #if SHARKSSL_AES_SMALL_FOOTPRINT
   U16 j, z, y;
   #endif

   baAssert(registermcasp->nr > 0);
   i = registermcasp->nr;
   #if ((!SHARKSSL_AES_SMALL_FOOTPRINT) && SHARKSSL_AES_CIPHER_LOOP_UNROLL)
   K = &registermcasp->key[(i + 1) << 3];
   #else
   K = &registermcasp->key[(i + 1) << 2];
   #endif

   read64uint32(S[0], updatecause,  0); S[0] ^= K[0];
   read64uint32(S[1], updatecause,  4); S[1] ^= K[1];
   read64uint32(S[2], updatecause,  8); S[2] ^= K[2];
   read64uint32(S[3], updatecause, 12); S[3] ^= K[3];

   #if SHARKSSL_AES_SMALL_FOOTPRINT
   do
   {
      j = 3;
      do
      {
         T[j] = *(--K);
         for (z = 4, y = 0; z > 0; z--, y += 8)
         {
            U32 r = domainalways[(U8)(S[(j + z) & 3] >> (24 - y))];
            T[j] ^= mcspidevice(r, y);
         }
      } while (j--);

      S[0] = T[0]; S[1] = T[1]; S[2] = T[2]; S[3] = T[3];
   } while (--i);

   i = 0;
   K -= 4;
   for (j = 0; !(j & 4); j++)
   {
      for (z = 0, y = 24; !(z & 4); z++, y -= 8)
      {
         enablehazard[i++] = (U8)((K[j] >> y) ^ powerpdata[(U8)(T[((U8)(j - z)) & 3] >> y)]);
      }
   }

   #else
   #if SHARKSSL_AES_CIPHER_LOOP_UNROLL
   AES_DEC_ROUND(S, T, K, domainalways);
   #endif
   do
   {
      #if SHARKSSL_AES_CIPHER_LOOP_UNROLL
      AES_DEC_ROUND(T, S, K, domainalways);
      AES_DEC_ROUND(S, T, K, domainalways);

      #else
      AES_DEC_ROUND(S, T, K, domainalways);
      S[0] = T[0]; S[1] = T[1]; S[2] = T[2]; S[3] = T[3];
      #endif
   } while (--i);

   AES_DEC_FINAL_ROUND(enablehazard, T, K, powerpdata);
   #endif
}

#undef AES_DEC_ROUND
#undef AES_DEC_FINAL_ROUND
#endif  

#undef mcspidevice


#if SHARKSSL_ENABLE_AES_CBC
SHARKSSL_API void SharkSslAesCtx_cbc_encrypt(SharkSslAesCtx *registermcasp, U8 vect[16],
                                             const U8 *updatecause, U8 *enablehazard, U16 len)
{
   U8 *q = vect;

   baAssert(registermcasp);
   baAssert(vect);
   baAssert(updatecause);
   baAssert(enablehazard);
   baAssert((len & 0x0F) == 0);
   len &= ~0xF;
   while (len > 0)
   {
      #if SHARKSSL_UNALIGNED_ACCESS
      ((__sharkssl_packed U32*)enablehazard)[0] = ((__sharkssl_packed U32*)updatecause)[0] ^ ((__sharkssl_packed U32*)q)[0];
      ((__sharkssl_packed U32*)enablehazard)[1] = ((__sharkssl_packed U32*)updatecause)[1] ^ ((__sharkssl_packed U32*)q)[1];
      ((__sharkssl_packed U32*)enablehazard)[2] = ((__sharkssl_packed U32*)updatecause)[2] ^ ((__sharkssl_packed U32*)q)[2];
      ((__sharkssl_packed U32*)enablehazard)[3] = ((__sharkssl_packed U32*)updatecause)[3] ^ ((__sharkssl_packed U32*)q)[3];
      #else
      enablehazard[0]  = (U8)(updatecause[0]  ^ q[0]);
      enablehazard[1]  = (U8)(updatecause[1]  ^ q[1]);
      enablehazard[2]  = (U8)(updatecause[2]  ^ q[2]);
      enablehazard[3]  = (U8)(updatecause[3]  ^ q[3]);
      enablehazard[4]  = (U8)(updatecause[4]  ^ q[4]);
      enablehazard[5]  = (U8)(updatecause[5]  ^ q[5]);
      enablehazard[6]  = (U8)(updatecause[6]  ^ q[6]);
      enablehazard[7]  = (U8)(updatecause[7]  ^ q[7]);
      enablehazard[8]  = (U8)(updatecause[8]  ^ q[8]);
      enablehazard[9]  = (U8)(updatecause[9]  ^ q[9]);
      enablehazard[10] = (U8)(updatecause[10] ^ q[10]);
      enablehazard[11] = (U8)(updatecause[11] ^ q[11]);
      enablehazard[12] = (U8)(updatecause[12] ^ q[12]);
      enablehazard[13] = (U8)(updatecause[13] ^ q[13]);
      enablehazard[14] = (U8)(updatecause[14] ^ q[14]);
      enablehazard[15] = (U8)(updatecause[15] ^ q[15]);
      #endif
      SharkSslAesCtx_encrypt(registermcasp, enablehazard, enablehazard);
      q  = enablehazard;
      updatecause  += 16;
      enablehazard += 16;
      len    -= 16;
   }

   memcpy(vect, q, 16);
}


SHARKSSL_API void SharkSslAesCtx_cbc_decrypt(SharkSslAesCtx *registermcasp, U8 vect[16],
                                             const U8 *updatecause, U8 *enablehazard, U16 len)
{
   U8 rememberstate[16];
   const U8 *q;

   rememberstate[0]=0; 
   baAssert(registermcasp);
   baAssert(updatecause);
   baAssert(enablehazard);
   baAssert((len & 0x0F) == 0);
   len &= ~0xF;

   if (0 == len)
   {
      return;
   }

   enablehazard += (len - 16);
   updatecause  += (len - 16);

   
   if (vect)
   {
      memcpy(rememberstate, updatecause, 16);
   }

   while (len > 0)
   {
      len -= 16;
      if (len)
      {
         q = updatecause - 16;
      }
      else if (vect)
      {
         q = vect;
      }
      else
      {
         return;
      }
      SharkSslAesCtx_decrypt(registermcasp, updatecause, enablehazard);
      updatecause = q;
      #if SHARKSSL_UNALIGNED_ACCESS
      ((__sharkssl_packed U32*)enablehazard)[0] ^= ((__sharkssl_packed U32*)q)[0];
      ((__sharkssl_packed U32*)enablehazard)[1] ^= ((__sharkssl_packed U32*)q)[1];
      ((__sharkssl_packed U32*)enablehazard)[2] ^= ((__sharkssl_packed U32*)q)[2];
      ((__sharkssl_packed U32*)enablehazard)[3] ^= ((__sharkssl_packed U32*)q)[3];
      #else
      enablehazard[0]  ^= q[0];
      enablehazard[1]  ^= q[1];
      enablehazard[2]  ^= q[2];
      enablehazard[3]  ^= q[3];
      enablehazard[4]  ^= q[4];
      enablehazard[5]  ^= q[5];
      enablehazard[6]  ^= q[6];
      enablehazard[7]  ^= q[7];
      enablehazard[8]  ^= q[8];
      enablehazard[9]  ^= q[9];
      enablehazard[10] ^= q[10];
      enablehazard[11] ^= q[11];
      enablehazard[12] ^= q[12];
      enablehazard[13] ^= q[13];
      enablehazard[14] ^= q[14];
      enablehazard[15] ^= q[15];
      #endif
      enablehazard -= 16;
   }

   baAssert(vect);
   memcpy(vect, rememberstate, 16);
}
#endif  


#if (SHARKSSL_ENABLE_AES_CTR_MODE)  
SHARKSSL_API void SharkSslAesCtx_ctr_mode(SharkSslAesCtx *registermcasp, U8 ctr[16],
                                          const U8 *updatecause, U8 *enablehazard, U16 len)
{
   U8 sossirecalc[16], k;

   baAssert(registermcasp);
   baAssert(ctr);
   baAssert(updatecause);
   baAssert(enablehazard);
   baAssert((len & 0x0F) == 0);

   len >>= 4;
   while (len--)
   {
      
      k = 0;
      #if (defined(B_LITTLE_ENDIAN) && SHARKSSL_UNALIGNED_ACCESS)
      while ((k < 4)  && (0 == ++((__sharkssl_packed U32*)ctr)[k]))
      #else
      while ((k < 16) && (0 == ++ctr[k]))
      #endif
      {
         k++;
      }

      
      SharkSslAesCtx_encrypt(registermcasp, ctr, sossirecalc);

      
      #if SHARKSSL_UNALIGNED_ACCESS
      ((__sharkssl_packed U32*)enablehazard)[0] = ((__sharkssl_packed U32*)updatecause)[0] ^ ((U32*)sossirecalc)[0];
      ((__sharkssl_packed U32*)enablehazard)[1] = ((__sharkssl_packed U32*)updatecause)[1] ^ ((U32*)sossirecalc)[1];
      ((__sharkssl_packed U32*)enablehazard)[2] = ((__sharkssl_packed U32*)updatecause)[2] ^ ((U32*)sossirecalc)[2];
      ((__sharkssl_packed U32*)enablehazard)[3] = ((__sharkssl_packed U32*)updatecause)[3] ^ ((U32*)sossirecalc)[3];
      #else
      enablehazard[0]  = (U8)(updatecause[0]  ^ sossirecalc[0]);
      enablehazard[1]  = (U8)(updatecause[1]  ^ sossirecalc[1]);
      enablehazard[2]  = (U8)(updatecause[2]  ^ sossirecalc[2]);
      enablehazard[3]  = (U8)(updatecause[3]  ^ sossirecalc[3]);
      enablehazard[4]  = (U8)(updatecause[4]  ^ sossirecalc[4]);
      enablehazard[5]  = (U8)(updatecause[5]  ^ sossirecalc[5]);
      enablehazard[6]  = (U8)(updatecause[6]  ^ sossirecalc[6]);
      enablehazard[7]  = (U8)(updatecause[7]  ^ sossirecalc[7]);
      enablehazard[8]  = (U8)(updatecause[8]  ^ sossirecalc[8]);
      enablehazard[9]  = (U8)(updatecause[9]  ^ sossirecalc[9]);
      enablehazard[10] = (U8)(updatecause[10] ^ sossirecalc[10]);
      enablehazard[11] = (U8)(updatecause[11] ^ sossirecalc[11]);
      enablehazard[12] = (U8)(updatecause[12] ^ sossirecalc[12]);
      enablehazard[13] = (U8)(updatecause[13] ^ sossirecalc[13]);
      enablehazard[14] = (U8)(updatecause[14] ^ sossirecalc[14]);
      enablehazard[15] = (U8)(updatecause[15] ^ sossirecalc[15]);
      #endif

      updatecause  += 16;
      enablehazard += 16;
   }
}
#endif


#if (SHARKSSL_ENABLE_AES_GCM || SHARKSSL_ENABLE_AES_CCM)

#define ntosd2nandflash(r, a, b, l)  do {  \
   register U16 debugstate = (U16)l;  \
   while (debugstate--) (r)[debugstate] = (a)[debugstate] ^ (b)[debugstate];  \
} while (0)


#if SHARKSSL_UNALIGNED_ACCESS

#define paz00wifikill(r, a, b)  do {  \
  ((__sharkssl_packed U32*)(r))[0] = ((__sharkssl_packed U32*)(a))[0] ^ ((__sharkssl_packed U32*)(b))[0];  \
  ((__sharkssl_packed U32*)(r))[1] = ((__sharkssl_packed U32*)(a))[1] ^ ((__sharkssl_packed U32*)(b))[1];  \
  ((__sharkssl_packed U32*)(r))[2] = ((__sharkssl_packed U32*)(a))[2] ^ ((__sharkssl_packed U32*)(b))[2];  \
  ((__sharkssl_packed U32*)(r))[3] = ((__sharkssl_packed U32*)(a))[3] ^ ((__sharkssl_packed U32*)(b))[3];  \
} while (0)

#else

#define paz00wifikill(r, a, b)   ntosd2nandflash(r, a, b, 16)

#endif
#endif  


#if SHARKSSL_ENABLE_AES_GCM
static const U16 serialsetup[16] =
{
    0x0000, 0x1C20, 0x3840, 0x2460,
    0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560,
    0x9180, 0x8da0, 0xa9c0, 0xb5e0
};


static void machinecheck(U8* X)
{
   U32 Z[4];
   U8  b;

   #if ((!defined(B_LITTLE_ENDIAN)) && (!defined(B_BIG_ENDIAN)))
   if (0x20 == (*(U8*)&serialsetup[1]))  
   #endif
   #ifndef B_BIG_ENDIAN
   {
      cleanupcount(Z[0], X, 0);
      cleanupcount(Z[1], X, 4);
      cleanupcount(Z[2], X, 8);
      cleanupcount(Z[3], X, 12);
   }
   #endif
   #if ((!defined(B_LITTLE_ENDIAN)) && (!defined(B_BIG_ENDIAN)))
   else
   #endif
   #ifndef B_LITTLE_ENDIAN
   {
      read64uint32(Z[0], X, 0);
      read64uint32(Z[1], X, 4);
      read64uint32(Z[2], X, 8);
      read64uint32(Z[3], X, 12);
   }
   #endif

   b = (U8)(Z[3] & 0x01);
   Z[3] >>= 1;
   if (Z[2] & 0x00000001)
   {
      Z[3] |= 0x80000000;
   }
   Z[2] >>= 1;
   if (Z[1] & 0x00000001)
   {
      Z[2] |= 0x80000000;
   }
   Z[1] >>= 1;
   if (Z[0] & 0x00000001)
   {
      Z[1] |= 0x80000000;
   }
   Z[0] >>= 1;
   if (b)
   {
      Z[0] ^= 0xE1000000;
   }

   #if ((!defined(B_LITTLE_ENDIAN)) && (!defined(B_BIG_ENDIAN)))
   if (0x20 == (*(U8*)&serialsetup[1]))  
   #endif
   #ifndef B_BIG_ENDIAN
   {
      hsotgpdata(Z[0], X, 0);
      hsotgpdata(Z[1], X, 4);
      hsotgpdata(Z[2], X, 8);
      hsotgpdata(Z[3], X, 12);
   }
   #endif
   #if ((!defined(B_LITTLE_ENDIAN)) && (!defined(B_BIG_ENDIAN)))
   else
   #endif
   #ifndef B_LITTLE_ENDIAN
   {
      inputlevel(Z[0], X, 0);
      inputlevel(Z[1], X, 4);
      inputlevel(Z[2], X, 8);
      inputlevel(Z[3], X, 12);
   }
   #endif
}


static void pcibiossetup(SharkSslAesGcmCtx *aes)
{
   U8 (*m)[16] = aes->M0;
   #if 0
   U8 i, j;
   #endif

   memset(m[0], 0, 16);
   memset(m[8], 0, 16);
   SharkSslAesCtx_encrypt((SharkSslAesCtx*)aes, m[8], m[8]);

   #ifndef B_BIG_ENDIAN
   #ifndef B_LITTLE_ENDIAN
   if (0x20 == (*(U8*)&serialsetup[1]))  
   #endif
   {
      U32 t;

      cleanupcount(t, (U8*)(&m[8]), 0);  inputlevel(t, m[8], 0);
      cleanupcount(t, (U8*)(&m[8]), 4);  inputlevel(t, m[8], 4);
      cleanupcount(t, (U8*)(&m[8]), 8);  inputlevel(t, m[8], 8);
      cleanupcount(t, (U8*)(&m[8]), 12); inputlevel(t, m[8], 12);
   }
   #endif

   memcpy(m[4], m[8], 16);
   machinecheck(m[4]);
   memcpy(m[2], m[4], 16);
   machinecheck(m[2]);
   memcpy(m[1], m[2], 16);
   machinecheck(m[1]);

   #if 1  
   memcpy(m[3],  m[2], 16);
   memcpy(m[5],  m[4], 16);
   memcpy(m[6],  m[4], 16);
   memcpy(m[7],  m[4], 16);
   memcpy(m[9],  m[8], 16);
   memcpy(m[10], m[8], 16);
   memcpy(m[11], m[8], 16);
   memcpy(m[12], m[8], 16);
   memcpy(m[13], m[8], 16);
   memcpy(m[14], m[8], 16);
   memcpy(m[15], m[8], 16);
   paz00wifikill(m[3],  m[3],  m[1]);
   paz00wifikill(m[5],  m[5],  m[1]);
   paz00wifikill(m[6],  m[6],  m[2]);
   paz00wifikill(m[7],  m[7],  m[3]);
   paz00wifikill(m[9],  m[9],  m[1]);
   paz00wifikill(m[10], m[10], m[2]);
   paz00wifikill(m[11], m[11], m[3]);
   paz00wifikill(m[12], m[12], m[4]);
   paz00wifikill(m[13], m[13], m[5]);
   paz00wifikill(m[14], m[14], m[6]);
   paz00wifikill(m[15], m[15], m[7]);

   #else
   for (i = 2; i <= 8; i <<= 1)
   {
      for (j = 1; j < i; j++)
      {
         memcpy(m[i+j], m[i], 16);
         paz00wifikill(m[i+j], m[i+j], m[j]);
      }
   }
   #endif
}


#define simplebuffer(c,x) audioplatdata(c->M0, x)
static void audioplatdata(U8 (*M0)[16], U8 *x)
{
    U32 Z[4];
    U8  i, a;

    Z[0] = Z[1] = Z[2] = Z[3] = 0;

    for (i = 15; ; i--)
    {
        paz00wifikill((U8*)&Z[0], (U8*)&Z[0], M0[x[i]&0xF]);
        a = (U8)(Z[3] & 0xF);
        Z[3] = (Z[3] >> 4) | (Z[2] << 28);
        Z[2] = (Z[2] >> 4) | (Z[1] << 28);
        Z[1] = (Z[1] >> 4) | (Z[0] << 28);
        Z[0] >>= 4;
        Z[0] ^= ((U32)serialsetup[a]) << 16;


        paz00wifikill((U8*)&Z[0], (U8*)&Z[0], M0[x[i]>>4]);
        if (i == 0) break;
        a = (U8)(Z[3] & 0xF);
        Z[3] = (Z[3] >> 4) | (Z[2] << 28);
        Z[2] = (Z[2] >> 4) | (Z[1] << 28);
        Z[1] = (Z[1] >> 4) | (Z[0] << 28);
        Z[0] >>= 4;
        Z[0] ^= ((U32)serialsetup[a]) << 16;
    }

    inputlevel(Z[0], x, 0);
    inputlevel(Z[1], x, 4);
    inputlevel(Z[2], x, 8);
    inputlevel(Z[3], x, 12);
}


SHARKSSL_API void SharkSslAesGcmCtx_constructor(SharkSslAesGcmCtx *registermcasp,
                                                const U8 *sourcerouting, U8 creategroup)
{
   SharkSslAesCtx_constructor((SharkSslAesCtx*)registermcasp, SharkSslAesCtx_Encrypt, sourcerouting, creategroup);
   pcibiossetup(registermcasp);
}


static int SharkSslAesGcmCtx_process(SharkSslAesGcmCtx *registermcasp,
                                     const U8 vect[12], U8 tag[16],
                                     const U8 *pmuv3event, U16 authlen,
                                     const U8 *updatecause, U8 *enablehazard, U16 len,
                                     SharkSslAesCtx_Type rightsvalid)
{
   U8 remapiospace[16], sossirecalc[16], tagi[16];
   U32 alen, pxafbmodes;

   baAssert(registermcasp);
   baAssert(vect);
   baAssert(tag);
   baAssert(updatecause);
   baAssert(enablehazard);

   alen = ((U32)authlen << 3);  
   pxafbmodes = ((U32)len << 3);      

   memset(&tagi[0], 0, 16);
   if (pmuv3event)
   {
      
      while (authlen)
      {
         if (authlen >= 16)
         {
            paz00wifikill(tagi, tagi, pmuv3event);  
            pmuv3event += 16;
            authlen -= 16;
         }
         else
         {
            ntosd2nandflash(tagi, tagi, pmuv3event, authlen);  
            authlen = 0;
         }
         simplebuffer(registermcasp, tagi);
      }
   }

   memcpy(&remapiospace[0], vect, 12);
   inputlevel(1, remapiospace, 12);  

   while (len)
   {
      
      #if (defined(B_LITTLE_ENDIAN) && (SHARKSSL_UNALIGNED_ACCESS))
      *(__sharkssl_packed U32*)&remapiospace[12] = blockarray(1 + blockarray(*(__sharkssl_packed U32*)&remapiospace[12]));
      #elif (defined(B_BIG_ENDIAN) && (SHARKSSL_UNALIGNED_ACCESS))
      *(__sharkssl_packed U32*)&remapiospace[12] = 1 + (*(__sharkssl_packed U32*)&remapiospace[12]);
      #else
      if ((0 == ++remapiospace[15]) && (0 == ++remapiospace[14]) && (0 == ++remapiospace[13]))
      {
         remapiospace[12]++;
      }
      #endif

      
      SharkSslAesCtx_encrypt((SharkSslAesCtx*)registermcasp, remapiospace, sossirecalc);

      
      if (len >= 16)
      {
         if (SharkSslAesCtx_Encrypt == rightsvalid)
         {
            paz00wifikill(enablehazard, updatecause, sossirecalc);
            paz00wifikill(tagi, tagi, enablehazard);
         }
         else
         {
            paz00wifikill(tagi, tagi, updatecause);
            paz00wifikill(enablehazard, updatecause, sossirecalc);
         }

         updatecause  += 16;
         enablehazard += 16;
         len -= 16;
      }
      else
      {
         if (SharkSslAesCtx_Encrypt == rightsvalid)
         {
            ntosd2nandflash(enablehazard, updatecause, sossirecalc, len);
            ntosd2nandflash(tagi, tagi, enablehazard, len);
         }
         else
         {
            ntosd2nandflash(tagi, tagi, updatecause, len);
            ntosd2nandflash(enablehazard, updatecause, sossirecalc, len);
         }
         len = 0;
      }

      simplebuffer(registermcasp, tagi);
   }

   
   inputlevel(0,    sossirecalc, 0);
   inputlevel(alen, sossirecalc, 4);
   inputlevel(0,    sossirecalc, 8);
   inputlevel(pxafbmodes, sossirecalc, 12);
   paz00wifikill(tagi, tagi, sossirecalc);
   simplebuffer(registermcasp, tagi);

   
   inputlevel(1, remapiospace, 12);
   SharkSslAesCtx_encrypt((SharkSslAesCtx*)registermcasp, remapiospace, sossirecalc);
   if (SharkSslAesCtx_Encrypt == rightsvalid)
   {
      paz00wifikill(tag, tagi, sossirecalc);
   }
   else
   {
      paz00wifikill(tagi, tagi, sossirecalc);
      return sharkssl_kmemcmp(tagi, tag, 16);
   }
   return 0;
}


SHARKSSL_API int SharkSslAesGcmCtx_encrypt(SharkSslAesGcmCtx *registermcasp,
                                           const U8 vect[12], U8 panickernel[16],
                                           const U8 *pmuv3event, U16 authlen,
                                           const U8 *updatecause, U8 *enablehazard, U16 len)
{
   return SharkSslAesGcmCtx_process(registermcasp, vect, panickernel, pmuv3event, authlen, updatecause, enablehazard, len, SharkSslAesCtx_Encrypt);
}


SHARKSSL_API int SharkSslAesGcmCtx_decrypt(SharkSslAesGcmCtx *registermcasp,
                                           const U8 vect[12], U8 directionoutput[16],
                                           const U8 *pmuv3event, U16 authlen,
                                           U8 *updatecause, U8 *enablehazard, U16 len)
{
   return SharkSslAesGcmCtx_process(registermcasp, vect, directionoutput, pmuv3event, authlen, updatecause, enablehazard, len, SharkSslAesCtx_Decrypt);
}
#endif  


#if SHARKSSL_ENABLE_AES_CCM
SHARKSSL_API void SharkSslAesCcmCtx_constructor(SharkSslAesCcmCtx *registermcasp,
                                                const U8 *sourcerouting, U8 creategroup, U8 requestarray)
{
   SharkSslAesCtx_constructor((SharkSslAesCtx*)registermcasp, SharkSslAesCtx_Encrypt, sourcerouting, creategroup);
   baAssert((requestarray == 8) || (requestarray == 16));
   registermcasp->tagLen = requestarray;
}


#ifndef SHARKSSL_ENABLE_CCM_AUTH_ALL
#define SHARKSSL_ENABLE_CCM_AUTH_ALL  0  
#endif

static int SharkSslAesCcmCtx_process(SharkSslAesCcmCtx *registermcasp,
                                     const U8 vect[12], U8 *tag,
                                     const U8 *pmuv3event, U16 authlen,
                                     const U8 *updatecause, U8 *enablehazard, U16 len,
                                     SharkSslAesCtx_Type rightsvalid)
{
   U8 remapiospace[16], sossirecalc[16], tagi[16];

   baAssert(registermcasp);
   baAssert(vect);
   baAssert(tag);
   baAssert(updatecause);
   baAssert(enablehazard);

   
   inputlevel((U32)len, remapiospace, 12);
   memcpy(&remapiospace[1], vect, 12);
   remapiospace[0] = (8 * ((registermcasp->tagLen >> 1) - 1))  + (3 - 1); 

   if ((pmuv3event) && (authlen))
   {
      remapiospace[0] += 64;
      SharkSslAesCtx_encrypt((SharkSslAesCtx*)registermcasp, remapiospace, tagi);  

      baAssert(authlen < 0xFEFF);
      remapiospace[0] = (U8)((authlen >> 8) & 0xFF);
      remapiospace[1] = (U8)(authlen & 0xFF);
      #if SHARKSSL_ENABLE_CCM_AUTH_ALL
      if (authlen < 15)
      #else
      baAssert(authlen < 15);
      #endif
      {
         memcpy(&remapiospace[2], pmuv3event, authlen);
         memset(&remapiospace[2 + authlen], 0, 14 - authlen);
      }
      #if SHARKSSL_ENABLE_CCM_AUTH_ALL
      else
      {
         memcpy(&remapiospace[2], pmuv3event, 14);
         pmuv3event += 14;
         authlen -= 14;
      }
      #endif
      paz00wifikill(tagi, tagi, remapiospace);
      SharkSslAesCtx_encrypt((SharkSslAesCtx*)registermcasp, tagi, tagi);  

      #if SHARKSSL_ENABLE_CCM_AUTH_ALL
      while (authlen)
      {
         if (authlen >= 16)
         {
            paz00wifikill(tagi, tagi, pmuv3event);  
            pmuv3event += 16;
            authlen -= 16;
         }
         else
         {
            ntosd2nandflash(tagi, tagi, pmuv3event, authlen);  
            authlen = 0;
         }
         SharkSslAesCtx_encrypt((SharkSslAesCtx*)registermcasp, tagi, tagi);
      }
      #endif
   }

   inputlevel(0, remapiospace, 12);  
   memcpy(&remapiospace[1], vect, 12);
   remapiospace[0] = (3 - 1);  

   while (len)
   {
      
      #if (defined(B_LITTLE_ENDIAN) && (SHARKSSL_UNALIGNED_ACCESS))
      *(__sharkssl_packed U32*)&remapiospace[12] = blockarray(1 + blockarray(*(__sharkssl_packed U32*)&remapiospace[12]));
      #elif (defined(B_BIG_ENDIAN) && (SHARKSSL_UNALIGNED_ACCESS))
      *(__sharkssl_packed U32*)&remapiospace[12] = 1 + (*(__sharkssl_packed U32*)&remapiospace[12]);
      #else
      if ((0 == ++remapiospace[15]) && (0 == ++remapiospace[14]) && (0 == ++remapiospace[13]))
      {
         remapiospace[12]++;
      }
      #endif

      
      SharkSslAesCtx_encrypt((SharkSslAesCtx*)registermcasp, remapiospace, sossirecalc);

      
      if (len >= 16)
      {
         if (SharkSslAesCtx_Encrypt == rightsvalid)
         {
            paz00wifikill(tagi, tagi, updatecause);
            paz00wifikill(enablehazard, updatecause, sossirecalc);
         }
         else
         {
            paz00wifikill(enablehazard, updatecause, sossirecalc);
            paz00wifikill(tagi, tagi, enablehazard);
         }

         updatecause  += 16;
         enablehazard += 16;
         len -= 16;
      }
      else
      {
         if (SharkSslAesCtx_Encrypt == rightsvalid)
         {
            ntosd2nandflash(tagi, tagi, updatecause, len);
            ntosd2nandflash(enablehazard, updatecause, sossirecalc, len);
         }
         else
         {
            ntosd2nandflash(enablehazard, updatecause, sossirecalc, len);
            ntosd2nandflash(tagi, tagi, enablehazard, len);
         }
         len = 0;
      }

      
      SharkSslAesCtx_encrypt((SharkSslAesCtx*)registermcasp, tagi, tagi);
   }

   
   remapiospace[13] =  remapiospace[14] = remapiospace[15] = 0;
   SharkSslAesCtx_encrypt((SharkSslAesCtx*)registermcasp, remapiospace, sossirecalc);
   if (SharkSslAesCtx_Encrypt == rightsvalid)
   {
      ntosd2nandflash(tag, tagi, sossirecalc, registermcasp->tagLen);
   }
   else
   {
      paz00wifikill(tagi, tagi, sossirecalc);
      return sharkssl_kmemcmp(tagi, tag, registermcasp->tagLen);
   }
   return 0;
}


SHARKSSL_API int SharkSslAesCcmCtx_encrypt(SharkSslAesCcmCtx *registermcasp,
                                           const U8 vect[12], U8 *panickernel,
                                           const U8 *pmuv3event, U16 authlen,
                                           const U8 *updatecause, U8 *enablehazard, U16 len)
{
   return SharkSslAesCcmCtx_process(registermcasp, vect, panickernel, pmuv3event, authlen, updatecause, enablehazard, len, SharkSslAesCtx_Encrypt);
}


SHARKSSL_API int SharkSslAesCcmCtx_decrypt(SharkSslAesCcmCtx *registermcasp,
                                           const U8 vect[12], U8 *directionoutput,
                                           const U8 *pmuv3event, U16 authlen,
                                           const U8 *updatecause, U8 *enablehazard, U16 len)
{
   return SharkSslAesCcmCtx_process(registermcasp, vect, directionoutput, pmuv3event, authlen, updatecause, enablehazard, len, SharkSslAesCtx_Decrypt);
}
#endif  
#endif


#ifndef BA_LIB
#define BA_LIB
#endif

#include "SharkSslASN1.h"

#include "SharkSslCrypto.h"
#if SHARKSSL_USE_ECC

#endif
#include <string.h>

#ifndef EXT_SHARK_LIB
#define sharkStrstr strstr
#endif

#define SHARKSSL_DIM_ARR(a)  (sizeof(a)/sizeof(a[0]))

#if SHARKSSL_USE_ECC
#if   SHARKSSL_ECC_USE_SECP521R1
#define SHARKSSL_MAX_ECC_POINTLEN  SHARKSSL_SECP521R1_POINTLEN
#elif SHARKSSL_ECC_USE_BRAINPOOLP512R1
#define SHARKSSL_MAX_ECC_POINTLEN  SHARKSSL_BRAINPOOLP512R1_POINTLEN
#elif SHARKSSL_ECC_USE_SECP384R1
#define SHARKSSL_MAX_ECC_POINTLEN  SHARKSSL_SECP384R1_POINTLEN
#elif SHARKSSL_ECC_USE_BRAINPOOLP384R1
#define SHARKSSL_MAX_ECC_POINTLEN  SHARKSSL_BRAINPOOLP384R1_POINTLEN
#elif SHARKSSL_ECC_USE_SECP256R1
#define SHARKSSL_MAX_ECC_POINTLEN  SHARKSSL_SECP256R1_POINTLEN
#elif SHARKSSL_ECC_USE_BRAINPOOLP256R1
#define SHARKSSL_MAX_ECC_POINTLEN  SHARKSSL_BRAINPOOLP256R1_POINTLEN
#else
#define SHARKSSL_MAX_ECC_POINTLEN  0
#endif
#endif


#if (((SHARKSSL_SSL_CLIENT_CODE || SHARKSSL_SSL_SERVER_CODE) && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)) ||  \
     (SHARKSSL_ENABLE_CERTSTORE_API) || (SHARKSSL_ENABLE_PEM_API))

#define ALGO_ID_UNKNOWN                    processsdccr
#define ALGO_ID_SHA512                     batterythread
#define ALGO_ID_SHA384                     probewrite
#define ALGO_ID_SHA256                     domainnumber
#define ALGO_ID_SHA1                       presentpages
#define ALGO_ID_MD5                        skciphercreate
#define ALGO_ID_MD2                        0x0F
#define ALGO_ID_PKCS5_PBES2                0x9A  
#define ALGO_ID_PKCS5_PBKDF2               0x9B  

#define ALGO_ID_RSA_ENCRYPTION             entryearly
#define ALGO_ID_ECDSA                      accessactive
#define ALGO_ID_HMAC                       0x08  

#define ALGO_ID_SHA512_WITH_RSA_ENCRYPTION ((ALGO_ID_RSA_ENCRYPTION << 4) | ALGO_ID_SHA512)
#define ALGO_ID_SHA384_WITH_RSA_ENCRYPTION ((ALGO_ID_RSA_ENCRYPTION << 4) | ALGO_ID_SHA384)
#define ALGO_ID_SHA256_WITH_RSA_ENCRYPTION ((ALGO_ID_RSA_ENCRYPTION << 4) | ALGO_ID_SHA256)
#define ALGO_ID_SHA1_WITH_RSA_ENCRYPTION   ((ALGO_ID_RSA_ENCRYPTION << 4) | ALGO_ID_SHA1)
#define ALGO_ID_MD5_WITH_RSA_ENCRYPTION    ((ALGO_ID_RSA_ENCRYPTION << 4) | ALGO_ID_MD5)
#define ALGO_ID_MD2_WITH_RSA_ENCRYPTION    ((ALGO_ID_RSA_ENCRYPTION << 4) | ALGO_ID_MD2)

#define ALGO_ID_ECDSA_WITH_SHA512          ((ALGO_ID_ECDSA << 4) | ALGO_ID_SHA512)
#define ALGO_ID_ECDSA_WITH_SHA384          ((ALGO_ID_ECDSA << 4) | ALGO_ID_SHA384)
#define ALGO_ID_ECDSA_WITH_SHA256          ((ALGO_ID_ECDSA << 4) | ALGO_ID_SHA256)
#define ALGO_ID_ECDSA_WITH_SHA1            ((ALGO_ID_ECDSA << 4) | ALGO_ID_SHA1)

#define ALGO_ID_HMAC_WITH_SHA256           ((ALGO_ID_HMAC << 4) | ALGO_ID_SHA256)

#define GET_ALGO_HASH_ID(id)               (id & 0x0F)
#define GET_ALGO_SIGNATURE_ID(id)          ((id & 0xF0) >> 4)

#define ALGO_ID_AES_128_CBC                0xE1  
#define ALGO_ID_AES_256_CBC                0xE2  
#define ALGO_ID_CHACHA20                   0xE4  


U8 SharkSslParseASN1_getAlgoID(const SharkSslParseASN1 *o)
{
   switch (o->datalen)
   {
      case 9:
         #if SHARKSSL_ENABLE_RSA
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_rsaEncryption, SHARKSSL_DIM_ARR(sharkssl_oid_rsaEncryption)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_rsaEncryption));  
            return ALGO_ID_RSA_ENCRYPTION;
         }
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_md2withRSAEncryption, SHARKSSL_DIM_ARR(sharkssl_oid_md2withRSAEncryption)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_md2withRSAEncryption));  
            return ALGO_ID_MD2_WITH_RSA_ENCRYPTION;
         }
         #if SHARKSSL_USE_MD5
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_md5withRSAEncryption, SHARKSSL_DIM_ARR(sharkssl_oid_md5withRSAEncryption)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_md5withRSAEncryption));  
            return ALGO_ID_MD5_WITH_RSA_ENCRYPTION;
         }
         #endif
         
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_sha1withRSAEncryption, SHARKSSL_DIM_ARR(sharkssl_oid_sha1withRSAEncryption)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_sha1withRSAEncryption));  
            return ALGO_ID_SHA1_WITH_RSA_ENCRYPTION;
         }
         #if SHARKSSL_USE_SHA_256
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_sha256withRSAEncryption, SHARKSSL_DIM_ARR(sharkssl_oid_sha256withRSAEncryption)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_sha256withRSAEncryption));  
            return ALGO_ID_SHA256_WITH_RSA_ENCRYPTION;
         }
         #endif
         #if SHARKSSL_USE_SHA_384
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_sha384withRSAEncryption, SHARKSSL_DIM_ARR(sharkssl_oid_sha384withRSAEncryption)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_sha384withRSAEncryption));  
            return ALGO_ID_SHA384_WITH_RSA_ENCRYPTION;
         }
         #endif
         #if SHARKSSL_USE_SHA_512
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_sha512withRSAEncryption, SHARKSSL_DIM_ARR(sharkssl_oid_sha512withRSAEncryption)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_sha512withRSAEncryption));  
            return ALGO_ID_SHA512_WITH_RSA_ENCRYPTION;
         }
         #endif
         #endif  

         #if SHARKSSL_USE_SHA_256
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_sha256, SHARKSSL_DIM_ARR(sharkssl_oid_sha256)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_sha256));  
            return ALGO_ID_SHA256;
         }
         #endif
         #if SHARKSSL_USE_SHA_384
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_sha384, SHARKSSL_DIM_ARR(sharkssl_oid_sha384)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_sha384));  
            return ALGO_ID_SHA384;
         }
         #endif
         #if SHARKSSL_USE_SHA_512
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_sha512, SHARKSSL_DIM_ARR(sharkssl_oid_sha512)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_sha512));  
            return ALGO_ID_SHA512;
         }
         #endif
         #if SHARKSSL_ENABLE_ENCRYPTED_PKCS8_SUPPORT
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_pkcs5PBES2, SHARKSSL_DIM_ARR(sharkssl_oid_pkcs5PBES2)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_pkcs5PBES2));  
            return ALGO_ID_PKCS5_PBES2;
         }
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_pkcs5PBKDF2, SHARKSSL_DIM_ARR(sharkssl_oid_pkcs5PBKDF2)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_pkcs5PBKDF2));  
            return ALGO_ID_PKCS5_PBKDF2;
         }
         #if (SHARKSSL_USE_AES_128 && SHARKSSL_ENABLE_AES_CBC)
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_aes128cbc, SHARKSSL_DIM_ARR(sharkssl_oid_aes128cbc)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_aes128cbc));  
            return ALGO_ID_AES_128_CBC;
         }
         #endif
         #if (SHARKSSL_USE_AES_256 && SHARKSSL_ENABLE_AES_CBC)
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_aes256cbc, SHARKSSL_DIM_ARR(sharkssl_oid_aes256cbc)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_aes256cbc));  
            return ALGO_ID_AES_256_CBC;
         }
         #endif
         #endif
         break;

      case 8:
         #if SHARKSSL_USE_MD5
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_md5, SHARKSSL_DIM_ARR(sharkssl_oid_md5)))
         {
            baAssert(8 == SHARKSSL_DIM_ARR(sharkssl_oid_md5));  
            return ALGO_ID_MD5;
         }
         #endif
         #if SHARKSSL_ENABLE_ECDSA
         #if SHARKSSL_USE_SHA_256
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_ecdsaWithSHA256, SHARKSSL_DIM_ARR(sharkssl_oid_ecdsaWithSHA256)))
         {
            baAssert(8 == SHARKSSL_DIM_ARR(sharkssl_oid_ecdsaWithSHA256));  
            return ALGO_ID_ECDSA_WITH_SHA256;
         }
         #endif
         #if SHARKSSL_USE_SHA_384
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_ecdsaWithSHA384, SHARKSSL_DIM_ARR(sharkssl_oid_ecdsaWithSHA384)))
         {
            baAssert(8 == SHARKSSL_DIM_ARR(sharkssl_oid_ecdsaWithSHA384));  
            return ALGO_ID_ECDSA_WITH_SHA384;
         }
         #endif
         #if SHARKSSL_USE_SHA_512
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_ecdsaWithSHA512, SHARKSSL_DIM_ARR(sharkssl_oid_ecdsaWithSHA512)))
         {
            baAssert(8 == SHARKSSL_DIM_ARR(sharkssl_oid_ecdsaWithSHA512));  
            return ALGO_ID_ECDSA_WITH_SHA512;
         }
         #endif
         #endif  
         #if SHARKSSL_ENABLE_ENCRYPTED_PKCS8_SUPPORT
         #if SHARKSSL_USE_SHA_256
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_HMACWithSHA256, SHARKSSL_DIM_ARR(sharkssl_oid_HMACWithSHA256)))
         {
            baAssert(8 == SHARKSSL_DIM_ARR(sharkssl_oid_HMACWithSHA256));  
            return ALGO_ID_HMAC_WITH_SHA256;
         }
         #endif
         #endif
         break;

      #if SHARKSSL_USE_ECC
      case 7:
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_ecPublicKey, SHARKSSL_DIM_ARR(sharkssl_oid_ecPublicKey)))
         {
            baAssert(7 == SHARKSSL_DIM_ARR(sharkssl_oid_ecPublicKey));  
            return ALGO_OID_EC_PUBLIC_KEY;
         }
         #if SHARKSSL_ENABLE_ECDSA
         #if SHARKSSL_USE_SHA1
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_ecdsaWithSHA1, SHARKSSL_DIM_ARR(sharkssl_oid_ecdsaWithSHA1)))
         {
            baAssert(7 == SHARKSSL_DIM_ARR(sharkssl_oid_ecdsaWithSHA1));  
            return ALGO_ID_ECDSA_WITH_SHA1;
         }
         #endif
         #endif
         break;
      #endif  

      #if SHARKSSL_USE_SHA1
      case 5:
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_sha1, SHARKSSL_DIM_ARR(sharkssl_oid_sha1)))
         {
            baAssert(5 == SHARKSSL_DIM_ARR(sharkssl_oid_sha1));  
            return ALGO_ID_SHA1;
         }
         break;
      #endif

      default:
         break;
   }

   return ALGO_ID_UNKNOWN;
}


#if SHARKSSL_USE_ECC
U8 controllerregister(U16 defaultsdhci1)
{
   
   switch (defaultsdhci1)
   {
      #if SHARKSSL_ECC_USE_SECP256R1
      case SHARKSSL_EC_CURVE_ID_SECP256R1:
         return SHARKSSL_SECP256R1_POINTLEN;
      #endif

      #if SHARKSSL_ECC_USE_SECP384R1
      case SHARKSSL_EC_CURVE_ID_SECP384R1:
         return SHARKSSL_SECP384R1_POINTLEN;
      #endif

      #if SHARKSSL_ECC_USE_SECP521R1
      case SHARKSSL_EC_CURVE_ID_SECP521R1:
         return SHARKSSL_SECP521R1_POINTLEN;
      #endif

      #if SHARKSSL_ECC_USE_BRAINPOOLP256R1
      case SHARKSSL_EC_CURVE_ID_BRAINPOOLP256R1:
         return SHARKSSL_BRAINPOOLP256R1_POINTLEN;
      #endif

      #if SHARKSSL_ECC_USE_BRAINPOOLP384R1
      case SHARKSSL_EC_CURVE_ID_BRAINPOOLP384R1:
         return SHARKSSL_BRAINPOOLP384R1_POINTLEN;
      #endif

      #if SHARKSSL_ECC_USE_BRAINPOOLP512R1
      case SHARKSSL_EC_CURVE_ID_BRAINPOOLP512R1:
         return SHARKSSL_BRAINPOOLP512R1_POINTLEN;
      #endif

      default:
         break;
   }

   return 0;
}


U8 SharkSslParseASN1_getCurveID(const SharkSslParseASN1 *o)
{
   switch (o->datalen)
   {
      case 5:
         #if SHARKSSL_ECC_USE_SECP384R1
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_secp384r1, SHARKSSL_DIM_ARR(sharkssl_oid_secp384r1)))
         {
            baAssert(5 == SHARKSSL_DIM_ARR(sharkssl_oid_secp384r1));  
            return SHARKSSL_EC_CURVE_ID_SECP384R1;
         }
         #endif
         #if SHARKSSL_ECC_USE_SECP521R1
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_secp521r1, SHARKSSL_DIM_ARR(sharkssl_oid_secp521r1)))
         {
            baAssert(5 == SHARKSSL_DIM_ARR(sharkssl_oid_secp521r1));  
            return SHARKSSL_EC_CURVE_ID_SECP521R1;
         }
         #endif
         break;

      case 8:
         #if SHARKSSL_ECC_USE_SECP256R1
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_prime256v1, SHARKSSL_DIM_ARR(sharkssl_oid_prime256v1)))
         {
            baAssert(8 == SHARKSSL_DIM_ARR(sharkssl_oid_prime256v1));  
            return SHARKSSL_EC_CURVE_ID_SECP256R1;
         }
         #endif
         break;

      case 9:
         #if SHARKSSL_ECC_USE_BRAINPOOLP256R1
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_brainpoolP256r1, SHARKSSL_DIM_ARR(sharkssl_oid_brainpoolP256r1)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_brainpoolP256r1));  
            return SHARKSSL_EC_CURVE_ID_BRAINPOOLP256R1;
         }
         #endif
         #if SHARKSSL_ECC_USE_BRAINPOOLP384R1
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_brainpoolP384r1, SHARKSSL_DIM_ARR(sharkssl_oid_brainpoolP384r1)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_brainpoolP384r1));  
            return SHARKSSL_EC_CURVE_ID_BRAINPOOLP384R1;
         }
         #endif
         #if SHARKSSL_ECC_USE_BRAINPOOLP512R1
         if (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_brainpoolP512r1, SHARKSSL_DIM_ARR(sharkssl_oid_brainpoolP512r1)))
         {
            baAssert(9 == SHARKSSL_DIM_ARR(sharkssl_oid_brainpoolP512r1));  
            return SHARKSSL_EC_CURVE_ID_BRAINPOOLP512R1;
         }
         #endif
         break;

      default:
         break;
   }

   return SHARKSSL_EC_CURVE_ID_UNKNOWN;
}
#endif
#endif


#if (((SHARKSSL_SSL_CLIENT_CODE || SHARKSSL_SSL_SERVER_CODE) && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)) || \
     (SHARKSSL_ENABLE_CERTSTORE_API))
static int sha256final(SharkSslParseASN1 *o)
{
   if (o->len < 1)
   {
      return -1;
   }

   o->datalen = 0;

   
   if (*(o->ptr) != 0xA0)  
   {
      return 0;
   }
   o->ptr++;
   o->len--;

   if (SharkSslParseASN1_getLength(o) < 0)
   {
      return -1;
   }
   if ((SharkSslParseASN1_getInt(o) < 0) || (o->datalen > 4))
   {
      return -1;
   }

   return 0;
}


static int deltacamera(SharkSslParseASN1 *o, SharkSslCertDN *dn)
{
   U8 *end, attrib, rightsvalid;
   int l;

   if ((l = SharkSslParseASN1_getSequence(o)) < 0)
   {
      return -1;
   }
   end = o->ptr + l;

   memset(dn, 0, sizeof(SharkSslCertDN));
   while (o->ptr < end)
   {
      SharkSslParseASN1_getSet(o);
      if ((SharkSslParseASN1_getSequence(o) < 0) || (o->ptr >= end) ||
          (*(o->ptr++) != SHARKSSL_ASN1_OID) ||
          ((l = SharkSslParseASN1_getLength(o)) < 0) || (o->len < 2))
      {
         return -1;
      }
      o->len--;

      attrib = 0;
      if (*(o->ptr) != SHARKSSL_OID_JIIT_DS)
      {
         attrib = 1;
         if (*(o->ptr) == sharkssl_oid_emailAddress[0])
         {
            attrib++;
         }
      }
      o->ptr++;
      o->len--;
      if (0 == attrib)
      {
         if (*(o->ptr++) != SHARKSSL_OID_JIIT_DS_ATTRTYPE)
         {
            attrib = 1;
         }
         o->len--;
      }
      if (attrib)
      {
         attrib = (U8)sharkssl_kmemcmp(o->ptr, &sharkssl_oid_emailAddress[1], (int)(SHARKSSL_DIM_ARR(sharkssl_oid_emailAddress) - 1));
         o->ptr += (U32)l;
         o->len -= (U32)l;
         if ((l = SharkSslParseASN1_getLength(o)) < 0)
         {
            return -1;
         }
         if (0 == attrib)
         {
            dn->emailAddress = o->ptr;
            dn->emailAddressLen = (U8)l;
         }
         o->ptr += (U32)l;
         o->len -= (U32)l;
         continue;
      }

      if (l != 3)
      {
         return -1;
      }

      attrib  = *(o->ptr++);
      rightsvalid    = *(o->ptr++);
      o->len -= 2;
      if ((l = SharkSslParseASN1_getLength(o)) < 0)
      {
         return -1;  
      }

      if (l > 0xFF)  
      {
         return -1;  
      }

      if ((rightsvalid == SHARKSSL_ASN1_UTF8_STRING) || (rightsvalid == SHARKSSL_ASN1_PRINTABLE_STRING) || (rightsvalid == SHARKSSL_ASN1_T61_STRING) ||
          (rightsvalid == SHARKSSL_ASN1_IA5_STRING) || (rightsvalid == SHARKSSL_ASN1_BMP_STRING))
      {
         switch (attrib)
         {
            case SHARKSSL_OID_JIIT_DS_ATTRTYPE_CN:
               dn->commonName = o->ptr;
               dn->commonNameLen = (U8)l;
               break;

            case SHARKSSL_OID_JIIT_DS_ATTRTYPE_COUNTRY:
               dn->countryName = o->ptr;
               dn->countryNameLen = (U8)l;
               break;

            case SHARKSSL_OID_JIIT_DS_ATTRTYPE_LOCALITY:
               dn->locality = o->ptr;
               dn->localityLen = (U8)l;
               break;

            case SHARKSSL_OID_JIIT_DS_ATTRTYPE_PROVINCE:
               dn->province = o->ptr;
               dn->provinceLen = (U8)l;
               break;

            case SHARKSSL_OID_JIIT_DS_ATTRTYPE_ORGANIZATION:
               dn->organization = o->ptr;
               dn->organizationLen = (U8)l;
               break;

            case SHARKSSL_OID_JIIT_DS_ATTRTYPE_UNIT:
               dn->unit = o->ptr;
               dn->unitLen = (U8)l;
               break;

            default:
               break;
         }
      }
      o->ptr += (U32)l;
      o->len -= (U32)l;
   }

   return 0;
}
#endif


#if ((SHARKSSL_SSL_CLIENT_CODE && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)) || \
     (SHARKSSL_SSL_SERVER_CODE) || (SHARKSSL_ENABLE_CSR_SIGNING))

int spromregister(SharkSslCertParam *o, const U8 *p, U32 len, U8 *doublefnmul)
{
   SharkSslParseASN1 parseCert, parseBitString;
   U8 *pTemp, tag;
   U32 probealchemy = 0;
   int l, v;

   baAssert((doublefnmul == (void*)0) || ((U32)-1 == len) || ((U32)-2 == len) || ((U32)-3 == len) || ((U32)-4 == len));

   parseCert.ptr = (U8*)p;
   #if (SHARKSSL_ENABLE_CSR_SIGNING)
   if ((U32)-4 == len)  
   {
      parseCert.len = *(U32*)doublefnmul;
   }
   else
   #endif
   {
      parseCert.len = len;
   }

   if ((l = SharkSslParseASN1_getSequence(&parseCert)) < 0)
   {
      return -1;    
   }

   
   pTemp = parseCert.ptr;

   if ((l = SharkSslParseASN1_getSequence(&parseCert)) < 0)
   {
      return -1;    
   }

   
   parseBitString.len = parseCert.len - (U32)l;
   parseBitString.ptr = parseCert.ptr + (U32)l;
   if (SharkSslParseASN1_getSequence(&parseBitString) < 0)
   {
      return -1;
   }
   if (SharkSslParseASN1_getOID(&parseBitString) < 0)
   {
      return -1;
   }
   
   tag = SharkSslParseASN1_getAlgoID(&parseBitString);

   if ((doublefnmul == (void*)0) && ((U32)-1 == len))  
   {
      baAssert(!o);
      return ((U16)(GET_ALGO_HASH_ID(tag)) << 8) + GET_ALGO_SIGNATURE_ID(tag);
   }

   #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI)
   if ((doublefnmul != (void*)0) && ((U32)-3 == len))  
   {
      *(int*)doublefnmul = ((U16)(GET_ALGO_HASH_ID(tag)) << 8) + GET_ALGO_SIGNATURE_ID(tag);
      goto SharkSslCertParam_parseCert_1;
   }
   #endif

   #if (SHARKSSL_ENABLE_CLIENT_AUTH || SHARKSSL_ENABLE_CSR_SIGNING)
   if ((U32)-2 == len)
   {
      goto SharkSslCertParam_parseCert_1;
   }
   #endif

   o->signature.hashAlgo = GET_ALGO_HASH_ID(tag);
   o->signature.signatureAlgo = GET_ALGO_SIGNATURE_ID(tag);

   
   if (tag == ALGO_ID_MD2_WITH_RSA_ENCRYPTION)  
   {
      memset(o->signature.hash, 0, 20);
   }
   #if (!SHARKSSL_USE_SHA1)
   else if (tag == ALGO_ID_SHA1_WITH_RSA_ENCRYPTION)  
   {
      memset(o->signature.hash, 0, 20);
   }
   #endif
   else if (sharkssl_hash(o->signature.hash, pTemp, (U16)(l + (U16)(parseCert.ptr - pTemp)), o->signature.hashAlgo) < 0)
   {
      return -1;  
   }

   
   probealchemy = parseBitString.len;
   pTemp  = parseBitString.ptr;

   #if (SHARKSSL_ENABLE_CLIENT_AUTH || (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI) || SHARKSSL_ENABLE_CSR_SIGNING)
   SharkSslCertParam_parseCert_1:
   #endif

   parseCert.len = (U32)l;

   #if (SHARKSSL_ENABLE_CSR_SIGNING)
   if ((U32)-4 != len)  
   #endif
   {
      if (sha256final(&parseCert) < 0)
      {
         return -1;    
      }

      #if (SHARKSSL_ENABLE_CLIENT_AUTH || (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI) || SHARKSSL_ENABLE_CSR_SIGNING)
      if (((U32)-2 != len) && ((U32)-3 != len))
      #endif
      {
         if (parseCert.datalen == 1)
         {
            o->certInfo.version = *(parseCert.dataptr);
         }
         else
         {
            o->certInfo.version = 0;
         }
      }
   }

   
   if (SharkSslParseASN1_getInt(&parseCert) < 0)
   {
      return -1;
   }

   #if (SHARKSSL_ENABLE_CSR_SIGNING)
   if ((U32)-4 != len)  
   #endif
   {
      #if (SHARKSSL_ENABLE_CLIENT_AUTH || (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI) || SHARKSSL_ENABLE_CSR_SIGNING)
      if (((U32)-2 != len) && ((U32)-3 != len))
      #endif
      {
         o->certInfo.sn = parseCert.dataptr;
         o->certInfo.snLen = (U16)parseCert.datalen;
      }

      
      if (SharkSslParseASN1_getSequence(&parseCert) < 0)
      {
         return -1;
      }
      if (SharkSslParseASN1_getOID(&parseCert) < 0)
      {
         return -1;
      }
      
      if (SharkSslParseASN1_getAlgoID(&parseCert) != tag)
      {
         return -1;
      }

      #if (SHARKSSL_ENABLE_CLIENT_AUTH || SHARKSSL_ENABLE_CSR_SIGNING)
      if ((U32)-2 == len)
      {
         
         if (doublefnmul)
         {
            
            parseBitString.ptr = parseCert.ptr;
            parseBitString.len = parseCert.len;
            if ((l = SharkSslParseASN1_getSequence(&parseBitString)) < 0)
            {
               return -1;
            }
            l += (int)(parseBitString.ptr - parseCert.ptr);
            if (((U32)l > parseCert.len) || ((U32)l > 0xFFFF))
            {
               return -1;
            }
            *(U16*)doublefnmul = (U16)l;
         }
         return (int)(parseCert.ptr - p);
      }
      #endif

      
      if (deltacamera(&parseCert, &(o->certInfo.issuer)) < 0)
      {
         return -1;
      }

      if (SharkSslParseASN1_getSequence(&parseCert) < 0)
      {
         return -1;
      }

      
      if (!SharkSslParseASN1_getUTCTime(&parseCert))
      {
         if ((parseCert.datalen != 13) || (parseCert.dataptr[12] != '\132'))
         {
            return -1;  
         }
      }
      else if (!SharkSslParseASN1_getGenTime(&parseCert))
      {
         if ((parseCert.datalen < 13) || (parseCert.dataptr[parseCert.datalen - 1] != '\132') || (parseCert.datalen > 0xFF))
         {
            return -1;  
         }
      }
      else
      {
         return -1;
      }
      o->certInfo.timeFrom = parseCert.dataptr;
      o->certInfo.timeFromLen = (U8)parseCert.datalen;

      
      if (!SharkSslParseASN1_getUTCTime(&parseCert))
      {
         if ((parseCert.datalen != 13) || (parseCert.dataptr[12] != '\132'))
         {
            return -1;  
         }
      }
      else if (!SharkSslParseASN1_getGenTime(&parseCert))
      {
         if ((parseCert.datalen < 13) || (parseCert.dataptr[parseCert.datalen - 1] != '\132') || (parseCert.datalen > 0xFF))
         {
            return -1;  
         }
      }
      else
      {
         return -1;
      }
      o->certInfo.timeTo = parseCert.dataptr;
      o->certInfo.timeToLen = (U8)parseCert.datalen;
   }

   #if (SHARKSSL_ENABLE_CSR_SIGNING)
   if ((U32)-4 == len)  
   {
      *(U16*)&(o->certInfo.issuer.countryNameLen) = (U16)parseCert.len;
   }
   #endif
   
   if (deltacamera(&parseCert, &(o->certInfo.subject)) < 0)
   {
      return -1;
   }
   #if (SHARKSSL_ENABLE_CSR_SIGNING)
   if ((U32)-4 == len)  
   {
      *(U16*)&(o->certInfo.issuer.countryNameLen) -= (U16)parseCert.len;
      
   }
   #endif

   
   if (SharkSslParseASN1_getSequence(&parseCert) < 0)
   {
      return -1;
   }

   
   if (SharkSslParseASN1_getSequence(&parseCert) < 0)
   {
      return -1;
   }
   if (SharkSslParseASN1_getOID(&parseCert) < 0)
   {
      return -1;
   }

   
   switch (SharkSslParseASN1_getAlgoID(&parseCert))
   {
      #if SHARKSSL_USE_ECC
      case ALGO_OID_EC_PUBLIC_KEY:
         if (SharkSslParseASN1_getOID(&parseCert) < 0)
         {
            return -1;
         }
         l = SharkSslParseASN1_getCurveID(&parseCert);
         baAssert(l < 0x0100);  
         if ((l == SHARKSSL_EC_CURVE_ID_UNKNOWN) || (SharkSslParseASN1_getBitString(&parseCert) < 0))
         {
            return -1;
         }

         #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI)
         if ((U32)-3 == len)
         {
            goto SharkSslCertParam_parseCert_2;
         }
         #endif

         parseBitString.len = parseCert.datalen;
         parseBitString.ptr = parseCert.dataptr;
         while ((0 == *parseBitString.ptr) && (parseBitString.len))
         {
            parseBitString.ptr++;
            parseBitString.len--;
         }
         if (0 == parseBitString.len)
         {
            return -1;
         }
         parseBitString.len--;
         if  (*parseBitString.ptr++ != SHARKSSL_EC_POINT_UNCOMPRESSED)
         {
            return -1;
         }

         
         baAssert(parseBitString.len < 0x0100);
         o->certKey.mod = parseBitString.ptr;
         o->certKey.modLen = (U16)parseBitString.len >> 1;
         if ((parseBitString.len & 0x1) || (o->certKey.modLen != (U16)controllerregister((U16)l)))
         {
            return -1;
         }

         
         baAssert((U8)l);
         nomsrnoirq(o->certKey.modLen, (U16)l);

         
         o->certKey.exp = (U8*)0;
         o->certKey.expLen = 0;
         deltaticks(o->certKey.expLen);

         
         baAssert(loaderbinfmt(o->certKey.modLen,o->certKey.expLen) == ((U16)parseBitString.len >> 1));
         baAssert(targetoracle(o->certKey.modLen,o->certKey.expLen) == (U8)l);
         baAssert(mousethresh(o->certKey.expLen) == 0);
         baAssert(monadiccheck(o->certKey.expLen) == 0);
         baAssert(coupledexynos(o->certKey.expLen));
         baAssert(machinereboot(o->certKey.expLen));
         parseBitString.ptr += parseBitString.len;
         break;
      #endif

      #if SHARKSSL_ENABLE_RSA
      case ALGO_ID_RSA_ENCRYPTION:
         
         if (SharkSslParseASN1_getBitString(&parseCert) < 0)
         {
            return -1;
         }

         #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI)
         if ((U32)-3 == len)
         {
            goto SharkSslCertParam_parseCert_2;
         }
         #endif

         parseBitString.len = parseCert.datalen;
         parseBitString.ptr = parseCert.dataptr;
         if ((parseBitString.len < 1) || (*(parseBitString.ptr++) != 0x00))
         {
            return -1;
         }
         parseBitString.len--;
         if (SharkSslParseASN1_getSequence(&parseBitString) < 0)
         {
            return -1;
         }

         
         if (SharkSslParseASN1_getInt(&parseBitString) < 0)
         {
            return -1;
         }
         o->certKey.mod = parseBitString.dataptr;
         o->certKey.modLen = (U16)parseBitString.datalen;

         
         baAssert(supportedvector(o->certKey.modLen) == (U16)parseBitString.datalen);

         
         while (supportedvector(o->certKey.modLen) & 0x1F)
         {
            
            o->certKey.modLen--;  
            if (*(o->certKey.mod++) != 0x00)
            {
               return -1;
            }
         }

         
         if ((SharkSslParseASN1_getInt(&parseBitString) < 0) || (parseBitString.len))
         {
            return -1;
         }
         o->certKey.exp = parseBitString.dataptr;
         o->certKey.expLen = (U16)parseBitString.datalen;
         specialmapping(o->certKey.expLen);

         
         baAssert(mousethresh(o->certKey.expLen) == (U16)parseBitString.datalen);

         

         
         baAssert(monadiccheck(o->certKey.expLen) == 0);
         baAssert(coupledexynos(o->certKey.expLen));
         baAssert(machinekexec(o->certKey.expLen));
         break;
      #endif


      default:
         return -1;
   }

   if (parseCert.ptr != parseBitString.ptr)
   {
      return -1;
   }

   #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI)
   SharkSslCertParam_parseCert_2:
   #endif

   #if (SHARKSSL_ENABLE_CSR_SIGNING)
   if ((U32)-4 == len)  
   {
      
      l = SharkSslParseASN1_getCSRAttributes(&parseCert);
      *(U32*)doublefnmul = 0;  
   }
   else
   #endif
   {
      
      SharkSslParseASN1_getIssuerUniqueID(&parseCert);
      SharkSslParseASN1_getSubjectUniqueID(&parseCert);
      l = SharkSslParseASN1_getExtensions(&parseCert);
   }

   
   if (parseCert.len != 0)
   {
      return -1;
   }

   o->certInfo.CAflag = 0;
   o->certInfo.subjectAltNamesPtr = 0;
   o->certInfo.subjectAltNamesLen = 0;

   if (l == 0)  
   {
      
      parseCert.ptr = parseCert.dataptr;
      parseCert.len = parseCert.datalen;
      if (((v = SharkSslParseASN1_getSequence(&parseCert)) > 0) && ((U32)v < parseCert.datalen))
      {
         #if (SHARKSSL_ENABLE_CSR_SIGNING)
         if ((U32)-4 == len)  
         {
            if (SharkSslParseASN1_getOID(&parseCert) < 0)
            {
               return -1;
            }
            if ((parseCert.datalen != SHARKSSL_DIM_ARR(sharkssl_oid_csr_ext_req)) ||
                (sharkssl_kmemcmp(parseCert.dataptr, sharkssl_oid_csr_ext_req, SHARKSSL_DIM_ARR(sharkssl_oid_csr_ext_req))))
            {
               return -1;
            }
            if ((v = SharkSslParseASN1_getSet(&parseCert)) <= 0)
            {
               return -1;
            }
            if ((v = SharkSslParseASN1_getSequence(&parseCert)) < 0)
            {
               return -1;
            }
            *(U16*)&(o->certInfo.issuer.commonNameLen) = (U16)(int)(parseCert.ptr - p);  
            *(U32*)doublefnmul = (U16)v;  
         }
         else
         #endif
         while (parseCert.len)
         {
            if ((l = SharkSslParseASN1_getSequence(&parseCert)) < 0)
            {
               break;
            }

            
            parseBitString.ptr = parseCert.ptr;
            parseBitString.len = (U32)l;

            parseCert.ptr += (U32)l;
            parseCert.len -= (U32)l;

            if (SharkSslParseASN1_getOID(&parseBitString) < 0)
            {
               continue;
            }

            if ((parseBitString.datalen == 3) && (parseBitString.dataptr[1] == SHARKSSL_OID_JIIT_DS_CERTEXT) && (parseBitString.dataptr[0] == SHARKSSL_OID_JIIT_DS))
            {
               if (parseBitString.dataptr[2] == SHARKSSL_OID_JIIT_DS_CERTEXT_BASICCONSTRAINTS)
               {
                  
                  SharkSslParseASN1_getBool(&parseBitString);
                  if ((SharkSslParseASN1_getOctetString(&parseBitString) == 0) && (parseBitString.len == 0))
                  {
                     
                     parseBitString.ptr = parseBitString.dataptr;
                     parseBitString.len = parseBitString.datalen;
                     if (SharkSslParseASN1_getSequence(&parseBitString) > 0)
                     {
                        if ((SharkSslParseASN1_getBool(&parseBitString) == 0) &&
                            (parseBitString.datalen == 1) && (parseBitString.dataptr[0] != 0))
                        {
                           o->certInfo.CAflag++;
                           break;  
                        }
                     }
                  }
               }
               #if SHARKSSL_ENABLE_CERT_KEYUSAGE
               else if (parseBitString.dataptr[2] == SHARKSSL_OID_JIIT_DS_CERTEXT_KEYUSAGE)  
               {
                  
                  if (SharkSslParseASN1_getBool(&parseBitString) == 0)
                  {
                     
                     if ((parseBitString.datalen == 1) && *(parseBitString.dataptr))
                     {
                        o->certInfo.keyUsagePurposes |= SHARKSSL_CERT_KEYUSAGE_CRITICAL;
                     }
                  }
                  #if (SHARKSSL_CERT_KEYUSAGE_DIGITALSIGNATURE !=  0x00000001) || \
                      (SHARKSSL_CERT_KEYUSAGE_NONREPUDIATION   !=  0x00000002) || \
                      (SHARKSSL_CERT_KEYUSAGE_KEYENCIPHERMENT  !=  0x00000004) || \
                      (SHARKSSL_CERT_KEYUSAGE_DATAENCIPHERMENT !=  0x00000008) || \
                      (SHARKSSL_CERT_KEYUSAGE_KEYAGREEMENT     !=  0x00000010) || \
                      (SHARKSSL_CERT_KEYUSAGE_KEYCERTSIGN      !=  0x00000020) || \
                      (SHARKSSL_CERT_KEYUSAGE_CRLSIGN          !=  0x00000040) || \
                      (SHARKSSL_CERT_KEYUSAGE_ENCIPHERONLY     !=  0x00000080) || \
                      (SHARKSSL_CERT_KEYUSAGE_DECIPHERONLY     !=  0x00000100)
                  #error wrong SHARKSSL_CERT_KEYUSAGE_ values
                  #endif
                  if (SharkSslParseASN1_getOctetString(&parseBitString) == 0)
                  {
                     parseBitString.ptr = parseBitString.dataptr;
                     parseBitString.len = parseBitString.datalen;
                     if (SharkSslParseASN1_getBitString(&parseBitString) == 0)
                     {
                        U8 *p = parseBitString.dataptr;
                        l = parseBitString.datalen;
                        if ((parseBitString.len == 0) && (l >= 2))
                        {
                           l--;
                           v = l * 8;  
                           if (v >= *p)
                           {
                              v -= *p++;  
                              if (v > 8)
                              {
                                 v = 8;
                                 if ((l > 1) && (p[1] & 0x80))  
                                 {
                                    o->certInfo.keyUsagePurposes |= 0x100;
                                 }
                              }
                              for (l = 0x1; v > 0; v--, l <<= 1, *p <<= 1)
                              {
                                 if (*p & 0x80)
                                 {
                                    o->certInfo.keyUsagePurposes |= (U8)l;
                                 }
                              }
                              o->certInfo.keyUsagePurposes |= SHARKSSL_CERT_KEYUSAGE_PRESENT;
                           }
                        }
                     }
                  }
               }
               #endif
               else if ((parseBitString.dataptr[2] == SHARKSSL_OID_JIIT_DS_CERTEXT_SUBJALTNAMES) && (!o->certInfo.CAflag)) 
               {
                  if ((SharkSslParseASN1_getOctetString(&parseBitString) == 0) && (parseBitString.len == 0))
                  {
                     parseBitString.ptr = parseBitString.dataptr;
                     parseBitString.len = parseBitString.datalen;
                     if (SharkSslParseASN1_getSequence(&parseBitString) > 0)
                     {
                        baAssert(parseBitString.len <= 0xFFFF);
                        o->certInfo.subjectAltNamesPtr = parseBitString.ptr;
                        o->certInfo.subjectAltNamesLen = (U16)parseBitString.len;
                     }
                  }
               }
            }
            else if ((parseBitString.datalen == SHARKSSL_DIM_ARR(sharkssl_oid_ns_cert_type)) &&
                     (0 == sharkssl_kmemcmp(parseBitString.dataptr, sharkssl_oid_ns_cert_type, SHARKSSL_DIM_ARR(sharkssl_oid_ns_cert_type))))
            {
               
               if ((SharkSslParseASN1_getOctetString(&parseBitString) == 0) && (parseBitString.len == 0))
               {
                  parseBitString.ptr = parseBitString.dataptr;
                  parseBitString.len = parseBitString.datalen;
                  if (SharkSslParseASN1_getBitString(&parseBitString) == 0)
                  {
                     
                     if ((parseBitString.datalen) &&  (parseBitString.dataptr[parseBitString.datalen - 1] & 0x04))
                     {
                        o->certInfo.CAflag++;
                        break;  
                     }
                  }
               }
            }
         }
      }
   }

   #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI)
   if ((U32)-3 == len)
   {
      return 0;
   }
   #endif

   parseBitString.ptr = pTemp;
   parseBitString.len = probealchemy;
   if (SharkSslParseASN1_getBitString(&parseBitString) < 0)
   {
      return -1;
   }
   o->signature.signature = parseBitString.dataptr;
   o->signature.signLen   = (U16)parseBitString.datalen;

   #if SHARKSSL_ENABLE_ECDSA
   if (o->signature.signatureAlgo == ALGO_ID_ECDSA)
   {
      
      while ((o->signature.signLen) && (0 == *(o->signature.signature)))
      {
         o->signature.signLen--;
         o->signature.signature++;
      }
   }
   #if SHARKSSL_ENABLE_RSA
   else
   #endif
   #endif
   #if SHARKSSL_ENABLE_RSA
   if (o->signature.signatureAlgo == ALGO_ID_RSA_ENCRYPTION)
   {
      
      while (o->signature.signLen & 0x1F)
      {
         
         o->signature.signLen--;
         if (*(o->signature.signature++) != 0x00)
         {
            return -1;
         }
      }
   }
   #endif  

   #if (SHARKSSL_ENABLE_CSR_SIGNING)
   if ((U32)-4 == len)  
   {
      *(U32*)doublefnmul |= ((U32)(*(U16*)&(o->certInfo.issuer.countryNameLen)) << 16);
      return (int)*(U16*)&(o->certInfo.issuer.commonNameLen);  
   }
   #endif

   return 0;
}


int systemcapabilities(const SharkSslSignParam *o)
{
   #if SHARKSSL_ENABLE_ECDSA
   U8 kexecprepare[claimresource(SHARKSSL_MAX_ECC_POINTLEN)];
   U8 stackoverflow[claimresource(SHARKSSL_MAX_ECC_POINTLEN)];
   SharkSslECDSAParam ecdsaParam;
   #endif
   SharkSslParseASN1 parseSgn;
   U8 *s;
   int len;

   s = o->signature.signature;

   switch (o->signature.signatureAlgo)
   {
      #if SHARKSSL_ENABLE_RSA
      case entryearly:
         if (!(machinekexec(o->pCertKey->expLen)) || (o->signature.signLen != supportedvector(o->pCertKey->modLen)))
         {
            return -1;
         }

         len = (int)handleguest(o->pCertKey, o->signature.signLen, s, s, SHARKSSL_RSA_PKCS1_PADDING);
         if (len < 0)
         {
            return -1;
         }

         if (o->signature.hashAlgo == defaultspectre)
         {
            if (sharkssl_kmemcmp(o->signature.hash, s, (U16)len))
            {
               return -1;
            }
         }
         else  
         {
            parseSgn.ptr = s;
            parseSgn.len = (U16)len;

            if ((len = SharkSslParseASN1_getSequence(&parseSgn)) < 0)
            {
               return -1;
            }

            if (((U32)len != parseSgn.len) || (SharkSslParseASN1_getSequence(&parseSgn) < 0) ||
                (SharkSslParseASN1_getOID(&parseSgn) < 0))
            {
               return -1;
            }

            if (SharkSslParseASN1_getAlgoID(&parseSgn) != o->signature.hashAlgo)
            {
               return -1;
            }

            if ((SharkSslParseASN1_getOctetString(&parseSgn)) || (parseSgn.len))
            {
               return -1;
            }

            if (parseSgn.datalen != sharkssl_getHashLen(o->signature.hashAlgo))
            {
               return -1;
            }

            if (sharkssl_kmemcmp(o->signature.hash, parseSgn.dataptr, parseSgn.datalen))
            {
               return -1;
            }
         }
         break;
      #endif

      #if SHARKSSL_ENABLE_ECDSA
      case accessactive:
         if (!(machinereboot(o->pCertKey->expLen)))
         {
            return -1;
         }

         parseSgn.ptr = s;
         parseSgn.len = o->signature.signLen;

         if (((len = SharkSslParseASN1_getSequence(&parseSgn)) < 0) || (SharkSslParseASN1_getInt(&parseSgn) < 0) || ((U32)len < parseSgn.datalen))
         {
            return -1;
         }
         ecdsaParam.keyLen = attachdevice(o->pCertKey->modLen);
         if ((U16)parseSgn.datalen > ecdsaParam.keyLen)
         {
            return -1;
         }
         #if 1
         len = (ecdsaParam.keyLen - parseSgn.datalen);
         if (len)
         {
            memset(kexecprepare, 0, len);
            memcpy(&kexecprepare[len], parseSgn.dataptr, parseSgn.datalen);
            ecdsaParam.R = kexecprepare;
         }
         else
         {
            ecdsaParam.R = parseSgn.dataptr;
         }

         if (SharkSslParseASN1_getInt(&parseSgn) < 0)
         {
            return -1;
         }
         len = (ecdsaParam.keyLen - parseSgn.datalen);
         if (len)
         {
            memset(stackoverflow, 0, len);
            memcpy(&stackoverflow[len], parseSgn.dataptr, parseSgn.datalen);
            ecdsaParam.S = stackoverflow;
         }
         else
         {
            ecdsaParam.S = parseSgn.dataptr;
         }
         #else
         ecdsaParam.R = parseSgn.dataptr;
         if (parseSgn.datalen < ecdsaParam.keyLen)  
         {
            *(--(ecdsaParam.R)) = 0x00;
            parseSgn.datalen++;
            if (parseSgn.datalen < ecdsaParam.keyLen)
            {
               *(--(ecdsaParam.R)) = 0x00;
               parseSgn.datalen++;
               if (parseSgn.datalen < ecdsaParam.keyLen)
               {
                  return -1;
               }
            }
         }
         if (SharkSslParseASN1_getInt(&parseSgn) < 0)
         {
            return -1;
         }
         ecdsaParam.S = parseSgn.dataptr;
         if (parseSgn.datalen < ecdsaParam.keyLen)  
         {
            *(--(ecdsaParam.S)) = 0x00;
            parseSgn.datalen++;
            if (parseSgn.datalen < ecdsaParam.keyLen)
            {
               *(--(ecdsaParam.S)) = 0x00;
               parseSgn.datalen++;
               if (parseSgn.datalen < ecdsaParam.keyLen)
               {
                  return -1;
               }
            }
         }
         #endif

         ecdsaParam.key = o->pCertKey->mod;
         ecdsaParam.curveType = wakeupenable(o->pCertKey->modLen);
         ecdsaParam.hash = (U8*)o->signature.hash;
         ecdsaParam.hashLen = sharkssl_getHashLen(o->signature.hashAlgo);

         if (SharkSslECDSAParam_ECDSA(&ecdsaParam, fixupdevices))
         {
            return -1;  
         }
         break;
      #endif

      default:
         return -1;
   }

   return 0;
}



static int systemconfiguration(const U8 *s1, const U8 *s2, const U32 disablechannel, const U32 modifymisccr)
{
   if (s1 == (void*)0)
   {
      if (s2 == (void*)0)
      {
         return (disablechannel + modifymisccr);
      }
   }
   else if ((s2) && (disablechannel == modifymisccr))
   {
      return sharkssl_kmemcmp((const char*)s1, (const char*)s2, disablechannel);
   }

   
   return 1;
}



U8 SharkSslCertDN_equal(const SharkSslCertDN *o1, const SharkSslCertDN *o2)
{
   if ( systemconfiguration(o1->organization, o2->organization, o1->organizationLen, o2->organizationLen) ||
        systemconfiguration(o1->unit,         o2->unit,         o1->unitLen,         o2->unitLen)         ||
        systemconfiguration(o1->commonName,   o2->commonName,   o1->commonNameLen,   o2->commonNameLen)   ||
        systemconfiguration(o1->countryName,  o2->countryName,  o1->countryNameLen,  o2->countryNameLen)  ||
        systemconfiguration(o1->locality,     o2->locality,     o1->localityLen,     o2->localityLen)     ||
        systemconfiguration(o1->province,     o2->province,     o1->provinceLen,     o2->provinceLen) )
   {
      return 0;
   }

   return 1;  
}

#endif  


#if SHARKSSL_ENABLE_ECDSA
static sharkssl_ECDSA_RetVal registerboard(SharkSslECDSAParam *audioshutdown, U8 *sig, U16 *platformconfig)
{
   SharkSslASN1Create wasn1;
   U8 kexecprepare[claimresource(SHARKSSL_MAX_ECC_POINTLEN)];
   U8 stackoverflow[claimresource(SHARKSSL_MAX_ECC_POINTLEN)];
   int ret;

   baAssert(0 == SHARKSSL_ECDSA_OK);
   audioshutdown->R = kexecprepare;
   audioshutdown->S = stackoverflow;

   ret = SharkSslECDSAParam_ECDSA(audioshutdown, iommupdata);
   if (ret)
   {
      if ((int)SharkSslCon_AllocationError == ret)
      {
         return SHARKSSL_ECDSA_ALLOCATION_ERROR;
      }

      return SHARKSSL_ECDSA_INTERNAL_ERROR;
   }

   if (0 == *platformconfig)
   {
      return SHARKSSL_ECDSA_SIGLEN_TOO_SMALL;
   }

   SharkSslASN1Create_constructor(&wasn1, sig, *platformconfig);
   *platformconfig = 0;
   
   if (SharkSslASN1Create_int(&wasn1, audioshutdown->S, audioshutdown->keyLen) < 0)
   {
      return SHARKSSL_ECDSA_INTERNAL_ERROR;
   }
   if (SharkSslASN1Create_int(&wasn1, audioshutdown->R, audioshutdown->keyLen) < 0)
   {
      return SHARKSSL_ECDSA_INTERNAL_ERROR;
   }
   if (SharkSslASN1Create_length(&wasn1, SharkSslASN1Create_getLen(&wasn1)) < 0)
   {
      return SHARKSSL_ECDSA_SIGLEN_TOO_SMALL;
   }
   if (SharkSslASN1Create_sequence(&wasn1) < 0)
   {
      return SHARKSSL_ECDSA_INTERNAL_ERROR;
   }
   *platformconfig = (U16)SharkSslASN1Create_getLen(&wasn1);
   memmove(sig, SharkSslASN1Create_getData(&wasn1), *platformconfig);

   return SHARKSSL_ECDSA_OK;
}
#endif


#if (((SHARKSSL_SSL_CLIENT_CODE && SHARKSSL_ENABLE_CLIENT_AUTH) || (SHARKSSL_SSL_SERVER_CODE) || \
     (SHARKSSL_ENABLE_CSR_SIGNING) || (SHARKSSL_ENABLE_CSR_CREATION)) && \
     (SHARKSSL_ENABLE_DHE_RSA || SHARKSSL_ENABLE_ECDHE_RSA || SHARKSSL_ENABLE_ECDHE_ECDSA))
int checkactions(SharkSslSignParam *o)
{
   #if SHARKSSL_ENABLE_RSA
   int len;
   #endif
   U8 *pciercxcfg448;
   U16 ftraceupdate;

   #if SHARKSSL_ENABLE_RSA
   const U8 *oid;
   U8  fieldvalue;
   #endif
   #if SHARKSSL_ENABLE_ECDSA
   SharkSslECDSAParam audioshutdown;
   #endif

   pciercxcfg448 = o->signature.signature;
   o->signature.signLen = 0;
   ftraceupdate = sharkssl_getHashLen(o->signature.hashAlgo);

   switch (o->signature.signatureAlgo)
   {
      #if SHARKSSL_ENABLE_RSA
      case entryearly:
         if (!(machinekexec(o->pCertKey->expLen)))
         {
            return -1;
         }

         switch (o->signature.hashAlgo)
         {
            #if SHARKSSL_USE_SHA_512
            case batterythread:
               oid    = sharkssl_oid_sha512;
               fieldvalue = SHARKSSL_DIM_ARR(sharkssl_oid_sha512);
               goto _sharkssl_cs_common_1_2;
            #endif

            #if SHARKSSL_USE_SHA_384
            case probewrite:
               oid    = sharkssl_oid_sha384;
               fieldvalue = SHARKSSL_DIM_ARR(sharkssl_oid_sha384);
               goto _sharkssl_cs_common_1_2;
            #endif

            #if SHARKSSL_USE_SHA_256
            case domainnumber:
               oid    = sharkssl_oid_sha256;
               fieldvalue = SHARKSSL_DIM_ARR(sharkssl_oid_sha256);
               goto _sharkssl_cs_common_1_2;
            #endif

            #if SHARKSSL_USE_SHA1
            case presentpages:
               oid    = sharkssl_oid_sha1;
               fieldvalue = SHARKSSL_DIM_ARR(sharkssl_oid_sha1);
            #endif
               _sharkssl_cs_common_1_2:
               len = (fieldvalue + ftraceupdate + 10);
               baAssert(len < 0x80);  
               *pciercxcfg448++ = 0x30;  
               *pciercxcfg448++ = (U8)(len - 2);
               *pciercxcfg448++ = 0x30;  
               *pciercxcfg448++ = (fieldvalue + 4);
               *pciercxcfg448++ = 0x06;  
               *pciercxcfg448++ = fieldvalue;
               memcpy(pciercxcfg448, oid, fieldvalue);
               pciercxcfg448 += fieldvalue;
               *pciercxcfg448++ = 0x05;
               *pciercxcfg448++ = 0x00;
               *pciercxcfg448++ = 0x04;
               *pciercxcfg448++ = (U8)ftraceupdate;
               break;

            default:
               return -1;
         }

         memcpy(pciercxcfg448, o->signature.hash, ftraceupdate);

         
         len = (int)clockaccess(o->pCertKey, (U16)len, o->signature.signature, o->signature.signature, SHARKSSL_RSA_PKCS1_PADDING);
         if ((len < 0) || ((U16)len != supportedvector(o->pCertKey->modLen)))
         {
            return -1;
         }
         o->signature.signLen = (U16)len;
         break;
      #endif

      #if SHARKSSL_ENABLE_ECDSA
      case accessactive:
         if (!(machinereboot(o->pCertKey->expLen)) || coupledexynos(o->pCertKey->expLen))
         {
            return -1;
         }
         audioshutdown.curveType = wakeupenable(o->pCertKey->modLen);
         audioshutdown.hash = o->signature.hash;
         audioshutdown.hashLen = ftraceupdate;
         audioshutdown.key = o->pCertKey->exp;
         audioshutdown.keyLen = mousethresh(o->pCertKey->expLen);
         if ((audioshutdown.key == NULL) || (audioshutdown.keyLen == 0))
         {
            return -1;
         }
         o->signature.signLen = relocationchain(o->pCertKey);
         if (registerboard(&audioshutdown, pciercxcfg448, &(o->signature.signLen)) < 0)
         {
            
            return -1;
         }
         break;
      #endif

      default:
         return -1;
   }

   return 0;
}
#endif  


#if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)

SHARKSSL_API U16 SharkSslCert_len(SharkSslCert kernelvaddr)
{
   if ((0x30 == kernelvaddr[0]) && (0x82 == kernelvaddr[1]))
   {
      return (U16)(((U16)(kernelvaddr[2]) * 256) + kernelvaddr[3] + 4);
   }
   return (U16)-1;
}



U16 interrupthandler(SharkSslCertKey *disableclock, SharkSslCert kernelvaddr)
{
   U16 ret, len;

   if (kernelvaddr)
   {
      ret = SharkSslCert_len(kernelvaddr);
      if (ret != (U16)-1)
      {
         ret += 0x03;
         ret &= ~0x03;  
         kernelvaddr += ret;
         disableclock->expLen = (U16)((U16)(kernelvaddr[0]) * 256 + kernelvaddr[1]);
         len = mousethresh(disableclock->expLen);
         kernelvaddr += 2;
         disableclock->modLen = (U16)((U16)(kernelvaddr[0]) * 256 + kernelvaddr[1]);
         kernelvaddr += 2;
         disableclock->exp = len ? (U8*)kernelvaddr : (U8*)0;
         kernelvaddr += len;
         disableclock->mod = (U8*)kernelvaddr;
         return ret;  
      }
   }

   memset(disableclock, 0, sizeof(SharkSslCertKey));
   return 0;
}



U16  SharkSslCert_vectSize_keyType(const SharkSslCert kernelvaddr, U8 *earlyconsole)
{
   SharkSslCertKey disableclock;
   U16 icachealiases;
   #if SHARKSSL_ENABLE_CERT_CHAIN
   U16 nc0;
   #endif

   
   icachealiases = interrupthandler(&disableclock, kernelvaddr);
   if (icachealiases)
   {
      #if SHARKSSL_ENABLE_CERT_CHAIN
      nc0 = monadiccheck(disableclock.expLen);
      #endif
      
      icachealiases += 4 + mousethresh(disableclock.expLen);
      if (machinekexec(disableclock.expLen))
      {
         if (earlyconsole)
         {
            *earlyconsole = SHARKSSL_KEYTYPE_RSA;
         }
         
         icachealiases += supportedvector(disableclock.modLen);
         if (!coupledexynos(disableclock.expLen))
         {
            
            icachealiases += (U16)((supportedvector(disableclock.modLen) / 2) * 5);
         }
      }
      else if (machinereboot(disableclock.expLen))
      {
         if (earlyconsole)
         {
            *earlyconsole = SHARKSSL_KEYTYPE_EC;
         }
         
         icachealiases += (U16)(2 * attachdevice(disableclock.modLen));
      }
      else
      {
         icachealiases = 0;  
      }
      #if SHARKSSL_ENABLE_CERT_CHAIN
      if (icachealiases && nc0)  
      {
         U8 *postcoreinitcall = (U8*)(&kernelvaddr[icachealiases]);
         while (nc0--)
         {
            U16 ebasecpunum = SharkSslCert_len((SharkSslCert)postcoreinitcall);
            if ((U16)-1 == ebasecpunum)
            {
               icachealiases = nc0 = 0;  
            }
            else
            {
               postcoreinitcall += ebasecpunum;
               icachealiases += ebasecpunum;
            }
         }
      }
      #endif
   }
   return icachealiases;
}



SHARKSSL_API U16 SharkSslKey_vectSize(const SharkSslKey sourcerouting)
{
   return SharkSslCert_vectSize_keyType((SharkSslCert)sourcerouting, (U8*)0);
}


#if ((SHARKSSL_SSL_CLIENT_CODE && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)) || \
     (SHARKSSL_SSL_SERVER_CODE))

U8 fixupresources(SharkSslCert kernelvaddr, U16 len, U8 *ptr)
{
   baAssert(len >= 3);
   baAssert(ptr);

   
   len -= 3;
   *ptr++ = 0x00;
   *ptr++ = (U8)(len >> 8);
   *ptr++ = (U8)(len & 0xFF);

   if (kernelvaddr)  
   {
      U16 pxafbmodes;

      #if SHARKSSL_ENABLE_CERT_CHAIN
      _sharkssl_cert_chain_output:
      #endif
      pxafbmodes = SharkSslCert_len(kernelvaddr);
      if (pxafbmodes == (U16)-1)  
      {
         return 0;
      }
      *ptr++ = 0x00;
      *ptr++ = (U8)(pxafbmodes >> 8);
      *ptr++ = (U8)(pxafbmodes & 0xFF);
      memcpy(ptr, kernelvaddr, pxafbmodes);
      ptr += pxafbmodes;
      len -= 3;
      if (len >= pxafbmodes)
      {
         len -= pxafbmodes;
         #if SHARKSSL_ENABLE_CERT_CHAIN
         if (len > 0)
         {
            kernelvaddr += pxafbmodes;
            if (SharkSslCert_len(kernelvaddr) != (U16)-1)  
            {
               goto _sharkssl_cert_chain_output;
            }
            while (*kernelvaddr == 0xFF)
            {
               kernelvaddr++;
            }
            pxafbmodes = (U16)((U16)(kernelvaddr[0]) * 256 + kernelvaddr[1]);
            if ((monadiccheck(pxafbmodes)) > 0)
            {
               U16 chargeerror;
               kernelvaddr += 2;
               chargeerror = (U16)((U16)(kernelvaddr[0]) * 256 + kernelvaddr[1]);
               kernelvaddr += 2;
               kernelvaddr += mousethresh(pxafbmodes);  
               
               if (machinekexec(pxafbmodes))
               {
                  baAssert(chargeerror == supportedvector(chargeerror));
                  baAssert((chargeerror <= 0x3FFF) && (0 == (chargeerror & 0x01)));
                  kernelvaddr += (U16)(chargeerror << 2);
                  kernelvaddr -= (U16)(chargeerror >> 1);
               }
               else if (machinereboot(pxafbmodes))
               {
                  chargeerror = attachdevice(chargeerror);
                  baAssert((chargeerror < 0x00FF) && (0 == (chargeerror & 0x01)));
                  kernelvaddr += (U16)(chargeerror << 1);
               }
               else
               {
                  return 0;  
               }
               goto _sharkssl_cert_chain_output;
            }
         }
         #endif
      }
   }

   return (U8)((len >> 8) + (len & 0xFF));
}



U16 setupboard(SharkSslCert kernelvaddr)
{
   U16 pxafbmodes;
   U16 len = 6;

   if (kernelvaddr)
   {
      pxafbmodes = SharkSslCert_len(kernelvaddr);
      if (pxafbmodes == (U16)-1)
      {
         return 0;
      }
      len += pxafbmodes;

      #if SHARKSSL_ENABLE_CERT_CHAIN
      
      kernelvaddr += pxafbmodes;
      while (*kernelvaddr == 0xFF) 
      {
         kernelvaddr++;
      }
      pxafbmodes = (U16)((U16)(kernelvaddr[0]) * 256 + kernelvaddr[1]);
      if ((monadiccheck(pxafbmodes)) > 0)  
      {
         U16 chargeerror;
         kernelvaddr += 2;
         chargeerror = (U16)((U16)(kernelvaddr[0]) * 256 + kernelvaddr[1]);
         kernelvaddr += 2;
         kernelvaddr += mousethresh(pxafbmodes);  
         
         if (machinekexec(pxafbmodes))
         {
            baAssert(chargeerror == supportedvector(chargeerror));
            baAssert((chargeerror <= 0x3FFF) && (0 == (chargeerror & 0x01)));
            kernelvaddr += (U16)(chargeerror << 2);
            kernelvaddr -= (U16)(chargeerror >> 1);
         }
         else if (machinereboot(pxafbmodes))
         {
            chargeerror = attachdevice(chargeerror);
            baAssert((chargeerror < 0x00FF) && (0 == (chargeerror & 0x01)));
            kernelvaddr += (U16)(chargeerror << 1);
         }
         else
         {
            return 0;  
         }
         chargeerror = monadiccheck(pxafbmodes);
         do
         {
            pxafbmodes = SharkSslCert_len(kernelvaddr);
            if (pxafbmodes == (U16)-1)
            {
               return 0;
            }
            len += (3 + pxafbmodes);
            kernelvaddr += pxafbmodes;
         } while (--chargeerror);
      }
      #endif
   }

   return len;
}
#endif


#if SHARKSSL_ENABLE_CLIENT_AUTH

U8 domainassociate(SharkSslCert kernelvaddr, U8 *dn, U16 installidmap)
{
   int registerinterrupts;
   U16 certLen, dnCLen;
   #if SHARKSSL_ENABLE_CERT_CHAIN
   U16 kernelsections;
   U16 writeenable = (U16)-1;
   #endif

   if (kernelvaddr)
   {
      #if SHARKSSL_ENABLE_CERT_CHAIN
      SharkSslCert_CAfound_1:
      #endif
      certLen = SharkSslCert_len(kernelvaddr);
      if (certLen != (U16)-1)
      {
         registerinterrupts = spromregister(0, (U8*)kernelvaddr, (U32)-2, (U8*)&dnCLen);
         if ((registerinterrupts > 0) && ((U32)registerinterrupts < certLen) && (installidmap == dnCLen))
         {
            if (0 == sharkssl_kmemcmp(((U8*)kernelvaddr + registerinterrupts), dn, installidmap))
            {
               return 1;  
            }
         }
         #if SHARKSSL_ENABLE_CERT_CHAIN
         kernelvaddr += certLen;
         if (writeenable == (U16)-1)  
         {
            while (*kernelvaddr == 0xFF)  
            {
               kernelvaddr++;
            }
            certLen = (U16)((U16)kernelvaddr[0] * 256 + kernelvaddr[1]);
            writeenable = monadiccheck(certLen);
            if (writeenable > 0)
            {
               kernelvaddr += 2;
               kernelsections = (U16)((U16)kernelvaddr[0] * 256 + kernelvaddr[1]);
               kernelvaddr += 2;
               kernelvaddr += mousethresh(certLen); 
               
               if (machinekexec(certLen))
               {
                  baAssert(kernelsections == supportedvector(kernelsections));
                  baAssert((kernelsections <= 0x3FFF) && (0 == (kernelsections & 0x01)));
                  kernelvaddr += (U16)(kernelsections << 2);
                  kernelvaddr -= (U16)(kernelsections >> 1);
               }
               else if (machinereboot(certLen))
               {
                  kernelsections = attachdevice(kernelsections);
                  baAssert((kernelsections < 0x00FF) && (0 == (kernelsections & 0x01)));
                  kernelvaddr += (U16)(kernelsections << 1);
               }
               else
               {
                  return 0;
               }
            }
         }
         if (writeenable)
         {
            writeenable--;
            goto SharkSslCert_CAfound_1;
         }
         #endif
      }
   }
   return 0;
}
#endif
#endif  


#if ((SHARKSSL_ENABLE_PEM_API) || (SHARKSSL_ENABLE_CERTSTORE_API))
static const U8 sysrqreboot[128] =
{
   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,  
   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,  
   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,  62,0xFF,0xFF,0xFF,  63,  
     52,  53,  54,  55,  56,  57,  58,  59,  60,  61,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,  
   0xFF,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,0xFF,0xFF,0xFF,0xFF,0xFF,  
   0xFF,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  
     41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,0xFF,0xFF,0xFF,0xFF,0xFF   
};



SHARKSSL_API U32 sharkssl_B64Decode(
   U8 *disableevent, U32 queryinput, const char *joystickmonitor, const char *requestpending)
{
   U32 len;
   U8  phase, d, prev_d, c;

   len = 0;
   prev_d = phase = 0;
   for (; joystickmonitor != requestpending; joystickmonitor++)
   {
      if (((U8)(*joystickmonitor)) & 0x80)
      {
         continue;
      }
      d = sysrqreboot[(U8)*joystickmonitor];
      if (d != 0xFF)
      {
         switch (phase & 0x03)
         {
            case 0:
               phase++;
               break;

            case 1:
               c = (U8)((prev_d << 2) | ((d & 0x30) >> 4));
               goto _sharkssl_outstr_c;

            case 2:
               c = (U8)(((prev_d & 0xf) << 4) | ((d & 0x3c) >> 2));
               goto _sharkssl_outstr_c;

            case 3:
               c = (U8)(((prev_d & 0x03) << 6) | d);
               _sharkssl_outstr_c:
               if (len < queryinput)
               {
                  disableevent[len++] = c;
               }
               phase++;
               break;
         }
         prev_d = d;
      }
   }

   return len;
}
#endif  


#if (SHARKSSL_ENABLE_PEM_API)
typedef enum
{
  mmcsd0device = 0,
  branchinstruction = 1,
  devicecamera,
  beforeprobe,
  unmapdomain
} key_enc_type;



#define setupfixed 4
#define disablehazard (4 + setupfixed)
#define pwrdmclear  4

static U32 sharkssl_PEM_alloc_B64decode(U8 **sourcerouting, const char *statesuspended, U32 pernodememory)
{
   if (pernodememory)
   {
      
      *sourcerouting = (U8*)baMalloc(((U32)(pernodememory * 3) >> 2) + disablehazard);
      if (*sourcerouting)
      {
         #if (4 == setupfixed)
         
         *(*sourcerouting+0) = 0x30;
         *(*sourcerouting+1) = 0x82;
         #if (disablehazard > setupfixed)
         memset(*sourcerouting + 2, 0, disablehazard - 2);
         #else
         (*sourcerouting)[2] = 0x00;
         (*sourcerouting)[3] = 0x00;
         #endif
         #elif (disablehazard > 0)
         memset(*sourcerouting, 0, disablehazard);
         #endif
         return sharkssl_B64Decode(*sourcerouting + disablehazard, pernodememory, statesuspended, statesuspended+pernodememory);
      }
   }
   return 0;
}


static sharkssl_PEM_RetVal tcpudpnofold(SharkSslCertKey *disableclock, U8 *sourcerouting, U32 signaldefined)
{
   
   U16 expLen, modLen;
   baAssert(signaldefined <= 0xFF);
   expLen = mousethresh(disableclock->expLen);
   if (signaldefined)
   {
      baAssert((U16)signaldefined >= expLen);
      gpiolibbanka(disableclock->expLen, signaldefined);
      signaldefined -= expLen;
   }
   
   *sourcerouting++ = (U8)(disableclock->expLen >> 8);
   *sourcerouting++ = (U8)disableclock->expLen;
   *sourcerouting++ = (U8)(disableclock->modLen >> 8);
   *sourcerouting++ = (U8)disableclock->modLen;
   
   memset(sourcerouting, 0, signaldefined);
   sourcerouting += signaldefined;
   memmove(sourcerouting, disableclock->exp, expLen);
   sourcerouting += expLen;
   modLen = loaderbinfmt(disableclock->modLen, disableclock->expLen);
   #if SHARKSSL_USE_ECC
   if (machinereboot(disableclock->expLen))
   {
      
      memmove(sourcerouting, disableclock->mod, modLen << 1);
   }
   else
   #endif
   {
      
      memmove(sourcerouting, disableclock->mod, modLen);
   }
   return SHARKSSL_PEM_OK;
}



int sharkssl_PEM_getSeqVersion(SharkSslParseASN1 *sharkrestart, U32 len)
{
   int l = SharkSslParseASN1_getSequence(sharkrestart);
   if ((l < 0) || ((U32)l > len))
   {
      return SHARKSSL_PEM_KEY_PARSE_ERROR;
   }
   l = SharkSslParseASN1_getInt(sharkrestart);
   if ((l < 0) || (sharkrestart->datalen != 1))
   {
      return SHARKSSL_PEM_KEY_PARSE_ERROR;
   }
   return *sharkrestart->dataptr;  
}


#if SHARKSSL_USE_ECC

static sharkssl_PEM_RetVal mmcsd1device(SharkSslParseASN1 *sharkrestart, SharkSslCertKey *disableclock)
{
   int l;
   if (SharkSslParseASN1_getOID(sharkrestart) < 0)
   {
      return SHARKSSL_PEM_KEY_PARSE_ERROR;
   }
   l = SharkSslParseASN1_getCurveID(sharkrestart);
   baAssert(l <= 0xFF);
   if (SHARKSSL_EC_CURVE_ID_UNKNOWN == (U8)l)
   {
      return SHARKSSL_PEM_KEY_UNSUPPORTED_FORMAT;
   }
   disableclock->modLen = 0;
   nomsrnoirq(disableclock->modLen, (U8)l);
   return SHARKSSL_PEM_OK;
}


static sharkssl_PEM_RetVal countslave(SharkSslParseASN1 *sharkrestart, SharkSslCertKey *disableclock)
{
   U32 softirqclear;
   if (!coupledexynos(disableclock->expLen))
   {
      
      if (SharkSslParseASN1_getECPublicKey(sharkrestart) < 0)
      {
         return SHARKSSL_PEM_KEY_PARSE_ERROR;
      }
   }
   if (SharkSslParseASN1_getBitString(sharkrestart) < 0)
   {
      return SHARKSSL_PEM_KEY_PARSE_ERROR;
   }
   while ((0 == *(sharkrestart->dataptr)) && (sharkrestart->datalen))
   {
      sharkrestart->dataptr++;
      sharkrestart->datalen--;
   }
   if (0 == sharkrestart->datalen)
   {
      return SHARKSSL_PEM_KEY_PARSE_ERROR;
   }
   sharkrestart->datalen--;
   if (SHARKSSL_EC_POINT_UNCOMPRESSED != *sharkrestart->dataptr++)
   {
      return SHARKSSL_PEM_KEY_UNSUPPORTED_FORMAT;
   }
   
   disableclock->mod = sharkrestart->dataptr;
   softirqclear = sharkrestart->datalen >> 1;
   if ((sharkrestart->datalen & 1) || (softirqclear != (U16)controllerregister(wakeupenable(disableclock->modLen))))
   {
      return SHARKSSL_PEM_KEY_WRONG_LENGTH;
   }
   baAssert(softirqclear <= 0xFF);
   dcdc1consumers(disableclock->modLen, (U8)softirqclear);
   return SHARKSSL_PEM_OK;
}
#endif


#if SHARKSSL_ENABLE_RSA
static sharkssl_PEM_RetVal signalinject(SharkSslParseASN1 *sharkrestart, SharkSslCertKey *disableclock)
{
   
   if (SharkSslParseASN1_getInt(sharkrestart) < 0)
   {
      return SHARKSSL_PEM_KEY_PARSE_ERROR;
   }
   disableclock->mod = sharkrestart->dataptr;
   disableclock->modLen = (U16)sharkrestart->datalen;
   
   if (disableclock->modLen & 0x1F)
   {
      return SHARKSSL_PEM_KEY_UNSUPPORTED_FORMAT;
   }
   
   if ((disableclock->modLen < 0x040) || (disableclock->modLen > 0x200))
   {
      return SHARKSSL_PEM_KEY_UNSUPPORTED_MODULUS_LENGTH;
   }
   
   if (SharkSslParseASN1_getInt(sharkrestart) < 0)
   {
      return SHARKSSL_PEM_KEY_PARSE_ERROR;
   }
   disableclock->exp = sharkrestart->dataptr;
   disableclock->expLen = (U16)sharkrestart->datalen;
   if (disableclock->expLen > 0xF0)  
   {
      return SHARKSSL_PEM_KEY_UNSUPPORTED_EXPONENT_LENGTH;
   }
   return SHARKSSL_PEM_OK;
}
#endif


#if (SHARKSSL_ENABLE_ENCRYPTED_PKCS8_SUPPORT || (SHARKSSL_USE_MD5 && (SHARKSSL_USE_AES_128 || SHARKSSL_USE_AES_256)))
static sharkssl_PEM_RetVal pwrdmdisable(U8 *out, U8 *in, U32 len, U8 *pcmciascoop, U8 *iv, U32 loongson3priority, key_enc_type debugpreserved)
{
   #if ((SHARKSSL_USE_AES_128 || SHARKSSL_USE_AES_256) && SHARKSSL_ENABLE_AES_CBC)
   union
   {
      SharkSslAesCtx aesCtx;
   } decCtx;

   if ((devicecamera == debugpreserved) || (beforeprobe == debugpreserved))
   {
      if (len & 0xF)
      {
         return SHARKSSL_PEM_KEY_WRONG_LENGTH;
      }
      if (loongson3priority != 16)
      {
         return SHARKSSL_PEM_KEY_WRONG_IV;
      }
      SharkSslAesCtx_constructor(&(decCtx.aesCtx), SharkSslAesCtx_Decrypt, pcmciascoop, ((debugpreserved == devicecamera) ? 16 : 32));
      SharkSslAesCtx_cbc_decrypt(&(decCtx.aesCtx), iv, in, in, (U16)len);  
      SharkSslAesCtx_destructor(&(decCtx.aesCtx));
   }
   else
   {
      return SHARKSSL_PEM_KEY_UNSUPPORTED_ENCRYPTION_TYPE;
   }

   if (out != in)
   {
      memmove(out, in, len);
   }
   return SHARKSSL_PEM_OK;
   #else
   (void)out;
   (void)in;
   (void)len;
   (void)pcmciascoop;
   (void)iv;
   (void)loongson3priority;
   (void)debugpreserved;
   return SHARKSSL_PEM_KEY_UNSUPPORTED_ENCRYPTION_TYPE;
   #endif
}
#endif


#if (SHARKSSL_USE_MD5 && (SHARKSSL_USE_AES_128 || SHARKSSL_USE_AES_256))
static U8 pxa270baseboard(U8 c)
{
    return (U8)((c >= '\101') ? (0xA + c - '\101') : (c - '\060'));
}
#endif


static sharkssl_PEM_RetVal debugmonitors(const char *pxa270flash, key_enc_type debugpreserved, U8 *ptr, U32 len, const char *registerguest, U8 fixupbridge)
{
   #if (SHARKSSL_USE_MD5 && (SHARKSSL_USE_AES_128 || SHARKSSL_USE_AES_256))
   SharkSslMd5Ctx md5Ctx;
   U8 softresetcomplete[16], pcmciascoop[32], i;

   
   fixupbridge >>= 1;
   if (fixupbridge > SHARKSSL_DIM_ARR(softresetcomplete))
   {
      return SHARKSSL_PEM_KEY_WRONG_LENGTH;
   }
   for (i = 0; i < fixupbridge; i++)
   {
      softresetcomplete[i] = pxa270baseboard(*registerguest++);
      softresetcomplete[i] <<= 4;
      softresetcomplete[i] |= pxa270baseboard(*registerguest++);
   }
   
   SharkSslMd5Ctx_constructor(&md5Ctx);
   SharkSslMd5Ctx_append(&md5Ctx, (const U8*)pxa270flash, (U32)strlen(pxa270flash));
   SharkSslMd5Ctx_append(&md5Ctx, (const U8*)softresetcomplete, 8 );
   SharkSslMd5Ctx_finish(&md5Ctx, &pcmciascoop[0]);

   SharkSslMd5Ctx_constructor(&md5Ctx);
   SharkSslMd5Ctx_append(&md5Ctx, &pcmciascoop[0], SHARKSSL_MD5_HASH_LEN);
   SharkSslMd5Ctx_append(&md5Ctx, (const U8*)pxa270flash, (U32)strlen(pxa270flash));
   SharkSslMd5Ctx_append(&md5Ctx, (const U8*)softresetcomplete, 8 );
   SharkSslMd5Ctx_finish(&md5Ctx, &pcmciascoop[SHARKSSL_MD5_HASH_LEN]);

   return pwrdmdisable(ptr, ptr, len, pcmciascoop, softresetcomplete, fixupbridge, debugpreserved);
   #else
   (void)pxa270flash;
   (void)debugpreserved;
   (void)ptr;
   (void)len;
   (void)registerguest;
   (void)fixupbridge;
   return SHARKSSL_PEM_KEY_UNSUPPORTED_ENCRYPTION_TYPE;
   #endif
}


#if SHARKSSL_ENABLE_ENCRYPTED_PKCS8_SUPPORT

SHARKSSL_API int sharkssl_PEM_PBKDF2(U8 *dk, const char *pxa270flash, const char *softresetcomplete, U32 singleftoui, U32 syskeyunlock, U16 registerioapic, U8 configwrite)
{
   SharkSslHMACCtx registermcasp;
   U8 handledomain[4], chargerplatform[SHARKSSL_MAX_HASH_LEN];
   U32 i;
   U16 usb11device, ftraceupdate, j;

   baAssert(pxa270flash);
   ftraceupdate = sharkssl_getHashLen(configwrite);
   if (0 == ftraceupdate)
   {
      return -1;
   }
   handledomain[0] = 0;
   handledomain[1] = 0;
   handledomain[2] = 0;
   handledomain[3] = 1;
   for (;;)
   {
      SharkSslHMACCtx_constructor(&registermcasp, configwrite, (const U8*)pxa270flash, (U16)strlen(pxa270flash));
      SharkSslHMACCtx_append(&registermcasp, (const U8*)softresetcomplete, singleftoui);
      SharkSslHMACCtx_append(&registermcasp, handledomain, 4);
      SharkSslHMACCtx_finish(&registermcasp, chargerplatform);  
      usb11device = (ftraceupdate >= registerioapic) ? ftraceupdate : registerioapic;
      memcpy(dk, chargerplatform, usb11device);
      for (i = 1; i < syskeyunlock; i++)
      {
         SharkSslHMACCtx_constructor(&registermcasp, configwrite, (const U8*)pxa270flash, (U16)strlen(pxa270flash));
         SharkSslHMACCtx_append(&registermcasp, chargerplatform, ftraceupdate);
         SharkSslHMACCtx_finish(&registermcasp, chargerplatform);
         for (j = 0; j < usb11device; j++)
         {
            dk[j] ^= chargerplatform[j];
         }
      }
      if (registerioapic > ftraceupdate)
      {
         registerioapic -= ftraceupdate;
         dk += ftraceupdate;
         
         if (0 == ++handledomain[3])
         {
            if (0 == ++handledomain[2])
            {
               if (0 == ++handledomain[1])
               {
                  handledomain[0]++;
               }
            }
         }
      }
      else
      {
         break;
      }
   }
   return 0;
}
#endif


static sharkssl_PEM_RetVal clusterpower(const char *logicpwrst, const char *pxa270flash, SharkSslCert *psizecompute)
{
   SharkSslParseASN1 sharkrestart;
   SharkSslCertKey disableclock;
   const char *statesuspended, *requestresources, *vectoraddress, *kaux, *kenc;
   int l;
   U32 pernodememory;
   U8 *sourcerouting;
   int loongson3priority = 0;
   key_enc_type debugpreserved = mmcsd0device;

   
   baAssert(NULL == (void*)0);
   *psizecompute = 0;

   if (logicpwrst == NULL)
   {
      return SHARKSSL_PEM_KEY_REQUIRED;
   }

   statesuspended = sharkStrstr(logicpwrst, "\055\055\055\055\055\102\105\107\111\116\040");
   if (NULL != statesuspended)
   {
      statesuspended += 11;  
      vectoraddress = sharkStrstr(statesuspended, "\040\113\105\131\055\055\055\055\055");
      if (NULL != vectoraddress)
      {
         vectoraddress += 9;  
         while (('\015' == *vectoraddress) || ('\012' == *vectoraddress))
         {
            vectoraddress++;  
         }
         requestresources = sharkStrstr(vectoraddress, "\055\055\055\055\055\105\116\104\040");
         if ((NULL != requestresources) && (vectoraddress < requestresources))  
         {
            kaux = sharkStrstr(statesuspended, "\120\122\111\126\101\124\105");
            if (NULL == kaux)
            {
               if (NULL == sharkStrstr(statesuspended, "\120\125\102\114\111\103"))
               {
                  return SHARKSSL_PEM_KEY_UNRECOGNIZED_FORMAT;
               }
               
               pernodememory = sharkssl_PEM_alloc_B64decode(&sourcerouting, vectoraddress, (U32)(requestresources - vectoraddress));
               if (0 == pernodememory)
               {
                  return SHARKSSL_PEM_ALLOCATION_ERROR;
               }
               sharkrestart.len = pernodememory;
               sharkrestart.ptr = sourcerouting + disablehazard;
               #if SHARKSSL_ENABLE_RSA
               if (NULL != sharkStrstr(statesuspended, "\122\123\101\040\120\125\102\114\111\103"))
               {
                  goto _key_parse_RSA_pub;
               }
               #endif
               
               l = SharkSslParseASN1_getSequence(&sharkrestart);
               if ((l < 0) || ((U32)l > pernodememory))
               {
                  _key_parse_error:
                  baFree(sourcerouting);
                  return SHARKSSL_PEM_KEY_PARSE_ERROR;
               }
               if ((SharkSslParseASN1_getSequence(&sharkrestart) < 0) || (SharkSslParseASN1_getOID(&sharkrestart) < 0))
               {
                  goto _key_parse_error;
               }
               l = SharkSslParseASN1_getAlgoID(&sharkrestart);
               #if SHARKSSL_ENABLE_RSA
               if (ALGO_ID_RSA_ENCRYPTION == l)
               {
                  if (SharkSslParseASN1_getBitString(&sharkrestart) < 0)
                  {
                     goto _key_parse_error;
                  }
                  sharkrestart.ptr = sharkrestart.dataptr;
                  sharkrestart.len = sharkrestart.datalen;
                  if ((0 == *(sharkrestart.ptr)) && (sharkrestart.len > 0))
                  {
                     sharkrestart.ptr++;
                     sharkrestart.len--;
                  }
                  _key_parse_RSA_pub:
                  if (SharkSslParseASN1_getSequence(&sharkrestart) < 0)
                  {
                     goto _key_parse_error;
                  }
                  l = signalinject(&sharkrestart, &disableclock);
                  if (SHARKSSL_PEM_OK != l)
                  {
                     baFree(sourcerouting);
                     return (sharkssl_PEM_RetVal)l;
                  }
                  specialmapping(disableclock.expLen);
                  pernodememory = claimresource(mousethresh(disableclock.expLen));
               }
               else
               #endif  
               #if SHARKSSL_USE_ECC
               if (ALGO_OID_EC_PUBLIC_KEY == l)
               {
                  disableclock.expLen = 0;
                  disableclock.exp = NULL;
                  deltaticks(disableclock.expLen);
                  l = mmcsd1device(&sharkrestart, &disableclock);
                  if (SHARKSSL_PEM_OK == l)
                  {
                     l = countslave(&sharkrestart, &disableclock);
                  }
                  if (SHARKSSL_PEM_OK != l)
                  {
                     baFree(sourcerouting);
                     return (sharkssl_PEM_RetVal)l;
                  }
                  pernodememory = 0;
               }
               else
               #endif  
               {
                  goto _key_parse_error;
               }
               l = tcpudpnofold(&disableclock, sourcerouting + setupfixed, pernodememory);
               if (SHARKSSL_PEM_OK != l)
               {
                  baFree(sourcerouting);
                  return (sharkssl_PEM_RetVal)l;
               }
               *psizecompute = (SharkSslCert)sourcerouting;
               return SHARKSSL_PEM_OK_PUBLIC;
            }
            if (kaux < vectoraddress)
            {
               
               kenc = strstr(statesuspended, "\105\116\103\122\131\120\124\105\104");
               if ((NULL == kenc) || (kenc > vectoraddress))
               {
                  if (NULL != kenc)
                  {
                     if (NULL == pxa270flash)
                     {
                        return SHARKSSL_PEM_KEY_PASSPHRASE_REQUIRED;
                     }
                     
                     kenc += 9;  
                     #if (SHARKSSL_USE_AES_256 && SHARKSSL_ENABLE_AES_CBC)
                     kaux = sharkStrstr(kenc, "\101\105\123\055\062\065\066\055\103\102\103");
                     if (kaux)
                     {
                        kaux += 11;  
                        debugpreserved = beforeprobe;
                     }
                     else
                     #endif
                     {
                        #if (SHARKSSL_USE_AES_128 && SHARKSSL_ENABLE_AES_CBC)
                        kaux = sharkStrstr(kenc, "\101\105\123\055\061\062\070\055\103\102\103");
                        if (kaux)
                        {
                           kaux += 11;  
                           debugpreserved = devicecamera;
                        }
                        else
                        #endif
                        {
                           #if 0 
                           kaux = sharkStrstr(kenc, "\103\150\141\103\150\141\062\060");
                           if (kaux)
                           {
                              kaux += 8;  
                              debugpreserved = unmapdomain;
                           }
                           else
                           #endif
                           {
                              return SHARKSSL_PEM_KEY_UNSUPPORTED_ENCRYPTION_TYPE;
                           }
                        }
                     }
                     #if ((SHARKSSL_USE_AES_128 || SHARKSSL_USE_AES_256) && SHARKSSL_ENABLE_AES_CBC)
                     
                     if ('\054' != *kaux++)
                     {
                        return SHARKSSL_PEM_KEY_UNRECOGNIZED_FORMAT;
                     }
                     
                     vectoraddress = kaux;
                     while (('\015' != *vectoraddress) && ('\012' != *vectoraddress))
                     {
                        if (((*vectoraddress < '\101') || (*vectoraddress > '\106')) && ((*vectoraddress < '\060') || (*vectoraddress > '\071')))
                        {
                           return SHARKSSL_PEM_KEY_WRONG_IV;
                        }
                        vectoraddress++;
                     }
                     
                     loongson3priority = (int)(vectoraddress - kaux);
                     if (0 ||
                         #if (SHARKSSL_USE_AES_128 || SHARKSSL_USE_AES_256)
                         ((loongson3priority != 0x20) && ((devicecamera == debugpreserved) || (beforeprobe == debugpreserved))) ||
                         #endif
                         0)
                     {
                        return SHARKSSL_PEM_KEY_WRONG_IV;
                     }
                     
                     while (('\015' == *vectoraddress) || ('\012' == *vectoraddress))
                     {
                        vectoraddress++;  
                     }
                     #endif
                  }
                  
                  pernodememory = sharkssl_PEM_alloc_B64decode(&sourcerouting, vectoraddress, (U32)(requestresources - vectoraddress));
                  if (0 == pernodememory)
                  {
                     return SHARKSSL_PEM_ALLOCATION_ERROR;
                  }
                  sharkrestart.len = pernodememory;
                  sharkrestart.ptr = sourcerouting + disablehazard;
                  #if SHARKSSL_ENABLE_RSA
                  if (statesuspended == sharkStrstr(statesuspended, "\122\123\101\040\120\122\111\126\101\124\105"))
                  {
                     
                     if (NULL != kenc)  
                     {
                        l = debugmonitors(pxa270flash, debugpreserved, sharkrestart.ptr, sharkrestart.len, kaux, (U8)loongson3priority);
                        if (SHARKSSL_PEM_OK != l)
                        {
                           goto _RSA_RetVal_not_OK;
                        }
                     }
                     
                     _key_parse_RSA_priv:
                     if (sharkssl_PEM_getSeqVersion(&sharkrestart, pernodememory) < 0)
                     {
                        goto _key_parse_error;
                     }
                     l = signalinject(&sharkrestart, &disableclock);
                     if (SHARKSSL_PEM_OK != l)
                     {
                        _RSA_RetVal_not_OK:
                        baFree(sourcerouting);
                        return (sharkssl_PEM_RetVal)l;
                     }
                     if (SharkSslParseASN1_getInt(&sharkrestart) < 0)  
                     {
                        goto _key_parse_error;
                     }
                     cryptoresources(disableclock.expLen);
                     pernodememory = claimresource(mousethresh(disableclock.expLen));
                     l = tcpudpnofold(&disableclock, sourcerouting + setupfixed, pernodememory);
                     if (SHARKSSL_PEM_OK != l)
                     {
                        goto _RSA_RetVal_not_OK;
                     }
                     pernodememory = supportedvector(disableclock.modLen);
                     kaux = (char*)(sourcerouting + setupfixed + pwrdmclear + mousethresh(disableclock.expLen) + pernodememory);
                     
                     baAssert((U8*)kaux <= sharkrestart.ptr);
                     
                     pernodememory >>= 1;
                     for (l = 5; l > 0; l--)
                     {
                        if ((SharkSslParseASN1_getInt(&sharkrestart) < 0) || (sharkrestart.datalen > pernodememory))
                        {
                           goto _key_parse_error;
                        }
                        if (sharkrestart.datalen < pernodememory)
                        {
                           
                           memset((U8*)kaux, 0, (U16)(pernodememory - sharkrestart.datalen));
                           kaux += (U16)(pernodememory - sharkrestart.datalen);
                        }
                        memmove((U8*)kaux, sharkrestart.dataptr, sharkrestart.datalen);
                        kaux += sharkrestart.datalen;
                     }
                     *psizecompute = (SharkSslCert)sourcerouting;
                     return SHARKSSL_PEM_OK;
                  }
                  else
                  #endif
                  #if SHARKSSL_USE_ECC
                  
                  if (statesuspended == sharkStrstr(statesuspended, "\105\103\040\120\101\122\101\115\105\124\105\122\123"))
                  {
                     statesuspended = sharkStrstr(statesuspended, "\105\103\040\120\122\111\126\101\124\105");
                     if (NULL == statesuspended)
                     {
                        l = SHARKSSL_PEM_KEY_UNRECOGNIZED_FORMAT;
                        goto _EC_RetVal_not_OK;
                     }
                  }
                  if (statesuspended == sharkStrstr(statesuspended, "\105\103\040\120\122\111\126\101\124\105"))
                  {
                     
                     if (NULL != kenc)  
                     {
                        l = debugmonitors(pxa270flash, debugpreserved, sharkrestart.ptr, sharkrestart.len, kaux, (U8)loongson3priority);
                        if (SHARKSSL_PEM_OK != l)
                        {
                           goto _EC_RetVal_not_OK;
                        }
                     }
                     kaux = NULL;  
                     _key_parse_EC_priv:
                     
                     if (sharkssl_PEM_getSeqVersion(&sharkrestart, pernodememory) != 1)
                     {
                        baFree(sourcerouting);
                        return SHARKSSL_PEM_KEY_UNSUPPORTED_VERSION;
                     }
                     if (SharkSslParseASN1_getOctetString(&sharkrestart) < 0)
                     {
                        goto _key_parse_error;
                     }
                     disableclock.exp = sharkrestart.dataptr;
                     disableclock.expLen = (U8)sharkrestart.datalen;
                     baAssert(disableclock.expLen <= 0xFF);
                     hsspidevice(disableclock.expLen);
                     
                     if (NULL == kaux)
                     {
                        if (SharkSslParseASN1_getECParameters(&sharkrestart) < 0)
                        {
                           goto _key_parse_error;
                        }
                        l = mmcsd1device(&sharkrestart, &disableclock);
                        if (SHARKSSL_PEM_OK != l)
                        {
                           _EC_RetVal_not_OK:
                           baFree(sourcerouting);
                           return (sharkssl_PEM_RetVal)l;
                        }
                     }
                     l = countslave(&sharkrestart, &disableclock);
                     if (SHARKSSL_PEM_OK != l)
                     {
                        goto _EC_RetVal_not_OK;
                     }
                     l = tcpudpnofold(&disableclock, sourcerouting + setupfixed, 0);
                     if (SHARKSSL_PEM_OK != l)
                     {
                        goto _EC_RetVal_not_OK;
                     }
                     *psizecompute = (SharkSslCert)sourcerouting;
                     return SHARKSSL_PEM_OK;
                  }
                  else
                  #endif
                  if (NULL == kenc)
                  {
                     if (statesuspended == kaux)  
                     {
                        
                        #if (SHARKSSL_ENABLE_ENCRYPTED_PKCS8_SUPPORT && SHARKSSL_ENABLE_AES_CBC)
                        _plain_PKCS8_parsing:
                        #endif
                        if (sharkssl_PEM_getSeqVersion(&sharkrestart, pernodememory) < 0)
                        {
                           goto _key_parse_error;
                        }
                        if ((SharkSslParseASN1_getSequence(&sharkrestart) < 0) || (SharkSslParseASN1_getOID(&sharkrestart) < 0))
                        {
                           goto _key_parse_error;
                        }
                        l = SharkSslParseASN1_getAlgoID(&sharkrestart);
                        #if SHARKSSL_ENABLE_RSA
                        if (ALGO_ID_RSA_ENCRYPTION == l)
                        {
                           if (SharkSslParseASN1_getOctetString(&sharkrestart) < 0)
                           {
                              goto _key_parse_error;
                           }
                           sharkrestart.ptr = sharkrestart.dataptr;
                           sharkrestart.len = sharkrestart.datalen;
                           goto _key_parse_RSA_priv;
                        }
                        else
                        #endif  
                        #if SHARKSSL_USE_ECC
                        if (ALGO_OID_EC_PUBLIC_KEY == l)
                        {
                           if (SharkSslParseASN1_getOID(&sharkrestart) < 0)
                           {
                              return SHARKSSL_PEM_KEY_PARSE_ERROR;
                           }
                           l = SharkSslParseASN1_getCurveID(&sharkrestart);
                           baAssert(l <= 0xFF);
                           if (SHARKSSL_EC_CURVE_ID_UNKNOWN == (U8)l)
                           {
                              return SHARKSSL_PEM_KEY_UNSUPPORTED_FORMAT;
                           }
                           if (SharkSslParseASN1_getOctetString(&sharkrestart) < 0)
                           {
                              goto _key_parse_error;
                           }
                           disableclock.modLen = 0;
                           nomsrnoirq(disableclock.modLen, (U8)l);
                           sharkrestart.ptr = sharkrestart.dataptr;
                           sharkrestart.len = sharkrestart.datalen;
                           baAssert(kaux);
                           goto _key_parse_EC_priv;
                        }
                        else
                        #endif  
                        goto _key_parse_error;
                     }
                  }
               }
               else if (kenc == statesuspended)  
               {
                  #if SHARKSSL_ENABLE_ENCRYPTED_PKCS8_SUPPORT
                  #if ((!SHARKSSL_USE_SHA_256) || (!SHARKSSL_ENABLE_AES_CBC))
                  #error SHARKSSL_ENABLE_ENCRYPTED_PKCS8_SUPPORT requires SHARKSSL_USE_SHA_256 and SHARKSSL_ENABLE_AES_CBC
                  #endif
                  
                  if (NULL == pxa270flash)
                  {
                     return SHARKSSL_PEM_KEY_PASSPHRASE_REQUIRED;
                  }
                  
                  pernodememory = sharkssl_PEM_alloc_B64decode(&sourcerouting, vectoraddress, (U32)(requestresources - vectoraddress));
                  if (0 == pernodememory)
                  {
                     return SHARKSSL_PEM_ALLOCATION_ERROR;
                  }
                  sharkrestart.len = pernodememory;
                  sharkrestart.ptr = sourcerouting + disablehazard;
                  
                  l = SharkSslParseASN1_getSequence(&sharkrestart);
                  if ((l < 0) || ((U32)l > pernodememory))
                  {
                     goto _key_parse_error;
                  }
                  if ((SharkSslParseASN1_getSequence(&sharkrestart) < 0) || (SharkSslParseASN1_getOID(&sharkrestart) < 0))
                  {
                     goto _key_parse_error;
                  }
                  if (ALGO_ID_PKCS5_PBES2 != SharkSslParseASN1_getAlgoID(&sharkrestart))
                  {
                     _key_unsupported_enctype:
                     baFree(sourcerouting);
                     return SHARKSSL_PEM_KEY_UNSUPPORTED_ENCRYPTION_TYPE;
                  }
                  if ((SharkSslParseASN1_getSequence(&sharkrestart) < 0) || (SharkSslParseASN1_getSequence(&sharkrestart) < 0) || (SharkSslParseASN1_getOID(&sharkrestart) < 0))
                  {
                     goto _key_parse_error;
                  }
                  if (ALGO_ID_PKCS5_PBKDF2 != SharkSslParseASN1_getAlgoID(&sharkrestart))
                  {
                     goto _key_unsupported_enctype;
                  }
                  if ((SharkSslParseASN1_getSequence(&sharkrestart) < 0) || (SharkSslParseASN1_getOctetString(&sharkrestart) < 0))
                  {
                     goto _key_parse_error;
                  }
                  loongson3priority = sharkrestart.datalen;
                  kaux = (const char*)sharkrestart.dataptr;
                  if (loongson3priority > 16)
                  {
                     _key_unsupported_format:
                     baFree(sourcerouting);
                     return SHARKSSL_PEM_KEY_UNSUPPORTED_FORMAT;
                  }
                  if (SharkSslParseASN1_getInt(&sharkrestart) < 0)  
                  {
                     goto _key_parse_error;
                  }
                  if (sharkrestart.datalen > 4)
                  {
                     goto _key_unsupported_format;  
                  }
                  pernodememory = 0;
                  while (sharkrestart.datalen--)
                  {
                     pernodememory <<= 8;
                     pernodememory |= *sharkrestart.dataptr++;
                  }
                  if ((SharkSslParseASN1_getSequence(&sharkrestart) < 0) || (SharkSslParseASN1_getOID(&sharkrestart) < 0))
                  {
                     goto _key_parse_error;
                  }
                  l = SharkSslParseASN1_getAlgoID(&sharkrestart);
                  
                  #if SHARKSSL_USE_SHA_256
                  if (ALGO_ID_HMAC_WITH_SHA256 != l)
                  #endif
                  {
                     goto _key_unsupported_enctype;
                  }
                  if (sharkssl_PEM_PBKDF2(sourcerouting + disablehazard, pxa270flash, kaux, loongson3priority, pernodememory, 32, GET_ALGO_HASH_ID(l)))
                  {
                     baFree(sourcerouting);
                     return SHARKSSL_PEM_INTERNAL_ERROR;
                  }
                  if ((SharkSslParseASN1_getSequence(&sharkrestart) < 0) || (SharkSslParseASN1_getOID(&sharkrestart) < 0))
                  {
                     goto _key_parse_error;
                  }
                  l = SharkSslParseASN1_getAlgoID(&sharkrestart);
                  #if SHARKSSL_ENABLE_AES_CBC
                  #if SHARKSSL_USE_AES_128
                  if (ALGO_ID_AES_128_CBC == l)
                  {
                     debugpreserved = devicecamera;
                  }
                  else
                  #endif
                  #if SHARKSSL_USE_AES_256
                  if (ALGO_ID_AES_256_CBC == l)
                  {
                     debugpreserved = beforeprobe;
                  }
                  else
                  #endif
                  #endif
                  {
                     goto _key_unsupported_enctype;
                  }
                  #if SHARKSSL_ENABLE_AES_CBC
                  if (SharkSslParseASN1_getOctetString(&sharkrestart) < 0)
                  {
                     goto _key_parse_error;
                  }
                  loongson3priority = sharkrestart.datalen;
                  kaux = (const char*)sharkrestart.dataptr;
                  if (SharkSslParseASN1_getOctetString(&sharkrestart) < 0)
                  {
                     goto _key_parse_error;
                  }
                  
                  sharkrestart.ptr = sourcerouting + disablehazard;  
                  sharkrestart.len = sharkrestart.datalen;
                  l = pwrdmdisable(sharkrestart.ptr, sharkrestart.dataptr, sharkrestart.datalen, sourcerouting + disablehazard, (U8*)kaux, loongson3priority, debugpreserved);
                  if (SHARKSSL_PEM_OK != l)
                  {
                     baFree(sourcerouting);
                     return (sharkssl_PEM_RetVal)l;
                  }
                  goto _plain_PKCS8_parsing;
                  #endif  
                  #else
                  return SHARKSSL_PEM_KEY_UNSUPPORTED_FORMAT;
                  #endif
               }
            }  
         }  
      }   
   }   
   return SHARKSSL_PEM_KEY_UNRECOGNIZED_FORMAT;
}



static sharkssl_PEM_RetVal sharkssl_PEM_findNextCert(const char **begin, const char **end)
{
   *begin = sharkStrstr(*begin, "\055\055\055\055\055\102\105\107\111\116");
   if (*begin)
   {
      *begin = sharkStrstr(*begin, "\103\105\122\124\111\106\111\103\101\124\105\055\055\055\055\055");
      if (NULL == *begin)
      {
         return SHARKSSL_PEM_CERT_UNRECOGNIZED_FORMAT;
      }
      *begin += 16;  
      while (('\015' == **begin) || ('\012' == **begin))
      {
         (*begin)++;
      }
      *end = sharkStrstr(*begin, "\055\055\055\055\055\105\116\104");
      if (NULL == *end)
      {
         return SHARKSSL_PEM_CERT_UNRECOGNIZED_FORMAT;
      }
   }
   return SHARKSSL_PEM_OK;
}



SHARKSSL_API sharkssl_PEM_RetVal sharkssl_PEM(const char *allowresize, const char *logicpwrst,
                                              const char *pxa270flash, SharkSslCert *psizecompute)
{
   U8 *ptr;
   const char *cbeg, *cend;
   sharkssl_PEM_RetVal ret = clusterpower(logicpwrst, pxa270flash, psizecompute);
   U32 pernodememory = 0;  
   U32 pxafbmodes;
   U8  rdlo12rdhi16rn0rm8rwflags;
   #if SHARKSSL_ENABLE_CERT_CHAIN
   U8  devicerelease;
   #endif

   if ((SHARKSSL_PEM_OK_PUBLIC == ret) && (allowresize))
   {
      return SHARKSSL_PEM_KEY_PRIVATE_KEY_REQUIRED;
   }
   if (ret >= 0)  
   {
      pernodememory = SharkSslKey_vectSize((SharkSslKey)*psizecompute);
   }
   
   if ((SHARKSSL_PEM_OK != ret) || (!allowresize))
   {
      if (ret >= 0)
      {
         
         void *devicehandle = baRealloc((void*)*psizecompute, pernodememory);
         if (devicehandle)
         {
            *psizecompute = (SharkSslCert)devicehandle;
         }
      }
      return ret;
   }
   
   cbeg = allowresize;
   pxafbmodes = 0;
   #if SHARKSSL_ENABLE_CERT_CHAIN
   devicerelease = 0;
   _sharkssl_PEM_scan_next_cert:
   #endif
   ret = sharkssl_PEM_findNextCert(&cbeg, &cend);
   if (SHARKSSL_PEM_OK != ret) 
   {
      _sharkssl_PEM_free_ret:
      baFree((void*)*psizecompute);
      return ret;
   }
   if (cbeg)
   {
      if (((U32)(cend - cbeg)) > 0xFFFF)
      {
         ret = SHARKSSL_PEM_CERT_UNSUPPORTED_TYPE;
         goto _sharkssl_PEM_free_ret;
      }
      pxafbmodes += (U32)(cend - cbeg);
      #if SHARKSSL_ENABLE_CERT_CHAIN
      devicerelease++;
      cbeg = cend;
      goto _sharkssl_PEM_scan_next_cert;
      #endif
   }
   else
   {
      #if SHARKSSL_ENABLE_CERT_CHAIN
      if (devicerelease)
      {
         devicerelease--;
      }
      else
      #endif
      {
         ret = SHARKSSL_PEM_CERT_UNRECOGNIZED_FORMAT;
         goto _sharkssl_PEM_free_ret;
      }
   }
   
   ptr = (U8*)baMalloc(((pxafbmodes * 3) >> 2) + pernodememory + SHARKSSL_ALIGNMENT - setupfixed);
   if (NULL == ptr)
   {
      ret = SHARKSSL_PEM_ALLOCATION_ERROR;
      goto _sharkssl_PEM_free_ret;
   }
   cbeg = allowresize;
   sharkssl_PEM_findNextCert(&cbeg, &cend);
   pxafbmodes = sharkssl_B64Decode(ptr, (U32)(cend - cbeg), cbeg, cend);
   
   if (pxafbmodes != SharkSslCert_len((SharkSslCert)ptr))
   {
      ret = SHARKSSL_PEM_CERT_UNSUPPORTED_TYPE;
      baFree(ptr);
      goto _sharkssl_PEM_free_ret;
   }
   rdlo12rdhi16rn0rm8rwflags = (((U8)(~pxafbmodes & 0x3)) + 1) & 0x3;  
   memset(ptr + pxafbmodes, 0xFF, rdlo12rdhi16rn0rm8rwflags);
   memcpy(ptr + pxafbmodes + rdlo12rdhi16rn0rm8rwflags, *psizecompute + setupfixed, pernodememory - setupfixed);
   baFree((void*)*psizecompute);  
   *psizecompute = ptr;
   #if SHARKSSL_ENABLE_CERT_CHAIN
   if (devicerelease)
   {
      ptr = (U8*)*psizecompute + pxafbmodes + rdlo12rdhi16rn0rm8rwflags;
      *ptr = (*ptr & 0x0F) | ((U8)devicerelease << 4);  
      ptr += pernodememory - setupfixed;
      while (devicerelease--)
      {
         
         cbeg = cend;
         sharkssl_PEM_findNextCert(&cbeg, &cend);
         pxafbmodes = sharkssl_B64Decode(ptr, (U32)(cend - cbeg), cbeg, cend);
         
         if (pxafbmodes != SharkSslCert_len((SharkSslCert)ptr))
         {
            ret = SHARKSSL_PEM_CERT_UNSUPPORTED_TYPE;
            goto _sharkssl_PEM_free_ret;
         }
         ptr += pxafbmodes;
      }
   }
   #endif
   return SHARKSSL_PEM_OK;
}



#if ((SHARKSSL_ENABLE_RSA_API || SHARKSSL_ENABLE_ECDSA_API) && \
    ((SHARKSSL_SSL_CLIENT_CODE && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)) || \
     (SHARKSSL_SSL_SERVER_CODE)))
SHARKSSL_API SharkSslKey sharkssl_PEM_extractPublicKey_ext(const char *allowresize, U8 *earlyconsole)
{
   SharkSslCertParam certParam;
   char *cbeg, *cend;
   U8  *aemifresources, *buttontable;
   U16  kco, kcoa, pxafbmodes;

   if (allowresize)
   {
      
      cbeg = (char*)sharkStrstr(allowresize, "\055\055\055\055\055\102\105\107\111\116");
      if (cbeg)
      {
         cbeg = sharkStrstr(cbeg, "\103\105\122\124\111\106\111\103\101\124\105\055\055\055\055\055");
      }
      if (cbeg == (void*)0)
      {
         return NULL;
      }
      cbeg += 16; 
      while ((*cbeg == '\015') || (*cbeg == '\012'))
      {
         cbeg++;
      }
      cend = (char*)sharkStrstr(cbeg, "\055\055\055\055\055\105\116\104");
      if (cend == (void*)0)
      {
         return NULL;
      }
      if (((U32)(cend - cbeg)) > 0xFFFF)
      {
         return NULL;
      }
      pxafbmodes = (U16)(cend - cbeg);
      kco  = ((U16)(pxafbmodes * 3)) >> 2;
   }
   else
   {
      return NULL;
   }

   aemifresources = (U8*)baMalloc(4 + kco);
   if (aemifresources == (void*)0)
   {
      return NULL;
   }

   
   kco = (U16)sharkssl_B64Decode(aemifresources, pxafbmodes, cbeg, cend);

   
   if ((kco != SharkSslCert_len((SharkSslCert)aemifresources)) || (spromregister(&certParam, aemifresources, kco, 0) < 0))
   {
      sharkssl_PEM_extractPublicKey_1:
      baFree(aemifresources);
      return NULL;
   }

   kco = kcoa = mousethresh(certParam.certKey.expLen);
   pxafbmodes = loaderbinfmt(certParam.certKey.modLen, certParam.certKey.expLen);
   *earlyconsole = allocatoralloc(certParam.certKey.expLen);
   if (rewindsingle == *earlyconsole)
   {
      
      kcoa = claimresource(kco);
      
      certParam.certKey.expLen = (certParam.certKey.expLen & 0xFF00) + kcoa;
   }
   #if SHARKSSL_USE_ECC
   else
   {
      baAssert(0 == kco);
      pxafbmodes *= 2;
   }
   #endif

   kcoa -= kco;
   buttontable = (U8*)baMalloc(8 + mousethresh(certParam.certKey.expLen) + pxafbmodes);
   if (buttontable == (void*)0)
   {
      goto sharkssl_PEM_extractPublicKey_1;
   }

   
   cbeg = (char*)buttontable;
   *cbeg++ = (char)0x30;
   *cbeg++ = (unsigned char)0x82;
   *cbeg++ = (char)0x00;
   *cbeg++ = (char)0x00;
   *cbeg++ = (char)(certParam.certKey.expLen >> 8);    
   *cbeg++ = (char)(certParam.certKey.expLen & 0xFF);
   *cbeg++ = (char)(certParam.certKey.modLen >> 8);
   *cbeg++ = (char)(certParam.certKey.modLen & 0xFF);  
   while (kcoa--)
   {
      *cbeg++ = 0;
   }
   memcpy(cbeg, certParam.certKey.exp, kco);
   cbeg += kco;
   memcpy(cbeg, certParam.certKey.mod, pxafbmodes);
   baFree(aemifresources);
   return (SharkSslKey)buttontable;
}


SHARKSSL_API SharkSslKey sharkssl_PEM_extractPublicKey(const char *allowresize)
{
   U8 earlyconsole;
   return sharkssl_PEM_extractPublicKey_ext(allowresize, &earlyconsole);
}
#endif  
#endif  


#if SHARKSSL_ENABLE_RSA

int omap3430common(const SharkSslCertKey *disableclock, U16 len, U8 *in, U8 *out, U8 seepromprobe)
{
   U16 creategroup;

   baAssert(NULL == (void*)0);
   baAssert((seepromprobe == SHARKSSL_RSA_NO_PADDING) || (seepromprobe == SHARKSSL_RSA_PKCS1_PADDING));
   if ((in == NULL) || (out == NULL) || (disableclock == NULL) || (!(machinekexec(disableclock->expLen))))
   {
      return (int)SHARKSSL_RSA_WRONG_PARAMETERS;
   }
   creategroup = supportedvector(disableclock->modLen);
   #if (SHARKSSL_ENABLE_RSA_PKCS1 || SHARKSSL_SSL_SERVER_CODE || SHARKSSL_SSL_CLIENT_CODE)
   if (seepromprobe == SHARKSSL_RSA_PKCS1_PADDING)
   {
      U16 kl;

      if (creategroup < 11)
      {
         return (int)SHARKSSL_RSA_WRONG_KEY_LENGTH;
      }

      if (len >= (creategroup - 11))
      {
         return (int)SHARKSSL_RSA_INPUT_DATA_LENGTH_TOO_BIG;
      }
      kl = creategroup - len;
      memmove(out + kl, in, len);
      in = out;
      *in++ = 0x00;  
      *in++ = 0x02;
      kl -= 3;
      len = (kl & 0x0003);
      kl &= 0xFFFC;  
      if (sharkssl_rng(in, kl) < 0)
      {
         return (int)SHARKSSL_RSA_INTERNAL_ERROR;
      }
      in += kl;
      if (len)
      {
         in -= (4 - len);
         if (sharkssl_rng(in, 4) < 0)
         {
            return (int)SHARKSSL_RSA_INTERNAL_ERROR;
         }
         in += 4;
      }
      *in-- = 0x00;
      while (in != out)
      {
         if (0x00 == *in)
         {
            *in = 0x55;
         }
         in--;
      }
   }
   else  
   #endif
   {
      if (len != creategroup)
      {
         return (int)SHARKSSL_RSA_INPUT_DATA_LENGTH_AND_KEY_LENGTH_MISMATCH;
      }
      memmove(out, in, len);
   }
   if (async3clksrc(disableclock, hsmmcplatform, out))
   {
      return (int)SHARKSSL_RSA_ALLOCATION_ERROR;
   }
   return creategroup;
}


int writemessage(const SharkSslCertKey *disableclock, U16 len, U8 *in, U8 *out, U8 seepromprobe)
{
   U16 creategroup;

   baAssert(NULL == (void*)0);
   baAssert((seepromprobe == SHARKSSL_RSA_NO_PADDING) || (seepromprobe == SHARKSSL_RSA_PKCS1_PADDING));
   if ((in == NULL) || (out == NULL) || (disableclock == NULL) || (!(machinekexec(disableclock->expLen))))
   {
      return (int)SHARKSSL_RSA_WRONG_PARAMETERS;
   }
   creategroup = supportedvector(disableclock->modLen);
   if (0 == creategroup)
   {
      return (int)SHARKSSL_RSA_WRONG_KEY_LENGTH;
   }
   if (len != creategroup)
   {
      return (int)SHARKSSL_RSA_INPUT_DATA_LENGTH_AND_KEY_LENGTH_MISMATCH;
   }
   if (async3clksrc(disableclock, sleepstore, in))
   {
      return (int)SHARKSSL_RSA_ALLOCATION_ERROR;
   }
   #if (SHARKSSL_ENABLE_RSA_PKCS1 || SHARKSSL_SSL_SERVER_CODE || SHARKSSL_SSL_CLIENT_CODE)
   if (seepromprobe == SHARKSSL_RSA_PKCS1_PADDING)
   {
      
      if ((*in++ != 0x00) || (*in++ != 0x02))
      {
         return (int)SHARKSSL_RSA_PKCS1_PADDING_ERROR;
      }
      creategroup -= 2;
      while ((--creategroup) && (*in++ != 0x00))
      {
      }
      if (0 == creategroup)
      {
         return (int)SHARKSSL_RSA_PKCS1_PADDING_ERROR;
      }
   }
   #endif
   memmove(out, in, creategroup);
   return creategroup;
}


int clockaccess(const SharkSslCertKey *disableclock, U16 len, U8 *in, U8 *out, U8 seepromprobe)
{
   U16 creategroup;

   baAssert(NULL == (void*)0);
   baAssert((seepromprobe == SHARKSSL_RSA_NO_PADDING) || (seepromprobe == SHARKSSL_RSA_PKCS1_PADDING));
   if ((in == NULL) || (out == NULL) || (disableclock == NULL) || (!(machinekexec(disableclock->expLen))))
   {
      return (int)SHARKSSL_RSA_WRONG_PARAMETERS;
   }
   creategroup = supportedvector(disableclock->modLen);
   #if (SHARKSSL_ENABLE_RSA_PKCS1 || SHARKSSL_SSL_SERVER_CODE || SHARKSSL_SSL_CLIENT_CODE)
   if (seepromprobe == SHARKSSL_RSA_PKCS1_PADDING)
   {
      U16 kl;

      if (creategroup < 11)
      {
         return (int)SHARKSSL_RSA_WRONG_KEY_LENGTH;
      }

      if (len >= (creategroup - 11))
      {
         return (int)SHARKSSL_RSA_INPUT_DATA_LENGTH_TOO_BIG;
      }
      kl = creategroup - len;
      memmove(out + kl, in, len);
      in = out;
      *in++ = 0x00;  
      *in++ = 0x01;
      kl -= 3;
      memset(in, 0xFF, kl);
      *(in + kl) = 0x00;
   }
   else  
   #endif
   {
      if (len != creategroup)
      {
         return (int)SHARKSSL_RSA_INPUT_DATA_LENGTH_AND_KEY_LENGTH_MISMATCH;
      }
      memmove(out, in, len);
   }
   if (async3clksrc(disableclock, sleepstore, out))
   {
      return (int)SHARKSSL_RSA_ALLOCATION_ERROR;
   }
   return creategroup;
}


int handleguest(const SharkSslCertKey *disableclock, U16 len, U8 *in, U8 *out, U8 seepromprobe)
{
   U16 creategroup;

   baAssert(NULL == (void*)0);
   baAssert((seepromprobe == SHARKSSL_RSA_NO_PADDING) || (seepromprobe == SHARKSSL_RSA_PKCS1_PADDING));
   if ((in == NULL) || (out == NULL) || (disableclock == NULL) || (!(machinekexec(disableclock->expLen))))
   {
      return (int)SHARKSSL_RSA_WRONG_PARAMETERS;
   }
   creategroup = supportedvector(disableclock->modLen);
   if (0 == creategroup)
   {
      return (int)SHARKSSL_RSA_WRONG_KEY_LENGTH;
   }
   if (len != creategroup)
   {
      return (int)SHARKSSL_RSA_INPUT_DATA_LENGTH_AND_KEY_LENGTH_MISMATCH;
   }
   if (async3clksrc(disableclock, hsmmcplatform, in))
   {
      return (int)SHARKSSL_RSA_ALLOCATION_ERROR;
   }
   #if (SHARKSSL_ENABLE_RSA_PKCS1 || SHARKSSL_SSL_SERVER_CODE || SHARKSSL_SSL_CLIENT_CODE)
   if (seepromprobe == SHARKSSL_RSA_PKCS1_PADDING)
   {
      
      if ((*in++ != 0x00) || (*in++ != 0x01))
      {
         return (int)SHARKSSL_RSA_PKCS1_PADDING_ERROR;
      }
      creategroup -= 2;
      while (--creategroup)
      {
         U8 c = *in++;
         if (c == 0)
         {
            break;
         }
         else if (c != 0xFF)
         {
            return (int)SHARKSSL_RSA_PKCS1_PADDING_ERROR;
         }
      }
      if (0 == creategroup)
      {
         return (int)SHARKSSL_RSA_PKCS1_PADDING_ERROR;
      }
   }
   #endif
   memmove(out, in, creategroup);
   return creategroup;
}


#if (SHARKSSL_ENABLE_RSA_API)
#if (SHARKSSL_ENABLE_PEM_API)
SHARKSSL_API SharkSslRSAKey sharkssl_PEM_to_RSAKey(const char *clearnopref, const char *pxa270flash)
{
   SharkSslCert kernelvaddr;

   baAssert(NULL == (void*)0);
   if ((clearnopref == (void*)0) || (sharkssl_PEM(NULL, clearnopref, pxa270flash, &kernelvaddr) < 0))
   {
      return NULL;
   }
   return (SharkSslRSAKey)kernelvaddr;
}


SHARKSSL_API void SharkSslRSAKey_free(SharkSslRSAKey hsspiregister)
{
   if (hsspiregister)
   {
      baFree((void*)hsspiregister);
   }
}
#endif  



SHARKSSL_API U16 SharkSslRSAKey_size(SharkSslRSAKey sourcerouting)
{
   SharkSslCertKey disableclock;
   baAssert(NULL == (void*)0);

   if (interrupthandler(&disableclock, (SharkSslCert)sourcerouting))
   {
      if (machinekexec(disableclock.expLen))
      {
         return disableclock.modLen;
      }
   }
   return 0;
}


typedef int (*SharkSslCertKey_RSA_func)(const SharkSslCertKey*, U16, U8*, U8*, U8);

static sharkssl_RSA_RetVal switchcompletion(SharkSslCertKey_RSA_func orderarray, SharkSslRSAKey sourcerouting, U16 len, U8 *in, U8 *out, U8 seepromprobe)
{
   SharkSslCertKey disableclock;

   if ((in == NULL) || (out == NULL) || (sourcerouting == NULL))
   {
      return SHARKSSL_RSA_WRONG_PARAMETERS;
   }

   if (0 == interrupthandler(&disableclock, sourcerouting))
   {
      return SHARKSSL_RSA_WRONG_KEY_FORMAT;
   }

   return (sharkssl_RSA_RetVal)orderarray(&disableclock, len, in, out, seepromprobe);
}


SHARKSSL_API sharkssl_RSA_RetVal sharkssl_RSA_public_encrypt(U16 len, U8 *in, U8 *out, SharkSslRSAKey sourcerouting, U8 seepromprobe)
{
   return switchcompletion(omap3430common, sourcerouting, len, in, out, seepromprobe);
}


SHARKSSL_API sharkssl_RSA_RetVal sharkssl_RSA_private_decrypt(U16 len, U8 *in, U8 *out, SharkSslRSAKey resumeenabler, U8 seepromprobe)
{
   return switchcompletion(writemessage, resumeenabler, len, in, out, seepromprobe);
}


#if (SHARKSSL_ENABLE_RSA_OAEP && SHARKSSL_USE_SHA1)
void sharkssl_MGF1(U8 *pciercxcfg448, U16 allocskcipher, U8 *src, U16 consolewrite)
{
   SharkSslSha1Ctx sha1Ctx;
   U8 chargerplatform[SHARKSSL_SHA1_HASH_LEN];
   U8 ctr[4], ftraceupdate, i;

   hsotgpdata(0, ctr, 0);
   ftraceupdate = SHARKSSL_SHA1_HASH_LEN;

   while (allocskcipher > 0)
   {
      if (allocskcipher < ftraceupdate)
      {
         ftraceupdate = (U8)allocskcipher;
      }
      SharkSslSha1Ctx_constructor(&sha1Ctx);
      SharkSslSha1Ctx_append(&sha1Ctx, src, consolewrite);
      SharkSslSha1Ctx_append(&sha1Ctx, ctr, SHARKSSL_DIM_ARR(ctr));
      SharkSslSha1Ctx_finish(&sha1Ctx, chargerplatform);
      for (i = 0; i < ftraceupdate; i++)
      {
         *pciercxcfg448++ ^= chargerplatform[i];
      }
      ctr[3]++;
      allocskcipher -= ftraceupdate;
   }

   memset(&sha1Ctx, 0, sizeof sha1Ctx);
   memset(chargerplatform, 0, SHARKSSL_DIM_ARR(chargerplatform));
}


SHARKSSL_API sharkssl_RSA_RetVal sharkssl_RSA_private_decrypt_OAEP(U16 len, U8 *in, U8 *out, SharkSslRSAKey resumeenabler, U8 configwrite, char *clkdmoperations, U16 auxdatalookup)
{
   
   int ret;
   U8 i, ftraceupdate;

   baAssert(configwrite == SHARKSSL_HASHID_SHA1);
   ftraceupdate = SHARKSSL_SHA1_HASH_LEN;
   ret = (int)switchcompletion(writemessage, resumeenabler, len, in, in, SHARKSSL_RSA_NO_PADDING);
   if (ret < (2 * ftraceupdate + 2))
   {
      ret = SHARKSSL_RSA_WRONG_KEY_LENGTH;
   }
   else
   {
      int PSLen, buttonsbuffalo;
      U8 logicstate[SHARKSSL_SHA1_HASH_LEN], *ptr, sum, flg;

      sharkssl_MGF1(&in[1], ftraceupdate, &in[1 + ftraceupdate], (U16)ret - ftraceupdate - 1);
      sharkssl_MGF1(&in[ftraceupdate + 1], (U16)ret - ftraceupdate - 1, &in[1], ftraceupdate);
      sharkssl_sha1((U8*)clkdmoperations, auxdatalookup, logicstate);

      
      ptr = in;
      sum = *ptr++; 
      ret--;
      ptr += ftraceupdate; 
      ret -= (ftraceupdate << 1);
      for (i = 0; ftraceupdate--; i++)
      {
         sum |= *ptr++ ^ logicstate[i];
      }
      
      buttonsbuffalo = ret;
      flg = 0;
      in = ptr;
      PSLen = 0;
      while (--buttonsbuffalo)
      {
         flg |= *in++;
         PSLen += (~flg) & 0x01;  
      }
      ret -= PSLen;
      ptr += PSLen;
      sum |= *ptr++ ^ 0x01;
      if ((0 == ret) || (sum))
      {
         return SHARKSSL_RSA_PKCS1_PADDING_ERROR;
      }
      ret--;
      memcpy(out, ptr, ret);
      memset(logicstate, 0, SHARKSSL_DIM_ARR(logicstate));
   }

   return (sharkssl_RSA_RetVal)ret;
}
#endif


SHARKSSL_API sharkssl_RSA_RetVal sharkssl_RSA_private_encrypt(U16 len, U8 *in, U8 *out, SharkSslRSAKey resumeenabler, U8 seepromprobe)
{
   return switchcompletion(clockaccess, resumeenabler, len, in, out, seepromprobe);
}


SHARKSSL_API sharkssl_RSA_RetVal sharkssl_RSA_public_decrypt(U16 len, U8 *in, U8 *out, SharkSslRSAKey sourcerouting, U8 seepromprobe)
{
   return switchcompletion(handleguest, sourcerouting, len, in, out, seepromprobe);
}
#endif  
#endif  


#if SHARKSSL_USE_ECC
#if (SHARKSSL_ENABLE_PEM_API)
SHARKSSL_API SharkSslECCKey sharkssl_PEM_to_ECCKey(const char *clearnopref, const char *pxa270flash)
{
   SharkSslCert kernelvaddr;

   baAssert(NULL == (void*)0);
   if ((clearnopref == (void*)0) || (sharkssl_PEM(NULL, clearnopref, pxa270flash, &kernelvaddr) < 0))
   {
      return NULL;
   }
   return (SharkSslECCKey)kernelvaddr;
}
#endif  


#if (SHARKSSL_ENABLE_PEM_API || SHARKSSL_ENABLE_ECCKEY_CREATE)
SHARKSSL_API void SharkSslECCKey_free(SharkSslECCKey dividetable)
{
   if (dividetable)
   {
      baFree((void*)dividetable);
   }
}
#endif


#if (SHARKSSL_ENABLE_ECDSA && SHARKSSL_ENABLE_ECDSA_API)
#if (!SHARKSSL_ECDSA_ONLY_VERIFY)

U16 relocationchain(SharkSslCertKey *disableclock)
{
   U16 len = mousethresh(disableclock->expLen);
   if (len && (len < 0x70))
   {
      len <<= 1;
      len += 8;
      #if SHARKSSL_ECC_USE_SECP521R1
      if (len >= 0x80)
      {
         len++;
      }
      #endif
      return len;
   }
   return 0;
}


SHARKSSL_API U16 sharkssl_ECDSA_siglen(SharkSslECCKey resumeenabler)
{
   SharkSslCertKey disableclock;

   if ((interrupthandler(&disableclock, resumeenabler)) &&
       (machinereboot(disableclock.expLen)) &&
       !(coupledexynos(disableclock.expLen)))
   {
      return relocationchain(&disableclock);
   }

   return 0;
}


SHARKSSL_API sharkssl_ECDSA_RetVal sharkssl_ECDSA_sign_hash(SharkSslECCKey resumeenabler, U8 *sig, U16 *platformconfig, U8 *chargerplatform, U8 clearscratchpad)
{
   SharkSslCertKey disableclock;
   SharkSslECDSAParam audioshutdown;
   sharkssl_ECDSA_RetVal ret;

   if ((NULL == sig) || (NULL == chargerplatform) || (0 == clearscratchpad))
   {
      return SHARKSSL_ECDSA_WRONG_PARAMETERS;
   }
   if ((0 == interrupthandler(&disableclock, resumeenabler)) || !(machinereboot(disableclock.expLen)))
   {
      return SHARKSSL_ECDSA_WRONG_KEY_FORMAT;
   }
   if (coupledexynos(disableclock.expLen))
   {
      return SHARKSSL_ECDSA_KEY_NOT_PRIVATE;
   }

   audioshutdown.curveType = wakeupenable(disableclock.modLen);
   audioshutdown.hash = chargerplatform;
   audioshutdown.hashLen = clearscratchpad;
   audioshutdown.key = disableclock.exp;
   audioshutdown.keyLen = mousethresh(disableclock.expLen);

   ret = registerboard(&audioshutdown, sig, platformconfig);
   if (ret < 0)
   {
      
      return ret;
   }

   return SHARKSSL_ECDSA_OK;
}
#endif


SHARKSSL_API sharkssl_ECDSA_RetVal sharkssl_ECDSA_verify_hash(SharkSslECCKey setupreset, U8 *sig, U16 platformconfig, U8 *chargerplatform, U8 clearscratchpad)
{
   U8 kexecprepare[claimresource(SHARKSSL_MAX_ECC_POINTLEN)];
   U8 stackoverflow[claimresource(SHARKSSL_MAX_ECC_POINTLEN)];
   SharkSslParseASN1 parseSgn;
   SharkSslCertKey disableclock;
   SharkSslECDSAParam audioshutdown;
   int ret;

   if ((NULL == sig) || (NULL == chargerplatform) || (0 == clearscratchpad) || (0 == platformconfig))
   {
      return SHARKSSL_ECDSA_WRONG_PARAMETERS;
   }
   if ((0 == interrupthandler(&disableclock, setupreset)) || !(machinereboot(disableclock.expLen)))
   {
      return SHARKSSL_ECDSA_WRONG_KEY_FORMAT;
   }
   if (!(coupledexynos(disableclock.expLen)))
   {
      
      return SHARKSSL_ECDSA_KEY_NOT_PUBLIC;
   }

   audioshutdown.curveType = wakeupenable(disableclock.modLen);
   audioshutdown.hash = chargerplatform;
   audioshutdown.hashLen = clearscratchpad;
   audioshutdown.key = disableclock.mod;
   audioshutdown.keyLen = attachdevice(disableclock.modLen);

   parseSgn.ptr = sig;
   parseSgn.len = platformconfig;
   if (((ret = SharkSslParseASN1_getSequence(&parseSgn)) < 0) ||
        (SharkSslParseASN1_getInt(&parseSgn) < 0) || ((U32)ret < parseSgn.datalen) ||
        (parseSgn.datalen > audioshutdown.keyLen))
   {
      return SHARKSSL_ECDSA_WRONG_SIGNATURE;
   }
   ret = (audioshutdown.keyLen - parseSgn.datalen);
   if (ret)
   {
      
      memset(kexecprepare, 0, ret);
      memcpy(&kexecprepare[ret], parseSgn.dataptr, parseSgn.datalen);
      audioshutdown.R = kexecprepare;
   }
   else
   {
      audioshutdown.R = parseSgn.dataptr;
   }

   if (SharkSslParseASN1_getInt(&parseSgn) < 0)
   {
      return SHARKSSL_ECDSA_WRONG_SIGNATURE;
   }
   ret = (audioshutdown.keyLen - parseSgn.datalen);
   if (ret)
   {
      
      memset(stackoverflow, 0, ret);
      memcpy(&stackoverflow[ret], parseSgn.dataptr, parseSgn.datalen);
      audioshutdown.S = stackoverflow;
   }
   else
   {
      audioshutdown.S = parseSgn.dataptr;
   }

   ret = SharkSslECDSAParam_ECDSA(&audioshutdown, fixupdevices);
   if (ret)
   {
      if ((int)SharkSslCon_AllocationError == ret)
      {
         return SHARKSSL_ECDSA_ALLOCATION_ERROR;
      }

      return SHARKSSL_ECDSA_VERIFICATION_FAIL;
   }

   return SHARKSSL_ECDSA_OK;
}
#endif  
#endif  


#if (SHARKSSL_ENABLE_CA_LIST && SHARKSSL_ENABLE_CERTSTORE_API)
SHARKSSL_API void SharkSslCertStore_constructor(SharkSslCertStore *o)
{
   DoubleList_constructor(&o->certList);
   o->caList = 0;
   o->elements = 0;
}


SHARKSSL_API void SharkSslCertStore_destructor(SharkSslCertStore* o)
{
   SharkSslCSCert *kernelvaddr;

   if (o->caList)
   {
      baFree((void*)o->caList);
      o->caList = 0;
   }

   while ((kernelvaddr = (SharkSslCSCert*)DoubleList_firstNode(&o->certList)) != 0)
   {
      DoubleLink_unlink((DoubleLink*)kernelvaddr);
      o->elements--;
      baAssert(kernelvaddr->ptr);
      baFree(kernelvaddr->ptr);
      baFree(kernelvaddr);
   }
}


#define SHARKSSL_PARSESEQ_SINGLE_CERT             1
#define SHARKSSL_PARSESEQ_MULTIPLE_CERT           0
#define SHARKSSL_PARSESEQ_PARSE_ERROR            -1
#define SHARKSSL_PARSESEQ_NOT_BINARY_FORMAT      -2
#define SHARKSSL_PARSESEQ_UNSUPPORTED_CERT       -3

static int clockgetres(SharkSslParseASN1 *o)
{
   int ls;

   o->dataptr = o->ptr;  
   o->datalen = o->len;  

   if ((ls = SharkSslParseASN1_getSequence(o)) < 0)
   {
      return SHARKSSL_PARSESEQ_NOT_BINARY_FORMAT;
   }

   if (!(SharkSslParseASN1_getOID(o) < 0))
   {
      
      if ((o->datalen == SHARKSSL_DIM_ARR(sharkssl_oid_signedData)) &&
          (0 == sharkssl_kmemcmp(o->dataptr, sharkssl_oid_signedData, SHARKSSL_DIM_ARR(sharkssl_oid_signedData))))
      {
         if ((SharkSslParseASN1_getVersion(o) < 0)  || (SharkSslParseASN1_getSequence(o) < 0) ||
             (SharkSslParseASN1_getInt(o) < 0)      || (SharkSslParseASN1_getSet(o) < 0) ||
             (SharkSslParseASN1_getSequence(o) < 0) || (SharkSslParseASN1_getOID(o) < 0))
         {
            return SHARKSSL_PARSESEQ_PARSE_ERROR;
         }

         #if 0
         if (0 == ls)  
         {
            if (SharkSslParseASN1_getSetSeq(o, 0x00))
            {
               return SHARKSSL_PARSESEQ_PARSE_ERROR;
            }
         }
         #endif

         if ((ls = SharkSslParseASN1_getVersion(o)) < 0)
         {
            return SHARKSSL_PARSESEQ_PARSE_ERROR;
         }

         o->datalen = ls;
         return SHARKSSL_PARSESEQ_MULTIPLE_CERT;
      }
   }

   else if (ls > 0) 
   {
      if ((U32)ls != o->len)
      {
         return SHARKSSL_PARSESEQ_PARSE_ERROR;
      }

      o->ptr = o->dataptr;  
      o->len = o->datalen;  
      return SHARKSSL_PARSESEQ_SINGLE_CERT;
   }

   return SHARKSSL_PARSESEQ_UNSUPPORTED_CERT;
}


static U16 serialdevice(SharkSslCertStore *o, SharkSslParseASN1 *p, U8 timer5hwmod)
{
   SharkSslCSCert *newCert = 0;
   SharkSslCertDN  issuerDN, subjectDN;
   U8 *gpio1config, *cp, *cr;
   int rc, ls;
   U16 nc = 0;  

   cp = p->ptr;
   rc = p->len;

   
   while (rc > 0)
   {
      if (o->elements == 0xFFFF)  
      {
         break;
      }

      p->ptr = cr = cp;
      p->len = rc;

      if ((ls = SharkSslParseASN1_getSequence(p)) < 0)
      {
         break;  
      }

      cp = p->ptr + ls;  
      rc = p->len - ls;

      if ((ls = SharkSslParseASN1_getSequence(p)) < 0)
      {
         continue;  
      }

      p->len = ls;
      if ((sha256final(p) < 0)  ||
          (SharkSslParseASN1_getInt(p) < 0)      ||
          (SharkSslParseASN1_getSequence(p) < 0) ||
          (SharkSslParseASN1_getOID(p) < 0)      ||
          (deltacamera(p, &issuerDN) < 0) ||
          (SharkSslParseASN1_getSequence(p) < 0))
      {
         continue;   
      }

      if (SharkSslParseASN1_getUTCTime(p) && (SharkSslParseASN1_getGenTime(p)))
      {
         continue;    
      }
      if (SharkSslParseASN1_getUTCTime(p) && (SharkSslParseASN1_getGenTime(p)))
      {
         continue;    
      }
      if ((deltacamera(p, &subjectDN) < 0) ||
          (SharkSslParseASN1_getSequence(p) < 0))
      {
         continue;    
      }

      newCert = (SharkSslCSCert*)baMalloc(sizeof(SharkSslCSCert));
      if (newCert == (void*)0)
      {
         break;  
      }

      if (timer5hwmod)  
      {
         ls = (U32)claimresource(cp - cr);
         newCert->ptr = (U8*)baMalloc((U32)ls);
         if (newCert->ptr == (void*)0)
         {
            baFree(newCert);
            break;  
         }
         memcpy(newCert->ptr, cr, (U32)ls);
      }
      else
      {
         baAssert(0 == nc);
         newCert->ptr = cr;
      }

      
      if ((subjectDN.commonName) && (subjectDN.commonNameLen))
      {
         ls = subjectDN.commonNameLen;
         gpio1config = (U8*)subjectDN.commonName;
      }
      else if ((subjectDN.organization) && (subjectDN.organizationLen))
      {
         ls = subjectDN.organizationLen;
         gpio1config = (U8*)subjectDN.organization;
      }
      else
      {
         continue;  
      }

      if (ls >= SHARKSSL_MAX_SNAME_LEN)
      {
         ls = SHARKSSL_MAX_SNAME_LEN;
         newCert->name[SHARKSSL_MAX_SNAME_LEN] = 0; 
      }
      else
      {
         memset(newCert->name, 0, (SHARKSSL_MAX_SNAME_LEN + 1));
      }
      memcpy(newCert->name, gpio1config, ls);

      o->elements++;
      nc++;

      DoubleLink_constructor(&newCert->super);
      if (DoubleList_isEmpty(&o->certList))
      {
         DoubleList_insertLast(&o->certList, newCert);
      }
      else
      {
         DoubleListEnumerator instructioncounter;
         SharkSslCSCert *kernelvaddr;
         DoubleListEnumerator_constructor(&instructioncounter, &o->certList);
         for (kernelvaddr = (SharkSslCSCert*)DoubleListEnumerator_getElement(&instructioncounter); kernelvaddr;
              kernelvaddr = (SharkSslCSCert*)DoubleListEnumerator_nextElement(&instructioncounter))
         {
            if (strcmp(newCert->name, kernelvaddr->name) < 0)
            {
               break;
            }
         }

         if (kernelvaddr)
         {
            DoubleLink_insertBefore(kernelvaddr, newCert);
         }
         else
         {
            DoubleList_insertLast(&o->certList, newCert);
         }
      }
   }

   return nc;
}



SHARKSSL_API U16 SharkSslCertStore_add(SharkSslCertStore *o, const char *kernelvaddr, U32 doublenormaliseround)
{
   SharkSslParseASN1 parseASN;
   const char *cbeg, *cend;
   U8 *freezemonarch;
   int ls, lr;
   U16 nc = 0;

   parseASN.ptr = (U8*)kernelvaddr;
   parseASN.len = doublenormaliseround;

   switch (clockgetres(&parseASN))
   {
      case SHARKSSL_PARSESEQ_NOT_BINARY_FORMAT:
         
         cbeg = sharkStrstr(kernelvaddr, "\055\055\055\055\055\102\105\107\111\116");
         cend = 0;

         do
         {
            if (cbeg)
            {
               cbeg += 10;  
               cbeg = sharkStrstr(cbeg, "\055\055\055\055\055");
               if (cbeg)
               {
                  cbeg += 5;  
                  while ((*cbeg == '\015') || (*cbeg == '\012'))
                  {
                     cbeg++;
                  }
                  cend = sharkStrstr(cbeg, "\055\055\055\055\055\105\116\104");
               }
            }
            if ((cbeg == (void*)0) || (cend == (void*)0))
            {
               return 0;  
            }

            parseASN.len = (U32)(cend - cbeg);
            freezemonarch = (U8*)baMalloc(claimresource((parseASN.len * 3) >> 2) + 4);
            if (freezemonarch == (void*)0)
            {
               return 0;  
            }

            
            parseASN.len = sharkssl_B64Decode(freezemonarch, parseASN.len, cbeg, cend);
            parseASN.ptr = freezemonarch;
            ls = lr = clockgetres(&parseASN);
            if (ls >= 0)
            {
               ls = (ls == SHARKSSL_PARSESEQ_MULTIPLE_CERT);
               
               lr = serialdevice(o, &parseASN, (U8)ls);
               if (lr > 0)
               {
                  baAssert(lr <= 0xFFFF);
                  nc += (U16)lr;
               }
            }
            if ((lr <= 0)  ||  ls)
            {
               
               baFree(freezemonarch);
            }


            
            cbeg = sharkStrstr(cend, "\055\055\055\055\055\102\105\107\111\116");
         } while (cbeg);
         break;


      case SHARKSSL_PARSESEQ_SINGLE_CERT:
      case SHARKSSL_PARSESEQ_MULTIPLE_CERT:
         nc = serialdevice(o, &parseASN, 1);
         break;

      default:
         nc--;  
         break;
   }

   return nc;
}


SHARKSSL_API U8
SharkSslCertStore_assemble(SharkSslCertStore *o, SharkSslCAList *flushcounts)
{
   DoubleListEnumerator instructioncounter;
   SharkSslCSCert *kernelvaddr;
   U8 *p;

   if (o->caList)
   {
      *flushcounts = o->caList;
   }
   else
   {
      p = (U8*)baMalloc(4 + o->elements * (SHARKSSL_CA_LIST_NAME_SIZE +
                                           SHARKSSL_CA_LIST_PTR_SIZE));
      *flushcounts = o->caList = (SharkSslCAList)p;
      if (p == (void*)0)
      {
         return 0;
      }

      *p++ = SHARKSSL_CA_LIST_PTR_TYPE;
      *p++ = 0;
      *p++ = (U8)(((o->elements) >> 8));
      *p++ = (U8)((o->elements) & 0xFF);

      DoubleListEnumerator_constructor(&instructioncounter, &o->certList);
      for (kernelvaddr = (SharkSslCSCert*)DoubleListEnumerator_getElement(&instructioncounter); kernelvaddr;
           kernelvaddr = (SharkSslCSCert*)DoubleListEnumerator_nextElement(&instructioncounter))
      {
         memcpy(p, kernelvaddr->name, SHARKSSL_CA_LIST_NAME_SIZE);
         p += SHARKSSL_CA_LIST_NAME_SIZE;
         *(U8**)p = kernelvaddr->ptr;
         p += SHARKSSL_CA_LIST_PTR_SIZE;
      }
   }
   return 1;  
}
#endif  


#ifndef BA_LIB
#define BA_LIB
#endif



#include <string.h>



void traceaddress(shtype_t *o, U16 writepmresrn, void *alloccontroller)
{
   #if ((SHARKSSL_BIGINT_WORDSIZE > 8) && (!(SHARKSSL_UNALIGNED_ACCESS)))
   baAssert(0 == ((unsigned int)(UPTR)alloccontroller & computereturn));  
   #endif
   baAssert((sizeof(U64) == 8) && (sizeof(S64) == 8));
   baAssert((sizeof(U32) == 4) && (sizeof(S32) == 4));
   baAssert((sizeof(U16) == 2) && (sizeof(S16) == 2));
   baAssert((sizeof(U8)  == 1) && (sizeof(S8)  == 1));
   o->len = writepmresrn;
   o->mem = o->beg = (shtype_tWord*)alloccontroller;
}



void unassignedvector(const shtype_t *src, shtype_t *pciercxcfg448)
{
   pciercxcfg448->len = src->len;
   pciercxcfg448->beg = pciercxcfg448->mem;
   memcpy(pciercxcfg448->beg, src->beg, src->len * SHARKSSL__M);
}



void deviceparse(const shtype_t *o)
{
   memset(o->beg, 0, o->len * SHARKSSL__M);
}



void blastscache(shtype_t *o)
{
   while ((o->len > 1) && (o->beg[0] == 0))
   {
      o->beg++;
      o->len--;
   }
}


#if SHARKSSL_ENABLE_ECDSA  

U8 eventtimeout(shtype_t *o)
{
   shtype_tWord *p = o->beg;
   U16 len = o->len;

   
   while ((len > 1) && (*p == 0))
   {
      p++;
      len--;
   }

   return (U8)(*p == 0);
}
#endif


#if SHARKSSL_OPTIMIZED_BIGINT_ASM
#if (SHARKSSL_BIGINT_WORDSIZE != 32)
#error SharkSSL optimized big int library requires SHARKSSL_BIGINT_WORDSIZE = 32
#endif

extern
#endif

shtype_tWord updatepmull(shtype_t *o1,
                                      const shtype_t *o2)
#if SHARKSSL_OPTIMIZED_BIGINT_ASM
;
#else
{
   shtype_tWord *p1, *p2;
   shtype_tDoubleWordS d;

   p1 = &o1->beg[o1->len - 1];
   p2 = &o2->beg[o2->len - 1];

   d = 0;
   while (p1 >= o1->beg)
   {
      d += *p1;

      if (p2 >= o2->beg)
      {
         d -= *p2--;
      }

      *p1-- = (shtype_tWord)d;
      anatopdisconnect(d);
   }

   
   return (shtype_tWord)d;
}
#endif


#if SHARKSSL_OPTIMIZED_BIGINT_ASM
extern
#endif

shtype_tWord resolverelocs(shtype_t *o1,       
                                      const shtype_t *o2)
#if SHARKSSL_OPTIMIZED_BIGINT_ASM
;
#else
{
   shtype_tWord *p1, *p2;
   shtype_tDoubleWord d;

   p1 = &o1->beg[o1->len - 1];
   p2 = &o2->beg[o2->len - 1];

   d = 0;
   while (p1 >= o1->beg)
   {
      d += *p1;

      if (p2 >= o2->beg)
      {
         d += *p2--;
      }

      *p1-- = (shtype_tWord)d;
      d >>= SHARKSSL_BIGINT_WORDSIZE;
   }

   return (shtype_tWord)d;
}
#endif



U8 timerwrite(const shtype_t *o1,
                     const shtype_t *o2)
{
   U16 l1 = 0;
   U16 l2 = 0;

   while ((l1 < o1->len) && (o1->beg[l1] == 0))
   {
      l1++;
   }

   while ((l2 < o2->len) && (o2->beg[l2] == 0))
   {
      l2++;
   }

   if ((o1->len - l1) == (o2->len - l2))
   {
      while (l1 < o1->len)
      {
         if (o1->beg[l1] != o2->beg[l2])
         {
            return (U8)(o1->beg[l1] > o2->beg[l2]);
         }

         l1++;
         l2++;
      }
   }

   else
   {
      return (U8)((o1->len - l1) > (o2->len - l2));
   }

   return 1;  
}



void keypaddevice(shtype_t *o1,
                           const shtype_t *o2,
                           const shtype_t *mod)
{
   int sha256export = (timerwrite(o2, mod));
   if (sha256export)
   {
      updatepmull((shtype_t*)o2, mod);
   }
   if (updatepmull(o1, o2))
   {
      resolverelocs(o1, mod);
   }
   if (sha256export)  
   {
      resolverelocs((shtype_t*)o2, mod);
   }
}



void setupsdhci1(shtype_t *o1,
                           const shtype_t *o2,
                           const shtype_t *mod)
{
   while (o1->len < mod->len)
   {
      o1->len++;
      o1->beg--;
      o1->beg[0] = 0;
   }
   baAssert(o1->beg >= o1->mem);
   if (resolverelocs(o1, o2) || timerwrite(o1, mod))
   {
      updatepmull(o1, mod);
   }
}


#if SHARKSSL_OPTIMIZED_BIGINT_ASM
extern
#else
static
#endif

void shtype_t_mult_(const shtype_t *o1,
                          const shtype_t *o2,
                          shtype_t *deltadevices)
#if SHARKSSL_OPTIMIZED_BIGINT_ASM
;
#else
{
   shtype_tWord *p1, *p2, *pr, *pt;
   shtype_tDoubleWord  s;
   U16 x1, x2;

   deltadevices->beg = deltadevices->mem;
   deviceparse(deltadevices);

   if (o1 != o2)
   {
      p2 = &o2->beg[o2->len];
      pt = &deltadevices->beg[deltadevices->len];
      for (x2 = o2->len; x2 > 0; x2--)
      {
         register shtype_tWord c = 0;
         p2--;
         pr = --pt;
         x1 = o1->len;
         p1 = &o1->beg[x1];
         #if SHARKSSL_BIGINT_MULT_LOOP_UNROLL
         while (x1 > 3)
         {
            s = ((shtype_tDoubleWord)(*--p1) * *p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
            s = ((shtype_tDoubleWord)(*--p1) * *p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
            s = ((shtype_tDoubleWord)(*--p1) * *p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
            s = ((shtype_tDoubleWord)(*--p1) * *p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
            x1 -= 4;
         }
         #endif
         while (x1--)
         {
            s = ((shtype_tDoubleWord)(*--p1) * *p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
         }
         *pr = c;
      }
   }
   else   
   {
      register shtype_tWord a, c;

      x1 = o1->len;
      p1 = &o1->beg[x1];
      pt = &deltadevices->beg[deltadevices->len];
      while (x1 > 1)
      {
         x1--;
         p1--;
         c = 0;
         x2 = x1;
         p2 = p1;
         pt--;
         pr = --pt;
         a = *p1;
         #if SHARKSSL_BIGINT_MULT_LOOP_UNROLL
         while (x2 > 3)
         {
            s = ((shtype_tDoubleWord)a * *--p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
            s = ((shtype_tDoubleWord)a * *--p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
            s = ((shtype_tDoubleWord)a * *--p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
            s = ((shtype_tDoubleWord)a * *--p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
            x2 -= 4;
         }
         #endif
         while (x2--)
         {
            s = ((shtype_tDoubleWord)a * *--p2) + *pr + c;
            *pr-- = (shtype_tWord)s;
            c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
         }
         *pr = c;
      }

      
      pr = &deltadevices->beg[deltadevices->len - 1];
      p1 = &deltadevices->beg[0];
      x2 = 0;
      while (pr >= p1)
      {
         x1 = (U16)((*pr & (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1))) ? 1 : 0);
         *pr <<= 1;
         if (x2)
         {
            *pr |= 0x1;
         }
         pr--;
         x2 = x1;
      }

      
      pr = &deltadevices->beg[deltadevices->len];
      x1 = o1->len;
      p1 = &o1->beg[x1];
      s = 0;
      while (x1--)
      {
         p1--;
         a = *p1;
         s += *--pr + ((shtype_tDoubleWord)a * a);
         *pr-- = (shtype_tWord)s;
         s >>= SHARKSSL_BIGINT_WORDSIZE;
         if (s)
         {
            s += *pr;
            *pr = (shtype_tWord)s;
            s >>= SHARKSSL_BIGINT_WORDSIZE;
         }
      }
   }
}
#endif



void hotplugpgtable(const shtype_t *o1,
                         const shtype_t *o2,
                         shtype_t *deltadevices)
{
   
   deltadevices->len = (U16)(o1->len + o2->len);
   
   shtype_t_mult_(o1, o2, deltadevices);
}


void envdatamcheck(shtype_t *injectexception,
                            const shtype_t *mod,
                            shtype_tWord *afterhandler)
{
   shtype_t q, tmp1, tmpd, tmp2, dm, dr;
   U16 i;

   if (timerwrite(injectexception, mod))
   {
      traceaddress(&q, (U16)((injectexception->len - mod->len) + 1), afterhandler);
      deviceparse(&q);
      afterhandler += q.len;

      traceaddress(&tmp1, injectexception->len, afterhandler);
      afterhandler += injectexception->len;
      traceaddress(&tmpd, injectexception->len, afterhandler);
      deviceparse(&tmpd);

      
      memcpy(tmpd.beg, mod->beg, mod->len * SHARKSSL__M);

      
      while (timerwrite(injectexception, &tmpd))
      {
         q.beg[0]++;
         updatepmull(injectexception, &tmpd);
      }

      dm.len = 2;
      dm.beg = mod->beg; 
      dr.len = 1;
      tmp2.len = 3;

      for (i = 0; i < (q.len - 1); i++)
      {
         tmp2.beg = &injectexception->beg[i];
         dr.beg = &(q.beg[i]);

         if (tmp2.beg[0] == mod->beg[0])
         {
            dr.beg[0] = (shtype_tWord)(-1);
         }
         #if 0  
         else
         {
            U32 doublefnmul = (shtype_tWord)
             (((shtype_tDoubleWord)
              (((shtype_tDoubleWord)(tmp2.beg[0]) << SHARKSSL_BIGINT_WORDSIZE) |
                 tmp2.beg[1])) / mod->beg[0]);
            dr.beg[0] = (shtype_tWord)doublefnmul;
         }
         #elif (SHARKSSL_BIGINT_WORDSIZE == 32)
         {
            shtype_t dd, rr;
            shtype_tWord R[3];  
            U32 k;
            
            
            dr.beg[0] = R[0] = R[1] = R[2] = 0;
            traceaddress(&dd, 2, &mod->beg[0]);
            traceaddress(&rr, 3, &R[0]);
            for (k = 0x80000000; k > 0; k >>= 1)
            {
               R[0] = ((R[0] << 1) | (R[1] >> 31));
               R[1] = ((R[1] << 1) | (R[2] >> 31));
               R[2] <<= 1;
               if (tmp2.beg[0] & k) R[2] |= 1;

               if (timerwrite(&rr, &dd))
               {
                  updatepmull(&rr, &dd);
               }
            }
            for (k = 0x80000000; k > 0; k >>= 1)
            {
               R[0] = ((R[0] << 1) | (R[1] >> 31));
               R[1] = ((R[1] << 1) | (R[2] >> 31));
               R[2] <<= 1;
               if (tmp2.beg[1] & k) R[2] |= 1;

               if (timerwrite(&rr, &dd))
               {
                  updatepmull(&rr, &dd);
               }
            }
            for (k = 0x80000000; k > 0; k >>= 1)
            {
               R[0] = ((R[0] << 1) | (R[1] >> 31));
               R[1] = ((R[1] << 1) | (R[2] >> 31));
               R[2] <<= 1;
               if (tmp2.beg[2] & k) R[2] |= 1;

               if (timerwrite(&rr, &dd))
               {
                  updatepmull(&rr, &dd);
                  dr.beg[0] |= k;
               }
            }
            if ((dr.beg[0] == 0) && timerwrite(&tmp2, &dd))
            {
               dr.beg[0] = (shtype_tWord)(-1);
            }
         }
         #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
         {
            U64 d1 = ((U64)(tmp2.beg[0]) << 32) | ((U32)(tmp2.beg[1]) << 16) | tmp2.beg[2];
            U32 d2 = ((U32)(mod->beg[0]) << 16) | mod->beg[1];
            dr.beg[0] = (U16)((U64)d1/(U32)d2);
            if ((d1 >= d2) && (dr.beg[0] == 0))
            {
               dr.beg[0] = (shtype_tWord)(-1);
            }
         }
         #elif (SHARKSSL_BIGINT_WORDSIZE == 8)
         {
            U32 d1 = ((U32)(tmp2.beg[0]) << 16) | ((U16)(tmp2.beg[1]) << 8) | tmp2.beg[2];
            U16 d2 = ((U16)(mod->beg[0]) << 8) | mod->beg[1];
            dr.beg[0] = (U8)((U32)d1/(U16)d2);
            if ((d1 >= d2) && (dr.beg[0] == 0))
            {
               dr.beg[0] = (shtype_tWord)(-1);
            }
         }
         #endif
         hotplugpgtable(&dm, &dr, &tmp1);
         while (!(timerwrite(&tmp2, &tmp1)))
         {
            dr.beg[0]--;
            hotplugpgtable(&dm, &dr, &tmp1);
         }
         tmpd.len--;
         hotplugpgtable(&tmpd, &dr, &tmp1); 
         if (timerwrite(injectexception, &tmp1))
         {
            updatepmull(injectexception, &tmp1);
         }
         else
         {
            updatepmull(&tmp1, &tmpd);
            updatepmull(injectexception, &tmp1);
            dr.beg[0]--;
         }
      }
   }

   blastscache(injectexception);
}


int suspendfinish(shtype_t *injectexception,
                          const shtype_t *mod)
{
   shtype_tWord *afterhandler;
   U16 flash1resources;

   flash1resources  = injectexception->len;
   flash1resources += (flash1resources << 1);
   flash1resources -= mod->len;
   flash1resources++;
   #if (SHARKSSL__M > 1)
   flash1resources *= SHARKSSL__M;
   #endif
   afterhandler = (shtype_tWord*)baMalloc(pcmciapdata(flash1resources));
   if (afterhandler == (void*)0)
   {
      return 1;
   }
   envdatamcheck(injectexception, mod, (shtype_tWord*)selectaudio(afterhandler));

   while (injectexception->len < mod->len)
   {
      baAssert(injectexception->beg > injectexception->mem);
      injectexception->len++;
      injectexception->beg--;
      baAssert(0 == injectexception->beg[0]);
   }

   baFree(afterhandler);
   return 0;
}

#if (SHARKSSL_ENABLE_RSA || (SHARKSSL_USE_ECC && SHARKSSL_ECC_USE_BRAINPOOL))

shtype_tWord remapcfgspace(const shtype_t *mod)
{
   shtype_tWord m0, mu;

   
   m0 = mod->beg[mod->len - 1];
   mu = (shtype_tWord)((((m0 + 2) & 4) << 1) + m0);
   mu = (shtype_tWord)(mu * (2 - m0 * mu));
   #if (SHARKSSL_BIGINT_WORDSIZE >= 16)
   mu = (shtype_tWord)(mu * (2 - m0 * mu));
   #endif
   #if (SHARKSSL_BIGINT_WORDSIZE == 32)
   mu = (shtype_tWord)(mu * (2 - m0 * mu));
   mu = (shtype_tWord)(mu * (2 - m0 * mu));
   #endif
   mu = (shtype_tWord)(~mu + 1);
   return mu;
}
#endif


#if (!SHARKSSL_OPTIMIZED_BIGINT_ASM)
void writebytes(const shtype_t *o1,
                           const shtype_t *o2,
                           shtype_t *deltadevices,
                           const shtype_t *mod,
                           shtype_tWord mu)
{
   shtype_tWord m0, *pr, *p1, *p2;
   shtype_tDoubleWord s;
   U16 x1, x2;

   deltadevices->len = (U16)((2 * mod->len) + 1);
   shtype_t_mult_(o1, o2, deltadevices);

   
   p2 = &deltadevices->beg[deltadevices->len];
   for (x2 = mod->len; x2 > 0; x2--)
   {
      register shtype_tWord c = 0;
      pr = --p2;
      x1 = mod->len;
      p1 = &mod->beg[x1];
      m0 = (shtype_tWord)((shtype_tDoubleWord)mu * *p2);
      #if SHARKSSL_BIGINT_MULT_LOOP_UNROLL
      while (x1 > 3)
      {
         s = ((shtype_tDoubleWord)m0 * *--p1) + *pr + c;
         *pr-- = (shtype_tWord)s;
         c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
         s = ((shtype_tDoubleWord)m0 * *--p1) + *pr + c;
         *pr-- = (shtype_tWord)s;
         c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
         s = ((shtype_tDoubleWord)m0 * *--p1) + *pr + c;
         *pr-- = (shtype_tWord)s;
         c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
         s = ((shtype_tDoubleWord)m0 * *--p1) + *pr + c;
         *pr-- = (shtype_tWord)s;
         c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
         x1 -= 4;
      }
      #endif
      while (x1--)
      {
         s = ((shtype_tDoubleWord)m0 * *--p1) + *pr + c;
         *pr-- = (shtype_tWord)s;
         c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
      }
      
      do
      {
         s = (shtype_tDoubleWord)*pr + c;
         *pr-- = (shtype_tWord)s;
         c = (shtype_tWord)(s >> SHARKSSL_BIGINT_WORDSIZE);
      } while (c > 0);
   }

   deltadevices->len = (U16)(mod->len + 1);

   if (timerwrite(deltadevices, mod))
   {
      updatepmull(deltadevices, mod);
   }

   deltadevices->beg++;
   deltadevices->len--;
}
#endif


#if SHARKSSL_ENABLE_RSA
int chunkmutex(const shtype_t *validconfig,
                          shtype_t *exp,
                          const shtype_t *mod,
                          shtype_t *res,
                          U8 countersvalid)
{
   shtype_t doublefnmul, *brightnesslimit, deltadevices, *r3000write;
   shtype_t **r, **s, **t;
   shtype_t g[1 << (SHARKSSL_BIGINT_EXP_SLIDING_WINDOW_K - 1)];
   shtype_tWord mu, bitmask, *tmp_buf, *tmp_b;
   U16 i, m2_len, flash1resources;
   U8  nbits, valbits, base2;

   
   tmp_buf = &(validconfig->beg[0]);
   m2_len  = validconfig->len;
   while ((m2_len > 1) && (*tmp_buf == 0))
   {
      tmp_buf++;
      m2_len--;
   }
   base2 = ((m2_len == 1) && (*tmp_buf == 2));

   if ((countersvalid == 0) || (countersvalid > SHARKSSL_BIGINT_EXP_SLIDING_WINDOW_K))
   {
      countersvalid = SHARKSSL_BIGINT_EXP_SLIDING_WINDOW_K;
   }

   
   flash1resources  = (U16)((mod->len * SHARKSSL__M) + 2 * SHARKSSL__M);
   #if (SHARKSSL_BIGINT_EXP_SLIDING_WINDOW_K <= 3)
   flash1resources += (10 * mod->len * SHARKSSL__M) + 4; 
   #else
   if (base2)
   {
      flash1resources += (9 * mod->len * SHARKSSL__M);
   }
   else
   {
      flash1resources += SHARKSSL__M * ((1 << (SHARKSSL_BIGINT_EXP_SLIDING_WINDOW_K - 1)) +
               (mod->len * (5 + (1 << (SHARKSSL_BIGINT_EXP_SLIDING_WINDOW_K - 1)))));
   }
   #endif
   tmp_b = (shtype_tWord*)baMalloc(pcmciapdata(flash1resources));
   if (tmp_b == (void*)0)
   {
      return 1;
   }

   
   mu = remapcfgspace(mod);

   tmp_buf = (shtype_tWord*)selectaudio(tmp_b);
   brightnesslimit = &doublefnmul;
   m2_len = (U16)(mod->len * 2);
   traceaddress(brightnesslimit, m2_len, tmp_buf);
   tmp_buf += m2_len;

   if (base2)
   {
      tmp_buf++;
      r3000write = &deltadevices;
      traceaddress(r3000write, (U16)(m2_len + 1), tmp_buf);
      tmp_buf += m2_len;
      tmp_buf++;
      deviceparse(r3000write);
      deltadevices.beg[0] = 1;
      envdatamcheck(r3000write, mod, tmp_buf);

      traceaddress(&g[0], 1, tmp_buf);
      g[0].beg[0] = 1;
      tmp_buf++;

      writebytes(r3000write, &g[0], brightnesslimit, mod, mu);
   }
   else
   {
      unassignedvector(validconfig, brightnesslimit);
      envdatamcheck(brightnesslimit, mod, tmp_buf); 

      r3000write = &deltadevices;
      traceaddress(r3000write, (U16)(m2_len + 2), tmp_buf);
      tmp_buf += m2_len + 2;
      r3000write->len = (U16)(mod->len + 1);
      r3000write->beg = r3000write->mem;
      deviceparse(r3000write);
      r3000write->beg[0] = 0x1;
      updatepmull(r3000write, mod);
      blastscache(r3000write);

      traceaddress(&g[0], m2_len, tmp_buf);
      deviceparse(&g[0]);
      tmp_buf += m2_len;
      hotplugpgtable(brightnesslimit, r3000write, &g[0]);
      envdatamcheck(&g[0], mod, tmp_buf); 

      #if (SHARKSSL_BIGINT_EXP_SLIDING_WINDOW_K > 1)
      writebytes(&g[0], &g[0], brightnesslimit, mod, mu);
      m2_len++;
      for (i = 1; i < (1 << (countersvalid - 1)); i++)
      {
         traceaddress(&g[i], m2_len, tmp_buf);
         writebytes(brightnesslimit, &g[i - 1], &g[i], mod, mu);
         tmp_buf += g[i].len;
         tmp_buf++;
      }
      #endif
   }

   
   blastscache(exp);
   for (bitmask = (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1));
        bitmask > 0; bitmask >>= 1)
   {
      if (exp->beg[0] & bitmask)
      {
         break;
      }
   }

   if (base2)
   {
      t = &r3000write;
      r = &brightnesslimit;

      for (i = 0; i < exp->len; i++)
      {
         for (; bitmask > 0; bitmask >>= 1)
         {
            
            if (g[0].beg[0] >= ((U32)1 << (SHARKSSL_BIGINT_WORDSIZE / 2)))
            {
               hotplugpgtable(*r, &g[0], *t);
               envdatamcheck(*t, mod, tmp_buf);
               s = r; r = t; t = s;
               g[0].beg[0] = 1;
            }
            else
            {
               g[0].beg[0] *= g[0].beg[0];
            }

            writebytes(*r, *r, *t, mod, mu);
            s = r; r = t; t = s;

            if (exp->beg[i] & bitmask)
            {
               if (g[0].beg[0] & (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1)))
               {
                  hotplugpgtable(*r, &g[0], *t);
                  envdatamcheck(*t, mod, tmp_buf);
                  s = r; r = t; t = s;
                  g[0].beg[0] = 2;
               }
               else
               {
                  g[0].beg[0] <<= 1; 
               }
            }
         }
         bitmask = (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1));
      }

      if (g[0].beg[0] != 1)
      {
         hotplugpgtable(*r, &g[0], *t);
         envdatamcheck(*t, mod, tmp_buf);
         s = r; r = t; t = s;
         g[0].beg[0] = 1;
      }
   }
   else
   {
      r = &r3000write;
      t = &brightnesslimit;

      nbits = valbits = 0;
      for (i = 0; i < exp->len; i++)
      {
         for (; bitmask > 0; bitmask >>= 1)
         {
            valbits <<= 1;

            if (exp->beg[i] & bitmask)
            {
               valbits |= 0x1;
            }

            nbits++;
            if ( (nbits == countersvalid) || ((bitmask == 0x1) && (i == (exp->len - 1))) )
            {
               if (valbits > 0)
               {
                  U8 parentoffset = nbits;

                  while (!(valbits & 0x1))
                  {
                     valbits >>= 1;
                     parentoffset--;
                  }

                  nbits -= parentoffset;
                  while (parentoffset)
                  {
                     writebytes(*r, *r, *t, mod, mu);
                     s = r; r = t; t = s;
                     parentoffset--;
                  }

                  writebytes(*r, &g[valbits >> 1], *t, mod, mu);
                  s = r; r = t; t = s;

                  valbits = 0;
               }

               while (nbits)
               {
                  writebytes(*r, *r, *t, mod, mu);
                  s = r; r = t; t = s;
                  nbits--;
               }
            }
         }

         bitmask = (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1));
      }

      g[0].len = mod->len;
      deviceparse(&g[0]);
      g[0].beg[g[0].len - 1] = 1;
   }

   writebytes(&g[0], *r, *t, mod, mu);
   s = r; r = t; t = s;

   if (*r != r3000write)
   {
      blastscache(*r);
      unassignedvector(*r, res);
   }
   else
   {
      blastscache(r3000write);
      unassignedvector(r3000write, res);
   }

   baFree((void*)tmp_b);
   return 0;
}
#endif  



#if ((SHARKSSL_USE_ECC) || (SHARKSSL_ENABLE_RSAKEY_CREATE && SHARKSSL_ENABLE_RSA))
#if SHARKSSL_OPTIMIZED_BIGINT_ASM
extern
#endif
void backlightpdata(shtype_t *o)
#if SHARKSSL_OPTIMIZED_BIGINT_ASM
;
#else
{
   shtype_tWord *p, *q;

   p = &o->beg[o->len - 1];
   q = p - 1;

   for (;;)
   {
      *p >>= 1;

      if (p > o->beg)
      {
         if (*q & 0x1)
         {
            *p |= (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1));
         }
      }
      else
      {
         break;
      }

      p--;
      q--;
   }
}
#endif  


void ioswabwdefault(shtype_t *u,   
                               const shtype_t *mod,
                               shtype_tWord *afterhandler)
{
   shtype_t v, A, C;

   traceaddress(&C, (U16)(mod->len + 1), afterhandler);
   deviceparse(&C);
   afterhandler += C.len;

   traceaddress(&v, 0 , afterhandler);
   unassignedvector(mod, &v);

   traceaddress(&A, (U16)(mod->len + 1), afterhandler + mod->len);
   deviceparse(&A);
   A.beg[A.len - 1] = 1;

   while ((u->len > 1) || (u->beg[0] > 0))
   {
      while (cachestride(u))
      {
         backlightpdata(u);
         if (!cachestride(&A))
         {
            resolverelocs(&A, mod);
         }
         backlightpdata(&A);
      }
      while (cachestride(&v))
      {
         backlightpdata(&v);
         if (!cachestride(&C))
         {
            resolverelocs(&C, mod);
         }
         backlightpdata(&C);
      }
      if (timerwrite(u, &v))
      {
         updatepmull(u, &v);
         keypaddevice(&A, &C, mod); 
      }
      else
      {
         updatepmull(&v, u);
         keypaddevice(&C, &A, mod); 
      }
      blastscache(u);
   }
   envdatamcheck(&C, mod, afterhandler);
   blastscache(&C);
   while ((C.len < mod->len) && (C.beg > C.mem))
   {
      C.len++;
      C.beg--;
      baAssert(0 == C.beg[0]);
   }
   unassignedvector(&C, u);
}
#endif  


#if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
#if SHARKSSL_ENABLE_RSAKEY_CREATE
static void ic0r1dispatch(shtype_t *o)
{
   
   backlightpdata(o);
   o->beg[0] |= ((o->beg[0] << 1) & (1 << (SHARKSSL_BIGINT_WORDSIZE - 1)));
}



static void shtype_t_invmod_buf_even(shtype_t *u,   
                                           const shtype_t *mod,
                                           shtype_tWord *afterhandler)
{
   shtype_t v, A, B, C, D, ucopy, brightnesslimit;

   traceaddress(&ucopy, 0 , afterhandler);
   unassignedvector(u, &ucopy);
   afterhandler += ucopy.len;  

   traceaddress(&C, (U16)(mod->len + 1), afterhandler);
   deviceparse(&C);
   afterhandler += C.len;

   traceaddress(&brightnesslimit, (U16)(mod->len + 1), afterhandler);
   deviceparse(&brightnesslimit);
   afterhandler += brightnesslimit.len;

   traceaddress(&B, (U16)(mod->len + 1), afterhandler);
   deviceparse(&B);
   afterhandler += B.len;

   traceaddress(&D, (U16)(mod->len + 1), afterhandler);
   deviceparse(&D);
   D.beg[D.len - 1] = 1;
   afterhandler += D.len;

   traceaddress(&v, 0 , afterhandler);
   unassignedvector(mod, &v);

   traceaddress(&A, (U16)(mod->len + 1), afterhandler + mod->len);
   deviceparse(&A);
   A.beg[A.len - 1] = 1;

   while ((u->len > 1) || (u->beg[0] > 0))
   {
      while (cachestride(u))
      {
         backlightpdata(u);
         if (!cachestride(&A) || !cachestride(&B))
         {
            resolverelocs(&A, mod);
            updatepmull(&B, &ucopy);
         }
         ic0r1dispatch(&A);
         ic0r1dispatch(&B);
      }
      while (cachestride(&v))
      {
         backlightpdata(&v);
         if (!cachestride(&C) || !cachestride(&D))
         {
            resolverelocs(&C, mod);
            updatepmull(&D, &ucopy);
         }
         ic0r1dispatch(&C);
         ic0r1dispatch(&D);
      }
      if (timerwrite(u, &v))
      {
         updatepmull(u, &v);
         updatepmull(&A, &C); 
         updatepmull(&B, &D); 
      }
      else
      {
         updatepmull(&v, u);
         updatepmull(&C, &A); 
         updatepmull(&D, &B); 
      }
      blastscache(u);
   }
   if (C.beg[0] > 0)  
   {
      resolverelocs(&C, mod);
   }
   blastscache(&C);
   while ((C.len < mod->len) && (C.beg > C.mem))
   {
      C.len++;
      C.beg--;
      baAssert(0 == C.beg[0]);
   }
   unassignedvector(&C, u);
}
#endif  


int iommumapping(shtype_t *o,   
                          const shtype_t *mod)
{
   shtype_tWord *afterhandler;
   U16 flash1resources;

   flash1resources  = mod->len;
   #if (SHARKSSL_ENABLE_RSA && SHARKSSL_ENABLE_RSAKEY_CREATE)
   if (cachestride(mod))
   {
      flash1resources += flash1resources + (flash1resources << 2);
      flash1resources += o->len;
   }
   else
   #else
   baAssert(!cachestride(mod));
   #endif
   {
      flash1resources += (flash1resources << 1);
   }
   flash1resources += 8;

   #if (SHARKSSL__M > 1)
   flash1resources *= SHARKSSL__M;
   #endif
   afterhandler = (shtype_tWord*)baMalloc(pcmciapdata(flash1resources));
   if (afterhandler == (void*)0)
   {
      return 1;
   }
   #if (SHARKSSL_ENABLE_RSA && SHARKSSL_ENABLE_RSAKEY_CREATE)
   if (cachestride(mod))
   {
      shtype_t_invmod_buf_even(o, mod, (shtype_tWord*)selectaudio(afterhandler));
   }
   else
   #endif
   {
      ioswabwdefault(o, mod, (shtype_tWord*)selectaudio(afterhandler));
   }
   #if (SHARKSSL_BIGINT_WORDSIZE == 8)
   while (o->len < mod->len)
   {
      baAssert(o->beg > o->mem);
      o->len++;
      o->beg--;
      baAssert(0 == o->beg[0]);
   }
   #endif
   baFree(afterhandler);
   return 0;
}
#endif


#if (SHARKSSL_ENABLE_RSA && SHARKSSL_ENABLE_RSAKEY_CREATE)

static U8 irqwakeintmask(shtype_t *o)
{
   static const shtype_tWord one = 1;
   U8 *afterhandler, *p;
   shtype_t N, R, A, Y, M, ONE;
   U16 s, j, t = (U16)(o->len * SHARKSSL__M);
   U8 ret = 0;

   p = afterhandler = (U8*)baMalloc(t * 6);
   if (afterhandler == (void*)0)
   {
      return (U8)-2;
   }

   onenandpartitions(&ONE, SHARKSSL_BIGINT_WORDSIZE, &one);
   onenandpartitions(&N, (t * 8), p);
   p += t;
   onenandpartitions(&R, (t * 8), p);
   p += t;
   onenandpartitions(&A, (t * 8), p);
   p += t;
   onenandpartitions(&Y, (t * 8), p);
   p += t;
   onenandpartitions(&M, (t * 2 * 8), p);

   unassignedvector(o, &N);
   updatepmull(&N, &ONE);
   unassignedvector(&N, &R);

   s = 0;
   while cachestride(&R)
   {
      backlightpdata(&R);
      s += 1;
   }

   
   t *= 8;  
   if (t >= 1300)
   {
      t = 2;
   }
   else if (t >= 850)
   {
      t = 4;
      if (t >= 850)
      {
         t--;
      }
   }
   else if (t >= 400)
   {
      t = 7;
      if (t >= 550)
      {
         t--;
      }
      if (t >= 450)
      {
         t--;
      }
   }
   else if (t >= 300)
   {
      t = 9;
      if (t >= 350)
      {
         t--;
      }
   }
   else if (t >= 150)
   {
      if (t >= 250)
      {
         t = 12;
      }
      else if (t >= 200)
      {
         t = 15;
      }
      else
      {
         t = 18;
      }
   }
   else
   {
      t = 27;
   }

   while ((t--) && (0 == ret))
   {
      sharkssl_rng((U8*)A.beg, A.len * SHARKSSL__M);
      A.beg[0] |= (1 << (SHARKSSL_BIGINT_WORDSIZE - 2));  
      A.beg[A.len - 1] |= 2;  
      while (timerwrite(&A, &N))
      {
         backlightpdata(&A);
      }
      chunkmutex(&A, &R, o, &Y, 0);
      if (timerwrite(&Y, &N) && timerwrite(&N, &Y))  
      {
         continue;
      }
      if (timerwrite(&Y, &ONE) && timerwrite(&ONE, &Y))  
      {
         continue;
      }
      j = 1;
      while ((j < s) && (!timerwrite(&Y, &N) || !timerwrite(&N, &Y)))
      {
         
         hotplugpgtable(&Y, &Y, &M);
         suspendfinish(&M, o);
         if (timerwrite(&M, &ONE) && timerwrite(&ONE, &M))  
         {
            ret = 1;
            break;
         }
         j++;
      }
      if (!timerwrite(&M, &N) || !timerwrite(&N, &M))  
      {
         ret = 1;
      }
   }

   baFree(afterhandler);
   return ret;
}


static U16 pc104irqmasks(shtype_t *o, U16 div)
{
   int i;
   U32 mod = 0;
   #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
   for (i = 0; i < o->len; i++)
   {
      mod <<= (SHARKSSL_BIGINT_WORDSIZE/2);
      mod |= (o->beg[i] >> (SHARKSSL_BIGINT_WORDSIZE/2));
      mod %= div;
      
      mod <<= (SHARKSSL_BIGINT_WORDSIZE/2);
      mod |= (o->beg[i] & ((1L << (SHARKSSL_BIGINT_WORDSIZE/2)) - 1));
      mod %= div;
   }
   #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
   for (i = 0; i < o->len; i++)
   {
      mod <<= (SHARKSSL_BIGINT_WORDSIZE/2);
      mod |= o->beg[i];
      mod %= div;
   }
   #elif (SHARKSSL_BIGINT_WORDSIZE == 8)
   for (i = 0; i < o->len; )
   {
      mod <<= (SHARKSSL_BIGINT_WORDSIZE/2);
      mod |= (((U16)o->beg[i]) << 8);
      i++;
      if (i < o->len)
      {
         mod |= (((U16)o->beg[i]) << 8);
         i++;
      }
      mod %= div;
   }
   #endif

   baAssert((mod >> 16) == 0);
   return (mod & 0xFFFF);
}


static U8 mcaspresources(shtype_t *o)
{
   static const U16 ethernatshutdown[] =
   {
        3,    5,    7,   11,   13,   17,   19,   23,
       29,   31,   37,   41,   43,   47,   53,   59,
       61,   67,   71,   73,   79,   83,   89,   97,
      101,  103,  107,  109,  113,  127,  131,  137,
      139,  149,  151,  157,  163,  167,  173,  179,
      181,  191,  193,  197,  199,  211,  223,  227,
      229,  233,  239,  241,  251,  257,  263,  269,
      271,  277,  281,  283,  293,  307,  311,  313,
      317,  331,  337,  347,  349,  353,  359,  367,
      373,  379,  383,  389,  397,  401,  409,  419,
      421,  431,  433,  439,  443,  449,  457,  461,
      463,  467,  479,  487,  491,  499,  503,  509,
      521,  523,  541,  547,  557,  563,  569,  571,
      577,  587,  593,  599,  601,  607,  613,  617,
      619,  631,  641,  643,  647,  653,  659,  661,
      673,  677,  683,  691,  701,  709,  719,  727,
      733,  739,  743,  751,  757,  761,  769,  773,
      787,  797,  809,  811,  821,  823,  827,  829,
      839,  853,  857,  859,  863,  877,  881,  883,
      887,  907,  911,  919,  929,  937,  941,  947,
      953,  967,  971,  977,  983,  991,  997, 1009,
     1013, 1019, 1021, 1031, 1033, 1039, 1049,    0 
   };
   const U16 *pciercxcfg006 = &ethernatshutdown[0];
   do
   {
      if (0 == pc104irqmasks(o, *pciercxcfg006))
      {
         return 1;
      }
      
   } while (*(++pciercxcfg006));

   return irqwakeintmask(o);
}



int aemifdevice(shtype_t *o)
{
   static const shtype_tWord two = 2;
   shtype_t TWO;

   if (0 == o->len)
   {
      return -1;
   }

   shtype_t_genPrime_1:
   o->beg = o->mem;
   sharkssl_rng((U8*)o->beg, o->len * SHARKSSL__M);
   o->beg[0] |= (1 << (SHARKSSL_BIGINT_WORDSIZE - 1));  
   o->beg[o->len - 1] |= 1;  
   onenandpartitions(&TWO, SHARKSSL_BIGINT_WORDSIZE, &two);

   while (mcaspresources(o))
   {
      resolverelocs(o, &TWO);
      if (0 == (o->beg[0] & (1 << (SHARKSSL_BIGINT_WORDSIZE - 1))))    
      {
         goto shtype_t_genPrime_1;
      }
   }

   return 0;
}


int translateaddress(const shtype_t *o1,
                       const shtype_t *o2,
                       shtype_t *deltadevices)
{
   U8 *afterhandler, *p;
   shtype_t A;
   #if 0
   U16 n;
   #endif

   p = afterhandler = (U8*)baMalloc(o1->len * SHARKSSL__M);
   if (afterhandler == (void*)0)
   {
      return -2;
   }

   onenandpartitions(&A, o1->len * SHARKSSL_BIGINT_WORDSIZE, p);

   unassignedvector(o1, &A);
   unassignedvector(o2, deltadevices);

   
   #if 0  
   n = 0;
   while ((0 == (A.beg[A.len - 1] & 0x01)) && (0 == (deltadevices->beg[deltadevices->len - 1] & 0x01)))
   {
      backlightpdata(&A);
      backlightpdata(deltadevices);
      n++;

      blastscache(&A);
      blastscache(deltadevices);

      if (((1 == A.len) && (0 == A.beg[0])) || ((1 == deltadevices->len) && (0 == deltadevices->beg[0])))
      {
         break;
      }
   }
   #endif

   while ((A.len > 1) || (A.beg[0] > 0))  
   {
      while ((0 == (A.beg[A.len - 1] & 0x01)) && ((A.len > 1) || (A.beg[0] > 0)))
      {
         backlightpdata(&A);
         blastscache(&A);
      }
      while ((0 == (deltadevices->beg[deltadevices->len - 1] & 0x01)) && ((deltadevices->len > 1) || (deltadevices->beg[0] > 0)))
      {
         backlightpdata(deltadevices);
         blastscache(deltadevices);
      }
      if (timerwrite(&A, deltadevices))  
      {
         updatepmull(&A, deltadevices);
         backlightpdata(&A);
      }
      else  
      {
         updatepmull(deltadevices, &A);
         backlightpdata(deltadevices);
      }
      blastscache(&A);
   }

   #if 0
   while (n--)
   {
      shtype_t_shiftl(deltadevices);
   }
   #endif
   
   baFree(afterhandler);
   return 0;
}
#endif


#ifndef BA_LIB
#define BA_LIB
#endif

#include <SharkSslEx.h>
#include <string.h>
#include <ctype.h>

#ifndef EXT_SHARK_LIB
#define sharkStrchr strchr
#endif




#include "SharkSslASN1.h"
void
SubjectAltNameEnumerator_constructor(
   SubjectAltNameEnumerator *o, U8 *ptr, U16 len)
{
   baAssert(o);
   baAssert(ptr);
   o->ptr = ptr;
   o->len = len;
}


void
SubjectAltNameEnumerator_getElement(
   SubjectAltNameEnumerator *o, SubjectAltName *s)
{
   if ((o->len) && (SharkSslParseASN1_getContextSpecific(
                       (SharkSslParseASN1*)o, &(s->tag)) == 0))
   {
      baAssert(o->datalen < 0xFFFF);
      s->ptr = o->dataptr;
      s->len = (U16)o->datalen;   
   }
   else
   {
      s->ptr = NULL;
   }
}


int
sharkStrCaseCmp(const char *a, int enableblock, const char *b, int timerinterrupt)
{
   if(enableblock == timerinterrupt)
   {
      register int n=-1;
      while((enableblock) && 
            ((n = tolower((unsigned char)*a) - 
              tolower((unsigned char)*b)) == 0))
      {
         enableblock--;
         a++, b++;
      }
      return n;
   }
   return enableblock - timerinterrupt; 
}


static int
memblockregions(const char* cn, int cnl, const char* gpio1config, int alignresource)
{
   if((cn[0] == '\052') && (cn[1] == '\056') && (cnl > 2)) 
   {
      char* writereg16;
      if( ! sharkStrCaseCmp(cn+2,(cnl-2),gpio1config, alignresource) )
         return 0;
      
      writereg16=sharkStrchr(gpio1config, '\056');
      if(writereg16)
      {
         
         if( ! sharkStrCaseCmp(cn+2,(cnl-2),writereg16+1,alignresource - (int)(writereg16 - gpio1config) -1) )
            return 0;
      }
   }
   return -1;
}



int 
sharkSubjectSubjectAltCmp(const char *cn, U16 registermmcsd1, U8 *programattributes,
                          U16 smemcresume, const char* gpio1config, U16 alignresource)
{
   if(cn && registermmcsd1)
   {
      if( ! sharkStrCaseCmp(cn, registermmcsd1, gpio1config, alignresource) || 
          ! memblockregions(cn, registermmcsd1, gpio1config, alignresource))
      {
         return 0;
      }
   }
   if (programattributes && smemcresume)
   {
      SubjectAltNameEnumerator se;
      SubjectAltName s;
      SubjectAltNameEnumerator_constructor(&se, programattributes, smemcresume);
      for (SubjectAltNameEnumerator_getElement(&se, &s); 
            SubjectAltName_isValid(&s); 
            SubjectAltNameEnumerator_nextElement(&se, &s))
      {
         if (SUBJECTALTNAME_DNSNAME == SubjectAltName_getTag(&s))
         {
            if( ! sharkStrCaseCmp((const char*)SubjectAltName_getPtr(&s),
                                  SubjectAltName_getLen(&s),gpio1config,alignresource) ||
                  ! memblockregions((const char*)SubjectAltName_getPtr(&s),
                                 SubjectAltName_getLen(&s),gpio1config, alignresource) )
            {
               return 0;
            }
            
         }
      }
   }
   return -1;
}

#if SHARKSSL_CHECK_DATE

BaTime sharkParseCertTime(const U8* utc, U8 len)
{
   int i;
   int dt[7];
   if(len > 15) return 0;
   for (i = 0; i < (len >> 1); utc += 2, i++)
   {
      if (!isdigit(*utc)) break;
      dt[i] = 10 * (utc[0] - '\060') + (utc[1] - '\060');
   }
   if(utc[0] == '\132' && (len == 13 || len == 15))
   {
#ifdef SHARKSSL_BA 
      struct BaTm ts;
      BaTimeEx tex;
      memset(&ts,0,sizeof(ts));
      if (len == 13)
      {
         ts.tm_sec =  dt[5];
         ts.tm_min =  dt[4];
         ts.tm_hour = dt[3];
         ts.tm_mday = dt[2]; 
         ts.tm_mon =  dt[1]-1;
         ts.tm_year = dt[0]+2000; 
      }
      else
      {
         ts.tm_sec = dt[6];
         ts.tm_min = dt[5];
         ts.tm_hour = dt[4];
         ts.tm_mday = dt[3];
         ts.tm_mon = dt[2] - 1;
         ts.tm_year = dt[1] + dt[0] * 100;
      }
      if(baTm2TimeEx(&ts, FALSE, &tex))
         return 0; 
      return tex.sec;
#else
      struct tm ts;
      memset(&ts,0,sizeof(ts));
      if (len == 13)
      {
         ts.tm_sec = dt[5];
         ts.tm_min = dt[4];
         ts.tm_hour = dt[3];
         ts.tm_mday = dt[2];
         ts.tm_mon = dt[1] - 1;
         ts.tm_year = dt[0] + 100; 
      }
      else
      {
         ts.tm_sec = dt[6];
         ts.tm_min = dt[5];
         ts.tm_hour = dt[4];
         ts.tm_mday = dt[3];
         ts.tm_mon = dt[2] - 1;
         ts.tm_year = (dt[1] + dt[0] * 100) - 1900;
          
         if(ts.tm_year >= 138 && sizeof(BaTime) <= 4)
         {  
            return (BaTime)(((U32)-1) - 1);
         }
      }
      return (BaTime)mktime(&ts);
#endif
   }
   return 0; 
}

SHARKSSL_API SharkSslConTrust
SharkSslCon_checkCertTime(SharkSslCertInfo* ci)
{
   SharkSslCertInfo* instructioncounter;
   for(instructioncounter = ci ; instructioncounter ; instructioncounter = instructioncounter->parent)
   {
      
      if(instructioncounter->parent || instructioncounter == ci)
      {
         BaTime forcereload = sharkParseCertTime(instructioncounter->timeFrom, instructioncounter->timeFromLen);
         BaTime now = baGetUnixTime();
         BaTime to = sharkParseCertTime(instructioncounter->timeTo, instructioncounter->timeToLen);
         if(forcereload == 0 || to == 0 || forcereload > (now+86400) || to < now)
            return SharkSslConTrust_CertCn;
      }
   }
   return SharkSslConTrust_CertCnDate; 
}
#else
#define SharkSslCon_checkCertTime(ci) SharkSslConTrust_CertCn
#endif



SHARKSSL_API SharkSslConTrust
SharkSslCon_trusted(SharkSslCon* o, const char* gpio1config, SharkSslCertInfo** cPtr)
{
   if(o) 
   {
      SharkSslCertInfo* ci = SharkSslCon_getCertInfo(o);
      if(cPtr)
      {
         *cPtr = ci;
      }
      if(ci)
      {
         int usbsshwmod = SharkSslCon_trustedCA(o);
         if( !gpio1config )
         {
            return usbsshwmod ? SharkSslConTrust_CertCn : SharkSslConTrust_None;
         }
         if (!sharkSubjectSubjectAltCmp((const char*)ci->subject.commonName,
                                        ci->subject.commonNameLen, 
                                        ci->subjectAltNamesPtr,
                                        ci->subjectAltNamesLen,
                                        gpio1config, (U16)strlen(gpio1config)))
         {
            return usbsshwmod ?
               SharkSslCon_checkCertTime(ci) : SharkSslConTrust_Cn;
         }
         return usbsshwmod ? SharkSslConTrust_Cert : SharkSslConTrust_None;
      }
      return  SharkSslConTrust_None;
   }
   if(cPtr)
   {
      *cPtr = 0;
   }
   return SharkSslConTrust_NotSSL;
}


#ifndef BA_LIB
#define BA_LIB
#endif

#define _SHARKSSL_C_

#undef  _SHARKSSL_C_
#include <string.h>


#if (SHARKSSL_SSL_SERVER_CODE || SHARKSSL_SSL_CLIENT_CODE)
SHARKSSL_API void SharkSsl_constructor(
   SharkSsl *o,
   SharkSsl_Role startkernel,
   U16 detectbootwidth,
   U16 inBufStartSize,
   U16 outBufSize
)
{
   baAssert(o);
   baAssert(NULL == (void*)0);
   #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_SSL_CLIENT_CODE)
   baAssert((startkernel == SharkSsl_Server) || (startkernel == SharkSsl_Client));
   o->role = startkernel;
   #else 
   #if   SHARKSSL_SSL_SERVER_CODE  
   baAssert(startkernel == SharkSsl_Server);
   #elif SHARKSSL_SSL_CLIENT_CODE  
   baAssert(startkernel == SharkSsl_Client);
   #endif
   (void)startkernel;
   #endif
   o->inBufStartSize = inBufStartSize;
   o->outBufSize = outBufSize;
   o->nCon = 0;  
   #if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
   SingleList_constructor(&o->certList);
   #if SHARKSSL_ENABLE_CA_LIST
   o->caList = 0;
   #endif
   #endif
   #if SHARKSSL_ENABLE_SESSION_CACHE
   counter1clocksource(&o->sessionCache, detectbootwidth);
   o->intf = 0;
   #else
   (void)detectbootwidth;
   #endif
}


SHARKSSL_API void SharkSsl_destructor(SharkSsl *o)
{
   #if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
   SharkSslCertList *link;
   while((link = (SharkSslCertList*)SingleList_removeFirst(&o->certList)) != 0)
   {
      baFree(link);
   }
   #endif
   baAssert(o);
   baAssert(o->nCon == 0);
   #if SHARKSSL_ENABLE_SESSION_CACHE
   if (o->intf)
   {
      o->intf->terminate(o->intf, o);
   }
   defaultsdhci0(&o->sessionCache);
   #endif
   memset(o, 0, sizeof(SharkSsl));
}


SharkSslCon *SharkSsl_createCon(SharkSsl *o)
{
   SharkSslCon *s;
   baAssert(o);
   s = (SharkSslCon*)baMalloc(pcmciapdata(sizeof(SharkSslCon)));
   if (s != (void*)0)
   {
      #if SHARKSSL_UNALIGNED_MALLOC
      SharkSslCon *su = s;
      s = (SharkSslCon*)selectaudio(s);
      conditionvalid(s, o);
      s->mem = su;
      #else
      conditionvalid(s, o);
      #endif
      o->nCon++;
   }
   return s;
}


void SharkSsl_terminateCon(const SharkSsl *o, SharkSslCon *emulaterd8rn16)
{
   #if SHARKSSL_UNALIGNED_MALLOC
   SharkSslCon *sslConMem = emulaterd8rn16->mem;
   baAssert(sslConMem);
   #endif
   baAssert(emulaterd8rn16);
   baAssert((!o) || (o == emulaterd8rn16->sharkSsl));
   baAssert(emulaterd8rn16->sharkSsl->nCon);
   (void)o;
   emulaterd8rn16->sharkSsl->nCon--;
   localenable(emulaterd8rn16);
   #if SHARKSSL_UNALIGNED_MALLOC
   baFree(sslConMem);
   #else
   baFree(emulaterd8rn16);
   #endif
}


#if SHARKSSL_ENABLE_SESSION_CACHE
U16 SharkSsl_getCacheSize(SharkSsl *o)
{
   baAssert(o);
   return (o->sessionCache.cacheSize);
}
#endif


#if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
SHARKSSL_API U8 SharkSsl_addCertificate(SharkSsl *o, SharkSslCert kernelvaddr)
{
   SharkSslCertList *c;
   SharkSslCertKey   sourcerouting;
   int modulesemaphore;

   baAssert(o);
   if (0 == o->nCon)
   {
      c = (SharkSslCertList*)baMalloc(sizeof(SharkSslCertList));

      if (c)
      {
         #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI)
         SharkSslCertInfo cp;
         #endif
         if ((c->certP.msgLen = setupboard(kernelvaddr)) == 0)
         {
            goto _SharkSsl_addCertificate_exit;
         }
         #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI)
         
         if (spromregister((SharkSslCertParam*)&cp, (U8*)kernelvaddr, (U32)-3, (U8*)&modulesemaphore) < 0)
         {
            goto _SharkSsl_addCertificate_exit;
         }
         #else
         modulesemaphore = spromregister(0, (U8*)kernelvaddr, (U32)-1, 0);
         if (modulesemaphore < 0)
         {
            goto _SharkSsl_addCertificate_exit;
         }
         #endif
         if (0 == interrupthandler(&sourcerouting, kernelvaddr))
         {
            goto _SharkSsl_addCertificate_exit;
         }
         if (machinekexec(sourcerouting.expLen))
         {
            c->certP.keyType = ahashchild;
            c->certP.keyOID  = camerareset(sourcerouting.modLen);
         }
         else if (machinereboot(sourcerouting.expLen))
         {
            c->certP.keyType = compatrestart;
            c->certP.keyOID =  wakeupenable(sourcerouting.modLen);
         }
         else  
         {
            _SharkSsl_addCertificate_exit:
            baFree(c);
            return 0;
         }
         c->certP.cert = kernelvaddr;
         c->certP.signatureAlgo = (modulesemaphore & 0xFF);
         c->certP.hashAlgo = ((modulesemaphore >> 8) & 0xFF);
         #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SNI)
         c->certP.commonName = cp.subject.commonName;
         c->certP.commonNameLen = cp.subject.commonNameLen;
         c->certP.subjectAltNamesPtr = cp.subjectAltNamesPtr;
         c->certP.subjectAltNamesLen = cp.subjectAltNamesLen;
         #endif
         SingleLink_constructor((SingleLink*)c);
         SingleList_insertLast(&o->certList, (SingleList*)c);
         return 1;
      }
   }

   return 0;
}


#if SHARKSSL_ENABLE_CA_LIST
SHARKSSL_API U8 SharkSsl_setCAList(SharkSsl *o, SharkSslCAList displaysetup)
{
   baAssert(o);
   if (0 == o->nCon)
   {
      o->caList = displaysetup;
      return 1;
   }

   return 0;
}
#endif  
#endif  

#endif  


#ifndef BA_LIB
#define BA_LIB
#endif



#include <string.h>


#if ((SHARKSSL_USE_AES_256 || SHARKSSL_USE_AES_128) && (SHARKSSL_ENABLE_AES_GCM))
int offsetkernel(SharkSslCon* o, U8 op, U8 *stackchecker, U16 len)
{
   SharkSslAesGcmCtx *registermcasp;

   baAssert(o);
   baAssert(o->minor >= 2);

   registermcasp = (SharkSslAesGcmCtx*)((op & populatebasepages) ? o->rCtx : o->wCtx);

   if (op & bcm1x80bcm1x55)
   {
      if (op & boardcompat)
      {
         if ((o->rCtx) && (op & populatebasepages))
         {
            SharkSslAesGcmCtx_destructor((SharkSslAesGcmCtx*)selectaudio(o->rCtx));
            baFree(o->rCtx);
            o->rCtx = 0;
         }
         else if ((o->wCtx) && (op & ptraceregsets))
         {
            SharkSslAesGcmCtx_destructor((SharkSslAesGcmCtx*)selectaudio(o->wCtx));
            baFree(o->wCtx);
            o->wCtx = 0;
         }
         return 0;
      }

      else
      {
         baAssert(!registermcasp);
         registermcasp = (SharkSslAesGcmCtx*)baMalloc(pcmciapdata(sizeof(SharkSslAesGcmCtx)));
         if (registermcasp == (void*)0)
         {
            return -1;  
         }
         if (op & populatebasepages)
         {
            SharkSslAesGcmCtx_constructor((SharkSslAesGcmCtx*)selectaudio(registermcasp), o->rKey, o->rCipherSuite->keyLen);
            o->rCtx = registermcasp;
         }
         else
         {
            SharkSslAesGcmCtx_constructor((SharkSslAesGcmCtx*)selectaudio(registermcasp), o->wKey, o->wCipherSuite->keyLen);
            o->wCtx = registermcasp;
         }
      }
   }

   if (op & populatebasepages)
   {
      U8 *branchtarget = func3fixup(&o->inBuf);
      memcpy(&o->rIV[4], stackchecker, 8);  
      stackchecker += 8 ;
      baAssert(16 == o->rCipherSuite->digestLen);
      baAssert(len >= 24);
      len -= (8 + 16);  
      templateentry(o, o->inBuf.data[0], branchtarget, len);
      return SharkSslAesGcmCtx_decrypt((SharkSslAesGcmCtx*)selectaudio(registermcasp), o->rIV, &stackchecker[len], branchtarget - 8, 13, stackchecker, stackchecker, len);
   }

   return SharkSslAesGcmCtx_encrypt((SharkSslAesGcmCtx*)selectaudio(registermcasp), o->wIV, &stackchecker[len], stackchecker - 13, 13, stackchecker, stackchecker, len);
}
#endif


#if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
int updatecontext(SharkSslCon* o, U8 op, U8 *stackchecker, U16 len)
{
   SharkSslPoly1305Ctx timer8hwmod;
   SharkSslChaChaCtx  *registermcasp;
   U8 *branchtarget, unalignedwarning[32];

   baAssert(o);
   baAssert(o->minor >= 2);

   registermcasp = (SharkSslChaChaCtx*)((op & populatebasepages) ? o->rCtx : o->wCtx);

   if (op & bcm1x80bcm1x55)
   {
      if (op & boardcompat)
      {
         if ((o->rCtx) && (op & populatebasepages))
         {
            SharkSslChaChaCtx_destructor((SharkSslChaChaCtx*)selectaudio(o->rCtx));
            baFree(o->rCtx);
            o->rCtx = 0;
         }
         else if ((o->wCtx) && (op & ptraceregsets))
         {
            SharkSslChaChaCtx_destructor((SharkSslChaChaCtx*)selectaudio(o->wCtx));
            baFree(o->wCtx);
            o->wCtx = 0;
         }
         return 0;
      }

      else
      {
         baAssert(!registermcasp);
         registermcasp = (SharkSslChaChaCtx*)baMalloc(pcmciapdata(sizeof(SharkSslChaChaCtx)));
         if (registermcasp == (void*)0)
         {
            return -1;  
         }
         if (op & populatebasepages)
         {
            SharkSslChaChaCtx_constructor((SharkSslChaChaCtx*)selectaudio(registermcasp), o->rKey, o->rCipherSuite->keyLen);
            o->rCtx = registermcasp;
         }
         else
         {
            SharkSslChaChaCtx_constructor((SharkSslChaChaCtx*)selectaudio(registermcasp), o->wKey, o->wCipherSuite->keyLen);
            o->wCtx = registermcasp;
         }
      }
   }

   if (op & populatebasepages)
   {
      branchtarget = func3fixup(&o->inBuf);
      baAssert(16 == o->rCipherSuite->digestLen);
      baAssert(len >= 16);
      len -= 16;  
      templateentry(o, o->inBuf.data[0], branchtarget, len);
      *(U32*)&unalignedwarning[0] = *(U32*)&(o->rIV[0]);
      *(U32*)&unalignedwarning[4] = *(U32*)&(o->rIV[4]);
      *(U32*)&unalignedwarning[8] = *(U32*)&(o->rIV[8]);
   }
   else  
   {
      branchtarget = func3fixup(&o->outBuf);
      baAssert(16 == o->wCipherSuite->digestLen);
      *(U32*)&unalignedwarning[0] = *(U32*)&(o->wIV[0]);
      *(U32*)&unalignedwarning[4] = *(U32*)&(o->wIV[4]);
      *(U32*)&unalignedwarning[8] = *(U32*)&(o->wIV[8]);
   }

   
   unalignedwarning[4]  ^= *(branchtarget-8);
   unalignedwarning[5]  ^= *(branchtarget-7);
   unalignedwarning[6]  ^= *(branchtarget-6);
   unalignedwarning[7]  ^= *(branchtarget-5);
   unalignedwarning[8]  ^= *(branchtarget-4);
   unalignedwarning[9]  ^= *(branchtarget-3);
   unalignedwarning[10] ^= *(branchtarget-2);
   unalignedwarning[11] ^= *(branchtarget-1);
   SharkSslChaChaCtx_setIV((SharkSslChaChaCtx*)selectaudio(registermcasp), (const U8*)unalignedwarning);

   *(U32*)&unalignedwarning[0]  = 0;
   *(U32*)&unalignedwarning[4]  = 0;
   *(U32*)&unalignedwarning[8]  = 0;
   *(U32*)&unalignedwarning[12] = 0;
   *(U32*)&unalignedwarning[16] = 0;
   *(U32*)&unalignedwarning[20] = 0;
   *(U32*)&unalignedwarning[24] = 0;
   *(U32*)&unalignedwarning[28] = 0;
   SharkSslChaChaCtx_crypt((SharkSslChaChaCtx*)selectaudio(registermcasp), unalignedwarning, unalignedwarning, 32);
   SharkSslPoly1305Ctx_constructor(&timer8hwmod, unalignedwarning);

   
   *(U32*)&unalignedwarning[0]  = 0;
   *(U32*)&unalignedwarning[4]  = 0;
   *(U32*)&unalignedwarning[8]  = 0;
   *(U32*)&unalignedwarning[12] = 0;

   SharkSslPoly1305Ctx_append(&timer8hwmod, branchtarget - 8, 13);
   SharkSslPoly1305Ctx_append(&timer8hwmod, unalignedwarning, SHARKSSL_POLY1305_HASH_LEN - 13);  

   if (op & ptraceregsets)
   {
      SharkSslChaChaCtx_crypt((SharkSslChaChaCtx*)selectaudio(registermcasp), stackchecker, stackchecker, len);
   }

   SharkSslPoly1305Ctx_append(&timer8hwmod, stackchecker, len);
   baAssert(0 == (SHARKSSL_POLY1305_HASH_LEN & (SHARKSSL_POLY1305_HASH_LEN - 1)));
   SharkSslPoly1305Ctx_append(&timer8hwmod, unalignedwarning, (U8)-((U8)len) & (SHARKSSL_POLY1305_HASH_LEN - 1));  

   unalignedwarning[0] = 13;               
   SharkSslPoly1305Ctx_append(&timer8hwmod, &unalignedwarning[0], 8);
   unalignedwarning[0] = (U8)(len & 0xFF); 
   unalignedwarning[1] = (U8)(len >> 8);   
   SharkSslPoly1305Ctx_append(&timer8hwmod, &unalignedwarning[0], 8);

   if (op & populatebasepages)
   {
      SharkSslPoly1305Ctx_finish(&timer8hwmod, &unalignedwarning[0]);
      SharkSslPoly1305Ctx_destructor(&timer8hwmod);

      if (sharkssl_kmemcmp(&stackchecker[len], &unalignedwarning[0], 16))  
      {
         return 1;
      }
      SharkSslChaChaCtx_crypt((SharkSslChaChaCtx*)selectaudio(registermcasp), stackchecker, stackchecker, len);
   }
   else  
   {
      SharkSslPoly1305Ctx_finish(&timer8hwmod, &stackchecker[len]);
      SharkSslPoly1305Ctx_destructor(&timer8hwmod);
   }

   return 0;
}
#endif


#ifndef BA_LIB
#define BA_LIB
#endif



#include <string.h>


#if SHARKSSL_ENABLE_SESSION_CACHE

void counter1clocksource(SharkSslSessionCache *commoncontiguous, U16 detectbootwidth)
{
   U32 flash1resources = detectbootwidth * sizeof(SharkSslSession);
   baAssert(commoncontiguous);
   memset(commoncontiguous, 0, sizeof(SharkSslSessionCache));
   ThreadMutex_constructor(&(commoncontiguous->cacheMutex));
   if (detectbootwidth != 0)
   {
      commoncontiguous->cache = (SharkSslSession*)baMalloc(pcmciapdata(flash1resources));
      if (commoncontiguous->cache != (void*)0)
      {
         commoncontiguous->cacheSize = detectbootwidth;
         memset(selectaudio(commoncontiguous->cache), 0, flash1resources);
      }
   }
}


void defaultsdhci0(SharkSslSessionCache *commoncontiguous)
{
   baAssert(commoncontiguous);
   if (commoncontiguous->cacheSize != 0)
   {
      #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_CLONE_CERTINFO)
      U32 uart2hwmod;
      SharkSslSession *func2fixup = (SharkSslSession*)selectaudio(commoncontiguous->cache);
      for (uart2hwmod = commoncontiguous->cacheSize; uart2hwmod > 0; uart2hwmod--, func2fixup++)
      {
         if (func2fixup->clonedCertInfo)
         {
            baAssert(0 == (func2fixup->clonedCertInfo->flags & SHARKSSL_CCINFO_CERT_CLONED));
            baFree((void*)func2fixup->clonedCertInfo);
         }
      }
      #endif
      memset(selectaudio(commoncontiguous->cache), 0, commoncontiguous->cacheSize * sizeof(SharkSslSession));
      baFree(commoncontiguous->cache);
   }
   ThreadMutex_destructor(&commoncontiguous->cacheMutex);
   memset(commoncontiguous, 0, sizeof(SharkSslSessionCache));
}


SharkSslSession *sa1111device(SharkSslSessionCache *commoncontiguous,
                                                 SharkSslCon *o, U8 *id, U16 setupinterface)
{
   SharkSslSession *func2fixup = 0;

   baAssert(o);
   if (commoncontiguous->cacheSize)
   {
      SharkSslSession *oldestSession = 0;
      U32 t, uart2hwmod, now;

      now = baGetUnixTime();
      t = 0xFFFFFFFF;
      func2fixup = (SharkSslSession*)selectaudio(commoncontiguous->cache);
      filtermatch(commoncontiguous);
      for (uart2hwmod = commoncontiguous->cacheSize; uart2hwmod > 0; uart2hwmod--, func2fixup++)
      {
         if (func2fixup->cipherSuite == 0)
         {
            break;
         }

         if ((func2fixup->latestAccess < t) && (func2fixup->nUse == 0))
         {
            t = func2fixup->latestAccess;
            oldestSession = func2fixup;
         }
      }

      if (uart2hwmod == 0)
      {
         func2fixup = oldestSession;  
      }

      if (func2fixup) 
      {
         uart2hwmod = (U32)(func2fixup - (SharkSslSession*)selectaudio(commoncontiguous->cache));
         if (uart2hwmod < commoncontiguous->cacheSize)
         {
            #if SHARKSSL_SSL_CLIENT_CODE
            #if SHARKSSL_SSL_SERVER_CODE
            if (SharkSsl_isClient(o->sharkSsl))
            #endif
            {
               baAssert(id);
               baAssert(setupinterface);
               #if SHARKSSL_ENABLE_CLONE_CERTINFO
               baAssert((SharkSslClonedCertInfo*)0 == func2fixup->clonedCertInfo);
               #endif
               if (setupinterface < SHARKSSL_MAX_SESSION_ID_LEN)
               {
                  memset(func2fixup->id, 0, SHARKSSL_MAX_SESSION_ID_LEN);
               }
               memcpy(func2fixup->id, id, setupinterface);
            }
            #if SHARKSSL_SSL_SERVER_CODE
            else  
            #endif
            #endif
            #if SHARKSSL_SSL_SERVER_CODE
            {
               baAssert(0 == id);
               baAssert(0 == setupinterface);
               uart2hwmod++;
               uart2hwmod = ~uart2hwmod;
               func2fixup->id[0] = (U8)(uart2hwmod >> 24);
               func2fixup->id[1] = (U8)(uart2hwmod >> 16);
               func2fixup->id[2] = (U8)(uart2hwmod >> 8);
               func2fixup->id[3] = (U8)(uart2hwmod & 0xFF);
               func2fixup->id[4] = (U8)(now >> 24);
               func2fixup->id[5] = (U8)(now >> 16);
               func2fixup->id[6] = (U8)(now >> 8);
               func2fixup->id[7] = (U8)(now & 0xFF);
               #if SHARKSSL_ENABLE_CLONE_CERTINFO
               
               if (func2fixup->clonedCertInfo)
               {
                  func2fixup->clonedCertInfo->flags &= ~SHARKSSL_CCINFO_CERT_CACHED;
                  if (0 == func2fixup->clonedCertInfo->flags)
                  {
                     baFree((void*)func2fixup->clonedCertInfo);
                  }
                  func2fixup->clonedCertInfo = (SharkSslClonedCertInfo*)0;
               }
               #endif  
               if (sharkssl_rng(&func2fixup->id[8], SHARKSSL_MAX_SESSION_ID_LEN - 8) < 0)
               {
                  func2fixup = 0;
               }
            }
            #endif

            if (func2fixup)
            {
               func2fixup->nUse = 1;
               func2fixup->cipherSuite  = hsParam(o)->cipherSuite;
               func2fixup->firstAccess  = now;
               func2fixup->latestAccess = now;
               func2fixup->flags        = 0;
               sha224final(func2fixup, o->major, o->minor);
            }
         }
         else
         {
            func2fixup = 0;
         }
      }
      helperglobal(commoncontiguous);
   }

   return func2fixup;
}


SharkSslSession *latchgpiochip(SharkSslSessionCache *commoncontiguous,
                                                  SharkSslCon *o, U8 *id, U16 setupinterface)
{
   SharkSslSession *func2fixup = 0;

   baAssert(id);
   baAssert(setupinterface);
   baAssert(commoncontiguous);
   if (commoncontiguous->cacheSize)
   {
      U32 now, uart2hwmod;

      now = baGetUnixTime();
      filtermatch(commoncontiguous);
      if (SharkSsl_isClient(o->sharkSsl))
      {
         func2fixup = (SharkSslSession*)selectaudio(commoncontiguous->cache);
         uart2hwmod = commoncontiguous->cacheSize - 1;
      }
      else  
      {
         uart2hwmod = (~(((U32)id[0] << 24) | ((U32)id[1] << 16) | ((U16)id[2] << 8) | id[3])) - 1;
         if (uart2hwmod < commoncontiguous->cacheSize)
         {
            func2fixup = (SharkSslSession*)((U8*)selectaudio(commoncontiguous->cache) + (uart2hwmod * sizeof(SharkSslSession)));
         }
      }
      for (;;)  
      {
         if ((func2fixup) &&
             (func2fixup->cipherSuite) &&
             (0 == sharkssl_kmemcmp(func2fixup->id, id, setupinterface)) &&
             (restarthandler(func2fixup, o->major, o->minor)) &&
             ((U32)(now - func2fixup->firstAccess) < 21600L ) &&
             (func2fixup->nUse < 0xFFFF))
         {
            func2fixup->nUse++;
            func2fixup->latestAccess = now;
            #if SHARKSSL_ENABLE_CA_LIST
            if (func2fixup->flags & ecoffaouthdr)
            {
               o->flags |= switcheractivation;
            }
            #endif
            break;
         }
         else
         {
            if ((SharkSsl_isServer(o->sharkSsl)) || (0 == uart2hwmod))
            {
               func2fixup = 0;
               break;
            }
            else
            {
               uart2hwmod--;
               func2fixup++;
            }
         }
      }
      helperglobal(commoncontiguous);
   }

   return func2fixup;
}
#endif



void atomiccmpxchg(SharkSslBuf *o, U16 icachealiases)
{
   U16 mcasp0device = icachealiases + gpio5config;
   baAssert(o);
   memset(o, 0, sizeof(SharkSslBuf));
   #if SHARKSSL_UNALIGNED_MALLOC
   o->mem = (U8*)baMalloc(pcmciapdata(mcasp0device));
   if (o->mem != (void*)0)
   {
      o->buf = (U8*)selectaudio(o->mem);
   #else
   baAssert(pcmciapdata(0) == 0);
   o->buf = (U8*)baMalloc(mcasp0device);
   if (o->buf != (void*)0)
   {
   #endif
      registerfixed(o);
      o->size = icachealiases;
   }
}


void guestconfig5(SharkSslBuf *o)
{
   baAssert(o);
   if (o->buf)
   {
      #if SHARKSSL_UNALIGNED_MALLOC
      memset(o->mem, 0, pcmciapdata(o->size) + gpio5config);
      baFree(o->mem);
      #else
      memset(o->buf, 0, o->size + gpio5config);
      baFree(o->buf);
      #endif
   }
   memset(o, 0, sizeof(SharkSslBuf));
}


void binaryheader(SharkSslBuf *o)
{
   U8 *doublefnmul = o->data;
   registerfixed(o);
   memmove(o->data, doublefnmul, o->dataLen);
}


#if (!SHARKSSL_DISABLE_INBUF_EXPANSION)
U8 *othersegments(SharkSslBuf *o, U16 kprobehandler)
{
   #if (SHARKSSL_UNALIGNED_MALLOC)
   U8 *percpuclockdev;
   #endif
   U8 *anatopenable;
   U16 mcasp0device;

   if (kprobehandler)
   {
      baAssert(o->size < kprobehandler);
      mcasp0device = ((kprobehandler + cachewback - 1) / cachewback) * cachewback;
      baAssert(mcasp0device >= kprobehandler);
   }
   else
   {
      mcasp0device = o->size + cachewback;
   }
   mcasp0device += gpio5config;

   #if (SHARKSSL_UNALIGNED_MALLOC)
   percpuclockdev = o->mem;
   anatopenable = (U8*)baMalloc(pcmciapdata(mcasp0device));
   if (anatopenable != (void*)0)
   {
      o->mem = anatopenable;
      anatopenable = (U8*)selectaudio(anatopenable);
      memcpy(anatopenable, o->buf, gpio5config + o->size);
   }
   baFree(percpuclockdev);
   #else
   anatopenable = (U8*)baRealloc(o->buf, mcasp0device);
   if (anatopenable == (void*)0)
   {
      anatopenable = (U8*)baMalloc(mcasp0device);
      if (anatopenable != (void*)0)
      {
         memcpy(anatopenable, o->buf, gpio5config + o->size);
      }
      baFree(o->buf);
   }
   #endif

   o->buf = anatopenable;
   if (anatopenable)
   {
      registerfixed(o);  
      o->size = (U16)mcasp0device - gpio5config;
   }

   return anatopenable;
}
#endif



void breakpointhandler(SharkSslHSParam *o)
{
   baAssert(o);
   memset(o, 0, sizeof(SharkSslHSParam));
   SharkSslSha256Ctx_constructor(&o->sha256Ctx);
   #if SHARKSSL_USE_SHA_384
   SharkSslSha384Ctx_constructor(&o->sha384Ctx);
   #endif
   #if SHARKSSL_USE_SHA_512
   SharkSslSha512Ctx_constructor(&o->sha512Ctx);
   #endif
}


void alignmentldmstm(SharkSslHSParam *o)
{
   baAssert(o);
   memset(o, 0, sizeof(SharkSslHSParam));
}


void ioremapresource(SharkSslHSParam *o, U8 *alloccontroller, U16 len)
{
   baAssert(o);
   baAssert(alloccontroller);
   baAssert(len);
   SharkSslSha256Ctx_append(&o->sha256Ctx, alloccontroller, len);
   #if SHARKSSL_USE_SHA_384
   SharkSslSha384Ctx_append(&o->sha384Ctx, alloccontroller, len);
   #endif
   #if SHARKSSL_USE_SHA_512
   SharkSslSha512Ctx_append(&o->sha512Ctx, alloccontroller, len);
   #endif
}


int wakeupvector(SharkSslHSParam* o, U8* chargerplatform, U8 configwrite)
{
   U8* buf;
   baAssert(o);
   baAssert(chargerplatform);
   switch (configwrite)
   {
      #if SHARKSSL_USE_SHA_512
      case batterythread:
         buf = (U8*)baMalloc(sizeof(SharkSslSha512Ctx));
         if (!buf)
         {
            return -1;
         }
         memcpy(buf, &o->sha512Ctx, sizeof(SharkSslSha512Ctx));
         SharkSslSha512Ctx_finish((SharkSslSha512Ctx*)buf, chargerplatform);
         break;
      #endif

      #if SHARKSSL_USE_SHA_384
      case probewrite:
         buf = (U8*)baMalloc(sizeof(SharkSslSha384Ctx));
         if (!buf)
         {
            return -1;
         }
         memcpy(buf, &o->sha384Ctx, sizeof(SharkSslSha384Ctx));
         SharkSslSha384Ctx_finish((SharkSslSha384Ctx*)buf, chargerplatform);
         break;
      #endif

      #if SHARKSSL_USE_SHA_256
      case domainnumber:
         buf = (U8*)baMalloc(sizeof(SharkSslSha256Ctx));
         if (!buf)
         {
            return -1;
         }
         memcpy(buf, &o->sha256Ctx, sizeof(SharkSslSha256Ctx));
         SharkSslSha256Ctx_finish((SharkSslSha256Ctx*)buf, chargerplatform);
         break;
      #endif

      default:
         return -1;
   }
   baFree(buf);
   return 0;
}



static void disablelevel(U8 *q)
{
   memset(q - (statsstruct - 1), 0, statsstruct);
}


static void clusterpowerdown(U8 *q)
{
   U8 n = statsstruct;

   while ((0 == ++(*q)) && (n > 0))
   {
      q--;
      n--;
   }
}



void conditionvalid(SharkSslCon *o, SharkSsl *resetcounters)
{
   baAssert(o);
   memset(o, 0, sizeof(SharkSslCon));

   o->sharkSsl = resetcounters;
   if (SharkSsl_isClient(resetcounters))
   {
      
      o->flags |= probedaddress;
   }
   else
   {
      baAssert(SharkSsl_isServer(resetcounters));
      
      o->state = pciercxcfg070;
   }
}


#if SHARKSSL_ENABLE_CLONE_CERTINFO
static void singleftosi(SharkSslCon *o)
{
   
   if (o->clonedCertInfo)
   {
      #if SHARKSSL_ENABLE_SESSION_CACHE
      
      filtermatch(&o->sharkSsl->sessionCache);
      o->clonedCertInfo->flags &= ~SHARKSSL_CCINFO_CERT_CLONED;
      if (0 == o->clonedCertInfo->flags)
      #endif
      {
         baFree((void*)o->clonedCertInfo);
      }
      #if SHARKSSL_ENABLE_SESSION_CACHE
      helperglobal(&o->sharkSsl->sessionCache);
      #endif
   }
}
#endif  


void localenable(SharkSslCon *o)
{
   baAssert(o);
   guestconfig5(&o->inBuf);
   guestconfig5(&o->outBuf);
   #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
   guestconfig5(&o->tmpBuf);
   #endif

   if (o->rCipherSuite)
   {
      o->rCipherSuite->cipherFunc(o, chargerworker | populatebasepages, (U8*)0, 0);
   }
   if (o->wCipherSuite)
   {
      o->wCipherSuite->cipherFunc(o, chargerworker | ptraceregsets, (U8*)0, 0);
   }

   #if SHARKSSL_ENABLE_SESSION_CACHE
   if (o->session)
   {
      SharkSslSession *s = o->session;

      
      o->session = 0;
      if ((SharkSsl_isServer(o->sharkSsl)) || (o->flags & gpiolibmbank))
      {
         SharkSslSession_release(s, o->sharkSsl);
      }
   }
   #endif

   #if SHARKSSL_ENABLE_CLONE_CERTINFO
   singleftosi(o);
   #endif

   memset(o, 0, sizeof(SharkSslCon));
}


SharkSslCon_RetVal SharkSslCon_decrypt(SharkSslCon *o, U16 pmattrstore)
{
   U8 *registeredevent;
   SharkSslCon_RetVal ret;
   U16 backuppdata, recLenDec, atagsprocfs;
   #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
   U16 dummyhwclk;
   #endif
   U8  recType, tvp5146pdata, minor;

   baAssert(o);

   if (o->flags & firstcomponent)
   {
      resvdexits(o);
      return SharkSslCon_Error;
   }

   #if SHARKSSL_SSL_CLIENT_CODE
   #if SHARKSSL_SSL_SERVER_CODE
   if (SharkSsl_isClient(o->sharkSsl))
   #endif
   {
      if (o->flags & probedaddress)
      {
         #if SHARKSSL_ENABLE_CLONE_CERTINFO
         return configdword(o, 0, 0, 0);
         #else
         recLenDec = 0;
         return configdword(o, 0, &recLenDec, 0);
         #endif
      }

      baAssert(!microresources(&o->inBuf));
   }
   #if SHARKSSL_SSL_SERVER_CODE
   else
   #endif
   #endif  
   #if SHARKSSL_SSL_SERVER_CODE
   {
      if (microresources(&o->inBuf))
      {
         #if (SHARKSSL_ENABLE_RSA || (SHARKSSL_ENABLE_ECDSA))
         SingleListEnumerator e;
         SingleLink *link;
         SingleListEnumerator_constructor(&e, (SingleList*)&o->sharkSsl->certList);
         recLenDec = 0;
         for (link = SingleListEnumerator_getElement(&e);
              link;
              link = SingleListEnumerator_nextElement(&e))
         {
            if (((SharkSslCertList*)link)->certP.msgLen > recLenDec)
            {
               recLenDec = ((SharkSslCertList*)link)->certP.msgLen;
            }
         }
         if (0 == recLenDec)
         {
            return SharkSslCon_CertificateError;
         }
         #else
         recLenDec = 0;
         #endif
         baAssert(!(o->flags & clockgettime32));
         baAssert(!SharkSslCon_isHandshakeComplete(o));
         backuppdata     = o->sharkSsl->inBufStartSize;
         recLenDec += 128 + SHARKSSL_MAX_SESSION_ID_LEN + SHARKSSL_MAX_BLOCK_LEN +
                      SHARKSSL_MAX_DIGEST_LEN + prefetchwrite;
         #if SHARKSSL_ENABLE_DHE_RSA
         
         recLenDec += 1024 + 14;
         #elif SHARKSSL_ENABLE_ECDHE_RSA
         recLenDec += 256;  
         #endif
         recLenDec  = claimresource(recLenDec);
         if (backuppdata < recLenDec)
         {
            backuppdata = recLenDec;
         }

         atomiccmpxchg(&o->inBuf, backuppdata);
         if (microresources(&o->inBuf))
         {
            return SharkSslCon_AllocationError;
         }

         if (microresources(&o->outBuf))
         {
            backuppdata = o->sharkSsl->outBufSize;
            baAssert(backuppdata >= (128 + sizeof(SharkSslHSParam)));
            atomiccmpxchg(&o->outBuf, backuppdata);
            if (microresources(&o->outBuf))
            {
               return SharkSslCon_AllocationError;
            }
         }
      }
   }
   #endif

   

   if (o->flags & clockgettime32)
   {
      if (o->inBuf.temp)
      {
         return SharkSslCon_Decrypted;
      }
      else
      {
         o->flags &= ~clockgettime32;
      }
   }

   registeredevent = o->inBuf.data;
   o->inBuf.dataLen += pmattrstore;
   atagsprocfs = o->inBuf.dataLen;
   backuppdata = 0;

   _sharkssl_process_another_record:
   if (atagsprocfs < clkctrlmanaged)
   {
      #if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SECURE_RENEGOTIATION)
      if (o->flags & registerbuses
          #if SHARKSSL_SSL_CLIENT_CODE
          && (SharkSsl_isServer(o->sharkSsl))
          #endif
         )
      {
         o->flags &= ~registerbuses;
         o->flags |=  skciphersetkey;
         return SharkSslCon_Handshake;
      }
      #endif

      _sharkssl_need_more_data:
      baAssert(o->inBuf.size >= o->inBuf.dataLen);
      if (!(serial2platform(&o->inBuf)))
      {
         
         binaryheader(&o->inBuf);
      }
      backuppdata += clkctrlmanaged; 
      if (o->inBuf.size < backuppdata)   
      {
         #if (!SHARKSSL_DISABLE_INBUF_EXPANSION)
         if (!othersegments(&o->inBuf, backuppdata))
         #endif
         {
            return SharkSslCon_AllocationError;
         }
      }

      return SharkSslCon_NeedMoreData;
   }

   if ((o->major) || (0 == (*registeredevent & 0x80)) || SharkSsl_isClient(o->sharkSsl))
   {
      recType = *registeredevent++;
      tvp5146pdata   = *registeredevent++;
      minor   = *registeredevent++;
      backuppdata  = (U16)(*registeredevent++) << 8;
      backuppdata += *registeredevent++;
      atagsprocfs -= clkctrlmanaged;
   }
   else
   {
      goto _sharkssl_alert_unexpected_message;
   }

   if ((recType != rangealigned) &&
       (recType != firstentry) &&
       (recType != controllegacy) &&
       (recType != polledbutton))
   {
      _sharkssl_alert_unexpected_message:
      return savedconfig(o, SHARKSSL_ALERT_UNEXPECTED_MESSAGE);
   }

   if ( (backuppdata == 0) || (backuppdata > gpio2enable) ||
        ((o->state != trampolinehandler) && 
         (o->state != pciercxcfg070) && 
         ((o->major != tvp5146pdata) || (o->minor != minor))) )
   {
      _sharkssl_alert_illegal_parameter:
      return savedconfig(o, SHARKSSL_ALERT_ILLEGAL_PARAMETER);
   }

   if (atagsprocfs < backuppdata)
   {
      goto _sharkssl_need_more_data;
   }

   recLenDec = backuppdata;

   #if ((!SHARKSSL_ENABLE_CLONE_CERTINFO) && SHARKSSL_ENABLE_SECURE_RENEGOTIATION)
   if (o->flags & symbolnodebug)
   {
      o->flags &= ~symbolnodebug;
      #if (SHARKSSL_ENABLE_AES_GCM || (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305))
      o->flags |= ftracehandler;
      #endif
   }
   else
   #endif
   if (o->rCipherSuite)
   {
      if ((backuppdata < o->rCipherSuite->digestLen)
          #if SHARKSSL_ENABLE_AES_GCM
          || ((o->rCipherSuite->flags & framekernel) && (backuppdata < (8  + o->rCipherSuite->digestLen )))
          #endif
          #if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
          || ((o->rCipherSuite->flags & suspendenter) && (backuppdata < o->rCipherSuite->digestLen))
          #endif
         )
      {
         _sharkssl_alert_bad_record_mac:
         return savedconfig(o, SHARKSSL_ALERT_BAD_RECORD_MAC);
      }

      
      if (o->flags & timerwritel)
      {
         if (o->rCipherSuite->cipherFunc(o, bcm1x80bcm1x55 | populatebasepages, registeredevent, backuppdata))
         {
            goto _sharkssl_cipher_func_error;
         }
         o->flags &= ~timerwritel;
      }
      else
      {
         if (o->rCipherSuite->cipherFunc(o, populatebasepages, registeredevent, backuppdata))
         {
            _sharkssl_cipher_func_error:
            if (0
                #if SHARKSSL_ENABLE_AES_GCM
                || (o->rCipherSuite->flags & framekernel)
                #endif
                #if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
                || (o->rCipherSuite->flags & suspendenter)
                #endif
               )
            {
               
               goto _sharkssl_alert_bad_record_mac;
            }
            resvdexits(o);
            return SharkSslCon_Error;
         }
      }

      #if SHARKSSL_ENABLE_AES_GCM
      if (o->rCipherSuite->flags & framekernel)
      {
         recLenDec -= (8  + o->rCipherSuite->digestLen );
         registeredevent += 8 ;
      }
      #endif
      #if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
      #if SHARKSSL_ENABLE_AES_GCM
      if (o->rCipherSuite->flags & suspendenter)
      #endif
      {
         recLenDec -= o->rCipherSuite->digestLen; 
      }
      #endif

      clusterpowerdown(((U8*)func3fixup(&o->inBuf)) - 1);

      o->padLen = 0; 
   }

   switch (recType)
   {
      case controllegacy:
         #if SHARKSSL_ENABLE_CLONE_CERTINFO
         ret = configdword(o, registeredevent, recLenDec, tvp5146pdata);
         _sharkssl_check_if_another_record:
         if (ret == SharkSslCon_Handshake)
         {
            atagsprocfs -= backuppdata;
            o->inBuf.dataLen = atagsprocfs;
            if (atagsprocfs)
            {
               registeredevent += backuppdata;

         #else
         dummyhwclk = recLenDec;
         ret = configdword(o, registeredevent, &dummyhwclk, tvp5146pdata);
         baAssert((backuppdata >= recLenDec) && (recLenDec >= dummyhwclk));
         _sharkssl_check_if_another_record:
         o->flags &= ~accountsoftirq;
         if ((ret == SharkSslCon_Handshake) || (ret == SharkSslCon_Certificate))
         {
            if (ret == SharkSslCon_Certificate)
            {
               o->flags |= accountsoftirq;
            }
            atagsprocfs -= backuppdata;
            atagsprocfs += dummyhwclk;  
            o->inBuf.dataLen = atagsprocfs;
            if (atagsprocfs)
            {
               registeredevent += backuppdata;

               if (dummyhwclk)
               {
                  registeredevent -= dummyhwclk;
                  #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
                  if (backuppdata > recLenDec)
                  {
                     baAssert(o->rCipherSuite);
                     baAssert(o->flags & symbolnodebug);
                     #if SHARKSSL_ENABLE_AES_GCM
                     if (o->rCipherSuite->flags & framekernel)
                     {
                        memmove(registeredevent - 8 , registeredevent - (backuppdata - recLenDec), dummyhwclk);
                     }
                     else
                     #endif
                     {
                        memmove(registeredevent, registeredevent - (backuppdata - recLenDec), dummyhwclk);
                     }
                  }
                  #endif
               }
         #endif

               #if (SHARKSSL_ENABLE_AES_GCM || (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305))
               #if ((!SHARKSSL_ENABLE_CLONE_CERTINFO) && SHARKSSL_ENABLE_SECURE_RENEGOTIATION)
               if (o->flags & ftracehandler)
               {
                  o->flags &= ~ftracehandler;
               }
               else
               #endif
               if ((o->flags & devicedriver) && (o->rCipherSuite->flags & framekernel))
               {
                  registeredevent -= 8;  
               }
               #endif
               o->inBuf.data = registeredevent;
               if ((ret == SharkSslCon_Handshake) && (o->state != loongson3notifier))
               {
                  goto _sharkssl_process_another_record;
               }
            }
            else
            {  
               registerfixed(&o->inBuf);
               #if ((SHARKSSL_ENABLE_AES_GCM || (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)) && \
                    ((!SHARKSSL_ENABLE_CLONE_CERTINFO) && SHARKSSL_ENABLE_SECURE_RENEGOTIATION))
               o->flags &= ~ftracehandler;
               #endif
            }
         }
         break;

      case rangealigned:
         ret = kexecprotect(o, registeredevent, recLenDec);
         #if (!SHARKSSL_ENABLE_CLONE_CERTINFO)
         dummyhwclk = recLenDec = 0;
         #endif
         goto _sharkssl_check_if_another_record;
         

      case polledbutton:
         if (!SharkSslCon_isHandshakeComplete(o))
         {
            goto _sharkssl_alert_unexpected_message;
         }

         if (recLenDec == 0)
         {
            
            if (o->flags & stealenabled)
            {
               goto _sharkssl_alert_unexpected_message;
            }
            o->flags |= stealenabled;
         }
         else
         {
            o->flags &= ~stealenabled;
         }

         o->flags |= clockgettime32;
         atagsprocfs -= backuppdata;
         o->inBuf.dataLen = atagsprocfs;
         o->inBuf.data = registeredevent;
         o->inBuf.temp = recLenDec;
         ret = SharkSslCon_Decrypted;
         break;

      default: 
      case firstentry:
         if ((recLenDec < 2) ||
             ((*registeredevent != SHARKSSL_ALERT_LEVEL_WARNING) && (*registeredevent != SHARKSSL_ALERT_LEVEL_FATAL)))
         {
            goto _sharkssl_alert_illegal_parameter;
         }

         if (*registeredevent != SHARKSSL_ALERT_LEVEL_WARNING)
         {
            fpemureturn(o);
         }

         o->flags |= switcherregister;
         o->alertLevel = *registeredevent++;
         o->alertDescr = *registeredevent++;
         atagsprocfs -= backuppdata;
         o->inBuf.dataLen = atagsprocfs;
         o->inBuf.data = registeredevent;
         ret = SharkSslCon_AlertRecv;
         break;
   }

   return ret;
}


SharkSslCon_RetVal kexecprotect(SharkSslCon *o,
                                                       U8  *registeredevent,
                                                       U16  atagsprocfs)
{
   SharkSslHSParam *sharkSslHSParam = hsParam(o);

   if (o->state != switcherdevice)
   {
      return savedconfig(o, SHARKSSL_ALERT_UNEXPECTED_MESSAGE);
   }

   if ((atagsprocfs != 1) || (*registeredevent != 1))
   {
      return savedconfig(o, SHARKSSL_ALERT_ILLEGAL_PARAMETER);
   }

   #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
   if (o->rCipherSuite)  
   {
      baAssert(o->flags & platformdevice);
      o->rCipherSuite->cipherFunc(o, chargerworker | populatebasepages, (U8*)0, 0);
   }
   #endif
   o->rCipherSuite = sharkSslHSParam->cipherSuite;

   o->flags |= cachematch;
   o->flags |= timerwritel;

   #if SHARKSSL_ENABLE_AES_GCM
   if (o->rCipherSuite->flags & framekernel)
   {
      baAssert(SHARKSSL_MAX_KEY_LEN);
      memcpy(o->rKey,
             sharkSslHSParam->sharedSecret + (SharkSsl_isClient(o->sharkSsl) ? o->rCipherSuite->keyLen : 0),
             o->rCipherSuite->keyLen);
      memcpy(o->rIV,
             sharkSslHSParam->sharedSecret + (2 * o->rCipherSuite->keyLen) + (SharkSsl_isClient(o->sharkSsl) ? 4 : 0),
             4);
      memset(&(o->rIV[4]), 0, 8);  
   }
   else
   #endif
   #if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
   #if SHARKSSL_ENABLE_AES_GCM
   if (o->rCipherSuite->flags & suspendenter)
   #endif
   {
      baAssert(SHARKSSL_MAX_KEY_LEN);
      memcpy(o->rKey,
             sharkSslHSParam->sharedSecret + (SharkSsl_isClient(o->sharkSsl) ? o->rCipherSuite->keyLen : 0),
             o->rCipherSuite->keyLen);
      memcpy(o->rIV,
               sharkSslHSParam->sharedSecret + (2 * o->rCipherSuite->keyLen) + (SharkSsl_isClient(o->sharkSsl) ? 12 : 0), 
               12);
   }
   #if SHARKSSL_ENABLE_AES_GCM
   else
   {
      return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
   }
   #endif
   #endif

   
   disablelevel((U8*)func3fixup(&o->inBuf) - 1);

   o->inBuf.temp = 0; 
   return SharkSslCon_Handshake;
}


int sanitisependbaser(SharkSslCon *o,
                              SharkSslCon_SendersRole fixupcy82c693,
                              U8 *pciercxcfg448)
{
   U8 *tp, i;
   SharkSslHSParam *sharkSslHSParam = hsParam(o);

   baAssert(serial2platform(&o->outBuf));
   #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
   if (o->wCipherSuite)
   {
      baAssert(o->flags & platformdevice);
      
      tp = templateentry(o, rangealigned, o->outBuf.data, 1);
      *tp++ = 1;
      if (writebackscache(o, ptraceregsets) < 0)
      {
         return -1;
      }
      if (pciercxcfg448 == (void*)0)
      {
         pciercxcfg448 = func3fixup(&o->inBuf);
         o->inBuf.temp = 0;
      }
      memcpy(pciercxcfg448, o->outBuf.data, o->outBuf.dataLen);
      registerfixed(&o->outBuf);
      o->inBuf.temp += o->outBuf.dataLen;
      pciercxcfg448 += o->outBuf.dataLen;

      o->wCipherSuite->cipherFunc(o, chargerworker | ptraceregsets, (U8*)0, 0);
   }
   #endif
   o->wCipherSuite = sharkSslHSParam->cipherSuite;

   
   #if SHARKSSL_ENABLE_AES_GCM
   if (o->wCipherSuite->flags & framekernel)
   {
      baAssert(o->minor >= 3);
      baAssert(SHARKSSL_MAX_KEY_LEN);
      memcpy(o->wKey,
             sharkSslHSParam->sharedSecret + (SharkSsl_isServer(o->sharkSsl) ? o->wCipherSuite->keyLen : 0),
             o->wCipherSuite->keyLen);
      memcpy(o->wIV,
             sharkSslHSParam->sharedSecret + (2 * o->wCipherSuite->keyLen) + (SharkSsl_isServer(o->sharkSsl) ? 4 : 0),
             4);
      disablelevel(&o->wIV[11]);
   }
   else
   #endif
   #if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
   #if SHARKSSL_ENABLE_AES_GCM
   if (o->wCipherSuite->flags & suspendenter)
   #endif
   {
      baAssert(SHARKSSL_MAX_KEY_LEN);
      memcpy(o->wKey,
             sharkSslHSParam->sharedSecret + (SharkSsl_isServer(o->sharkSsl) ? o->wCipherSuite->keyLen : 0),
             o->wCipherSuite->keyLen);
      memcpy(o->wIV,
               sharkSslHSParam->sharedSecret + (2 * o->wCipherSuite->keyLen) + (SharkSsl_isServer(o->sharkSsl) ? 12 : 0),
               12);
   }
   #if SHARKSSL_ENABLE_AES_GCM
   else
   {
      return savedconfig(o, SHARKSSL_ALERT_INTERNAL_ERROR);
   }
   #endif
   #endif

   tp = o->outBuf.data;
   disablelevel(tp - 1);
   i = sapicvector;

   tp = templateentry(o, controllegacy, tp, i + 4);
   *tp++ = switcherdevice;
   *tp++ = 0x00;
   *tp++ = 0x00;
   *tp++ = i;

   if (printsilicon(o, fixupcy82c693, tp) < 0)
   {
      return -1;
   }

   #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
   memcpy(SharkSsl_isServer(o->sharkSsl) ? o->serverVerifyData : o->clientVerifyData, tp, i);
   #endif

   
   if (((fixupcy82c693 == rodatastart) && (o->flags & startqueue))
       ||
       ((fixupcy82c693 == tvp5146routes) && (!(o->flags & startqueue))))
   {
      ioremapresource(sharkSslHSParam, tp - 4, i + 4);
   }

   if (writebackscache(o, bcm1x80bcm1x55 | ptraceregsets) < 0)
   {
      return -1;
   }

   if (pciercxcfg448 == (void*)0)  
   {
      baAssert(!(o->flags & createmappings));
      o->flags |= createmappings;
      pciercxcfg448 = o->outBuf.data;
   }

   #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
   if (o->flags & platformdevice)
   {
      
      memcpy(pciercxcfg448, o->outBuf.data, o->outBuf.dataLen);
      o->inBuf.temp += o->outBuf.dataLen;
   }
   else
   #endif
   {
      
      memmove(pciercxcfg448 + clkctrlmanaged + 1, o->outBuf.data, o->outBuf.dataLen);

      
      tp = templateentry(o, rangealigned, pciercxcfg448, 1);
      *tp++ = 1;

      
      baAssert((clkctrlmanaged + 1) == (U16)(tp - pciercxcfg448));
      o->inBuf.temp += (clkctrlmanaged + 1 + o->outBuf.dataLen);
   }
   return 0;
}


SharkSslCon_RetVal savedconfig(SharkSslCon *o, U8 local1irqdispatch)
{
   fpemureturn(o);
   return securememblock(o, SHARKSSL_ALERT_LEVEL_FATAL, local1irqdispatch);
}


SharkSslCon_RetVal securememblock(SharkSslCon *o,
                                                 U8 disableerrgen,
                                                 U8 local1irqdispatch)
   {
   U8 *tp;

   baAssert(o);

   baAssert((disableerrgen == SHARKSSL_ALERT_LEVEL_WARNING) || (disableerrgen == SHARKSSL_ALERT_LEVEL_FATAL));
   baAssert(
            (local1irqdispatch <= SHARKSSL_ALERT_UNRECOGNIZED_NAME));

   
   if (microresources(&o->outBuf))
   {
      resvdexits(o);
      return SharkSslCon_Error;
   }

   
   o->inBuf.dataLen = o->inBuf.temp = 0;
   registerfixed(&o->inBuf);

   registerfixed(&o->outBuf);
   tp = templateentry(o, firstentry, o->outBuf.data, 2);

   o->flags |= switcherregister;
   *tp++ = o->alertLevel = disableerrgen;
   *tp++ = o->alertDescr = local1irqdispatch;
   o->outBuf.dataLen = (U16)(tp - o->outBuf.data);
   if (o->wCipherSuite)
   {
      if (writebackscache(o, ptraceregsets) < 0)
      {
         resvdexits(o);
         return SharkSslCon_Error;
      }
   }
   return SharkSslCon_AlertSend;
}


U8 *templateentry(SharkSslCon *o,
                               U8 defaultattrs,
                               U8 *ptr,
                               U16 backuppdata)
{
   *ptr++ = defaultattrs;
   *ptr++ = o->major;
   *ptr++ = o->minor;
   *ptr++ = (U8)(backuppdata >> 8);
   *ptr++ = (U8)(backuppdata & 0xFF);

   return ptr;
}


void fpemureturn(SharkSslCon* o)
{
   baAssert(o);
   baAssert(!(o->flags & firstcomponent));

   o->flags |= firstcomponent;
}


U16 disableclean(SharkSslCipherSuite *c)
{
   U16 hwcapfixup;

   hwcapfixup = c->keyLen;
   #if SHARKSSL_ENABLE_AES_GCM
   if (c->flags & framekernel)
   {
      hwcapfixup += 4;
   }
   else
   #endif
   #if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
   if (c->flags & suspendenter)
   {
      hwcapfixup += 12;  
   }
   #endif
   baAssert(hwcapfixup < (U16)0x8000);
   return ((U16)(hwcapfixup << 1));
}


int allocalloc(SharkSslCon* o, U8 *pciercxcfg448, U16 len,
                                U8* s, U16 sLen, U8 r1[32], U8 r2[32])
{
   #if SHARKSSL_CRYPTO_USE_HEAP
   U8* buf;
   #else 
   U8  buf[claimresource(SHARKSSL_MAX_DIGEST_LEN + 13 + 32 + 32)];
   #endif
   U8* p;
   int offsetarray = -1;
   U16 ftraceupdate;
   U8  configwrite, n;

   baAssert(o && pciercxcfg448 && len && sLen && s && r1 && r2);
   baAssert(pcmciaplatform(pciercxcfg448));
   baAssert((len & 0x03) == 0);

   #if SHARKSSL_CRYPTO_USE_HEAP
   buf = (U8*)baMalloc(claimresource(SHARKSSL_MAX_DIGEST_LEN + 13 + 32 + 32));
   baAssert(buf);
   if (!buf)
   {
      return offsetarray;
   }
   #endif
   configwrite = hsParam(o)->cipherSuite->hashID;
   ftraceupdate = sharkssl_getHashLen(configwrite);
   n = (U8)((len + (ftraceupdate - 1)) / ftraceupdate);
   baAssert(n > 0);

   p = &buf[ftraceupdate];
   memcpy(p, (pciercxcfg448 == hsParam(o)->masterSecret) ? "\155\141\163\164\145\162\040\163\145\143\162\145\164" : "\153\145\171\040\145\170\160\141\156\163\151\157\156", 13);
   memcpy(p + 13, r1, 32);
   memcpy(p + 13 + 32, r2, 32);

   if (sharkssl_HMAC(configwrite, p, 13 + 32 + 32, s, sLen, buf) < 0)
   {
      goto _SharkSslCon_calcCryptoParam_exit;
   }
             
   for (; ; pciercxcfg448 += ftraceupdate)
   {
      if (sharkssl_HMAC(configwrite, buf, ftraceupdate + 13 + 32 + 32, s, sLen, pciercxcfg448) < 0)
      {
         goto _SharkSslCon_calcCryptoParam_exit;
      }

      if (--n == 0)
      {
         break;
      }

      if (sharkssl_HMAC(configwrite, buf, ftraceupdate, s, sLen, buf) < 0)
      {
         goto _SharkSslCon_calcCryptoParam_exit;
      }
   }
   offsetarray = 0;
   _SharkSslCon_calcCryptoParam_exit:
   #if SHARKSSL_CRYPTO_USE_HEAP
   baFree(buf);
   #endif
   return offsetarray;
}


int printsilicon(SharkSslCon *o, SharkSslCon_SendersRole fixupcy82c693, U8 *chargerplatform)
{
   U8  *buf;
   int offsetarray = -1;
   U16 ftraceupdate;
   U8  configwrite;

   configwrite = hsParam(o)->cipherSuite->hashID;
   ftraceupdate = sharkssl_getHashLen(configwrite);
   buf = (U8*)baMalloc((ftraceupdate << 1) + 16 );
   if (!buf)
   {
      return offsetarray;
   }
   memcpy(&buf[ftraceupdate], (fixupcy82c693 == tvp5146routes) ? "\143\154\151\145\156\164\040\146\151\156\151\163\150\145\144" : "\163\145\162\166\145\162\040\146\151\156\151\163\150\145\144", 15);
   wakeupvector(hsParam(o), &buf[ftraceupdate + 15], configwrite);
   if (sharkssl_HMAC(configwrite, &buf[ftraceupdate], 15 + ftraceupdate, hsParam(o)->masterSecret, SHARKSSL_MASTER_SECRET_LEN, buf) < 0)
   {
      goto _SharkSslCon_calcFinishedHash_exit;
   }
   if (sharkssl_HMAC(configwrite, buf, (U16)(ftraceupdate << 1) + 15 , hsParam(o)->masterSecret, SHARKSSL_MASTER_SECRET_LEN, buf) < 0)
   {
      goto _SharkSslCon_calcFinishedHash_exit;
   }
   memcpy(chargerplatform, buf, 12);
   offsetarray = 0;
   _SharkSslCon_calcFinishedHash_exit:
   baFree(buf);
   return offsetarray;
}


int writebackscache(SharkSslCon *o, U8 op)
{
   U8 *p;
   U16 fastforwardsingle;
   #if SHARKSSL_ENABLE_AES_GCM
   U8 guestconfig4;
   #endif

   baAssert(serial2platform(&o->outBuf));
   baAssert(o->wCipherSuite);
   p = o->outBuf.data;
   #if SHARKSSL_ENABLE_AES_GCM
   guestconfig4 = *p;
   #endif
   fastforwardsingle = (U16)(((U16)(*(p + 3)) << 8) + *(p + 4));
   #if (SHARKSSL_ENABLE_AES_GCM || (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305))
   #if SHARKSSL_ENABLE_AES_GCM
   if (o->wCipherSuite->flags & (framekernel | suspendenter))
   #endif
   {
      
      baAssert(statsstruct == 8);
      #if SHARKSSL_ENABLE_AES_GCM
      if (o->wCipherSuite->flags & framekernel)
      {
         memcpy(p - statsstruct, &o->wIV[4], statsstruct);
      }
      #endif
   }
   #endif

   p += clkctrlmanaged;
   if (o->wCipherSuite->cipherFunc(o, op, p, fastforwardsingle))
   {
      return -1;
   }

   #if (SHARKSSL_USE_CHACHA20 && SHARKSSL_USE_POLY1305)
   if (o->wCipherSuite->flags & suspendenter)
   {
      baAssert(16 == o->wCipherSuite->digestLen);
      clusterpowerdown(p - 1 - clkctrlmanaged);
      fastforwardsingle += 16;  
      *(p + 3 - clkctrlmanaged) = (U8)(fastforwardsingle >> 8);
      *(p + 4 - clkctrlmanaged) = (U8)(fastforwardsingle & 0xFF);
   }
   #if SHARKSSL_ENABLE_AES_GCM
   else
   #endif
   #endif
   #if SHARKSSL_ENABLE_AES_GCM
   if (o->wCipherSuite->flags & framekernel)
   {
      memcpy(p - statsstruct, &o->wIV[4], statsstruct);
      clusterpowerdown(&o->wIV[11]);
      fastforwardsingle += o->wCipherSuite->digestLen + statsstruct;  
      o->outBuf.data = (p - clkctrlmanaged - statsstruct);
      templateentry(o, guestconfig4, o->outBuf.data, fastforwardsingle);
   }
   #endif

   o->outBuf.dataLen = clkctrlmanaged + fastforwardsingle;
   baAssert(o->outBuf.size >= o->outBuf.dataLen);
   return 0;
}


SHARKSSL_API U16 SharkSslCon_getDecData(SharkSslCon *o, U8 **ptregdefines)
{
   U16 guestdebug;
   baAssert(o);
   baAssert(ptregdefines);
   baAssert(!(o->flags & firstcomponent));

   *ptregdefines = o->inBuf.data;
   guestdebug = o->inBuf.temp;
   o->inBuf.data += guestdebug;
   o->inBuf.temp = 0;

   if (o->inBuf.dataLen) 
   {
      o->inBuf.data += o->padLen + o->rCipherSuite->digestLen;
      o->padLen = 0;
   }
   else
   {
      o->flags &= ~clockgettime32;
      registerfixed(&o->inBuf);
   }

   return guestdebug;
}


U16 SharkSslCon_copyDecData(SharkSslCon *o, U8 *buf, U16 masterclock)
{
   baAssert(o);
   baAssert(buf);
   baAssert(!(o->flags & firstcomponent));

   if (o->inBuf.temp < masterclock)
   {
      masterclock = o->inBuf.temp;
   }
   memcpy(buf, o->inBuf.data, masterclock);
   o->inBuf.data += masterclock;
   o->inBuf.temp -= masterclock;

   if (0 == o->inBuf.temp)
   {
      if (o->inBuf.dataLen) 
      {
         o->inBuf.data += o->padLen + o->rCipherSuite->digestLen;
         o->padLen = 0;
      }
      else
      {
         o->flags &= ~clockgettime32;
         registerfixed(&o->inBuf);
      }
   }

   return masterclock;
}


U8 *SharkSslCon_getBuf(SharkSslCon *o)
{
   baAssert(o);
   baAssert(o->inBuf.data);
   return (o->inBuf.data + o->inBuf.dataLen);
}


U16 SharkSslCon_getBufLen(SharkSslCon *o)
{
   baAssert(o);
   return (o->inBuf.size - o->inBuf.dataLen);
}


U8 SharkSslCon_decryptMore(SharkSslCon *o)
{
   baAssert(o);
   return ((o->flags & clockgettime32) ? 1 : 0);
}


U8 SharkSslCon_encryptMore(SharkSslCon *o)
{
   baAssert(o);
   return ((o->flags & audiosuspend) ? 1 : 0);
}


U8 *SharkSslCon_getHandshakeData(SharkSslCon *o)
{
   baAssert(o);
   if (o->flags & createmappings)
   {
      baAssert(o->outBuf.data);
      o->flags &= ~createmappings;
      return (o->outBuf.data);
   }

   baAssert(o->inBuf.data);
   return (o->inBuf.data);
}


U16 SharkSslCon_getHandshakeDataLen(SharkSslCon *o)
{
   baAssert(o);
   return (o->inBuf.temp);
}


U8 SharkSslCon_isHandshakeComplete(SharkSslCon *o)
{
   baAssert(o);
   if ((o->state == loongson3notifier)
      #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
       && (!(o->flags & skciphersetkey))
      #endif
      )
   {
      return 1;
   }

   return 0;
}


U8 SharkSslCon_getAlertLevel(SharkSslCon *o)
{
   baAssert(o);
   return (o->alertLevel);
}


U8 SharkSslCon_getAlertDescription(SharkSslCon *o)
{
   baAssert(o);
   return (o->alertDescr);
}


SharkSslCon_RetVal SharkSslCon_encrypt(SharkSslCon *o, U8 *buf, U16 masterclock)
{
   U8 *tp, iotimingdebugfs;
   U16 brightnesslimit;
   SharkSslBuf *oBuf;

   baAssert(o);
   if (o->flags & firstcomponent)
   {
      resvdexits(o);
      return SharkSslCon_Error;
   }

   #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
   if (o->flags & (registerbuses | skciphersetkey))
   {
      resvdexits(o);
      return SharkSslCon_Error;
   }
   #endif

   if (!SharkSslCon_isHandshakeComplete(o))
   {
      return SharkSslCon_HandshakeNotComplete;
   }

   baAssert(!microresources(&o->outBuf));

   oBuf = &o->outBuf;
   registerfixed(oBuf);  

   brightnesslimit = oBuf->temp;
   masterclock -= brightnesslimit;
   if ((!buf) && (brightnesslimit))
   {
      resvdexits(o);
      return SharkSslCon_Error;
   }

   iotimingdebugfs = r3000tlbchange(o);
   baAssert(oBuf->size > iotimingdebugfs);
   if (masterclock <= (oBuf->size - iotimingdebugfs))
   {
      o->flags &= ~audiosuspend;
      oBuf->temp = 0;
   }
   else
   {
      if (!buf)
      {
         return SharkSslCon_AllocationError;  
      }
      o->flags |= audiosuspend;
      masterclock = (oBuf->size - iotimingdebugfs);
      oBuf->temp += masterclock;
   }
   tp = templateentry(o, polledbutton, oBuf->data, masterclock);
   if (buf)
   {
      memcpy(tp, buf + brightnesslimit, (oBuf->dataLen = masterclock));
   }
   if (writebackscache(o, ptraceregsets) < 0)
   {
      resvdexits(o);
      return SharkSslCon_Error;
   }
   return SharkSslCon_Encrypted;
}


U8 *SharkSslCon_getEncBufPtr(SharkSslCon *o)
{
   baAssert(o);
   if (o->outBuf.data)
   {
      return (func3fixup(&(o->outBuf)) + clkctrlmanaged);
   }
   return (U8*)0;
}


U16 SharkSslCon_getEncBufSize(SharkSslCon *o)
{
   baAssert(o);
   if (o->outBuf.data)
   {
      return (o->outBuf.size - r3000tlbchange(o));
   }
   return 0;
}


U8 *SharkSslCon_getEncData(SharkSslCon *o)
{
   baAssert(o);
   baAssert(o->outBuf.data);
   return (o->outBuf.data);
}


U16 SharkSslCon_getEncDataLen(SharkSslCon *o)
{
   baAssert(o);
   return (o->outBuf.dataLen);
}


#if SHARKSSL_ENABLE_INFO_API
SHARKSSL_API U16 SharkSslCon_getCiphersuite(SharkSslCon *o)
{
   baAssert(o);
   if (SharkSslCon_isHandshakeComplete(o) && (o->rCipherSuite))
   {
      baAssert(o->rCipherSuite == o->wCipherSuite);
      return o->rCipherSuite->id;
   }

   return 0;
}
#endif


#if (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA)
SHARKSSL_API SharkSslCertInfo *SharkSslCon_getCertInfo(SharkSslCon *o)
{
   if (o)
   {
      #if SHARKSSL_ENABLE_CLONE_CERTINFO
      #if SHARKSSL_ENABLE_SESSION_CACHE
      if ((o->session) && (o->session->clonedCertInfo))
      {
         return &(o->session->clonedCertInfo->ci);
      }
      #endif  
      if (o->clonedCertInfo)
      {
         return &(o->clonedCertInfo->ci);
      }
      #else
      if ((o->flags & accountsoftirq) && (!(o->flags & serialreset)))
      {
         return &(hsParam(o)->certParam.certInfo);
      }
      #endif  
   }

   return (SharkSslCertInfo*)0;
}


#if SHARKSSL_ENABLE_CLONE_CERTINFO
U8 realnummemory(SharkSslCon *o, SharkSslClonedCertInfo **outCertInfoPtr)
{
   baAssert(outCertInfoPtr);
   if (!(o->flags & serialreset))
   {
      U32 stringlookup;
      SharkSslCertInfo *ci;
      SharkSslClonedCertInfo *cci;

      ci = &(hsParam(o)->certParam.certInfo);
      baAssert(ci);

      
      stringlookup = 0;
      while (ci)
      {
         
         #if SHARKSSL_ENABLE_SESSION_CACHE
         if (stringlookup == 0)
         {
            stringlookup += sizeof(SharkSslClonedCertInfo);
         }
         else
         #endif
         {
            stringlookup += sizeof(SharkSslCertInfo);
         }
         stringlookup += SHARKSSL_ALIGNMENT;

         stringlookup += ci->snLen +
                    ci->timeFromLen +
                    ci->timeToLen +
                    ci->issuer.commonNameLen +
                    ci->issuer.countryNameLen +
                    ci->issuer.localityLen +
                    ci->issuer.organizationLen +
                    ci->issuer.provinceLen +
                    ci->issuer.unitLen +
                    ci->subject.commonNameLen +
                    ci->subject.countryNameLen +
                    ci->subject.localityLen +
                    ci->subject.organizationLen +
                    ci->subject.provinceLen +
                    ci->subject.unitLen +
                    ci->subjectAltNamesLen;

         ci = ci->parent;
      }

      
      cci = (SharkSslClonedCertInfo*)baMalloc(claimresource(stringlookup));
      if (cci != (void*)0)
      {
         U8  *p = (U8*)0;
         SharkSslCertInfo *di = &cci->ci;

         ci = &(hsParam(o)->certParam.certInfo);
         *outCertInfoPtr = cci;
         #if SHARKSSL_ENABLE_SESSION_CACHE
         cci->flags = SHARKSSL_CCINFO_CERT_CLONED;
         #endif

         
         for (;;)
         {
            
            if (p)
            {
               p = (U8*)((SharkSslCertInfo*)(di + 1));
            }
            else
            {
               p = (U8*)((SharkSslClonedCertInfo*)(cci + 1));
            }

            memcpy(di, ci, sizeof(SharkSslCertInfo));

            memcpy(p, ci->sn, ci->snLen);
            di->sn = p;
            p += ci->snLen;

            memcpy(p, ci->timeFrom, ci->timeFromLen);
            di->timeFrom = p;
            p += ci->timeFromLen;

            memcpy(p, ci->timeTo, ci->timeToLen);
            di->timeTo = p;
            p += ci->timeToLen;

            if (ci->subjectAltNamesPtr) 
            {
               baAssert(ci->subjectAltNamesLen > 0);
               memcpy(p, ci->subjectAltNamesPtr, ci->subjectAltNamesLen);
               di->subjectAltNamesPtr = p;
               di->subjectAltNamesLen = ci->subjectAltNamesLen;
               p += ci->subjectAltNamesLen;
            }

            if (ci->issuer.commonName)
            {
               memcpy(p, ci->issuer.commonName, ci->issuer.commonNameLen);
               di->issuer.commonName = p;
               p += ci->issuer.commonNameLen;
            }
            if (ci->issuer.countryName)
            {
               memcpy(p, ci->issuer.countryName, ci->issuer.countryNameLen);
               di->issuer.countryName = p;
               p += ci->issuer.countryNameLen;
            }
            if (ci->issuer.locality)
            {
               memcpy(p, ci->issuer.locality, ci->issuer.localityLen);
               di->issuer.locality = p;
               p += ci->issuer.localityLen;
            }
            if (ci->issuer.organization)
            {
               memcpy(p, ci->issuer.organization, ci->issuer.organizationLen);
               di->issuer.organization = p;
               p += ci->issuer.organizationLen;
            }
            if (ci->issuer.province)
            {
               memcpy(p, ci->issuer.province, ci->issuer.provinceLen);
               di->issuer.province = p;
               p += ci->issuer.provinceLen;
            }
            if (ci->issuer.unit)
            {
               memcpy(p, ci->issuer.unit, ci->issuer.unitLen);
               di->issuer.unit = p;
               p += ci->issuer.unitLen;
            }

            if (ci->subject.commonName)
            {
               memcpy(p, ci->subject.commonName, ci->subject.commonNameLen);
               di->subject.commonName = p;
               p += ci->subject.commonNameLen;
            }
            if (ci->subject.countryName)
            {
               memcpy(p, ci->subject.countryName, ci->subject.countryNameLen);
               di->subject.countryName = p;
               p += ci->subject.countryNameLen;
            }
            if (ci->subject.locality)
            {
               memcpy(p, ci->subject.locality, ci->subject.localityLen);
               di->subject.locality = p;
               p += ci->subject.localityLen;
            }
            if (ci->subject.organization)
            {
               memcpy(p, ci->subject.organization, ci->subject.organizationLen);
               di->subject.organization = p;
               p += ci->subject.organizationLen;
            }
            if (ci->subject.province)
            {
               memcpy(p, ci->subject.province, ci->subject.provinceLen);
               di->subject.province = p;
               p += ci->subject.provinceLen;
            }
            if (ci->subject.unit)
            {
               memcpy(p, ci->subject.unit, ci->subject.unitLen);
               di->subject.unit = p;
               p += ci->subject.unitLen;
            }

            
            p = (U8*)regulatorconsumer(p);

            ci = ci->parent;
            if (ci)
            {
               di->parent = (SharkSslCertInfo*)p;
               di = (SharkSslCertInfo*)p;
            }
            else
            {
               di->parent = (SharkSslCertInfo*)0;
               break;
            }
         }

         return 1;
      }
   }

   return 0;
}
#endif


#if (SHARKSSL_SSL_CLIENT_CODE && SHARKSSL_ENABLE_CLIENT_AUTH)
U8 SharkSslCon_certificateRequested(SharkSslCon *o)
{
   baAssert(o);
   return (o->flags & nresetconsumers) ? 1 : 0;
}
#endif


#if SHARKSSL_ENABLE_CA_LIST
SHARKSSL_API U8 SharkSslCon_trustedCA(SharkSslCon *o)
{
   baAssert(o);
   return (o->flags & switcheractivation) ? 1 : 0;
}


U8 SharkSslCon_isCAListEmpty(SharkSslCon *o)
{
   baAssert(o);
   baAssert(o->sharkSsl);
   baAssert(NULL == (void*)0);
   return ((void*)0 == o->sharkSsl->caList);
}
#endif


#if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_RSA)
U8  SharkSslCon_favorRSA(SharkSslCon *o, U8 sha256export)
{
   if (o &&
       ((!(SharkSslCon_isHandshakeComplete(o)))
        #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
        || (o->flags & registerbuses)
        #endif
       )
       #if SHARKSSL_SSL_CLIENT_CODE
       && (SharkSsl_isServer(o->sharkSsl))
       #endif
      )
   {
      if (sha256export)
      {
         o->flags |= uprobeabort;
      }
      else
      {
         o->flags &= ~uprobeabort;
      }
      return 1;  
   }

   return 0;
}
#endif
#endif  


#if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_CLIENT_AUTH && (SHARKSSL_ENABLE_RSA || SHARKSSL_ENABLE_ECDSA))
U8 SharkSslCon_requestClientCert(SharkSslCon *o, const void *displaysetup)
{
   if (o &&
       ((!(SharkSslCon_isHandshakeComplete(o)))
        #if SHARKSSL_ENABLE_SECURE_RENEGOTIATION
        || (o->flags & registerbuses)
        #endif
       )
       #if SHARKSSL_SSL_CLIENT_CODE
       && (SharkSsl_isServer(o->sharkSsl))
       #endif
      )
   {
      o->flags |= unregistershash;
      #if SHARKSSL_ENABLE_CA_LIST
      o->caListCertReq = (SharkSslCAList)displaysetup;
      #else
      (void)displaysetup;
      #endif
      return 1;  
   }

   return 0;
}
#endif


#if (SHARKSSL_SSL_SERVER_CODE && SHARKSSL_ENABLE_SECURE_RENEGOTIATION)
U8 SharkSslCon_renegotiate(SharkSslCon *o)
{
   if (o && (SharkSslCon_isHandshakeComplete(o)
       && (!(o->flags & (registerbuses | skciphersetkey))))
       #if SHARKSSL_SSL_CLIENT_CODE
       && (SharkSsl_isServer(o->sharkSsl))
       #endif
      )
   {
      U8 *tp;
      #if SHARKSSL_ENABLE_ALPN_EXTENSION
      
      o->rALPN = NULL;
      #endif
      
      registerfixed(&o->outBuf);
      tp = templateentry(o, controllegacy, o->outBuf.data, 4);
      *tp++ = switchessetup;
      *tp++ = 0;
      *tp++ = 0;
      *tp++ = 0;
      if (writebackscache(o, ptraceregsets) >= 0)
      {
         o->inBuf.temp = o->outBuf.dataLen;
         o->flags |= registerbuses;
         o->flags |= createmappings;
         #if SHARKSSL_ENABLE_CLONE_CERTINFO
         singleftosi(o);
         o->clonedCertInfo = (SharkSslClonedCertInfo*)0;
         #endif
         return 1;  
      }
   }

   return 0;
}
#endif


#if (SHARKSSL_SSL_CLIENT_CODE && SHARKSSL_ENABLE_SNI)
U8 SharkSslCon_setSNI(SharkSslCon *o, const char *gpio1config, U16 traceleave)
{
   baAssert(o);
   baAssert(gpio1config || !traceleave);

   #if SHARKSSL_SSL_SERVER_CODE
   if (SharkSsl_isClient(o->sharkSsl))
   #endif
   {
      if ((o->state == 0) && (traceleave <= 64))
      {
         
         o->padLen = (U8)traceleave;
         o->rCtx = (void*)gpio1config;
         return 1;  
      }
   }

   return 0;
}
#endif


#if SHARKSSL_ENABLE_SESSION_CACHE
U8 SharkSslSession_release(SharkSslSession *o, SharkSsl *s)
{
   baAssert(s);
   if (o)
   {
      filtermatch(&s->sessionCache);
      baAssert(o->nUse);
      if (o->nUse)  
      {
         o->nUse--;
         #if SHARKSSL_SSL_CLIENT_CODE
         if ((SharkSsl_isClient(s)) && (0 == o->nUse))
         {
            #if SHARKSSL_ENABLE_CA_LIST
            o->flags &= ~ecoffaouthdr;
            #endif
            #if SHARKSSL_ENABLE_CLONE_CERTINFO
            if (o->clonedCertInfo)
            {
               o->clonedCertInfo->flags &= ~SHARKSSL_CCINFO_CERT_CACHED;
               if (0 == o->clonedCertInfo->flags)
               {
                  baFree((void*)o->clonedCertInfo);
               }
               o->clonedCertInfo = (SharkSslClonedCertInfo*)0;
            }
            #endif  
         }
         #endif  
      }
      helperglobal(&s->sessionCache);
      return 1;  
   }

   return 0;
}


#if SHARKSSL_SSL_SERVER_CODE

U8 SharkSslCon_releaseSession(SharkSslCon *o)
{
   baAssert(o);
   if ((SharkSsl_isServer(o->sharkSsl)) &&  (SharkSslCon_isHandshakeComplete(o)) &&
       (o->session))
   {
      SharkSslSession *s = o->session;
      o->session = NULL;
      return SharkSslSession_release(s, o->sharkSsl);
   }
   return 0;
}
#endif


#if SHARKSSL_SSL_CLIENT_CODE
SharkSslSession *SharkSslCon_acquireSession(SharkSslCon *o)
{
   baAssert(o);
   if ((SharkSsl_isClient(o->sharkSsl)) && (SharkSslCon_isHandshakeComplete(o)) &&
       (o->sharkSsl->sessionCache.cache) && (o->session))
   {
      
      return latchgpiochip(&(o->sharkSsl->sessionCache), o,
                                              o->session->id, SHARKSSL_MAX_SESSION_ID_LEN);
   }

   return 0;
}


U8 SharkSslCon_resumeSession(SharkSslCon *o, SharkSslSession *s)
{
   baAssert(o);

   
   if ((SharkSsl_isClient(o->sharkSsl)) && (o->session == 0) && (s))
   {
      U32 uart2hwmod = o->sharkSsl->sessionCache.cacheSize;

      if (uart2hwmod)
      {
         SharkSslSession *sv = o->sharkSsl->sessionCache.cache;

         do
         {
            if (s == sv)
            {
               baAssert(s->cipherSuite);
               o->session = s;
               return 1;  
            }

            uart2hwmod--;
            sv++;
         } while (uart2hwmod > 0);

         baAssert(0);  
      }
   }

   return 0;
}


U32 SharkSslSession_getLatestAccessTime(SharkSslSession *o)
{
   if (o)
   {
      return (o->latestAccess);
   }

   return 0;
}
#endif
#endif


#ifndef BA_LIB
#define BA_LIB
#endif



#include <string.h>


#if SHARKSSL_USE_ECC
#define fpscroffset(o, vect) \
        traceaddress(o, sizeof(vect)/sizeof(vect[0]), (void*)vect)


#if SHARKSSL_ECC_USE_BRAINPOOL
#define SharkSslECCurve_constructor1_(c, i, gpio1config) do {     \
   c->bits = i;                                            \
   fpscroffset(&c->prime, gpio1config##_prime);   \
   fpscroffset(&c->order, gpio1config##_order);   \
   fpscroffset(&c->G.x,   gpio1config##_Gx);      \
   fpscroffset(&c->G.y,   gpio1config##_Gy);      \
   fpscroffset(&c->a,     gpio1config##_a);       \
} while (0)

#else
#define SharkSslECCurve_constructor1_(c, i, gpio1config) do {     \
   c->bits = i;                                            \
   fpscroffset(&c->prime, gpio1config##_prime);   \
   fpscroffset(&c->order, gpio1config##_order);   \
   fpscroffset(&c->G.x,   gpio1config##_Gx);      \
   fpscroffset(&c->G.y,   gpio1config##_Gy);      \
} while (0)

#endif


#if SHARKSSL_ECC_VERIFY_POINT
#define SharkSslECCurve_constructor_(c, i, gpio1config) do {      \
   SharkSslECCurve_constructor1_(c, i, gpio1config);              \
   fpscroffset(&c->b, gpio1config##_b);           \
} while (0)

#else
#define SharkSslECCurve_constructor_(c, i, gpio1config)           \
   SharkSslECCurve_constructor1_(c, i, gpio1config);              

#endif


#if SHARKSSL_ECC_USE_NIST
static void availableasids(shtype_t *o, shtype_t *mod)
{
   
   #if SHARKSSL_ECC_USE_SECP521R1
   shtype_t checkcontext;
   #endif
   #if (SHARKSSL_ECC_USE_SECP256R1 || SHARKSSL_ECC_USE_SECP384R1)
   shtype_tDoubleWordS d;
   #endif

   #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
   baAssert(o->len == (mod->len * 2));
   switch (mod->len)
   {
      #if SHARKSSL_ECC_USE_SECP256R1
      case 8:  
         d  = (shtype_tDoubleWordS)o->beg[15] + o->beg[7] + o->beg[6] - o->beg[4] - o->beg[3] - o->beg[2] - o->beg[1];
         o->beg[15] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[14] + o->beg[6] + o->beg[5] - o->beg[3] - o->beg[2] - o->beg[1] - o->beg[0];
         o->beg[14] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[13] + o->beg[5] + o->beg[4] - o->beg[2] - o->beg[1] - o->beg[0];
         o->beg[13] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[12] + o->beg[4] + o->beg[4] + o->beg[3] + o->beg[3] + o->beg[2] - o->beg[0] - o->beg[7] - o->beg[6];
         o->beg[12] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[11] + o->beg[3] + o->beg[3] + o->beg[2] + o->beg[2] + o->beg[1] - o->beg[6] - o->beg[5];
         o->beg[11] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[10] + o->beg[2] + o->beg[2] + o->beg[1] + o->beg[1] + o->beg[0] - o->beg[5] - o->beg[4];
         o->beg[10] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[9] + o->beg[1] + o->beg[1] + o->beg[1] + o->beg[0] + o->beg[0] + o->beg[2] - o->beg[7] - o->beg[6];
         o->beg[9] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[8] + o->beg[0] + o->beg[0] + o->beg[0] + o->beg[7] - o->beg[5] - o->beg[4] - o->beg[3] - o->beg[2];
         o->beg[8] = (shtype_tWord)d; anatopdisconnect(d);
         break;
      #endif

      #if SHARKSSL_ECC_USE_SECP384R1
      case 12:  
         d  = (shtype_tDoubleWordS)o->beg[23] + o->beg[11] + o->beg[3] + o->beg[2] - o->beg[0];
         o->beg[23] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[22] + o->beg[10] + o->beg[1] + o->beg[0] - o->beg[11] - o->beg[3];
         o->beg[22] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[21] + o->beg[9] + o->beg[0] - o->beg[10] - o->beg[2];
         o->beg[21] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[20] + o->beg[11] + o->beg[8] + o->beg[3] + o->beg[2] - o->beg[9] - o->beg[1] - o->beg[0];
         o->beg[20] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[19] + o->beg[2] + o->beg[2] + o->beg[7] + o->beg[10] + o->beg[11] + o->beg[3] + o->beg[1] - o->beg[8] - o->beg[0] - o->beg[0];
         o->beg[19] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[18] + o->beg[1] + o->beg[1] + o->beg[6] + o->beg[9] + o->beg[10] + o->beg[2] + o->beg[0] - o->beg[7];
         o->beg[18] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[17] + o->beg[0] + o->beg[0] + o->beg[5] + o->beg[8] + o->beg[9] + o->beg[1] - o->beg[6];
         o->beg[17] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[16] + o->beg[4] + o->beg[7] + o->beg[8] + o->beg[0] - o->beg[5];
         o->beg[16] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[15] + o->beg[3] + o->beg[6] + o->beg[7] - o->beg[4];
         o->beg[15] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[14] + o->beg[2] + o->beg[5] + o->beg[6] - o->beg[3];
         o->beg[14] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[13] + o->beg[1] + o->beg[4] + o->beg[5] - o->beg[2];
         o->beg[13] = (shtype_tWord)d; anatopdisconnect(d);

         d += (shtype_tDoubleWordS)o->beg[12] + o->beg[0] + o->beg[3] + o->beg[4] - o->beg[1];
         o->beg[12] = (shtype_tWord)d; anatopdisconnect(d);
         break;
      #endif

      #if SHARKSSL_ECC_USE_SECP521R1
      case 17:  
         o->len = 17;
         traceaddress(&checkcontext, 17, &o->beg[17]);
         memmove(&o->beg[0], &o->beg[1], 17 * SHARKSSL__M);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         checkcontext.beg[0] &= 0x1FF;
         setupsdhci1(o, &checkcontext, mod);
         return;
      #endif

      default:
         return;
   }

   #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
   #if (SHARKSSL_ECC_USE_SECP256R1 || SHARKSSL_ECC_USE_SECP384R1)
   shtype_tWord *r, *s1, *s2, *s3;
   shtype_tWord *s4;
   shtype_tWord *s5, *s6;
   #endif
   #if SHARKSSL_ECC_USE_SECP521R1
   shtype_tWord d0;
   #endif
   U16 i = mod->len;

   #if (SHARKSSL_ECC_USE_SECP256R1 || SHARKSSL_ECC_USE_SECP384R1)
   d = 0;
   r = &o->beg[i * 2 - 1];
   #endif
   baAssert(o->len == (i * 2));
   switch (i)
   {
      #if SHARKSSL_ECC_USE_SECP256R1
      case 16:  
         s1 = &o->beg[13];
         s2 = NULL;
         s3 = NULL;
         s4 = &o->beg[9];
         s5 = &o->beg[5];
         s6 = &o->beg[3];
         while (i--)
         {
            d += (shtype_tDoubleWordS)*r;
            d += *(r - 16);
            d += *s1--;
            d -= *s4--;
            d -= *(s4 - 1);
            if (s2)
            {
               d += *s2;
               d += *s2--;
            }
            if (s3)
            {
               d += *s3;
               d += *s3--;
            }
            if (s5)
            {
               d -= *s5--;
            }
            if (s6)
            {
               d -= *s6--;
            }

            *r-- = (shtype_tWord)d; anatopdisconnect(d);

            if (i & 1)
            {
               continue;
            }
            if ((i == 12) || (i == 8))
            {
               s6 = NULL;
            }
            else if (i == 10)
            {
               s1 = &o->beg[9];
               s2 = &o->beg[7];
               s3 = s5 = &o->beg[5];
               s4 = &o->beg[15];
               s6 = &o->beg[1];
            }
            else if (i == 4)
            {
               s1 = &o->beg[5];
               s2 = &o->beg[3];
               s3 = &o->beg[1];
               s4 = &o->beg[15];
               s5 = NULL;
            }
            else if (i == 2)
            {
               s1 = &o->beg[15];
               s3 = NULL;
               s4 = &o->beg[11];
               s5 = &o->beg[7];
               s6 = &o->beg[5];
            }
         }
         break;
      #endif

      #if SHARKSSL_ECC_USE_SECP384R1
      case 24:  
         s1 = &o->beg[7];
         s2 = &o->beg[1];
         s3 = NULL;
         s4 = NULL;
         s5 = NULL;
         s6 = &o->beg[25];
         while (i--)
         {
            d += (shtype_tDoubleWordS)*r;
            d += *(r - 24);
            d -= *(r - 22);
            d += *s1--;
            d += *(s1 - 1);
            if (s2)
            {
               d -= *s2--;
            }
            if (s3)
            {
               d -= *s3--;
            }
            if (s4)
            {
               d += *s4--;
            }
            if (s5)
            {
               d += *s5;
               d += *s5--;
            }
            if (s6)
            {
               d += *s6--;
            }

            *r-- = (shtype_tWord)d; anatopdisconnect(d);

            if ((i & 1) || (i <= 6))
            {
               continue;
            }
            if (i == 22)
            {
               s1 = &o->beg[3];
               s2 = &o->beg[7];
               s6 = NULL;
            }
            else if (i == 20)
            {
               s1 = s3 = &o->beg[3];
            }
            else if (i == 18)
            {
               s1 = &o->beg[7];
               s6 = &o->beg[23];
            }
            else if (i == 16)
            {
               s1 = &o->beg[23];
               s3 = &o->beg[1];
               s4 = &o->beg[7];
               s5 = &o->beg[5];
               s6 = &o->beg[3];
            }
            else if (i == 14)
            {
               s2 = s3 = NULL;
            }
            else if (i == 12)
            {
               s6 = NULL;
            }
            else if (i == 10)
            {
               s5 = NULL;
            }
            else if (i == 8)
            {
               s4 = NULL;
            }
         }
         break;
      #endif

      #if SHARKSSL_ECC_USE_SECP521R1
      case 33:  
         o->len = 33;
         traceaddress(&checkcontext, 33, &o->beg[33]);
         d0 = (o->beg[0] & 0x3) << 7;
         memmove(&o->beg[0], &o->beg[1], 33 * SHARKSSL__M);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         backlightpdata(o);
         o->beg[0] |= d0;
         checkcontext.beg[0] &= 0x1FF;
         setupsdhci1(o, &checkcontext, mod);
         return;
      #endif

      default:
         return;
   }

   #elif (SHARKSSL_BIGINT_WORDSIZE == 8)
   #if (SHARKSSL_ECC_USE_SECP256R1 || SHARKSSL_ECC_USE_SECP384R1)
   shtype_tWord *r, *s1, *s2, *s3;
   shtype_tWord *s4;
   shtype_tWord *s5, *s6;
   #endif
   U16 i = mod->len;

   #if (SHARKSSL_ECC_USE_SECP256R1 || SHARKSSL_ECC_USE_SECP384R1)
   d = 0;
   r = &o->beg[i * 2 - 1];
   #endif
   baAssert(o->len == (i * 2));
   switch (i)
   {
      #if SHARKSSL_ECC_USE_SECP256R1
      case 32:  
         s1 = &o->beg[27];
         s2 = NULL;
         s3 = NULL;
         s4 = &o->beg[19];
         s5 = &o->beg[11];
         s6 = &o->beg[7];
         while (i--)
         {
            d += (shtype_tDoubleWordS)*r;
            d += *(r - 32);
            d += *s1--;
            d -= *s4--;
            d -= *(s4 - 3);
            if (s2)
            {
               d += *s2;
               d += *s2--;
            }
            if (s3)
            {
               d += *s3;
               d += *s3--;
            }
            if (s5)
            {
               d -= *s5--;
            }
            if (s6)
            {
               d -= *s6--;
            }

            *r-- = (shtype_tWord)d; anatopdisconnect(d);

            if (i & 1)
            {
               continue;
            }
            if ((i == 24) || (i == 16))
            {
               s6 = NULL;
            }
            else if (i == 20)
            {
               s1 = &o->beg[19];
               s2 = &o->beg[15];
               s3 = s5 = &o->beg[11];
               s4 = &o->beg[31];
               s6 = &o->beg[3];
            }
            else if (i == 8)
            {
               s1 = &o->beg[11];
               s2 = &o->beg[7];
               s3 = &o->beg[3];
               s4 = &o->beg[31];
               s5 = NULL;
            }
            else if (i == 4)
            {
               s1 = &o->beg[31];
               s3 = NULL;
               s4 = &o->beg[23];
               s5 = &o->beg[15];
               s6 = &o->beg[11];
            }
         }
         break;
      #endif

      #if SHARKSSL_ECC_USE_SECP384R1
      case 48:  
         s1 = &o->beg[15];
         s2 = &o->beg[3];
         s3 = NULL;
         s4 = NULL;
         s5 = NULL;
         s6 = &o->beg[51];
         while (i--)
         {
            d += (shtype_tDoubleWordS)*r;
            d += *(r - 48);
            d -= *(r - 44);
            d += *s1--;
            d += *(s1 - 3);
            if (s2)
            {
               d -= *s2--;
            }
            if (s3)
            {
               d -= *s3--;
            }
            if (s4)
            {
               d += *s4--;
            }
            if (s5)
            {
               d += *s5;
               d += *s5--;
            }
            if (s6)
            {
               d += *s6--;
            }

            *r-- = (shtype_tWord)d; anatopdisconnect(d);

            if ((i & 1) || (i <= 14))
            {
               continue;
            }
            if (i == 44)
            {
               s1 = &o->beg[7];
               s2 = &o->beg[15];
               s6 = NULL;
            }
            else if (i == 40)
            {
               s1 = s3 = &o->beg[7];
            }
            else if (i == 36)
            {
               s1 = &o->beg[15];
               s6 = &o->beg[47];
            }
            else if (i == 32)
            {
               s1 = &o->beg[47];
               s3 = &o->beg[3];
               s4 = &o->beg[15];
               s5 = &o->beg[11];
               s6 = &o->beg[7];
            }
            else if (i == 28)
            {
               s2 = s3 = NULL;
            }
            else if (i == 24)
            {
               s6 = NULL;
            }
            else if (i == 20)
            {
               s5 = NULL;
            }
            else if (i == 16)
            {
               s4 = NULL;
            }
         }
         break;
      #endif

      #if SHARKSSL_ECC_USE_SECP521R1
      case 66:  
         o->len = 66;
         traceaddress(&checkcontext, 66, &o->beg[66]);
         memmove(&o->beg[0], &o->beg[1], 66 * SHARKSSL__M);
         backlightpdata(o);
         checkcontext.beg[0] &= 0x1;
         setupsdhci1(o, &checkcontext, mod);
         return;
      #endif

      default:
         return;
   }

   #else
   #error unsupported SHARKSSL_BIGINT_WORDSIZE

   #endif  

   #if (SHARKSSL_ECC_USE_SECP256R1 || SHARKSSL_ECC_USE_SECP384R1)
   o->len >>= 1;
   o->beg += o->len;

   while (d != 0)
   {
      if (d < 0)
      {
         d += (shtype_tWordS)resolverelocs(o, mod);
      }
      else 
      {
         d += (shtype_tWordS)updatepmull(o, mod);
      }
   }

   if (timerwrite(o, mod))
   {
      updatepmull(o, mod);
   }
   #endif
}
#endif


void clearerrors(SharkSslECCurve *o, U16 rightsvalid)
{
   
   #if SHARKSSL_ECC_USE_SECP256R1
   #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
   static const shtype_tWord SECP256R1_prime[8]   = {0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000,
                                                           0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
   static const shtype_tWord SECP256R1_order[8]   = {0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF,
                                                           0xBCE6FAAD, 0xA7179E84, 0xF3B9CAC2, 0xFC632551};
   static const shtype_tWord SECP256R1_Gx[8]      = {0x6B17D1F2, 0xE12C4247, 0xF8BCE6E5, 0x63A440F2,
                                                           0x77037D81, 0x2DEB33A0, 0xF4A13945, 0xD898C296};
   static const shtype_tWord SECP256R1_Gy[8]      = {0x4FE342E2, 0xFE1A7F9B, 0x8EE7EB4A, 0x7C0F9E16,
                                                           0x2BCE3357, 0x6B315ECE, 0xCBB64068, 0x37BF51F5};
   #if SHARKSSL_ECC_USE_BRAINPOOL
   static const shtype_tWord SECP256R1_a[1]       = {(shtype_tWord)-3};
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord SECP256R1_b[8]       = {0x5AC635D8, 0xAA3A93E7, 0xB3EBBD55, 0x769886BC,
                                                           0x651D06B0, 0xCC53B0F6, 0x3BCE3C3E, 0x27D2604B};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
   static const shtype_tWord SECP256R1_prime[16]  = {0xFFFF, 0xFFFF, 0x0000, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000,
                                                           0x0000, 0x0000, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF};
   static const shtype_tWord SECP256R1_order[16]  = {0xFFFF, 0xFFFF, 0x0000, 0x0000, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                                           0xBCE6, 0xFAAD, 0xA717, 0x9E84, 0xF3B9, 0xCAC2, 0xFC63, 0x2551};
   static const shtype_tWord SECP256R1_Gx[16]     = {0x6B17, 0xD1F2, 0xE12C, 0x4247, 0xF8BC, 0xE6E5, 0x63A4, 0x40F2,
                                                           0x7703, 0x7D81, 0x2DEB, 0x33A0, 0xF4A1, 0x3945, 0xD898, 0xC296};
   static const shtype_tWord SECP256R1_Gy[16]     = {0x4FE3, 0x42E2, 0xFE1A, 0x7F9B, 0x8EE7, 0xEB4A, 0x7C0F, 0x9E16,
                                                           0x2BCE, 0x3357, 0x6B31, 0x5ECE, 0xCBB6, 0x4068, 0x37BF, 0x51F5};
   #if SHARKSSL_ECC_USE_BRAINPOOL
   static const shtype_tWord SECP256R1_a[1]       = {(shtype_tWord)-3};
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord SECP256R1_b[16]      = {0x5AC6, 0x35D8, 0xAA3A, 0x93E7, 0xB3EB, 0xBD55, 0x7698, 0x86BC,
                                                           0x651D, 0x06B0, 0xCC53, 0xB0F6, 0x3BCE, 0x3C3E, 0x27D2, 0x604B};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 8)
   static const shtype_tWord SECP256R1_prime[32]  = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                           0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
   static const shtype_tWord SECP256R1_order[32]  = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
                                                           0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
   static const shtype_tWord SECP256R1_Gx[32]     = {0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
                                                           0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
                                                           0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
                                                           0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96};
   static const shtype_tWord SECP256R1_Gy[32]     = {0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
                                                           0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
                                                           0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
                                                           0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5};
   #if SHARKSSL_ECC_USE_BRAINPOOL
   static const shtype_tWord SECP256R1_a[1]       = {(shtype_tWord)-3};
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord SECP256R1_b[32]      = {0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
                                                           0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
                                                           0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
                                                           0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B};
   #endif
   #endif  
   #endif  

   #if SHARKSSL_ECC_USE_SECP384R1
   #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
   static const shtype_tWord SECP384R1_prime[12]  = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
                                                           0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF};
   static const shtype_tWord SECP384R1_order[12]  = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                                           0xFFFFFFFF, 0xFFFFFFFF, 0xC7634D81, 0xF4372DDF,
                                                           0x581A0DB2, 0x48B0A77A, 0xECEC196A, 0xCCC52973};
   static const shtype_tWord SECP384R1_Gx[12]     = {0xAA87CA22, 0xBE8B0537, 0x8EB1C71E, 0xF320AD74,
                                                           0x6E1D3B62, 0x8BA79B98, 0x59F741E0, 0x82542A38,
                                                           0x5502F25D, 0xBF55296C, 0x3A545E38, 0x72760AB7};
   static const shtype_tWord SECP384R1_Gy[12]     = {0x3617DE4A, 0x96262C6F, 0x5D9E98BF, 0x9292DC29,
                                                           0xF8F41DBD, 0x289A147C, 0xE9DA3113, 0xB5F0B8C0,
                                                           0x0A60B1CE, 0x1D7E819D, 0x7A431D7C, 0x90EA0E5F};
   #if SHARKSSL_ECC_USE_BRAINPOOL
   static const shtype_tWord SECP384R1_a[1]       = {(shtype_tWord)-3};
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord SECP384R1_b[12]      = {0xB3312FA7, 0xE23EE7E4, 0x988E056B, 0xE3F82D19,
                                                           0x181D9C6E, 0xFE814112, 0x0314088F, 0x5013875A,
                                                           0xC656398D, 0x8A2ED19D, 0x2A85C8ED, 0xD3EC2AEF};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
   static const shtype_tWord SECP384R1_prime[24]  = {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                                           0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE,
                                                           0xFFFF, 0xFFFF, 0x0000, 0x0000, 0x0000, 0x0000, 0xFFFF, 0xFFFF};
   static const shtype_tWord SECP384R1_order[24]  = {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                                           0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xC763, 0x4D81, 0xF437, 0x2DDF,
                                                           0x581A, 0x0DB2, 0x48B0, 0xA77A, 0xECEC, 0x196A, 0xCCC5, 0x2973};
   static const shtype_tWord SECP384R1_Gx[24]     = {0xAA87, 0xCA22, 0xBE8B, 0x0537, 0x8EB1, 0xC71E, 0xF320, 0xAD74,
                                                           0x6E1D, 0x3B62, 0x8BA7, 0x9B98, 0x59F7, 0x41E0, 0x8254, 0x2A38,
                                                           0x5502, 0xF25D, 0xBF55, 0x296C, 0x3A54, 0x5E38, 0x7276, 0x0AB7};
   static const shtype_tWord SECP384R1_Gy[24]     = {0x3617, 0xDE4A, 0x9626, 0x2C6F, 0x5D9E, 0x98BF, 0x9292, 0xDC29,
                                                           0xF8F4, 0x1DBD, 0x289A, 0x147C, 0xE9DA, 0x3113, 0xB5F0, 0xB8C0,
                                                           0x0A60, 0xB1CE, 0x1D7E, 0x819D, 0x7A43, 0x1D7C, 0x90EA, 0x0E5F};
   #if SHARKSSL_ECC_USE_BRAINPOOL
   static const shtype_tWord SECP384R1_a[1]       = {(shtype_tWord)-3};
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord SECP384R1_b[24]      = {0xB331, 0x2FA7, 0xE23E, 0xE7E4, 0x988E, 0x056B, 0xE3F8, 0x2D19,
                                                           0x181D, 0x9C6E, 0xFE81, 0x4112, 0x0314, 0x088F, 0x5013, 0x875A,
                                                           0xC656, 0x398D, 0x8A2E, 0xD19D, 0x2A85, 0xC8ED, 0xD3EC, 0x2AEF};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 8)
   static const shtype_tWord SECP384R1_prime[48]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                                           0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
   static const shtype_tWord SECP384R1_order[48]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
                                                           0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
                                                           0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73};
   static const shtype_tWord SECP384R1_Gx[48]     = {0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37,
                                                           0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
                                                           0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
                                                           0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
                                                           0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C,
                                                           0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7};
   static const shtype_tWord SECP384R1_Gy[48]     = {0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F,
                                                           0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
                                                           0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C,
                                                           0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0,
                                                           0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D,
                                                           0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F};
   #if SHARKSSL_ECC_USE_BRAINPOOL
   static const shtype_tWord SECP384R1_a[1]       = {(shtype_tWord)-3};
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord SECP384R1_b[48]      = {0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4,
                                                           0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
                                                           0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
                                                           0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
                                                           0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D,
                                                           0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF};
   #endif
   #endif  
   #endif  

   #if SHARKSSL_ECC_USE_SECP521R1
   #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
   static const shtype_tWord SECP521R1_prime[17]  = {0x000001FF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                                           0xFFFFFFFF};
   static const shtype_tWord SECP521R1_order[17]  = {0x000001FF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                                           0xFFFFFFFA, 0x51868783, 0xBF2F966B, 0x7FCC0148,
                                                           0xF709A5D0, 0x3BB5C9B8, 0x899C47AE, 0xBB6FB71E,
                                                           0x91386409};
   static const shtype_tWord SECP521R1_Gx[17]     = {0x000000C6, 0x858E06B7, 0x0404E9CD, 0x9E3ECB66,
                                                           0x2395B442, 0x9C648139, 0x053FB521, 0xF828AF60,
                                                           0x6B4D3DBA, 0xA14B5E77, 0xEFE75928, 0xFE1DC127,
                                                           0xA2FFA8DE, 0x3348B3C1, 0x856A429B, 0xF97E7E31,
                                                           0xC2E5BD66};
   static const shtype_tWord SECP521R1_Gy[17]     = {0x00000118, 0x39296A78, 0x9A3BC004, 0x5C8A5FB4,
                                                           0x2C7D1BD9, 0x98F54449, 0x579B4468, 0x17AFBD17,
                                                           0x273E662C, 0x97EE7299, 0x5EF42640, 0xC550B901,
                                                           0x3FAD0761, 0x353C7086, 0xA272C240, 0x88BE9476,
                                                           0x9FD16650};
   #if SHARKSSL_ECC_USE_BRAINPOOL
   static const shtype_tWord SECP521R1_a[1]       = {(shtype_tWord)-3};
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord SECP521R1_b[17]      = {0x00000051, 0x953EB961, 0x8E1C9A1F, 0x929A21A0,
                                                           0xB68540EE, 0xA2DA725B, 0x99B315F3, 0xB8B48991,
                                                           0x8EF109E1, 0x56193951, 0xEC7E937B, 0x1652C0BD,
                                                           0x3BB1BF07, 0x3573DF88, 0x3D2C34F1, 0xEF451FD4,
                                                           0x6B503F00};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
   static const shtype_tWord SECP521R1_prime[33]  = {0x01FF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                                           0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                                           0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                                           0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                                           0xFFFF, 0xFFFF};
   static const shtype_tWord SECP521R1_order[33]  = {0x01FF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                                           0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                                           0xFFFF, 0xFFFA, 0x5186, 0x8783, 0xBF2F, 0x966B, 0x7FCC, 0x0148,
                                                           0xF709, 0xA5D0, 0x3BB5, 0xC9B8, 0x899C, 0x47AE, 0xBB6F, 0xB71E,
                                                           0x9138, 0x6409};
   static const shtype_tWord SECP521R1_Gx[33]     = {0x00C6, 0x858E, 0x06B7, 0x0404, 0xE9CD, 0x9E3E, 0xCB66,
                                                           0x2395, 0xB442, 0x9C64, 0x8139, 0x053F, 0xB521, 0xF828, 0xAF60,
                                                           0x6B4D, 0x3DBA, 0xA14B, 0x5E77, 0xEFE7, 0x5928, 0xFE1D, 0xC127,
                                                           0xA2FF, 0xA8DE, 0x3348, 0xB3C1, 0x856A, 0x429B, 0xF97E, 0x7E31,
                                                           0xC2E5, 0xBD66};
   static const shtype_tWord SECP521R1_Gy[33]     = {0x0118, 0x3929, 0x6A78, 0x9A3B, 0xC004, 0x5C8A, 0x5FB4,
                                                           0x2C7D, 0x1BD9, 0x98F5, 0x4449, 0x579B, 0x4468, 0x17AF, 0xBD17,
                                                           0x273E, 0x662C, 0x97EE, 0x7299, 0x5EF4, 0x2640, 0xC550, 0xB901,
                                                           0x3FAD, 0x0761, 0x353C, 0x7086, 0xA272, 0xC240, 0x88BE, 0x9476,
                                                           0x9FD1, 0x6650};
   #if SHARKSSL_ECC_USE_BRAINPOOL
   static const shtype_tWord SECP521R1_a[1]       = {(shtype_tWord)-3};
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord SECP521R1_b[33]      = {0x0051, 0x953E, 0xB961, 0x8E1C, 0x9A1F, 0x929A, 0x21A0,
                                                           0xB685, 0x40EE, 0xA2DA, 0x725B, 0x99B3, 0x15F3, 0xB8B4, 0x8991,
                                                           0x8EF1, 0x09E1, 0x5619, 0x3951, 0xEC7E, 0x937B, 0x1652, 0xC0BD,
                                                           0x3BB1, 0xBF07, 0x3573, 0xDF88, 0x3D2C, 0x34F1, 0xEF45, 0x1FD4,
                                                           0x6B50, 0x3F00};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 8)
   static const shtype_tWord SECP521R1_prime[66]  = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF};
   static const shtype_tWord SECP521R1_order[66]  = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                           0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83,
                                                           0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48,
                                                           0xF7, 0x09, 0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8,
                                                           0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E,
                                                           0x91, 0x38, 0x64, 0x09};
   static const shtype_tWord SECP521R1_Gx[66]     = {0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7,
                                                           0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66,
                                                           0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39,
                                                           0x05, 0x3F, 0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60,
                                                           0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77,
                                                           0xEF, 0xE7, 0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27,
                                                           0xA2, 0xFF, 0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1,
                                                           0x85, 0x6A, 0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31,
                                                           0xC2, 0xE5, 0xBD, 0x66};
   static const shtype_tWord SECP521R1_Gy[66]     = {0x01, 0x18, 0x39, 0x29, 0x6A, 0x78,
                                                           0x9A, 0x3B, 0xC0, 0x04, 0x5C, 0x8A, 0x5F, 0xB4,
                                                           0x2C, 0x7D, 0x1B, 0xD9, 0x98, 0xF5, 0x44, 0x49,
                                                           0x57, 0x9B, 0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17,
                                                           0x27, 0x3E, 0x66, 0x2C, 0x97, 0xEE, 0x72, 0x99,
                                                           0x5E, 0xF4, 0x26, 0x40, 0xC5, 0x50, 0xB9, 0x01,
                                                           0x3F, 0xAD, 0x07, 0x61, 0x35, 0x3C, 0x70, 0x86,
                                                           0xA2, 0x72, 0xC2, 0x40, 0x88, 0xBE, 0x94, 0x76,
                                                           0x9F, 0xD1, 0x66, 0x50};
   #if SHARKSSL_ECC_USE_BRAINPOOL
   static const shtype_tWord SECP521R1_a[1]       = {(shtype_tWord)-3};
   #endif
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord SECP521R1_b[66]      = {0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61,
                                                           0x8E, 0x1C, 0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0,
                                                           0xB6, 0x85, 0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B,
                                                           0x99, 0xB3, 0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91,
                                                           0x8E, 0xF1, 0x09, 0xE1, 0x56, 0x19, 0x39, 0x51,
                                                           0xEC, 0x7E, 0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD,
                                                           0x3B, 0xB1, 0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88,
                                                           0x3D, 0x2C, 0x34, 0xF1, 0xEF, 0x45, 0x1F, 0xD4,
                                                           0x6B, 0x50, 0x3F, 0x00};
   #endif
   #endif  
   #endif  

   #if SHARKSSL_ECC_USE_BRAINPOOLP256R1
   
   #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
   static const shtype_tWord brainpoolP256R1_prime[8]   = {0xA9FB57DB, 0xA1EEA9BC, 0x3E660A90, 0x9D838D72,
                                                                 0x6E3BF623, 0xD5262028, 0x2013481D, 0x1F6E5377};
   static const shtype_tWord brainpoolP256R1_order[8]   = {0xA9FB57DB, 0xA1EEA9BC, 0x3E660A90, 0x9D838D71,
                                                                 0x8C397AA3, 0xB561A6F7, 0x901E0E82, 0x974856A7};
   
   static const shtype_tWord brainpoolP256R1_Gx[8]      = {0x8E1F767A, 0x9E119BDF, 0x704C311D, 0x6B892AD3, 
                                                                 0x80DE4D9A, 0xB97CF30A, 0x27C0D92D, 0x351FD10C};
   static const shtype_tWord brainpoolP256R1_Gy[8]      = {0x14EB78C6, 0x026EB0A2, 0x16FDF6E8, 0xDFBD8B03, 
                                                                 0xA618F259, 0xCD950162, 0x9A4FE948, 0xA0917A17};
   static const shtype_tWord brainpoolP256R1_a[8]       = {0x1E4676AB, 0xD666BC17, 0x95EC1E5E, 0x6398556E, 
                                                                 0xA68123F1, 0xC1D20C64, 0xD5D18EDF, 0x69696261};
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord brainpoolP256R1_b[8]       = {0x26DC5C6C, 0xE94A4B44, 0xF330B5D9, 0xBBD77CBF, 
                                                                 0x95841629, 0x5CF7E1CE, 0x6BCCDC18, 0xFF8C07B6};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
   static const shtype_tWord brainpoolP256R1_prime[16]  = {0xA9FB, 0x57DB, 0xA1EE, 0xA9BC, 0x3E66, 0x0A90, 0x9D83, 0x8D72,
                                                                 0x6E3B, 0xF623, 0xD526, 0x2028, 0x2013, 0x481D, 0x1F6E, 0x5377};
   static const shtype_tWord brainpoolP256R1_order[16]  = {0xA9FB, 0x57DB, 0xA1EE, 0xA9BC, 0x3E66, 0x0A90, 0x9D83, 0x8D71,
                                                                 0x8C39, 0x7AA3, 0xB561, 0xA6F7, 0x901E, 0x0E82, 0x9748, 0x56A7};
   static const shtype_tWord brainpoolP256R1_Gx[16]     = {0x8E1F, 0x767A, 0x9E11, 0x9BDF, 0x704C, 0x311D, 0x6B89, 0x2AD3, 
                                                                 0x80DE, 0x4D9A, 0xB97C, 0xF30A, 0x27C0, 0xD92D, 0x351F, 0xD10C};
   static const shtype_tWord brainpoolP256R1_Gy[16]     = {0x14EB, 0x78C6, 0x026E, 0xB0A2, 0x16FD, 0xF6E8, 0xDFBD, 0x8B03, 
                                                                 0xA618, 0xF259, 0xCD95, 0x0162, 0x9A4F, 0xE948, 0xA091, 0x7A17};
   static const shtype_tWord brainpoolP256R1_a[16]      = {0x1E46, 0x76AB, 0xD666, 0xBC17, 0x95EC, 0x1E5E, 0x6398, 0x556E, 
                                                                 0xA681, 0x23F1, 0xC1D2, 0x0C64, 0xD5D1, 0x8EDF, 0x6969, 0x6261};
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord brainpoolP256R1_b[16]      = {0x26DC, 0x5C6C, 0xE94A, 0x4B44, 0xF330, 0xB5D9, 0xBBD7, 0x7CBF, 
                                                                 0x9584, 0x1629, 0x5CF7, 0xE1CE, 0x6BCC, 0xDC18, 0xFF8C, 0x07B6};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 8)                         
   static const shtype_tWord brainpoolP256R1_prime[32]  = {0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC,
                                                                 0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x72,
                                                                 0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
                                                                 0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77};
   static const shtype_tWord brainpoolP256R1_order[32]  = {0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC,
                                                                 0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x71, 
                                                                 0x8C, 0x39, 0x7A, 0xA3, 0xB5, 0x61, 0xA6, 0xF7, 
                                                                 0x90, 0x1E, 0x0E, 0x82, 0x97, 0x48, 0x56, 0xA7};
   static const shtype_tWord brainpoolP256R1_Gx[32]     = {0x8E, 0x1F, 0x76, 0x7A, 0x9E, 0x11, 0x9B, 0xDF, 
                                                                 0x70, 0x4C, 0x31, 0x1D, 0x6B, 0x89, 0x2A, 0xD3, 
                                                                 0x80, 0xDE, 0x4D, 0x9A, 0xB9, 0x7C, 0xF3, 0x0A, 
                                                                 0x27, 0xC0, 0xD9, 0x2D, 0x35, 0x1F, 0xD1, 0x0C};
   static const shtype_tWord brainpoolP256R1_Gy[32]     = {0x14, 0xEB, 0x78, 0xC6, 0x02, 0x6E, 0xB0, 0xA2, 
                                                                 0x16, 0xFD, 0xF6, 0xE8, 0xDF, 0xBD, 0x8B, 0x03, 
                                                                 0xA6, 0x18, 0xF2, 0x59, 0xCD, 0x95, 0x01, 0x62, 
                                                                 0x9A, 0x4F, 0xE9, 0x48, 0xA0, 0x91, 0x7A, 0x17};
   static const shtype_tWord brainpoolP256R1_a[32]      = {0x1E, 0x46, 0x76, 0xAB, 0xD6, 0x66, 0xBC, 0x17, 
                                                                 0x95, 0xEC, 0x1E, 0x5E, 0x63, 0x98, 0x55, 0x6E, 
                                                                 0xA6, 0x81, 0x23, 0xF1, 0xC1, 0xD2, 0x0C, 0x64, 
                                                                 0xD5, 0xD1, 0x8E, 0xDF, 0x69, 0x69, 0x62, 0x61};
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord brainpoolP256R1_b[32]      = {0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x4A, 0x4B, 0x44, 
                                                                 0xF3, 0x30, 0xB5, 0xD9, 0xBB, 0xD7, 0x7C, 0xBF, 
                                                                 0x95, 0x84, 0x16, 0x29, 0x5C, 0xF7, 0xE1, 0xCE, 
                                                                 0x6B, 0xCC, 0xDC, 0x18, 0xFF, 0x8C, 0x07, 0xB6};
   #endif
   #endif  
   #endif  

   #if SHARKSSL_ECC_USE_BRAINPOOLP384R1
   
   #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
   static const shtype_tWord brainpoolP384R1_prime[12]  = {0x8CB91E82, 0xA3386D28, 0x0F5D6F7E, 0x50E641DF, 
                                                                 0x152F7109, 0xED5456B4, 0x12B1DA19, 0x7FB71123, 
                                                                 0xACD3A729, 0x901D1A71, 0x87470013, 0x3107EC53};
   static const shtype_tWord brainpoolP384R1_order[12]  = {0x8CB91E82, 0xA3386D28, 0x0F5D6F7E, 0x50E641DF, 
                                                                 0x152F7109, 0xED5456B3, 0x1F166E6C, 0xAC0425A7, 
                                                                 0xCF3AB6AF, 0x6B7FC310, 0x3B883202, 0xE9046565};
   
   static const shtype_tWord brainpoolP384R1_Gx[12]     = {0x85007533, 0x88F53FC1, 0x9CDD0DCF, 0xBACD0099, 
                                                                 0x068B264E, 0xF95C2164, 0x94C378E9, 0x9D202F23, 
                                                                 0x66FC80E8, 0xD5A886BF, 0xA189DEEB, 0xD438FBC1};
   static const shtype_tWord brainpoolP384R1_Gy[12]     = {0x2CF4A062, 0x458968B5, 0xC6162566, 0x4F21DDB6, 
                                                                 0xA180ACD4, 0xD5719217, 0xF88309A3, 0x8F0737FC, 
                                                                 0xF5E0D246, 0xC7996F55, 0xE738B331, 0x0DE140A5};
   static const shtype_tWord brainpoolP384R1_a[12]      = {0x7C338021, 0xA2E8C0D1, 0x400A8FDF, 0x42B00C60, 
                                                                 0xE7FFE9E5, 0x35529374, 0x936771B9, 0xD7F10DB4, 
                                                                 0x75D7F3FE, 0xF157B07B, 0xDB26B895, 0x466C3C99};
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord brainpoolP384R1_b[12]      = {0x04A8C7DD, 0x22CE2826, 0x8B39B554, 0x16F0447C, 
                                                                 0x2FB77DE1, 0x07DCD2A6, 0x2E880EA5, 0x3EEB62D5, 
                                                                 0x7CB43902, 0x95DBC994, 0x3AB78696, 0xFA504C11};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
   static const shtype_tWord brainpoolP384R1_prime[24]  = {0x8CB9, 0x1E82, 0xA338, 0x6D28, 0x0F5D, 0x6F7E, 0x50E6, 0x41DF, 
                                                                 0x152F, 0x7109, 0xED54, 0x56B4, 0x12B1, 0xDA19, 0x7FB7, 0x1123, 
                                                                 0xACD3, 0xA729, 0x901D, 0x1A71, 0x8747, 0x0013, 0x3107, 0xEC53};
   static const shtype_tWord brainpoolP384R1_order[24]  = {0x8CB9, 0x1E82, 0xA338, 0x6D28, 0x0F5D, 0x6F7E, 0x50E6, 0x41DF, 
                                                                 0x152F, 0x7109, 0xED54, 0x56B3, 0x1F16, 0x6E6C, 0xAC04, 0x25A7, 
                                                                 0xCF3A, 0xB6AF, 0x6B7F, 0xC310, 0x3B88, 0x3202, 0xE904, 0x6565};
   static const shtype_tWord brainpoolP384R1_Gx[24]     = {0x8500, 0x7533, 0x88F5, 0x3FC1, 0x9CDD, 0x0DCF, 0xBACD, 0x0099, 
                                                                 0x068B, 0x264E, 0xF95C, 0x2164, 0x94C3, 0x78E9, 0x9D20, 0x2F23, 
                                                                 0x66FC, 0x80E8, 0xD5A8, 0x86BF, 0xA189, 0xDEEB, 0xD438, 0xFBC1};
   static const shtype_tWord brainpoolP384R1_Gy[24]     = {0x2CF4, 0xA062, 0x4589, 0x68B5, 0xC616, 0x2566, 0x4F21, 0xDDB6, 
                                                                 0xA180, 0xACD4, 0xD571, 0x9217, 0xF883, 0x09A3, 0x8F07, 0x37FC, 
                                                                 0xF5E0, 0xD246, 0xC799, 0x6F55, 0xE738, 0xB331, 0x0DE1, 0x40A5};
   static const shtype_tWord brainpoolP384R1_a[24]      = {0x7C33, 0x8021, 0xA2E8, 0xC0D1, 0x400A, 0x8FDF, 0x42B0, 0x0C60, 
                                                                 0xE7FF, 0xE9E5, 0x3552, 0x9374, 0x9367, 0x71B9, 0xD7F1, 0x0DB4, 
                                                                 0x75D7, 0xF3FE, 0xF157, 0xB07B, 0xDB26, 0xB895, 0x466C, 0x3C99};
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord brainpoolP384R1_b[24]      = {0x04A8, 0xC7DD, 0x22CE, 0x2826, 0x8B39, 0xB554, 0x16F0, 0x447C, 
                                                                 0x2FB7, 0x7DE1, 0x07DC, 0xD2A6, 0x2E88, 0x0EA5, 0x3EEB, 0x62D5, 
                                                                 0x7CB4, 0x3902, 0x95DB, 0xC994, 0x3AB7, 0x8696, 0xFA50, 0x4C11};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 8)                         
   static const shtype_tWord brainpoolP384R1_prime[48]  = {0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 
                                                                 0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF, 
                                                                 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4, 
                                                                 0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23, 
                                                                 0xAC, 0xD3, 0xA7, 0x29, 0x90, 0x1D, 0x1A, 0x71, 
                                                                 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53};
   static const shtype_tWord brainpoolP384R1_order[48]  = {0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 
                                                                 0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF, 
                                                                 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB3, 
                                                                 0x1F, 0x16, 0x6E, 0x6C, 0xAC, 0x04, 0x25, 0xA7, 
                                                                 0xCF, 0x3A, 0xB6, 0xAF, 0x6B, 0x7F, 0xC3, 0x10, 
                                                                 0x3B, 0x88, 0x32, 0x02, 0xE9, 0x04, 0x65, 0x65};
   static const shtype_tWord brainpoolP384R1_Gx[48]     = {0x85, 0x00, 0x75, 0x33, 0x88, 0xF5, 0x3F, 0xC1, 
                                                                 0x9C, 0xDD, 0x0D, 0xCF, 0xBA, 0xCD, 0x00, 0x99, 
                                                                 0x06, 0x8B, 0x26, 0x4E, 0xF9, 0x5C, 0x21, 0x64, 
                                                                 0x94, 0xC3, 0x78, 0xE9, 0x9D, 0x20, 0x2F, 0x23, 
                                                                 0x66, 0xFC, 0x80, 0xE8, 0xD5, 0xA8, 0x86, 0xBF, 
                                                                 0xA1, 0x89, 0xDE, 0xEB, 0xD4, 0x38, 0xFB, 0xC1};
   static const shtype_tWord brainpoolP384R1_Gy[48]     = {0x2C, 0xF4, 0xA0, 0x62, 0x45, 0x89, 0x68, 0xB5, 
                                                                 0xC6, 0x16, 0x25, 0x66, 0x4F, 0x21, 0xDD, 0xB6, 
                                                                 0xA1, 0x80, 0xAC, 0xD4, 0xD5, 0x71, 0x92, 0x17, 
                                                                 0xF8, 0x83, 0x09, 0xA3, 0x8F, 0x07, 0x37, 0xFC, 
                                                                 0xF5, 0xE0, 0xD2, 0x46, 0xC7, 0x99, 0x6F, 0x55, 
                                                                 0xE7, 0x38, 0xB3, 0x31, 0x0D, 0xE1, 0x40, 0xA5};
   static const shtype_tWord brainpoolP384R1_a[48]      = {0x7C, 0x33, 0x80, 0x21, 0xA2, 0xE8, 0xC0, 0xD1, 
                                                                 0x40, 0x0A, 0x8F, 0xDF, 0x42, 0xB0, 0x0C, 0x60, 
                                                                 0xE7, 0xFF, 0xE9, 0xE5, 0x35, 0x52, 0x93, 0x74, 
                                                                 0x93, 0x67, 0x71, 0xB9, 0xD7, 0xF1, 0x0D, 0xB4, 
                                                                 0x75, 0xD7, 0xF3, 0xFE, 0xF1, 0x57, 0xB0, 0x7B, 
                                                                 0xDB, 0x26, 0xB8, 0x95, 0x46, 0x6C, 0x3C, 0x99};
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord brainpoolP384R1_b[48]      = {0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26, 
                                                                 0x8B, 0x39, 0xB5, 0x54, 0x16, 0xF0, 0x44, 0x7C, 
                                                                 0x2F, 0xB7, 0x7D, 0xE1, 0x07, 0xDC, 0xD2, 0xA6, 
                                                                 0x2E, 0x88, 0x0E, 0xA5, 0x3E, 0xEB, 0x62, 0xD5, 
                                                                 0x7C, 0xB4, 0x39, 0x02, 0x95, 0xDB, 0xC9, 0x94, 
                                                                 0x3A, 0xB7, 0x86, 0x96, 0xFA, 0x50, 0x4C, 0x11};
   #endif
   #endif  
   #endif  

   #if SHARKSSL_ECC_USE_BRAINPOOLP512R1
   
   #if   (SHARKSSL_BIGINT_WORDSIZE == 32)
   static const shtype_tWord brainpoolP512R1_prime[16]  = {0xAADD9DB8, 0xDBE9C48B, 0x3FD4E6AE, 0x33C9FC07, 
                                                                 0xCB308DB3, 0xB3C9D20E, 0xD6639CCA, 0x70330871, 
                                                                 0x7D4D9B00, 0x9BC66842, 0xAECDA12A, 0xE6A380E6, 
                                                                 0x2881FF2F, 0x2D82C685, 0x28AA6056, 0x583A48F3};
   static const shtype_tWord brainpoolP512R1_order[16]  = {0xAADD9DB8, 0xDBE9C48B, 0x3FD4E6AE, 0x33C9FC07, 
                                                                 0xCB308DB3, 0xB3C9D20E, 0xD6639CCA, 0x70330870, 
                                                                 0x553E5C41, 0x4CA92619, 0x41866119, 0x7FAC1047, 
                                                                 0x1DB1D381, 0x085DDADD, 0xB5879682, 0x9CA90069};
   static const shtype_tWord brainpoolP512R1_Gx[16]     = {0x5A2BA14C, 0x0994E981, 0x871CB5CA, 0x006D4573, 
                                                                 0xB2B6EA37, 0xF36D3CF7, 0x2433D76F, 0x905C8737, 
                                                                 0x85505395, 0x14C01FC8, 0x34AB0414, 0x6DF55E8F, 
                                                                 0x683E4D64, 0x272C02A4, 0xC4CE9609, 0x5161D9D3};
   static const shtype_tWord brainpoolP512R1_Gy[16]     = {0x8C50C9D1, 0x2ACB7281, 0x9A5ED7DA, 0x870F3F9B,
                                                                 0x585D2B77, 0xCD9D3F8C, 0x7C170B88, 0x8FE62FDC,
                                                                 0x360EC775, 0x598ECC3E, 0xBF845553, 0x4C859490,
                                                                 0x7518DF6F, 0x4742F325, 0x2F906629, 0x25042A6D};
   static const shtype_tWord brainpoolP512R1_a[16]      = {0x5EC4F187, 0x227D2A83, 0xB83B84FA, 0xE2D0850C,
                                                                 0x182D0F59, 0xF41E8778, 0xA5EC30C8, 0x3F80D1C7,
                                                                 0xCF8F0111, 0x9E6E87FF, 0x40B04B72, 0x4675BBAB,
                                                                 0x14E4957D, 0xAFA7D283, 0xDA1F8A34, 0xEA10C446};
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord brainpoolP512R1_b[16]      = {0x3DF91610, 0xA83441CA, 0xEA9863BC, 0x2DED5D5A, 
                                                                 0xA8253AA1, 0x0A2EF1C9, 0x8B9AC8B5, 0x7F1117A7, 
                                                                 0x2BF2C7B9, 0xE7C1AC4D, 0x77FC94CA, 0xDC083E67, 
                                                                 0x984050B7, 0x5EBAE5DD, 0x2809BD63, 0x8016F723};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 16)
   static const shtype_tWord brainpoolP512R1_prime[32]  = {0xAADD, 0x9DB8, 0xDBE9, 0xC48B, 0x3FD4, 0xE6AE, 0x33C9, 0xFC07, 
                                                                 0xCB30, 0x8DB3, 0xB3C9, 0xD20E, 0xD663, 0x9CCA, 0x7033, 0x0871, 
                                                                 0x7D4D, 0x9B00, 0x9BC6, 0x6842, 0xAECD, 0xA12A, 0xE6A3, 0x80E6, 
                                                                 0x2881, 0xFF2F, 0x2D82, 0xC685, 0x28AA, 0x6056, 0x583A, 0x48F3};
   static const shtype_tWord brainpoolP512R1_order[32]  = {0xAADD, 0x9DB8, 0xDBE9, 0xC48B, 0x3FD4, 0xE6AE, 0x33C9, 0xFC07, 
                                                                 0xCB30, 0x8DB3, 0xB3C9, 0xD20E, 0xD663, 0x9CCA, 0x7033, 0x0870, 
                                                                 0x553E, 0x5C41, 0x4CA9, 0x2619, 0x4186, 0x6119, 0x7FAC, 0x1047, 
                                                                 0x1DB1, 0xD381, 0x085D, 0xDADD, 0xB587, 0x9682, 0x9CA9, 0x0069};
   static const shtype_tWord brainpoolP512R1_Gx[32]     = {0x5A2B, 0xA14C, 0x0994, 0xE981, 0x871C, 0xB5CA, 0x006D, 0x4573, 
                                                                 0xB2B6, 0xEA37, 0xF36D, 0x3CF7, 0x2433, 0xD76F, 0x905C, 0x8737, 
                                                                 0x8550, 0x5395, 0x14C0, 0x1FC8, 0x34AB, 0x0414, 0x6DF5, 0x5E8F, 
                                                                 0x683E, 0x4D64, 0x272C, 0x02A4, 0xC4CE, 0x9609, 0x5161, 0xD9D3};
   static const shtype_tWord brainpoolP512R1_Gy[32]     = {0x8C50, 0xC9D1, 0x2ACB, 0x7281, 0x9A5E, 0xD7DA, 0x870F, 0x3F9B,
                                                                 0x585D, 0x2B77, 0xCD9D, 0x3F8C, 0x7C17, 0x0B88, 0x8FE6, 0x2FDC,
                                                                 0x360E, 0xC775, 0x598E, 0xCC3E, 0xBF84, 0x5553, 0x4C85, 0x9490,
                                                                 0x7518, 0xDF6F, 0x4742, 0xF325, 0x2F90, 0x6629, 0x2504, 0x2A6D};
   static const shtype_tWord brainpoolP512R1_a[32]      = {0x5EC4, 0xF187, 0x227D, 0x2A83, 0xB83B, 0x84FA, 0xE2D0, 0x850C,
                                                                 0x182D, 0x0F59, 0xF41E, 0x8778, 0xA5EC, 0x30C8, 0x3F80, 0xD1C7,
                                                                 0xCF8F, 0x0111, 0x9E6E, 0x87FF, 0x40B0, 0x4B72, 0x4675, 0xBBAB,
                                                                 0x14E4, 0x957D, 0xAFA7, 0xD283, 0xDA1F, 0x8A34, 0xEA10, 0xC446};
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord brainpoolP512R1_b[32]      = {0x3DF9, 0x1610, 0xA834, 0x41CA, 0xEA98, 0x63BC, 0x2DED, 0x5D5A, 
                                                                 0xA825, 0x3AA1, 0x0A2E, 0xF1C9, 0x8B9A, 0xC8B5, 0x7F11, 0x17A7, 
                                                                 0x2BF2, 0xC7B9, 0xE7C1, 0xAC4D, 0x77FC, 0x94CA, 0xDC08, 0x3E67, 
                                                                 0x9840, 0x50B7, 0x5EBA, 0xE5DD, 0x2809, 0xBD63, 0x8016, 0xF723};
   #endif

   #elif (SHARKSSL_BIGINT_WORDSIZE == 8)                         
   static const shtype_tWord brainpoolP512R1_prime[64]  = {0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 
                                                                 0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07, 
                                                                 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E, 
                                                                 0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71, 
                                                                 0x7D, 0x4D, 0x9B, 0x00, 0x9B, 0xC6, 0x68, 0x42, 
                                                                 0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6, 
                                                                 0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85, 
                                                                 0x28, 0xAA, 0x60, 0x56, 0x58, 0x3A, 0x48, 0xF3};
   static const shtype_tWord brainpoolP512R1_order[64]  = {0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 
                                                                 0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07, 
                                                                 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E, 
                                                                 0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x70, 
                                                                 0x55, 0x3E, 0x5C, 0x41, 0x4C, 0xA9, 0x26, 0x19, 
                                                                 0x41, 0x86, 0x61, 0x19, 0x7F, 0xAC, 0x10, 0x47, 
                                                                 0x1D, 0xB1, 0xD3, 0x81, 0x08, 0x5D, 0xDA, 0xDD, 
                                                                 0xB5, 0x87, 0x96, 0x82, 0x9C, 0xA9, 0x00, 0x69};
   static const shtype_tWord brainpoolP512R1_Gx[64]     = {0x5A, 0x2B, 0xA1, 0x4C, 0x09, 0x94, 0xE9, 0x81, 
                                                                 0x87, 0x1C, 0xB5, 0xCA, 0x00, 0x6D, 0x45, 0x73, 
                                                                 0xB2, 0xB6, 0xEA, 0x37, 0xF3, 0x6D, 0x3C, 0xF7, 
                                                                 0x24, 0x33, 0xD7, 0x6F, 0x90, 0x5C, 0x87, 0x37, 
                                                                 0x85, 0x50, 0x53, 0x95, 0x14, 0xC0, 0x1F, 0xC8, 
                                                                 0x34, 0xAB, 0x04, 0x14, 0x6D, 0xF5, 0x5E, 0x8F, 
                                                                 0x68, 0x3E, 0x4D, 0x64, 0x27, 0x2C, 0x02, 0xA4, 
                                                                 0xC4, 0xCE, 0x96, 0x09, 0x51, 0x61, 0xD9, 0xD3};
   static const shtype_tWord brainpoolP512R1_Gy[64]     = {0x8C, 0x50, 0xC9, 0xD1, 0x2A, 0xCB, 0x72, 0x81, 
                                                                 0x9A, 0x5E, 0xD7, 0xDA, 0x87, 0x0F, 0x3F, 0x9B,
                                                                 0x58, 0x5D, 0x2B, 0x77, 0xCD, 0x9D, 0x3F, 0x8C, 
                                                                 0x7C, 0x17, 0x0B, 0x88, 0x8F, 0xE6, 0x2F, 0xDC,
                                                                 0x36, 0x0E, 0xC7, 0x75, 0x59, 0x8E, 0xCC, 0x3E, 
                                                                 0xBF, 0x84, 0x55, 0x53, 0x4C, 0x85, 0x94, 0x90,
                                                                 0x75, 0x18, 0xDF, 0x6F, 0x47, 0x42, 0xF3, 0x25, 
                                                                 0x2F, 0x90, 0x66, 0x29, 0x25, 0x04, 0x2A, 0x6D};
   static const shtype_tWord brainpoolP512R1_a[64]      = {0x5E, 0xC4, 0xF1, 0x87, 0x22, 0x7D, 0x2A, 0x83, 
                                                                 0xB8, 0x3B, 0x84, 0xFA, 0xE2, 0xD0, 0x85, 0x0C,
                                                                 0x18, 0x2D, 0x0F, 0x59, 0xF4, 0x1E, 0x87, 0x78, 
                                                                 0xA5, 0xEC, 0x30, 0xC8, 0x3F, 0x80, 0xD1, 0xC7,
                                                                 0xCF, 0x8F, 0x01, 0x11, 0x9E, 0x6E, 0x87, 0xFF, 
                                                                 0x40, 0xB0, 0x4B, 0x72, 0x46, 0x75, 0xBB, 0xAB,
                                                                 0x14, 0xE4, 0x95, 0x7D, 0xAF, 0xA7, 0xD2, 0x83, 
                                                                 0xDA, 0x1F, 0x8A, 0x34, 0xEA, 0x10, 0xC4, 0x46};
   #if SHARKSSL_ECC_VERIFY_POINT
   static const shtype_tWord brainpoolP512R1_b[64]      = {0x3D, 0xF9, 0x16, 0x10, 0xA8, 0x34, 0x41, 0xCA, 
                                                                 0xEA, 0x98, 0x63, 0xBC, 0x2D, 0xED, 0x5D, 0x5A, 
                                                                 0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9, 
                                                                 0x8B, 0x9A, 0xC8, 0xB5, 0x7F, 0x11, 0x17, 0xA7, 
                                                                 0x2B, 0xF2, 0xC7, 0xB9, 0xE7, 0xC1, 0xAC, 0x4D, 
                                                                 0x77, 0xFC, 0x94, 0xCA, 0xDC, 0x08, 0x3E, 0x67, 
                                                                 0x98, 0x40, 0x50, 0xB7, 0x5E, 0xBA, 0xE5, 0xDD, 
                                                                 0x28, 0x09, 0xBD, 0x63, 0x80, 0x16, 0xF7, 0x23};
   #endif
   #endif  
   #endif  

   baAssert(o);
   baAssert((rightsvalid >= SHARKSSL_EC_CURVE_ID_SECP256R1) || (rightsvalid <= SHARKSSL_EC_CURVE_ID_BRAINPOOLP512R1));

   switch (rightsvalid)
   {
      #if SHARKSSL_ECC_USE_SECP256R1
      case SHARKSSL_EC_CURVE_ID_SECP256R1:
         SharkSslECCurve_constructor_(o, 256, SECP256R1);
         break;
      #endif

      #if SHARKSSL_ECC_USE_SECP384R1
      case SHARKSSL_EC_CURVE_ID_SECP384R1:
         SharkSslECCurve_constructor_(o, 384, SECP384R1);
         break;
      #endif

      #if SHARKSSL_ECC_USE_SECP521R1
      case SHARKSSL_EC_CURVE_ID_SECP521R1:
         SharkSslECCurve_constructor_(o, 521, SECP521R1);
         break;
      #endif

      #if SHARKSSL_ECC_USE_BRAINPOOLP256R1
      case SHARKSSL_EC_CURVE_ID_BRAINPOOLP256R1:
         SharkSslECCurve_constructor_(o, 256, brainpoolP256R1);
         break;
      #endif

      #if SHARKSSL_ECC_USE_BRAINPOOLP384R1
      case SHARKSSL_EC_CURVE_ID_BRAINPOOLP384R1:
         SharkSslECCurve_constructor_(o, 384, brainpoolP384R1);
         break;
      #endif

      #if SHARKSSL_ECC_USE_BRAINPOOLP512R1
      case SHARKSSL_EC_CURVE_ID_BRAINPOOLP512R1:
         SharkSslECCurve_constructor_(o, 512, brainpoolP512R1);
         break;
      #endif

      default:
         memset(o, 0, sizeof(SharkSslECCurve));
   }

   return;
}

typedef void (*func_mulmod)(const shtype_t*, const shtype_t*, shtype_t*, shtype_t*, shtype_tWord*);
typedef void (*func_fmulmod)(const shtype_t*, const shtype_t*, shtype_t*, shtype_t*, shtype_tWord);

typedef struct
{
   shtype_t A, B, C, D, E, F;
   #if (SHARKSSL_ECC_USE_NIST && SHARKSSL_ECC_USE_BRAINPOOL)
   func_mulmod mulmod;
   func_fmulmod fmulmod;
   #endif
   #if SHARKSSL_ECC_USE_BRAINPOOL
   shtype_t *factor_a;
   shtype_tWord mu;
   #endif
} SharkSslEC_temp;


#if (SHARKSSL_ECC_USE_NIST && SHARKSSL_ECC_USE_BRAINPOOL)
#define probehandler(x,y,z) brightnesslimit->fmulmod(x, y, z, mod, brightnesslimit->mu);
#define traceguest(x,y,z)  brightnesslimit->mulmod(x, y, z, mod, &brightnesslimit->D.mem[0]);
void shtype_t_mulmodNORMAL(const shtype_t *o1, const shtype_t *o2, shtype_t *deltadevices, shtype_t *cpuidfeature, shtype_tWord *afterhandler)
{
   hotplugpgtable(o1, o2, deltadevices);
   envdatamcheck(deltadevices, cpuidfeature, afterhandler);
}

void shtype_t_mulmodMONTGOMERY(const shtype_t *o1, const shtype_t *o2, shtype_t *deltadevices, shtype_t *cpuidfeature, shtype_tWord mu)
{
   writebytes(o1, o2, deltadevices, cpuidfeature, mu);
}

void shtype_t_mulmodNIST(const shtype_t *o1, const shtype_t *o2, shtype_t *deltadevices, shtype_t *cpuidfeature, shtype_tWord mu)
{
   (void)mu;
   hotplugpgtable(o1, o2, deltadevices);
   availableasids(deltadevices, cpuidfeature);
}

#elif SHARKSSL_ECC_USE_NIST  
   #define probehandler(x,y,z) hotplugpgtable(x, y, z); availableasids(z, mod)
   #define traceguest(x,y,z)  hotplugpgtable(x, y, z); availableasids(z, mod)

#elif SHARKSSL_ECC_USE_BRAINPOOL  
   #define probehandler(x,y,z) writebytes(x, y, z, mod, brightnesslimit->mu)
   #define traceguest(x,y,z)  hotplugpgtable(x, y, z); envdatamcheck(z, mod, &brightnesslimit->D.mem[0])

#else
   

#endif


#if SHARKSSL_ECC_USE_BRAINPOOL
void SharkSslEC_temp_setmulmod(SharkSslEC_temp *brightnesslimit, SharkSslECCurve *o)
{
   if (((shtype_tWord)-3) == o->a.beg[0])
   {
      #if (SHARKSSL_ECC_USE_NIST && SHARKSSL_ECC_USE_BRAINPOOL)
      brightnesslimit->mulmod = (func_mulmod)shtype_t_mulmodNIST;
      brightnesslimit->fmulmod = shtype_t_mulmodNIST;
      #endif
      brightnesslimit->factor_a = NULL;
      brightnesslimit->mu = 0;
   }
   else
   {
      #if (SHARKSSL_ECC_USE_NIST && SHARKSSL_ECC_USE_BRAINPOOL)
      brightnesslimit->mulmod = shtype_t_mulmodNORMAL;
      brightnesslimit->fmulmod = shtype_t_mulmodMONTGOMERY;
      #endif
      brightnesslimit->factor_a = &(o->a);
      brightnesslimit->mu = remapcfgspace(&o->prime);
   }
   return;
}

#else
#define SharkSslEC_temp_setmulmod(t,o)

#endif


int initialdomain(SharkSslECCurve *o, SharkSslECPoint *p)
{
   if ((void*)p != (void*)NULL)
   {
      if ((p->x.len <= o->G.x.len) && (p->y.len <= o->G.y.len))
      {
         #if SHARKSSL_ECC_VERIFY_POINT
         
         SharkSslEC_temp doublefnmul, *brightnesslimit;
         shtype_t *mod;
         shtype_tWord *tmp_b, *tmp_buf;
         U16 i = o->prime.len * 2;

         mod = &o->prime;
         brightnesslimit = &doublefnmul;  
         if ((timerwrite(&p->x, mod)) || (timerwrite(&p->y, mod)))
         {
            return 2;  
         }

         i = (o->prime.len << 1) + 1;  
         tmp_b = (shtype_tWord*)baMalloc(pcmciapdata(i * SHARKSSL__M * 6));
         if (tmp_b == (void*)0)
         {
            return 3;  
         }

         tmp_buf = (shtype_tWord*)selectaudio(tmp_b);

         traceaddress(&doublefnmul.A, i, tmp_buf); tmp_buf += i;
         traceaddress(&doublefnmul.B, i, tmp_buf); tmp_buf += i;
         traceaddress(&doublefnmul.C, i, tmp_buf); tmp_buf += i;
         traceaddress(&doublefnmul.D, i, tmp_buf); tmp_buf += i;
         traceaddress(&doublefnmul.E, i, tmp_buf); tmp_buf += i;
         traceaddress(&doublefnmul.F, i, tmp_buf);

         SharkSslEC_temp_setmulmod(&doublefnmul, o);

         traceguest(&p->x, &p->x, &doublefnmul.A);    
         traceguest(&p->x, &doublefnmul.A, &doublefnmul.B);   
         setupsdhci1(&doublefnmul.B, &o->b, mod);      
         #if (SHARKSSL_ECC_USE_NIST && SHARKSSL_ECC_USE_BRAINPOOL)
         if (NULL == doublefnmul.factor_a)  
         #endif
         #if SHARKSSL_ECC_USE_NIST
         {
            keypaddevice(&doublefnmul.B, &p->x, mod);
            keypaddevice(&doublefnmul.B, &p->x, mod);
            keypaddevice(&doublefnmul.B, &p->x, mod);  
         }
         #if SHARKSSL_ECC_USE_BRAINPOOL
         else
         #endif
         #endif
         #if SHARKSSL_ECC_USE_BRAINPOOL
         {
            
            doublefnmul.D.len = 1; 
            doublefnmul.D.beg[0] = 1;
            writebytes(&doublefnmul.D, &o->a, &doublefnmul.C, &o->prime, doublefnmul.mu);
            traceguest(&doublefnmul.C, &p->x, &doublefnmul.A);  
            setupsdhci1(&doublefnmul.B, &doublefnmul.A, mod);    
         }
         #endif
         traceguest(&p->y, &p->y, &doublefnmul.A);  
         keypaddevice(&doublefnmul.A, &doublefnmul.B, mod);   
         blastscache(&doublefnmul.A);
         i = (U16)(doublefnmul.A.len - 1) | (U16)(doublefnmul.A.beg[0] & 0xFFFF);
         #if (SHARKSSL_BIGINT_WORDSIZE == 32)
         i |= (doublefnmul.A.beg[0] >> 16);
         #endif
         baFree((void*)tmp_b);
         if (i)
         {
            return 1;  
         }
         #endif
         o->G.x = p->x;
         o->G.y = p->y;
      }
      else
      {
         memset(o, 0, sizeof(SharkSslECCurve));
         return 4;  
      }
   }

   return 0;
}


typedef struct  
{
   shtype_t x, y, z;
} SharkSslECPointJ;

#define SharkSslECPointJ_copy(s,d) \
        unassignedvector(&((s)->x), &((d)->x)); unassignedvector(&((s)->y), &((d)->y)); unassignedvector(&((s)->z), &((d)->z))


static void timerconfig(SharkSslECPointJ *p,
                                    shtype_t   *mod,
                                    SharkSslEC_temp  *brightnesslimit)
{
   probehandler(&p->y, &p->z, &brightnesslimit->A);
   setupsdhci1(&brightnesslimit->A, &brightnesslimit->A, mod);
   probehandler(&p->y, &p->y, &brightnesslimit->B);
   probehandler(&p->z, &p->z, &brightnesslimit->C);
   unassignedvector(&brightnesslimit->A, &p->z);
   probehandler(&p->x, &brightnesslimit->B, &brightnesslimit->A);
   setupsdhci1(&brightnesslimit->A, &brightnesslimit->A, mod);
   setupsdhci1(&brightnesslimit->A, &brightnesslimit->A, mod);
   probehandler(&brightnesslimit->B, &brightnesslimit->B, &brightnesslimit->D);
   unassignedvector(&brightnesslimit->D, &brightnesslimit->B);
   setupsdhci1(&brightnesslimit->B, &brightnesslimit->B, mod);
   setupsdhci1(&brightnesslimit->B, &brightnesslimit->B, mod);
   setupsdhci1(&brightnesslimit->B, &brightnesslimit->B, mod);
   #if SHARKSSL_ECC_USE_BRAINPOOL
   if (brightnesslimit->factor_a != NULL)  
   {
      probehandler(&p->x, &p->x, &brightnesslimit->D);
      unassignedvector(&brightnesslimit->D, &brightnesslimit->F);
      setupsdhci1(&brightnesslimit->D, &brightnesslimit->D, mod);
      setupsdhci1(&brightnesslimit->D, &brightnesslimit->F, mod);
      probehandler(&brightnesslimit->C, &brightnesslimit->C, &brightnesslimit->F);
      probehandler(brightnesslimit->factor_a, &brightnesslimit->F, &brightnesslimit->E);
      setupsdhci1(&brightnesslimit->D, &brightnesslimit->E, mod);
   }
   #if SHARKSSL_ECC_USE_NIST
   else
   #endif
   #endif
   #if SHARKSSL_ECC_USE_NIST
   {
      unassignedvector(&p->x, &brightnesslimit->E);
      keypaddevice(&brightnesslimit->E, &brightnesslimit->C, mod);
      setupsdhci1(&brightnesslimit->C, &p->x, mod);
      probehandler(&brightnesslimit->E, &brightnesslimit->C, &brightnesslimit->D);
      unassignedvector(&brightnesslimit->D, &brightnesslimit->E);
      setupsdhci1(&brightnesslimit->E, &brightnesslimit->E, mod);
      setupsdhci1(&brightnesslimit->D, &brightnesslimit->E, mod);
   }
   #endif
   probehandler(&brightnesslimit->D, &brightnesslimit->D, &brightnesslimit->F);
   keypaddevice(&brightnesslimit->F, &brightnesslimit->A, mod);
   keypaddevice(&brightnesslimit->F, &brightnesslimit->A, mod);
   unassignedvector(&brightnesslimit->F, &p->x);
   keypaddevice(&brightnesslimit->A, &brightnesslimit->F, mod);
   probehandler(&brightnesslimit->D, &brightnesslimit->A, &brightnesslimit->F);
   keypaddevice(&brightnesslimit->F, &brightnesslimit->B, mod);
   unassignedvector(&brightnesslimit->F, &p->y);
}


static void deviceu2ootg(SharkSslECPointJ *p,
                                 SharkSslECPoint  *g,
                                 shtype_t   *mod,
                                 SharkSslEC_temp  *brightnesslimit)
{
   
   probehandler(&p->z, &p->z, &brightnesslimit->A);
   probehandler(&brightnesslimit->A, &g->x, &brightnesslimit->C);
   keypaddevice(&brightnesslimit->C, &p->x, mod);
   probehandler(&brightnesslimit->A, &p->z, &brightnesslimit->D);
   probehandler(&brightnesslimit->D, &g->y, &brightnesslimit->A);
   keypaddevice(&brightnesslimit->A, &p->y, mod);
   probehandler(&brightnesslimit->C, &p->z, &brightnesslimit->B);
   unassignedvector(&brightnesslimit->B, &p->z);
   probehandler(&brightnesslimit->C, &brightnesslimit->C, &brightnesslimit->B);
   probehandler(&brightnesslimit->B, &brightnesslimit->C, &brightnesslimit->F);
   unassignedvector(&p->x, &brightnesslimit->C);
   setupsdhci1(&brightnesslimit->C, &p->x, mod);
   probehandler(&brightnesslimit->C, &brightnesslimit->B, &brightnesslimit->D);
   setupsdhci1(&brightnesslimit->D, &brightnesslimit->F, mod);
   probehandler(&brightnesslimit->A, &brightnesslimit->A, &brightnesslimit->E);
   keypaddevice(&brightnesslimit->E, &brightnesslimit->D, mod);
   probehandler(&brightnesslimit->F, &p->y, &brightnesslimit->D);
   probehandler(&brightnesslimit->B, &p->x, &brightnesslimit->F);
   unassignedvector(&brightnesslimit->E, &p->x);
   keypaddevice(&brightnesslimit->F, &p->x, mod);
   probehandler(&brightnesslimit->F, &brightnesslimit->A, &brightnesslimit->E);
   keypaddevice(&brightnesslimit->E, &brightnesslimit->D, mod);
   unassignedvector(&brightnesslimit->E, &p->y);
}


static void panicblink(SharkSslECPointJ *j,
                                      SharkSslECPoint  *p,
                                      shtype_t   *mod,
                                      SharkSslEC_temp  *brightnesslimit)
{
   ioswabwdefault(&j->z, mod, &brightnesslimit->A.mem[0]);
   traceguest(&j->z, &j->z, &brightnesslimit->A);     
   traceguest(&j->z, &brightnesslimit->A, &brightnesslimit->B);  
   traceguest(&j->x, &brightnesslimit->A, &brightnesslimit->C);
   unassignedvector(&brightnesslimit->C, &p->x);
   traceguest(&j->y, &brightnesslimit->B, &brightnesslimit->C);
   unassignedvector(&brightnesslimit->C, &p->y);
}


#undef probehandler
#undef traceguest


#if (!SHARKSSL_ECDSA_ONLY_VERIFY)
int unregisterskciphers(SharkSslECCurve *o,
                             shtype_t *k,
                             SharkSslECPoint *deltadevices)
{
   SharkSslEC_temp brightnesslimit;
   shtype_tWord *tmp_b, *tmp_buf, bitmask;
   #if (SHARKSSL_ECC_TIMING_RESISTANT)
   shtype_tWord m0;
   #endif
   #if SHARKSSL_ECC_TIMING_RESISTANT
   SharkSslECPointJ point[2];
   #else
   SharkSslECPointJ point[1];
   #endif
   U16 i, flash1resources;

   i = o->prime.len;
   baAssert((deltadevices->x.len == i) && (deltadevices->y.len == i));
   #if SHARKSSL_ECC_TIMING_RESISTANT
   flash1resources  = (i * SHARKSSL__M) * (3 + 3 + 12);
   #else
   flash1resources  = (i * SHARKSSL__M) * (3 + 12);
   #endif

   SharkSslEC_temp_setmulmod(&brightnesslimit, o);
   #if SHARKSSL_ECC_USE_BRAINPOOL
   #if SHARKSSL_ECC_USE_NIST
   if (brightnesslimit.factor_a != NULL)
   #endif
   {
      
      flash1resources += (6 * SHARKSSL__M);  
   }
   #endif

   tmp_b = (shtype_tWord*)baMalloc(pcmciapdata(flash1resources));
   if (tmp_b == (void*)0)
   {
      return 1;
   }

   tmp_buf = (shtype_tWord*)selectaudio(tmp_b);

   #if SHARKSSL_ECC_TIMING_RESISTANT
   m0 = 0;
   #endif

   traceaddress(&point[0].x, i, tmp_buf); tmp_buf += i;
   traceaddress(&point[0].y, i, tmp_buf); tmp_buf += i;
   traceaddress(&point[0].z, i, tmp_buf); tmp_buf += i;
   mipidplatform(&(o->G), &point[0]);
   deviceparse(&point[0].z);
   point[0].z.beg[i - 1] = 1;  

   #if SHARKSSL_ECC_TIMING_RESISTANT
   traceaddress(&point[1].x, i, tmp_buf); tmp_buf += i;
   traceaddress(&point[1].y, i, tmp_buf); tmp_buf += i;
   traceaddress(&point[1].z, i, tmp_buf); tmp_buf += i;
   SharkSslECPointJ_copy(&point[0], &point[1]);
   #endif

   
   i <<= 1;
   #if SHARKSSL_ECC_USE_BRAINPOOL
   #if SHARKSSL_ECC_USE_NIST
   if (brightnesslimit.factor_a != NULL)
   #endif
   {
      i++;  
      brightnesslimit.A.beg = brightnesslimit.A.mem = tmp_buf;
      brightnesslimit.A.len = o->prime.len + 1;
      deviceparse(&brightnesslimit.A);
      brightnesslimit.A.beg[0] = 1;
      updatepmull(&brightnesslimit.A, &o->prime);
      blastscache(&brightnesslimit.A);
      unassignedvector(&brightnesslimit.A, &point[0].z);  
   }
   #endif
   traceaddress(&brightnesslimit.A, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.B, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.C, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.D, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.E, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.F, i, tmp_buf);

   blastscache(k);  
   bitmask = (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1));
   #if SHARKSSL_ECC_TIMING_RESISTANT
   m0  = (SHARKSSL_BIGINT_WORDSIZE - 1);
   for (; bitmask > 0; bitmask >>= 1, m0--)
   #else
   for (; bitmask > 0; bitmask >>= 1)
   #endif
   {
      if (k->beg[0] & bitmask)
      {
         bitmask >>= 1;
         #if SHARKSSL_ECC_TIMING_RESISTANT
         m0--;
         #endif
         break;
      }
   }
   for (i = 0; i < k->len; i++)
   {
      #if SHARKSSL_ECC_TIMING_RESISTANT
      for (; bitmask > 0; bitmask >>= 1, m0--)
      #else
      for (; bitmask > 0; bitmask >>= 1)
      #endif
      {
         timerconfig(&point[0], &o->prime, &brightnesslimit);

         #if SHARKSSL_ECC_TIMING_RESISTANT
         deviceu2ootg(&point[((~(k->beg[i] & bitmask)) >> m0) & 0x1], &o->G, &o->prime, &brightnesslimit);

         #else
         if (k->beg[i] & bitmask)
         {
            deviceu2ootg(&point[0], &o->G, &o->prime, &brightnesslimit);
         }

         #endif  
      }

      bitmask = (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1));
      #if SHARKSSL_ECC_TIMING_RESISTANT
      m0  = (SHARKSSL_BIGINT_WORDSIZE - 1);
      #endif
   }

   #if SHARKSSL_ECC_USE_BRAINPOOL
   #if SHARKSSL_ECC_USE_NIST
   if (brightnesslimit.factor_a != NULL)
   #endif
   {
      
      brightnesslimit.A.len = 1; 
      brightnesslimit.A.beg[0] = 1;
      writebytes(&brightnesslimit.A, &point[0].x, &brightnesslimit.C, &o->prime, brightnesslimit.mu);
      writebytes(&brightnesslimit.A, &point[0].y, &brightnesslimit.D, &o->prime, brightnesslimit.mu);
      writebytes(&brightnesslimit.A, &point[0].z, &brightnesslimit.E, &o->prime, brightnesslimit.mu);
      unassignedvector(&brightnesslimit.C, &point[0].x);
      unassignedvector(&brightnesslimit.D, &point[0].y);
      unassignedvector(&brightnesslimit.E, &point[0].z);
   }
   #endif

   panicblink(&point[0], deltadevices, &o->prime, &brightnesslimit);

   baFree((void*)tmp_b);
   return 0;
}
#endif  


#if (SHARKSSL_ENABLE_ECDSA || (SHARKSSL_ENABLE_ECDH_RSA && SHARKSSL_ENABLE_CLIENT_AUTH))
int directalloc(SharkSslECCurve *S,
                              shtype_t *d,
                              SharkSslECCurve *T,
                              shtype_t *e,
                              SharkSslECPoint *deltadevices)
{
   SharkSslEC_temp brightnesslimit;
   shtype_tWord *tmp_b, *tmp_buf, bitmask;
   SharkSslECPointJ point[1];
   SharkSslECPoint sum;
   #if SHARKSSL_ECC_USE_BRAINPOOL
   SharkSslECPoint TG, *TGP;
   #endif
   U16 i, flash1resources;

   i = S->prime.len;
   if ((i != T->prime.len) || (S->bits != T->bits) || (d->len != e->len))
   {
      return 1;
   }

   baAssert(T->prime.beg == S->prime.beg);
   baAssert((deltadevices->x.len == i) && (deltadevices->y.len == i));

   flash1resources  = (i * SHARKSSL__M) * (3 + 2 + 12);

   SharkSslEC_temp_setmulmod(&brightnesslimit, S);
   #if SHARKSSL_ECC_USE_BRAINPOOL
   #if SHARKSSL_ECC_USE_NIST
   if (brightnesslimit.factor_a != NULL)
   #endif
   {
      
      flash1resources += (6 * SHARKSSL__M);
      
      flash1resources += (i * SHARKSSL__M) * 2; 
   }
   #endif

   tmp_b = (shtype_tWord*)baMalloc(pcmciapdata(flash1resources));
   memset(tmp_b, 0xBE, pcmciapdata(flash1resources));  

   if (tmp_b == (void*)0)
   {
      return 1;
   }

   tmp_buf = (shtype_tWord*)selectaudio(tmp_b);

   traceaddress(&point[0].x, i, tmp_buf); tmp_buf += i;
   traceaddress(&point[0].y, i, tmp_buf); tmp_buf += i;
   traceaddress(&point[0].z, i, tmp_buf); tmp_buf += i;
   deviceparse(&point[0].z);
   point[0].z.beg[i - 1] = 1;  

   mipidplatform(&(S->G), &point[0]);

   receivebroadcast(&sum, i, tmp_buf, tmp_buf + i); tmp_buf += (i << 1);

   i <<= 1;
   #if SHARKSSL_ECC_USE_BRAINPOOL
   #if SHARKSSL_ECC_USE_NIST
   if (brightnesslimit.factor_a != NULL)
   #endif
   {
      
      receivebroadcast(&TG, T->prime.len, tmp_buf, tmp_buf + T->prime.len);
      tmp_buf += i;

      i++;  
      brightnesslimit.A.beg = brightnesslimit.A.mem = tmp_buf;  
      brightnesslimit.A.len = T->prime.len + 1;
      deviceparse(&brightnesslimit.A);
      brightnesslimit.A.beg[0] = 1;
      updatepmull(&brightnesslimit.A, &T->prime);
      blastscache(&brightnesslimit.A);
      unassignedvector(&brightnesslimit.A, &point[0].z);  

      
      hotplugpgtable(&T->G.x, &point[0].z, &brightnesslimit.A);  
      envdatamcheck(&brightnesslimit.A, &T->prime, tmp_buf + i);
      unassignedvector(&brightnesslimit.A, &TG.x);
      hotplugpgtable(&T->G.y, &point[0].z, &brightnesslimit.A);
      envdatamcheck(&brightnesslimit.A, &T->prime, tmp_buf + i);
      unassignedvector(&brightnesslimit.A, &TG.y);
   }
   #endif
   traceaddress(&brightnesslimit.A, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.B, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.C, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.D, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.E, i, tmp_buf); tmp_buf += i;
   traceaddress(&brightnesslimit.F, i, tmp_buf);


   #if SHARKSSL_ECC_USE_BRAINPOOL
   #if SHARKSSL_ECC_USE_NIST
   if (brightnesslimit.factor_a != NULL)
   #endif
   {
      
      deviceu2ootg(&point[0], &TG, &S->prime, &brightnesslimit);
      
      brightnesslimit.A.len = 1; 
      brightnesslimit.A.beg[0] = 1;
      writebytes(&brightnesslimit.A, &point[0].x, &brightnesslimit.C, &T->prime, brightnesslimit.mu);
      writebytes(&brightnesslimit.A, &point[0].y, &brightnesslimit.D, &T->prime, brightnesslimit.mu);
      writebytes(&brightnesslimit.A, &point[0].z, &brightnesslimit.E, &T->prime, brightnesslimit.mu);
      unassignedvector(&brightnesslimit.C, &point[0].x);
      unassignedvector(&brightnesslimit.D, &point[0].y);
      unassignedvector(&brightnesslimit.E, &point[0].z);
   }
   #if SHARKSSL_ECC_USE_NIST
   else
   #endif
   #endif
   #if SHARKSSL_ECC_USE_NIST
   {
      
      deviceu2ootg(&point[0], &T->G, &S->prime, &brightnesslimit);
   }
   #endif

   panicblink(&point[0], &sum, &S->prime, &brightnesslimit);

   #if SHARKSSL_ECC_USE_BRAINPOOL
   #if SHARKSSL_ECC_USE_NIST
   if (brightnesslimit.factor_a != NULL)
   #endif
   {
      
      brightnesslimit.A.len = T->prime.len + 1;
      deviceparse(&brightnesslimit.A);
      brightnesslimit.A.beg[0] = 1;
      updatepmull(&brightnesslimit.A, &T->prime);
      blastscache(&brightnesslimit.A);
      unassignedvector(&brightnesslimit.A, &point[0].z);

      hotplugpgtable(&sum.x, &point[0].z, &brightnesslimit.A);
      envdatamcheck(&brightnesslimit.A, &T->prime, &brightnesslimit.B.beg[0]);
      unassignedvector(&brightnesslimit.A, &sum.x);
      hotplugpgtable(&sum.y, &point[0].z, &brightnesslimit.A);
      envdatamcheck(&brightnesslimit.A, &T->prime, &brightnesslimit.B.beg[0]);
      unassignedvector(&brightnesslimit.A, &sum.y);
      TGP = &TG;
   }
   #if SHARKSSL_ECC_USE_NIST
   else
   #endif
   #endif
   #if SHARKSSL_ECC_USE_NIST
   {
      
      point[0].z.len = S->prime.len;
      deviceparse(&point[0].z);
      point[0].z.beg[S->prime.len - 1] = 1;  
      #if SHARKSSL_ECC_USE_BRAINPOOL
      TGP = &T->G;
      #endif
   }
   #endif

   while ((e->beg[0] == 0) && (d->beg[0] == 0) && (e->len > 1) && (d->len > 1))
   {
      e->beg++;
      e->len--;
      d->beg++;
      d->len--;
   }
   bitmask = (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1));
   for (; bitmask > 0; bitmask >>= 1)
   {
      if (e->beg[0] & bitmask)
      {
         if (d->beg[0] & bitmask)
         {
            mipidplatform(&sum, &point[0]);
         }
         else
         #if SHARKSSL_ECC_USE_BRAINPOOL
         {
            mipidplatform(TGP, &point[0]);
         }
         #else
         {
            mipidplatform(&(T->G), &point[0]);
         }
         #endif
      }
      else if (d->beg[0] & bitmask)
      {
         mipidplatform(&(S->G), &point[0]);
      }
      else
      {
         continue;
      }

      bitmask >>= 1;
      break;
   }

   for (i = 0; i < e->len; i++)
   {
      for (; bitmask > 0; bitmask >>= 1)
      {
         timerconfig(&point[0], &S->prime, &brightnesslimit);

         if (e->beg[i] & bitmask)
         {
            if (d->beg[i] & bitmask)
            {
               deviceu2ootg(&point[0], &sum, &S->prime, &brightnesslimit);
            }
            else
            #if SHARKSSL_ECC_USE_BRAINPOOL
            {
               deviceu2ootg(&point[0], TGP, &S->prime, &brightnesslimit);
            }
            #else
            {
               deviceu2ootg(&point[0], &T->G, &S->prime, &brightnesslimit);
            }
            #endif
         }
         else if (d->beg[i] & bitmask)
         {
            deviceu2ootg(&point[0], &S->G, &S->prime, &brightnesslimit);
         }
      }

      bitmask = (shtype_tWord)((shtype_tWord)1 << (SHARKSSL_BIGINT_WORDSIZE - 1));
   }

   #if SHARKSSL_ECC_USE_BRAINPOOL
   #if SHARKSSL_ECC_USE_NIST
   if (brightnesslimit.factor_a != NULL)
   #endif
   {
      
      brightnesslimit.A.len = 1; 
      brightnesslimit.A.beg[0] = 1;
      writebytes(&brightnesslimit.A, &point[0].x, &brightnesslimit.C, &T->prime, brightnesslimit.mu);
      writebytes(&brightnesslimit.A, &point[0].y, &brightnesslimit.D, &T->prime, brightnesslimit.mu);
      writebytes(&brightnesslimit.A, &point[0].z, &brightnesslimit.E, &T->prime, brightnesslimit.mu);
      unassignedvector(&brightnesslimit.C, &point[0].x);
      unassignedvector(&brightnesslimit.D, &point[0].y);
      unassignedvector(&brightnesslimit.E, &point[0].z);
   }
   #endif

   panicblink(&point[0], deltadevices, &S->prime, &brightnesslimit);

   baFree((void*)tmp_b);
   return 0;
}
#endif  


#if SHARKSSL_ENABLE_ECCKEY_CREATE
extern U8 controllerregister(U16 defaultsdhci1);

SHARKSSL_API int SharkSslECCKey_create(SharkSslECCKey *mcbspplatform, U16 defaultsdhci1)
{
   static const shtype_tWord w_one = 0x1;
   SharkSslECCurve nandflashpartition;
   SharkSslECPoint Q;
   shtype_t one, d, order;
   U8 *buf;
   int buttonsbuffalo = 0;
   U8  allockuser, plen;

   *mcbspplatform = NULL;
   plen = controllerregister(defaultsdhci1);
   if (0 == plen)
   {
      return -1;  
   }
   allockuser = (U8)((plen + 3) & ~3);  
   buttonsbuffalo = (int)(((unsigned int)allockuser << 1) + allockuser + 8);
   *mcbspplatform = buf = (U8*)baMalloc(buttonsbuffalo);
   if (NULL == buf)
   {
      return -1;  
   }
   if (sharkssl_rng(buf, allockuser + 8))
   {
      baFree(buf);
      return -1;  
   }

   onenandpartitions(&one, sizeof(shtype_tWord) * 8, &w_one);
   onenandpartitions(&d, ((allockuser + 8) * 8), buf);
   clearerrors(&nandflashpartition, defaultsdhci1);
   #if SHARKSSL_ECC_USE_SECP521R1
   if (allockuser > plen)
   {
      d.beg[0] &= nandflashpartition.prime.beg[0];
   }
   #endif

   
   buf += allockuser + 8;
   onenandpartitions(&order, (nandflashpartition.prime.len * SHARKSSL_BIGINT_WORDSIZE), buf);  
   unassignedvector(&(nandflashpartition.order), &order);
   updatepmull(&order, &one);
   suspendfinish(&d, &order);
   resolverelocs(&d, &one);

   updatefrequency(&Q, (nandflashpartition.prime.len * SHARKSSL_BIGINT_WORDSIZE), buf , buf + allockuser);  
   unregisterskciphers(&nandflashpartition, &d, &Q);

   buf = *mcbspplatform;
   buf[0] = 0x30;
   buf[1] = 0x82;
   buf[2] = buf[3] = 0x00;
   buf[4] = 0x02;  
   buf[5] = buf[7] = plen;
   buf[6] = (U8)defaultsdhci1;
   memmove_endianess(&buf[8], &buf[8], (allockuser << 1) + allockuser);
   #if SHARKSSL_ECC_USE_SECP521R1
   if (allockuser > plen)
   {
      allockuser -= plen;
      memmove(&buf[8], &buf[8 + allockuser], plen);
      memmove(&buf[8 + plen], &buf[8 + plen + (allockuser * 2)], plen);
      memmove(&buf[8 + (plen * 2)], &buf[8 + (plen * 2) + (allockuser * 2) + allockuser], plen);
   }
   #endif

   return buttonsbuffalo;
}

#endif

#endif  

