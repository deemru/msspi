// microsspi

#ifdef _WIN32
#ifndef __MINGW32__
#   pragma warning( disable:4820 )
#   pragma warning( disable:4710 )
#   pragma warning( disable:4668 )
#   pragma warning( disable:4623 )
#   pragma warning( disable:4625 )
#   pragma warning( disable:4626 )
#   pragma warning( disable:5026 )
#   pragma warning( disable:5027 )
#   pragma warning( disable:4774 )
#endif // __MINGW32__
#include <Windows.h>
#endif

#if defined( __cplusplus )
extern "C" {
#endif
#ifdef _WIN32
#define LIBLOAD( name ) LoadLibraryA( name )
#define LIBFUNC( lib, name ) (UINT_PTR)GetProcAddress( lib, name )
#else
#include <dlfcn.h>
#define LIBLOAD( name ) dlopen( name, RTLD_LAZY )
#define LIBFUNC( lib, name ) dlsym( lib, name )
#endif
#if defined( __cplusplus )
}
#endif

#if defined( QT_NO_EXCEPTIONS ) || defined( NO_EXCEPTIONS ) || ( defined( __clang__ ) && !defined( __EXCEPTIONS ) )
#define MSSPIEHTRY
#define MSSPIEHCATCH
#define MSSPIEHCATCH_HERRRET( ret )
#define MSSPIEHCATCH_RET( ret )
#define MSSPIEHCATCH_0 MSSPIEHCATCH
#else // EXCEPTIONS
#define MSSPIEHTRY try {
#define MSSPIEHCATCH } catch( ... ) {
#define MSSPIEHCATCH_HERRRET( ret ) MSSPIEHCATCH; h->state |= MSSPI_ERROR; return ret; }
#define MSSPIEHCATCH_RET( ret ) MSSPIEHCATCH; return ret; }
#define MSSPIEHCATCH_0 MSSPIEHCATCH; }
#endif // EXCEPTIONS

#ifndef EXTERCALL
#if defined( __clang__ ) && defined( __has_attribute ) // NOCFI
#if __has_attribute( no_sanitize )
#if __cplusplus >= 201103L
#define EXTERCALL( call ) [&]()__attribute__((no_sanitize("cfi-icall"))){ call; }()
#endif
#endif
#endif
#ifndef EXTERCALL
#define EXTERCALL( call ) call
#endif
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define SECURITY_WIN32
#ifdef _WIN32
#ifdef __MINGW32__
#include "CSP_WinDef.h"
#include "CSP_WinCrypt.h"
#include "CSP_Sspi.h"
#include "CSP_SChannel.h"
#define UNIX
#else
#include <schannel.h>
#include <sspi.h>
#endif
#else
#define LEGACY_FORMAT_MESSAGE_IMPL
#include "CSP_WinDef.h"
#include "CSP_WinCrypt.h"
#include "CSP_Sspi.h"
#include "CSP_SChannel.h"
#include <sys/time.h>

static DWORD GetTickCount()
{
    struct timeval tv;
    if( gettimeofday( &tv, NULL ) != 0 )
        return 0;

    return (DWORD)( ( tv.tv_sec * 1000 ) + ( tv.tv_usec / 1000 ) );
}
#define UNIX
#endif // _WIN32

#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS
#include <map>
#include <string>
#include <vector>

#define SSPI_CREDSCACHE_DEFAULT_TIMEOUT 600000 // 10 minutes
#define SSPI_BUFFER_SIZE 32896 // 2 * ( 0x4000 + 128 )

#ifdef _WIN32
#define CPROLIBS_PATH ""
#elif defined( __APPLE__ )
#define CPROLIBS_PATH "/opt/cprocsp/lib/"
#include <TargetConditionals.h>
#ifdef TARGET_OS_IPHONE
#define IOS
#endif
#else // other LINUX
#if defined( __mips__ ) // archs
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define CPROLIBS_PATH "/opt/cprocsp/lib/mipsel/"
#else // __BYTE_ORDER__
    #define CPROLIBS_PATH "/opt/cprocsp/lib/mips/"
#endif // __BYTE_ORDER__
#elif defined( __arm__ ) // archs
    #define CPROLIBS_PATH "/opt/cprocsp/lib/arm/"
#elif defined( __aarch64__ ) // archs
    #define CPROLIBS_PATH "/opt/cprocsp/lib/aarch64/"
#elif defined( __e2k__ ) // archs
    #define CPROLIBS_PATH "/opt/cprocsp/lib/lib64/"
#elif defined( __PPC64__ ) // archs
    #define CPROLIBS_PATH "/opt/cprocsp/lib/lib64/"
#elif defined( __i386__ ) // archs
    #define CPROLIBS_PATH "/opt/cprocsp/lib/ia32/"
#else // archs
#define CPROLIBS_PATH "/opt/cprocsp/lib/amd64/"
#endif // archs
#endif // CPROLIBS_PATH

#ifdef _WIN32
#define LIBSSP_NAME "Security.dll"
#elif defined( __APPLE__ )
#define LIBSSP_NAME "libssp.dylib"
#else // other LINUX
#define LIBSSP_NAME "libssp.so"
#endif // LIBSSP_NAME
#define LIBSSP_PATH_NAME CPROLIBS_PATH LIBSSP_NAME

#include "msspi.h"

#ifndef __MINGW32__
#include "common.h"
#endif // __MINGW32__
#include "WinCryptEx.h"

#ifdef MSSPI_USE_CAPIX
#include "capix.hpp"
#endif

#ifdef MSSPI_LOGGER
void msspi_logger_func( char level, const char * format, ... );
#define msspi_logger_info( format, ... ) msspi_logger_func( 'i', "INFO (%s:%d): " format, __FUNCTION__, __LINE__, __VA_ARGS__ )
#define msspi_logger_error( format, ... ) msspi_logger_func( 'e', "ERROR (%s:%d): " format, __FUNCTION__, __LINE__, __VA_ARGS__ )
#define msspi_logger_crit( format, ... ) msspi_logger_func( 'x', "CRITICAL (%s:%d): " format, __FUNCTION__, __LINE__, __VA_ARGS__ )

#define MSSPI_LOGGER_MAX 1024
#define MSSPI_LOGGER_ID "msspi"

#ifndef _WIN32
#include <stdarg.h>
#include <syslog.h>
#endif

void msspi_logger_func( char level, const char * format, ... )
{
    va_list ap;
    va_start( ap, format );
    char out[MSSPI_LOGGER_MAX];
    int n = sizeof( out );

    n = vsnprintf( out, n, format, ap );
    va_end( ap );

    if( n < 0 || n >= (int)sizeof( out ) )
    {
        if( level != 'x' )
            msspi_logger_crit( "vsnprintf = %d", n );
        return;
    }

#ifdef _WIN32

    static HANDLE es = RegisterEventSourceA( NULL, MSSPI_LOGGER_ID );

    if( !es )
        return;

    WORD type;

    switch( level )
    {
        case 'x':
        case 'e':
            type = EVENTLOG_ERROR_TYPE;
            break;

        case 'i':
        default:
            type = EVENTLOG_INFORMATION_TYPE;
    }

    const char * msgs[9] = { out, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "\n" };
    ReportEventA( es, type, 0, 3299, NULL, 9, 0, (LPCSTR *)msgs, NULL );

#else // not _WIN32

    int priority;

    switch( level )
    {
        case 'e':
            priority = LOG_ERR;
            break;

        case 'x':
            priority = LOG_CRIT;
            break;

        case 'i':
        default:
            priority = LOG_INFO;
    }

    closelog();
    openlog( MSSPI_LOGGER_ID, LOG_PID, LOG_USER );
    syslog( priority, "%s", out );

#endif // _WIN32
}

#else // not MSSPI_LOGGER
#define msspi_logger_info( format, ... )
#endif // MSSPI_LOGGER

#ifndef SECBUFFER_APPLICATION_PROTOCOLS
#define SECBUFFER_APPLICATION_PROTOCOLS 18  // Lists of application protocol IDs, one per negotiation extension

typedef enum _SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT
{
    SecApplicationProtocolNegotiationExt_None,
    SecApplicationProtocolNegotiationExt_NPN,
    SecApplicationProtocolNegotiationExt_ALPN
} SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT, *PSEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT;

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1
#endif

typedef struct _SEC_APPLICATION_PROTOCOL_LIST {
    SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT ProtoNegoExt; // Protocol negotiation extension type to use with this list of protocols
    unsigned short ProtocolListSize;                       // Size in bytes of the protocol ID list
    unsigned char ProtocolList[ANYSIZE_ARRAY];             // 8-bit length-prefixed application protocol IDs, most preferred first
} SEC_APPLICATION_PROTOCOL_LIST, *PSEC_APPLICATION_PROTOCOL_LIST;

typedef struct _SEC_APPLICATION_PROTOCOLS {
    unsigned long ProtocolListsSize;                            // Size in bytes of the protocol ID lists array
    SEC_APPLICATION_PROTOCOL_LIST ProtocolLists[ANYSIZE_ARRAY]; // Array of protocol ID lists
} SEC_APPLICATION_PROTOCOLS, *PSEC_APPLICATION_PROTOCOLS;

#define SECPKG_ATTR_APPLICATION_PROTOCOL 35

typedef enum _SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS
{
    SecApplicationProtocolNegotiationStatus_None,
    SecApplicationProtocolNegotiationStatus_Success,
    SecApplicationProtocolNegotiationStatus_SelectedClientOnly
} SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS, *PSEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS;

#define MAX_PROTOCOL_ID_SIZE 0xff

typedef struct _SecPkgContext_ApplicationProtocol
{
    SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS ProtoNegoStatus; // Application  protocol negotiation status
    SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT ProtoNegoExt;       // Protocol negotiation extension type corresponding to this protocol ID
    unsigned char ProtocolIdSize;                                // Size in bytes of the application protocol ID
    unsigned char ProtocolId[MAX_PROTOCOL_ID_SIZE];              // Byte string representing the negotiated application protocol ID
} SecPkgContext_ApplicationProtocol, *PSecPkgContext_ApplicationProtocol;

#endif /*SECBUFFER_APPLICATION_PROTOCOLS*/

// credentials_api
#ifdef USE_BOOST
#define BOOST_ALL_NO_LIB 1
#include <boost/thread/recursive_mutex.hpp>
#define std_prefix boost
#else
#include <mutex>
#include <random>
#define std_prefix std
#endif /* WITH BOOST */

static std_prefix::recursive_mutex & g_mtx = *( new std_prefix::recursive_mutex() );
#define UNIQUE_LOCK( mtx ) std_prefix::unique_lock<std_prefix::recursive_mutex> lck( mtx )

struct MSSPI_CredCache;
typedef std::map< std::string, MSSPI_CredCache * > CREDENTIALS_DB;
static CREDENTIALS_DB & credentials_db = *( new CREDENTIALS_DB() );
static char credentials_api( MSSPI_HANDLE h, bool just_find = false );
static void credentials_release( MSSPI_HANDLE h );

// sspi
static PSecurityFunctionTableA sspi = NULL;

static char msspi_init_sspi( void )
{
    UNIQUE_LOCK( g_mtx ); // serialize init

    if( sspi )
        return 1;

    INIT_SECURITY_INTERFACE_A pInitSecurityInterface;

#if TARGET_OS_IPHONE

    pInitSecurityInterface = InitSecurityInterfaceA;

#else

    HMODULE hSecurity = (HMODULE)LIBLOAD( LIBSSP_PATH_NAME );

    if( hSecurity == NULL )
        hSecurity = (HMODULE)LIBLOAD( LIBSSP_NAME );

    if( hSecurity == NULL )
        return 0;

    pInitSecurityInterface = (INIT_SECURITY_INTERFACE_A)LIBFUNC( hSecurity, "InitSecurityInterfaceA" );

    if( pInitSecurityInterface == NULL )
        return 0;

#endif

    EXTERCALL( sspi = pInitSecurityInterface() );

    msspi_logger_info( "InitSecurityInterface = %016llX", (uint64_t)(uintptr_t)sspi );

    if( sspi == NULL )
        return 0;

    return 1;
}

struct MSSPI_CredCache
{
    CredHandle hCred;
    std::vector<PCCERT_CONTEXT> certs;
    DWORD dwLastActive;
    DWORD dwRefs;

    MSSPI_CredCache( CredHandle h, std::vector<PCCERT_CONTEXT> & c )
    {
        hCred = h;
        for( size_t i = 0; i < c.size(); i++ )
            certs.push_back( CertDuplicateCertificateContext( c[i] ) );
        dwLastActive = GetTickCount();
        dwRefs = 1;
    }

    ~MSSPI_CredCache()
    {
        if( hCred.dwLower || hCred.dwUpper )
        {
            msspi_logger_info( "FreeCredentialsHandle( hCred = %016llX:%016llX )", (uint64_t)hCred.dwUpper, (uint64_t)hCred.dwLower );
            EXTERCALL( sspi->FreeCredentialsHandle( &hCred ) );
        }

        for( size_t i = 0; i < certs.size(); i++ )
            CertFreeCertificateContext( certs[i] );
    }

    void Ping( DWORD dwNow )
    {
        dwLastActive = dwNow;
    }

    bool isActive( DWORD dwNow )
    {
        return dwNow - dwLastActive < SSPI_CREDSCACHE_DEFAULT_TIMEOUT;
    }
};

struct MSSPI_VerifyProvider
{
    HCRYPTPROV hProv;

    MSSPI_VerifyProvider()
    {
        hProv = 0;
    }

    ~MSSPI_VerifyProvider()
    {
        if( hProv )
            CryptReleaseContext( hProv, 0 );
    }

    char Random( BYTE * pb, DWORD dw )
    {
        if( Init() && CryptGenRandom( hProv, dw, pb ) )
            return 1;
        return 0;
    }

    char Init()
    {
        if( hProv || CryptAcquireContextW( &hProv, NULL, NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT ) )
            return 1;
        return 0;
    }
};

static MSSPI_VerifyProvider g_prov;

#ifdef _WIN32
typedef unsigned long bufsize_t;
#else
typedef unsigned int bufsize_t;
#endif

struct MSSPI
{
    MSSPI( void * arg, msspi_read_cb read, msspi_write_cb write )
    {
        is.client = 0;
        is.connected = 0;
        is.peerauth = 0;
        is.cipherinfo = 0;
        is.renegotiate = 0;
        is.alpn = 0;
        is.can_append = 0;
        is.names = 0;
        is.pin_cache = 0;
        state = MSSPI_OK;
        hCtx.dwLower = 0;
        hCtx.dwUpper = 0;
        cred = NULL;
        in_len = 0;
        dec_len = 0;
        out_hdr_len = 0;
        out_msg_max = 0;
        out_trl_max = 0;
        out_len = 0;
        out_saved_len = 0;
        cb_arg = arg;
        read_cb = read;
        write_cb = write;
        cert_cb = NULL;
        certstore = "MY";
        peercert = NULL;
        grbitEnabledProtocols = 0;
    }

    ~MSSPI()
    {
        if( cred )
            credentials_release( this );

        if( hCtx.dwLower || hCtx.dwUpper )
        {
            msspi_logger_info( "DeleteSecurityContext( hCtx = %016llX:%016llX )", (uint64_t)hCtx.dwUpper, (uint64_t)hCtx.dwLower );
            EXTERCALL( sspi->DeleteSecurityContext( &hCtx ) );
        }

        for( size_t i = 0; i < certs.size(); i++ )
            CertFreeCertificateContext( certs[i] );

        if( peercert )
            CertFreeCertificateContext( peercert );
    }

    struct
    {
        unsigned client : 1;
        unsigned connected : 1;
        unsigned peerauth : 1;
        unsigned cipherinfo : 1;
        unsigned renegotiate : 1;
        unsigned alpn : 1;
        unsigned can_append : 1;
        unsigned names : 1;
        unsigned pin_cache : 1;
    } is;

    int state;
    std::string hostname;
    std::string cachestring;
    std::string alpn;
    DWORD grbitEnabledProtocols;
    std::vector<ALG_ID> ciphers;
    SecPkgContext_CipherInfo cipherinfo;
    PCCERT_CONTEXT peercert;
    std::string peercert_subject;
    std::string peercert_issuer;
    std::vector<std::string> peercerts;
    std::vector<std::string> peerchain;
    std::vector<std::string> issuerlist;

    CtxtHandle hCtx;
    MSSPI_CredCache * cred;
    std::vector<PCCERT_CONTEXT> certs;
    std::string certstore;
    std::string credstring;
    std::string credprovider;

    int in_len;
    int dec_len;
    bufsize_t out_hdr_len;
    bufsize_t out_msg_max;
    bufsize_t out_trl_max;
    int out_len;
    int out_saved_len;
    char in_buf[SSPI_BUFFER_SIZE];
    char dec_buf[SSPI_BUFFER_SIZE];
    char out_buf[SSPI_BUFFER_SIZE];

    void * cb_arg;
    msspi_read_cb read_cb;
    msspi_write_cb write_cb;
    msspi_cert_cb cert_cb;

    std_prefix::recursive_mutex mtx;
};

static char credentials_acquire( MSSPI_HANDLE h )
{
    CredHandle      hCred;
    TimeStamp       tsExpiry;
    SCHANNEL_CRED   SchannelCred = { 0 };
    unsigned long   usage;

    SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    SchannelCred.grbitEnabledProtocols = h->grbitEnabledProtocols;
    if( h->is.client )
    {
        usage = SECPKG_CRED_OUTBOUND;
        SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
        SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
        SchannelCred.dwFlags |= SCH_CRED_REVOCATION_CHECK_CHAIN;
    }
    else
    {
        usage = SECPKG_CRED_INBOUND;
        SchannelCred.dwFlags |= SCH_CRED_NO_SYSTEM_MAPPER;
    }

    if( h->certs.size() )
    {
        SchannelCred.cCreds = (DWORD)h->certs.size();
        SchannelCred.paCred = &h->certs[0];
    }

    if( h->ciphers.size() )
    {
        SchannelCred.cSupportedAlgs = (DWORD)h->ciphers.size();
        SchannelCred.palgSupportedAlgs = &h->ciphers[0];
    }

    SECURITY_STATUS scRet;
    EXTERCALL( scRet = sspi->AcquireCredentialsHandleA( NULL, (char *)h->credprovider.data(), usage, NULL, &SchannelCred, NULL, NULL, &hCred, &tsExpiry ) );
    msspi_logger_info( "AcquireCredentialsHandle( cert = %016llX ) returned %08X, hCred = %016llX:%016llX ", (uint64_t)(uintptr_t)h->cert, (uint32_t)scRet, (uint64_t)hCred.dwUpper, (uint64_t)hCred.dwLower );

    if( scRet != SEC_E_OK )
        return 0;

    if( h->cred )
        h->cred->dwRefs--;

    h->cred = new MSSPI_CredCache( hCred, h->certs );
    return 1;
}

static void credentials_release( MSSPI_HANDLE h )
{
    UNIQUE_LOCK( g_mtx );
    h->cred->dwRefs--;
    h->cred = NULL;
}

#define B2C_VALUE( b ) ( ( ( b ) < 10 ) ? '0' + ( b ) : 'A' - 10 + ( b ) )

static std::string to_hex_string( uint32_t val )
{
    std::string str( "00000000" );
    size_t i = str.length();

    while( val )
    {
        uint8_t b = val & 0x0F;
        str[--i] = B2C_VALUE( b );
        val >>= 4;
    }

    return str;
}

static std::string to_dec_string( uint32_t val )
{
    std::string str;

    while( val )
    {
        char c = B2C_VALUE( (char)( val % 10 ) );
        str = c + str;
        val /= 10;
    }

    return str;
}

static std::string credstring( MSSPI_HANDLE h )
{
    std::string credstring;
    credstring = h->hostname.length() ? h->hostname : "**";
    credstring += "::";
    credstring += h->cachestring.length() ? h->cachestring : "**";
    credstring += "::";
    credstring += to_hex_string( h->is.peerauth );
    credstring += "::";
    credstring += to_hex_string( h->grbitEnabledProtocols );
    credstring += "::";

    if( h->ciphers.size() )
        for( size_t i = 0; i < h->ciphers.size(); i++ )
            credstring += to_hex_string( h->ciphers[i] );
    else
        credstring += "**";

    return credstring;
}

static char credentials_api( MSSPI_HANDLE h, bool just_find )
{
    CREDENTIALS_DB::iterator it;
    DWORD dwNow = GetTickCount();

    if( h->credstring.length() == 0 )
        h->credstring = credstring( h );

    UNIQUE_LOCK( g_mtx );

    // release creds > SSPI_CREDSCACHE_DEFAULT_TIMEOUT
    for( it = credentials_db.begin(); it != credentials_db.end(); )
    {
        if( it->second->dwRefs || it->second->isActive( dwNow ) )
        {
            it++;
        }
        else
        {
            CREDENTIALS_DB::iterator tmp = it;
            ++tmp;
            delete it->second;
            credentials_db.erase( it );
            it = tmp;
        }
    }

    // credentials_db for records with certs only
    it = credentials_db.find( h->credstring );

    // dereference or ping found
    if( it != credentials_db.end() )
    {
        if( h->cred )
            h->cred->dwRefs--;

        h->cred = it->second;
        h->cred->dwRefs++;
        h->cred->Ping( dwNow );
        return 1;
    }

    // new record
    else if( !just_find )
    {
        if( !h->credprovider.length() )
        {
            const char * credprovider;

            // default (no detours)
            credprovider = DEFAULT_TLS_SSP_NAME_A;
            if( msspi_set_credprovider( h, credprovider ) && credentials_acquire( h ) )
            {
                credentials_db.insert( it, CREDENTIALS_DB::value_type( h->credstring, h->cred ) );
                return 1;
            }

            // legacy default
#if TARGET_OS_IPHONE
            credprovider = "Crypto Provider";
#else
            credprovider = UNISP_NAME_A;
#endif
            if( !msspi_set_credprovider( h, credprovider ) )
                return 0;
        }

        if( credentials_acquire( h ) )
        {
            credentials_db.insert( it, CREDENTIALS_DB::value_type( h->credstring, h->cred ) );
            return 1;
        }
    }

    return 0;
}

static int write_common( MSSPI_HANDLE h )
{
    while( h->out_len )
    {
        int io;
        EXTERCALL( io = h->write_cb( h->cb_arg, h->out_buf, h->out_len ) );

        if( io < 0 )
        {
            h->state |= MSSPI_LAST_PROC_WRITE | MSSPI_WRITING;
            return io;
        }

        h->state &= ~MSSPI_WRITING;

        if( io == h->out_len )
        {
            h->out_len = 0;
            break;
        }

        if( io == 0 )
        {
            h->state |= MSSPI_SENT_SHUTDOWN;
            return 0;
        }

        if( io > h->out_len )
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        h->out_len -= io;
        memmove( h->out_buf, h->out_buf + io, (size_t)h->out_len );
    }

    return 1;
}

static int read_common( MSSPI_HANDLE h )
{
    int io;
    EXTERCALL( io = h->read_cb( h->cb_arg, h->in_buf + h->in_len, SSPI_BUFFER_SIZE - h->in_len ) );

    h->state &= ~MSSPI_LAST_PROC_WRITE;

    if( io < 0 )
        return io;

    h->state &= ~MSSPI_READING;

    if( io == 0 )
    {
        h->state |= MSSPI_RECEIVED_SHUTDOWN;
        return 0;
    }

    h->in_len = h->in_len + io;
    return 1;
}

int msspi_read( MSSPI_HANDLE h, void * buf, int len )
{
    MSSPIEHTRY;

    if( h->dec_len )
    {
        if( buf == NULL )
            return 0;

        int decrypted = h->dec_len;

        if( decrypted > len )
            decrypted = len;

        memcpy( buf, h->dec_buf, (size_t)decrypted );
        h->dec_len -= decrypted;

        if( h->dec_len )
            memmove( h->dec_buf, h->dec_buf + decrypted, (size_t)h->dec_len );
        else if( h->in_len )
            msspi_read( h, NULL, 0 );

        return decrypted;
    }

    if( h->state & MSSPI_ERROR || h->state & MSSPI_RECEIVED_SHUTDOWN )
        return 0;

    if( !h->is.connected )
    {
        UNIQUE_LOCK( h->mtx );

        int i = h->is.client ? msspi_connect( h ) : msspi_accept( h );

        if( i != 1 )
            return i;

        return msspi_read( h, buf, len );
    }

    if( h->in_len == 0 )
        h->state |= MSSPI_READING;

    for( ;; )
    {
        SECURITY_STATUS scRet;
        SecBufferDesc   Message;
        SecBuffer       Buffers[4];

        int i;
        int decrypted = 0;
        int extra = 0;
        int returning = 0;

        if( h->state & MSSPI_READING )
        {
            if( len == 0 )
                return 0;

            int io = read_common( h );
            if( io <= 0 )
                return io;
        }

        Buffers[0].pvBuffer = h->in_buf;
        Buffers[0].cbBuffer = (bufsize_t)h->in_len;
        Buffers[0].BufferType = SECBUFFER_DATA;

        Buffers[1].BufferType = SECBUFFER_EMPTY;
        Buffers[2].BufferType = SECBUFFER_EMPTY;
        Buffers[3].BufferType = SECBUFFER_EMPTY;

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        EXTERCALL( scRet = sspi->DecryptMessage( &h->hCtx, &Message, 0, NULL ) );

        msspi_logger_info( "DecryptMessage( hCtx = %016llX:%016llX, pMessage (length) = %d ) returned %08X",
            (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower, h->in_len, (uint32_t)scRet );

        if( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            h->state |= MSSPI_READING;

            if( len == 0 )
                return 0;

            continue;
        }

        if( scRet != SEC_E_OK &&
            scRet != SEC_I_RENEGOTIATE &&
            scRet != SEC_I_CONTEXT_EXPIRED &&
            scRet != SEC_E_CONTEXT_EXPIRED )
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_I_CONTEXT_EXPIRED ||
            scRet == SEC_E_CONTEXT_EXPIRED )
        {
            h->state |= MSSPI_RECEIVED_SHUTDOWN;
            h->in_len = 0;
            return 0;
        }

        for( i = 1; i < 4; i++ )
        {
            if( !decrypted && Buffers[i].BufferType == SECBUFFER_DATA )
            {
                returning = decrypted = (int)Buffers[i].cbBuffer;

                if( returning > len )
                {
                    memcpy( h->dec_buf, (char *)Buffers[i].pvBuffer + len, (size_t)returning - len );
                    h->dec_len = returning - len;
                    returning = len;
                }

                if( returning )
                    memcpy( buf, Buffers[i].pvBuffer, (size_t)returning );
                continue;
            }

            if( !extra && Buffers[i].BufferType == SECBUFFER_EXTRA )
            {
                memmove( h->in_buf, Buffers[i].pvBuffer, Buffers[i].cbBuffer );
                extra = (int)Buffers[i].cbBuffer;
            }

            if( decrypted && extra )
                break;
        }

        h->in_len = extra;

        if( scRet == SEC_E_OK && decrypted )
        {
            if( h->in_len && h->dec_len == 0 )
                msspi_read( h, NULL, 0 );

            return returning;
        }

        if( scRet == SEC_I_RENEGOTIATE )
        {
            h->is.connected = 0;
            h->is.renegotiate = 1;
            return msspi_read( h, buf, len );
        }
    }

    MSSPIEHCATCH_HERRRET( 0 );
}

int msspi_write( MSSPI_HANDLE h, const void * buf, int len )
{
    MSSPIEHTRY;

    if( h->state & MSSPI_ERROR || h->state & MSSPI_SENT_SHUTDOWN )
        return 0;

    if( !h->is.connected )
    {
        UNIQUE_LOCK( h->mtx );

        int i = h->is.client ? msspi_connect( h ) : msspi_accept( h );

        if( i != 1 )
            return i;
    }

    if( !h->out_msg_max )
    {
        SECURITY_STATUS           scRet;
        SecPkgContext_StreamSizes Sizes;

        EXTERCALL( scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_STREAM_SIZES, &Sizes ) );

        msspi_logger_info( "QueryContextAttributes( hCtx = %016llX:%016llX, SECPKG_ATTR_STREAM_SIZES ) returned %08X", (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower, (uint32_t)scRet );

        if( scRet != SEC_E_OK )
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        if( Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer > SSPI_BUFFER_SIZE )
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        h->out_hdr_len = (bufsize_t)Sizes.cbHeader;
        h->out_msg_max = (bufsize_t)Sizes.cbMaximumMessage;
        h->out_trl_max = (bufsize_t)Sizes.cbTrailer;
    }

    if( h->out_len )
    {
        // len can only grow
        if( len < h->out_saved_len )
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }
    }
    else
    {
        SECURITY_STATUS           scRet;
        SecBufferDesc             Message;
        SecBuffer                 Buffers[4];

        if( len > (int)h->out_msg_max )
            len = (int)h->out_msg_max;

        Buffers[0].pvBuffer = h->out_buf;
        Buffers[0].cbBuffer = h->out_hdr_len;
        Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

        Buffers[1].pvBuffer = h->out_buf + h->out_hdr_len;
        Buffers[1].cbBuffer = (bufsize_t)len;
        Buffers[1].BufferType = SECBUFFER_DATA;

        Buffers[2].pvBuffer = h->out_buf + h->out_hdr_len + len;
        Buffers[2].cbBuffer = h->out_trl_max;
        Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

        Buffers[3].BufferType = SECBUFFER_EMPTY;

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        memcpy( Buffers[1].pvBuffer, buf, (size_t)len );

        EXTERCALL( scRet = sspi->EncryptMessage( &h->hCtx, 0, &Message, 0 ) );

        msspi_logger_info( "EncryptMessage( hCtx = %016llX:%016llX, pMessage (length) = %d ) returned %08X",
            (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower, len, (uint32_t)scRet );

        if( scRet != SEC_E_OK &&
            scRet != SEC_I_CONTEXT_EXPIRED &&
            scRet != SEC_E_CONTEXT_EXPIRED )
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_I_CONTEXT_EXPIRED ||
            scRet == SEC_E_CONTEXT_EXPIRED )
        {
            return msspi_shutdown( h );
        }

        h->out_len = len + (int)( h->out_hdr_len + Buffers[2].cbBuffer );
        h->out_saved_len = len;
    }

    if( h->out_len )
    {
        int io = write_common( h );
        if( io <= 0 )
            return io;
    }

    return h->out_saved_len;

    MSSPIEHCATCH_HERRRET( 0 );
}

int msspi_state( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    return h->state;

    MSSPIEHCATCH_RET( MSSPI_ERROR );
}

int msspi_pending( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    if( h->dec_len )
        return h->dec_len;

    return 0;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_peek( MSSPI_HANDLE h, void * buf, int len )
{
    MSSPIEHTRY;

    if( h->dec_len )
    {
        if( len > h->dec_len )
            len = h->dec_len;

        memcpy( buf, h->dec_buf, (size_t)len );
        return len;
    }

    return 0;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_shutdown( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    if( h->state & MSSPI_ERROR || h->state & MSSPI_SENT_SHUTDOWN )
        return 0;

    h->state |= MSSPI_SHUTDOWN_PROC;

    if( h->hCtx.dwLower || h->hCtx.dwUpper )
    {
        SecBufferDesc   OutBuffer;
        SecBuffer       OutBuffers[1];
        DWORD           dwType;

        dwType = SCHANNEL_SHUTDOWN;

        OutBuffers[0].pvBuffer = &dwType;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer = sizeof( dwType );

        OutBuffer.cBuffers = 1;
        OutBuffer.pBuffers = OutBuffers;
        OutBuffer.ulVersion = SECBUFFER_VERSION;

        SECURITY_STATUS scRet;
        EXTERCALL( scRet = sspi->ApplyControlToken( &h->hCtx, &OutBuffer ) );

        msspi_logger_info( "ApplyControlToken( hCtx = %016llX:%016llX, SCHANNEL_SHUTDOWN ) returned %08X", (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower, (uint32_t)scRet );

        if( FAILED( scRet ) )
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        return h->is.client ? msspi_connect( h ) : msspi_accept( h );
    }

    h->state |= MSSPI_ERROR;
    return 0;

    MSSPIEHCATCH_HERRRET( 0 );
}

static void connected( MSSPI_HANDLE h )
{
    msspi_get_cipherinfo( h );
    msspi_get_peercerts( h, NULL, NULL, NULL );
    msspi_get_peernames( h, NULL, NULL, NULL, NULL );
    h->is.connected = 1;
}

int msspi_accept( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    if( h->state & MSSPI_ERROR || h->state & MSSPI_SENT_SHUTDOWN )
        return 0;

    for( ;; )
    {
        SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;

        if( h->state & MSSPI_READING && !( h->state & MSSPI_SHUTDOWN_PROC ) )
        {
            int io = read_common( h );
            if( io <= 0 )
                return io;
        }

        if( !h->out_len )
        {
            SecBufferDesc   InBuffer = { 0 };
            SecBuffer       InBuffers[2];
            SecBufferDesc   OutBuffer;
            SecBuffer       OutBuffers[2];
            unsigned long   dwSSPIOutFlags;
            TimeStamp       tsExpiry;

            static DWORD dwSSPIFlags =
                ASC_REQ_SEQUENCE_DETECT |
                ASC_REQ_REPLAY_DETECT |
                ASC_REQ_CONFIDENTIALITY |
                ASC_REQ_EXTENDED_ERROR |
                ASC_REQ_ALLOCATE_MEMORY |
                ASC_REQ_STREAM;

            if( !h->cred )
            {
                if( !credentials_api( h ) )
                {
                    h->state |= MSSPI_ERROR;
                    return 0;
                }
            }

            OutBuffers[0].pvBuffer = NULL;
            OutBuffers[0].BufferType = SECBUFFER_TOKEN;
            OutBuffers[0].cbBuffer = 0;

            OutBuffers[1].pvBuffer = NULL;
            OutBuffers[1].BufferType = SECBUFFER_ALERT;
            OutBuffers[1].cbBuffer = 0;

            OutBuffer.cBuffers = 2;
            OutBuffer.pBuffers = OutBuffers;
            OutBuffer.ulVersion = SECBUFFER_VERSION;

            if( h->in_len && !( h->state & MSSPI_SHUTDOWN_PROC ) )
            {
                InBuffers[0].pvBuffer = h->in_buf;
                InBuffers[0].cbBuffer = (bufsize_t)h->in_len;
                InBuffers[0].BufferType = SECBUFFER_TOKEN;

                InBuffers[1].pvBuffer = NULL;
                InBuffers[1].cbBuffer = 0;
                InBuffers[1].BufferType = SECBUFFER_EMPTY;

                InBuffer.cBuffers = 2;
                InBuffer.pBuffers = InBuffers;
                InBuffer.ulVersion = SECBUFFER_VERSION;
            }

            EXTERCALL( scRet = sspi->AcceptSecurityContext(
                &h->cred->hCred,
                ( h->hCtx.dwLower || h->hCtx.dwUpper ) ? &h->hCtx : NULL,
                InBuffer.cBuffers ? &InBuffer : NULL,
                dwSSPIFlags | ( h->is.peerauth ? ASC_REQ_MUTUAL_AUTH : 0 ),
                SECURITY_NATIVE_DREP,
                ( h->hCtx.dwLower || h->hCtx.dwUpper ) ? NULL : &h->hCtx,
                &OutBuffer,
                &dwSSPIOutFlags,
                &tsExpiry ) );

            msspi_logger_info( "AcceptSecurityContext( hCred = %016llX:%016llX, hCtx = %016llX:%016llX, pInput (length) = %d, fContextReq = %08X ) returned %08X",
                (uint64_t)(uintptr_t)h->cred->hCred.dwUpper, (uint64_t)(uintptr_t)h->cred->hCred.dwLower,
                (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower,
                h->in_len, dwSSPIFlags | ( h->is.peerauth ? ASC_REQ_MUTUAL_AUTH : 0 ), (uint32_t)scRet );

            if( h->in_len && !( h->state & MSSPI_SHUTDOWN_PROC ) )
            {
                if( InBuffers[1].BufferType == SECBUFFER_EXTRA )
                {
                    memmove( h->in_buf, h->in_buf + ( h->in_len - InBuffers[1].cbBuffer ), InBuffers[1].cbBuffer );
                    h->in_len = (int)InBuffers[1].cbBuffer;
                }
                else if( !FAILED( scRet ) )
                    h->in_len = 0;
            }

            if( ( scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED ) &&
                OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL )
            {
                memcpy( h->out_buf, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer );
                h->out_len = (int)OutBuffers[0].cbBuffer;

                msspi_logger_info( "FreeContextBuffer( pvBuffer = %016llX )", (uint64_t)(uintptr_t)OutBuffers[0].pvBuffer );
                EXTERCALL( sspi->FreeContextBuffer( OutBuffers[0].pvBuffer ) );
            }
            else if( FAILED( scRet ) && ( dwSSPIOutFlags & ASC_RET_EXTENDED_ERROR ) &&
                     OutBuffers[1].cbBuffer != 0 && OutBuffers[1].pvBuffer != NULL )
            {
                memcpy( h->out_buf, OutBuffers[1].pvBuffer, OutBuffers[1].cbBuffer );
                h->out_len = (int)OutBuffers[1].cbBuffer;

                msspi_logger_info( "FreeContextBuffer( pvBuffer = %016llX )", (uint64_t)(uintptr_t)OutBuffers[1].pvBuffer );
                EXTERCALL( sspi->FreeContextBuffer( OutBuffers[1].pvBuffer ) );
            }
        }

        if( h->out_len )
        {
            int io = write_common( h );
            if( io <= 0 )
                return io;
        }

        if( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            h->state |= MSSPI_READING;
            continue;
        }

        if( scRet == SEC_I_CONTINUE_NEEDED )
            continue;

        // shutdown OK
        if( h->state & MSSPI_SHUTDOWN_PROC )
        {
            if( scRet == SEC_E_OK ||
                scRet == SEC_I_CONTEXT_EXPIRED ||
                scRet == SEC_E_CONTEXT_EXPIRED )
            {
                h->state |= MSSPI_SENT_SHUTDOWN;
                return 0;
            }
        }

        // handshake OK
        if( scRet == SEC_E_OK )
        {
            connected( h );
            if( h->in_len )
                msspi_read( h, NULL, 0 );
            return 1;
        }

        if( scRet == SEC_E_UNKNOWN_CREDENTIALS ) // GOST, but RSA cert
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_E_INTERNAL_ERROR ) // RSA, but GOST cert (or license expired)
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        if( FAILED( scRet ) )
            break;
    }

    h->state |= MSSPI_ERROR;
    return 0;

    MSSPIEHCATCH_HERRRET( 0 );
}

static char is_new_session_unmodified( MSSPI_HANDLE h )
{
    std::string old_session;
    std::string new_session;

    old_session.append( (char *)&h->cipherinfo, sizeof( h->cipherinfo ) );
    for( size_t i = 0; i < h->peercerts.size(); i++ )
        old_session.append( h->peercerts[i] );

    h->is.cipherinfo = 0;
    if( !msspi_get_cipherinfo( h ) )
        return 0;

    h->peercerts.clear();
    if( !msspi_get_peercerts( h, NULL, NULL, NULL ) )
        return 0;

    new_session.append( (char *)&h->cipherinfo, sizeof( h->cipherinfo ) );
    for( size_t i = 0; i < h->peercerts.size(); i++ )
        new_session.append( h->peercerts[i] );

    if( new_session != old_session )
        return 0;

    return 1;
}

char msspi_set_input( MSSPI_HANDLE h, const void * buf, int len )
{
    MSSPIEHTRY;

    if( h->in_len || len > SSPI_BUFFER_SIZE )
        return 0;

    memcpy( h->in_buf, buf, (size_t)len );
    h->in_len = len;
    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

int msspi_connect( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    if( h->state & MSSPI_ERROR || h->state & MSSPI_SENT_SHUTDOWN )
        return 0;

    if( h->is.client == 0 )
        h->is.client = 1;

    for( ;; )
    {
        SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;

        if( h->state & MSSPI_X509_LOOKUP )
        {
            if( h->cert_cb )
            {
                int io;
                EXTERCALL( io = h->cert_cb( h->cb_arg ) );

                if( io != 1 )
                    return io;

                h->state &= ~MSSPI_X509_LOOKUP;

                if( h->cred && h->certs.size() )
                    credentials_release( h );
            }
        }

        if( h->state & MSSPI_READING && !( h->state & MSSPI_SHUTDOWN_PROC ) )
        {
            int io = read_common( h );
            if( io <= 0 )
                return io;
        }

        if( !h->out_len )
        {
            SecBufferDesc   InBuffer = { 0 };
            SecBuffer       InBuffers[2];
            SecBufferDesc   OutBuffer;
            SecBuffer       OutBuffers[2];
            unsigned long   dwSSPIOutFlags;
            TimeStamp       tsExpiry;
            std::string     alpn_holder;

            static DWORD dwSSPIFlags =
                ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_REPLAY_DETECT |
                ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_EXTENDED_ERROR |
                ISC_REQ_ALLOCATE_MEMORY |
                ISC_REQ_STREAM;

            if( !h->cred )
            {
                if( !credentials_api( h ) )
                {
                    h->state |= MSSPI_ERROR;
                    return 0;
                }
            }

            OutBuffers[0].pvBuffer = NULL;
            OutBuffers[0].BufferType = SECBUFFER_TOKEN;
            OutBuffers[0].cbBuffer = 0;

            OutBuffers[1].pvBuffer = NULL;
            OutBuffers[1].BufferType = SECBUFFER_ALERT;
            OutBuffers[1].cbBuffer = 0;

            OutBuffer.cBuffers = 2;
            OutBuffer.pBuffers = OutBuffers;
            OutBuffer.ulVersion = SECBUFFER_VERSION;

            if( h->in_len && !( h->state & MSSPI_SHUTDOWN_PROC ) )
            {
                InBuffers[0].pvBuffer = h->in_buf;
                InBuffers[0].cbBuffer = (bufsize_t)h->in_len;
                InBuffers[0].BufferType = SECBUFFER_TOKEN;

                InBuffers[1].pvBuffer = NULL;
                InBuffers[1].cbBuffer = 0;
                InBuffers[1].BufferType = SECBUFFER_EMPTY;

                InBuffer.cBuffers = 2;
                InBuffer.pBuffers = InBuffers;
                InBuffer.ulVersion = SECBUFFER_VERSION;
            }
            else if( !h->hCtx.dwLower && !h->hCtx.dwUpper && h->alpn.length() )
            {
                {
                    alpn_holder.resize( sizeof( SEC_APPLICATION_PROTOCOLS ) + h->alpn.length() );

                    SEC_APPLICATION_PROTOCOLS * sap = (SEC_APPLICATION_PROTOCOLS *)&alpn_holder[0];
                    sap->ProtocolListsSize = (unsigned long)( sizeof( SEC_APPLICATION_PROTOCOL_LIST ) + h->alpn.length() );
                    sap->ProtocolLists[0].ProtoNegoExt = SecApplicationProtocolNegotiationExt_ALPN;
                    sap->ProtocolLists[0].ProtocolListSize = (unsigned short)h->alpn.length();
                    memcpy( sap->ProtocolLists[0].ProtocolList, h->alpn.data(), h->alpn.length() );
                }

                InBuffers[0].pvBuffer = &alpn_holder[0];
                InBuffers[0].cbBuffer = (bufsize_t)alpn_holder.length();
                InBuffers[0].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;

                InBuffer.cBuffers = 1;
                InBuffer.pBuffers = InBuffers;
                InBuffer.ulVersion = SECBUFFER_VERSION;
            }

            EXTERCALL( scRet = sspi->InitializeSecurityContextA(
                &h->cred->hCred,
                ( h->hCtx.dwLower || h->hCtx.dwUpper ) ? &h->hCtx : NULL,
                h->hostname.length() ? (char *)h->hostname.data() : NULL,
                dwSSPIFlags,
                0,
                SECURITY_NATIVE_DREP,
                InBuffer.cBuffers ? &InBuffer : NULL,
                0,
                ( h->hCtx.dwLower || h->hCtx.dwUpper ) ? NULL : &h->hCtx,
                &OutBuffer,
                &dwSSPIOutFlags,
                &tsExpiry ) );

            msspi_logger_info( "InitializeSecurityContext( hCred = %016llX:%016llX, hCtx = %016llX:%016llX, pszTargetName = %s, fContextReq = %08X, pInput (length) = %d ) returned %08X",
                (uint64_t)(uintptr_t)h->cred->hCred.dwUpper, (uint64_t)(uintptr_t)h->cred->hCred.dwLower,
                (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower,
                h->hostname.length() ? (char *)h->hostname.data() : "NULL", dwSSPIFlags, h->in_len, (uint32_t)scRet );

            if( h->in_len && !( h->state & MSSPI_SHUTDOWN_PROC ) )
            {
                if( InBuffers[1].BufferType == SECBUFFER_EXTRA )
                {
                    memmove( h->in_buf, h->in_buf + ( h->in_len - InBuffers[1].cbBuffer ), InBuffers[1].cbBuffer );
                    h->in_len = (int)InBuffers[1].cbBuffer;
                }
                else if( !FAILED( scRet ) )
                    h->in_len = 0;
            }

            if( ( scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED ) &&
                OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL )
            {
                memcpy( h->out_buf, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer );
                h->out_len = (int)OutBuffers[0].cbBuffer;

                msspi_logger_info( "FreeContextBuffer( pvBuffer = %016llX )", (uint64_t)(uintptr_t)OutBuffers[0].pvBuffer );
                EXTERCALL( sspi->FreeContextBuffer( OutBuffers[0].pvBuffer ) );
            }
            else if( FAILED( scRet ) && ( dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR ) &&
                     OutBuffers[1].cbBuffer != 0 && OutBuffers[1].pvBuffer != NULL )
            {
                memcpy( h->out_buf, OutBuffers[1].pvBuffer, OutBuffers[1].cbBuffer );
                h->out_len = (int)OutBuffers[1].cbBuffer;

                msspi_logger_info( "FreeContextBuffer( pvBuffer = %016llX )", (uint64_t)(uintptr_t)OutBuffers[1].pvBuffer );
                EXTERCALL( sspi->FreeContextBuffer( OutBuffers[1].pvBuffer ) );
            }
        }

        if( h->out_len )
        {
            int io = write_common( h );
            if( io <= 0 )
                return io;
        }

        if( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            h->state |= MSSPI_READING;
            continue;
        }

        if( scRet == SEC_I_CONTINUE_NEEDED )
            continue;

        // shutdown OK
        if( h->state & MSSPI_SHUTDOWN_PROC )
        {
            if( scRet == SEC_E_OK ||
                scRet == SEC_I_CONTEXT_EXPIRED ||
                scRet == SEC_E_CONTEXT_EXPIRED )
            {
                h->state |= MSSPI_SENT_SHUTDOWN;
                return 0;
            }
        }

        // handshake OK
        if( scRet == SEC_E_OK )
        {
            // shutdown if params are changed in renegotiation
            if( h->is.renegotiate && !is_new_session_unmodified( h ) )
            {
                msspi_shutdown( h );
                h->state |= MSSPI_SENT_SHUTDOWN | MSSPI_RECEIVED_SHUTDOWN;
                return 0;
            }

            connected( h );
            if( h->in_len )
                msspi_read( h, NULL, 0 );
            return 1;
        }

        if( scRet == SEC_E_UNKNOWN_CREDENTIALS ) // GOST, but RSA cert
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_E_INTERNAL_ERROR ) // RSA, but GOST cert (or license expired)
        {
            h->state |= MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_I_INCOMPLETE_CREDENTIALS )
        {
            h->state |= MSSPI_X509_LOOKUP;
            continue;
        }

        if( FAILED( scRet ) )
            break;
    }

    h->state |= MSSPI_ERROR;
    return 0;

    MSSPIEHCATCH_HERRRET( 0 );
}

MSSPI_HANDLE msspi_open( void * cb_arg, msspi_read_cb read_cb, msspi_write_cb write_cb )
{
    MSSPIEHTRY;

    if( !msspi_init_sspi() )
        return NULL;

    if( !read_cb || !write_cb )
        return NULL;

    return new MSSPI( cb_arg, read_cb, write_cb );

    MSSPIEHCATCH_RET( NULL );
}

char msspi_set_hostname( MSSPI_HANDLE h, const char * hostname )
{
    MSSPIEHTRY;

    if( hostname )
        h->hostname = hostname;

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

char msspi_set_cachestring( MSSPI_HANDLE h, const char * cachestring )
{
    MSSPIEHTRY;

    if( cachestring )
        h->cachestring = cachestring;

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

char msspi_set_alpn( MSSPI_HANDLE h, const char * alpn, unsigned len )
{
    MSSPIEHTRY;

    if( alpn && len )
        h->alpn.assign( alpn, len );

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

#define C2B_IS_SKIP( c ) ( c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ':' )
#define C2B_VALUE( c ) ( ( '0' <= c && c <= '9' ) ? (char)( c - '0' ) : ( ( 'a' <= c && c <= 'f' ) ? (char)( c - 'a' + 10 ) : ( ( 'A' <= c && c <= 'F' ) ? (char)( c - 'A' + 10 ) : -1 ) ) )

static int str2bin( const char * str, char * bin )
{
    char c;
    char is_filled = 0;
    int n = 0;

    while( 0 != ( c = *str++ ) )
    {
        char v;

        if( C2B_IS_SKIP( c ) )
            continue;

        v = C2B_VALUE( c );

        if( v == -1 )
            return -1;

        if( !is_filled )
        {
            bin[n] = (char)( v << 4 );
            is_filled = 1;
        }
        else
        {
            bin[n] = (char)( bin[n] + v );
            is_filled = 0;
            n++;
        }
    }

    if( is_filled )
        return -1;

    return n;
}

void msspi_set_peerauth( MSSPI_HANDLE h, char is_peerauth )
{
    MSSPIEHTRY;

    h->is.peerauth = (unsigned)is_peerauth;

    MSSPIEHCATCH_0;
}

void msspi_set_cert_cb( MSSPI_HANDLE h, msspi_cert_cb cert )
{
    MSSPIEHTRY;

    h->cert_cb = cert;

    MSSPIEHCATCH_0;
}

void msspi_set_client( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    h->is.client = 1;

    MSSPIEHCATCH_0;
}

void msspi_set_pin_cache( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    h->is.pin_cache = 1;

    MSSPIEHCATCH_0;
}

void msspi_set_version( MSSPI_HANDLE h, int min, int max )
{
    MSSPIEHTRY;

    h->grbitEnabledProtocols = 0;

    if( ( !min || min <= TLS1_VERSION ) && ( !max || TLS1_VERSION <= max ) )
        h->grbitEnabledProtocols |= SP_PROT_TLS1;
    if( ( !min || min <= TLS1_1_VERSION ) && ( !max || TLS1_1_VERSION <= max ) )
        h->grbitEnabledProtocols |= SP_PROT_TLS1_1;
    if( ( !min || min <= TLS1_2_VERSION ) && ( !max || TLS1_2_VERSION <= max ) )
        h->grbitEnabledProtocols |= SP_PROT_TLS1_2;
    if( ( !min || min <= TLS1_3_VERSION ) && ( !max || TLS1_3_VERSION <= max ) )
        h->grbitEnabledProtocols |= SP_PROT_TLS1_3;

    MSSPIEHCATCH_0;
}

#ifndef ALG_TYPE_CIPHER_SUITE
#define ALG_TYPE_CIPHER_SUITE (15 << 9)
#endif

char msspi_set_cipherlist( MSSPI_HANDLE h, const char * cipherlist )
{
    MSSPIEHTRY;

    h->ciphers.clear();

    char c;
    ALG_ID cipher = 0;

    while( 0 != ( c = *cipherlist++ ) )
    {
        if( !c )
            break;

        if( C2B_IS_SKIP( c ) )
        {
            if( cipher )
            {
                h->ciphers.push_back( ALG_TYPE_CIPHER_SUITE | cipher );
                cipher = 0;
            }

            continue;
        }

        c = C2B_VALUE( c );

        if( c == -1 )
            break;

        cipher = ( cipher << 4 ) | c;
    }

    if( cipher )
        h->ciphers.push_back( ALG_TYPE_CIPHER_SUITE | cipher );

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

char msspi_set_credprovider( MSSPI_HANDLE h, const char * credprovider )
{
    MSSPIEHTRY;

    if( credprovider )
        h->credprovider = credprovider;

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

#ifndef _UN
#ifdef _WIN32
#define _UN
#else
#define _UN f_name.
#endif // _WIN32
#endif // _UN

static BOOL is_cert_oid( PCCERT_CONTEXT pcert, const char * oid )
{
    DWORD ekuLength = 0;
    BOOL result = CertGetEnhancedKeyUsage( pcert, 0, NULL, &ekuLength );
    if( result && ekuLength > 0 )
    {
        std::vector<BYTE> ekuListBuffer(ekuLength);
        PCERT_ENHKEY_USAGE ekuList = (PCERT_ENHKEY_USAGE)&ekuListBuffer[0];
        if( CertGetEnhancedKeyUsage( pcert, 0, ekuList, &ekuLength ) )
            for( DWORD i = 0; i < ekuList->cUsageIdentifier; i++ )
                if( 0 == strcmp( ekuList->rgpszUsageIdentifier[i], oid ) )
                    return TRUE;
    }
    return FALSE;
}

char msspi_set_mycert_options( MSSPI_HANDLE h, char silent, const char * pin, char selftest )
{
    MSSPIEHTRY;

    if( h->cred && !h->certs.size() )
        return 1;

    PCRYPT_KEY_PROV_INFO provinfo = NULL;
    char isOK = 0;

    for( ;; )
    {
        DWORD dw;

        if( !h->certs.size() )
            break;

        PCCERT_CONTEXT cert = h->certs.back();

        if( !CertGetCertificateContextProperty( cert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dw ) )
            break;

        provinfo = (PCRYPT_KEY_PROV_INFO)( new char[dw] );

        if( !CertGetCertificateContextProperty( cert, CERT_KEY_PROV_INFO_PROP_ID, provinfo, &dw ) )
            break;

        if( silent )
        {
            provinfo->dwFlags |= CRYPT_SILENT;
            provinfo->cProvParam = 0;
            provinfo->rgProvParam = NULL;

            if( !CertSetCertificateContextProperty( cert, CERT_KEY_PROV_INFO_PROP_ID, 0, provinfo ) )
                break;
        }

        if( pin )
        {
            CRYPT_KEY_PROV_PARAM pinparam;

            pinparam.dwParam = PP_KEYEXCHANGE_PIN;
            pinparam.dwFlags = 0;
            pinparam.pbData = (BYTE *)pin;
            pinparam.cbData = (DWORD)strlen( pin ) + 1;

            provinfo->cProvParam = 1;
            provinfo->rgProvParam = &pinparam;

            if( !CertSetCertificateContextProperty( cert, CERT_KEY_PROV_INFO_PROP_ID, 0, provinfo ) )
                break;
        }

        if( selftest )
        {
            UNIQUE_LOCK( g_mtx ); // serialize selftests

            HCRYPTKEY hUserKey = 0;
            HCRYPTKEY hTestKey = 0;
            HCRYPTHASH hTestHash = 0;
            HCRYPTPROV hProv = 0;

            selftest = 0;

            for( ;; )
            {
                delete[]( char * )provinfo;
                provinfo = NULL;

                if( !CertGetCertificateContextProperty( cert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dw ) )
                    break;

                provinfo = (PCRYPT_KEY_PROV_INFO)( new char[dw] );

                if( !CertGetCertificateContextProperty( cert, CERT_KEY_PROV_INFO_PROP_ID, provinfo, &dw ) )
                    break;

                if( !CryptAcquireContextW( &hProv, provinfo->pwszContainerName, provinfo->pwszProvName, provinfo->dwProvType, provinfo->dwFlags ) )
                    break;

                PCRYPT_KEY_PROV_PARAM param = provinfo->cProvParam ? provinfo->rgProvParam : NULL;
                if( param && !CryptSetProvParam( hProv, param->dwParam, param->cbData ? param->pbData : NULL, param->dwFlags ) )
                    break;

                if( provinfo->dwProvType != PROV_GOST_2001_DH &&
                    provinfo->dwProvType != PROV_GOST_2012_256 &&
                    provinfo->dwProvType != PROV_GOST_2012_512 )
                {
                    selftest = 1;
                    break;
                }

                if( is_cert_oid( cert, szOID_PKIX_KP_SERVER_AUTH ) )
                {
                    BYTE bbPK[256/*MAX_PUBLICKEYBLOB_LEN*/];
                    DWORD dwPK = sizeof( bbPK );
                    DWORD dwAlgid = CALG_G28147;

                    // CryptImportKey - checks PIN
                    if( CryptGetUserKey( hProv, provinfo->dwKeySpec, &hUserKey ) &&
                        CryptExportKey( hUserKey, 0, PUBLICKEYBLOB, 0, bbPK, &dwPK ) &&
                        CryptImportKey( hProv, bbPK, dwPK, hUserKey, 0, &hTestKey ) && // check PIN
                        CryptSetKeyParam( hTestKey, KP_ALGID, (BYTE*)&dwAlgid, 0 ) &&
                        CryptEncrypt( hTestKey, 0, TRUE, 0, 0, &dwPK, dwPK ) ) // check LICENSE
                        selftest = 1;
                }
                else // szOID_PKIX_KP_CLIENT_AUTH
                {
                    BYTE bbSig[128/*MAX_SIG_LEN*/];
                    DWORD dwSig = sizeof( bbSig );
                    DWORD hashAlgid;
                    if( provinfo->dwProvType == PROV_GOST_2001_DH )
                        hashAlgid = CALG_GR3411;
                    else if( provinfo->dwProvType == PROV_GOST_2012_256 )
                        hashAlgid = CALG_GR3411_2012_256;
                    else // if( provinfo->dwProvType == PROV_GOST_2012_512 )
                        hashAlgid = CALG_GR3411_2012_512;

                    if( CryptCreateHash( hProv, hashAlgid, 0, 0, &hTestHash ) &&
                        CryptHashData( hTestHash, (const BYTE *)"\01\00\00\00\03\03", 6, 0 ) &&
                        CryptSignHashW( hTestHash, provinfo->dwKeySpec, NULL, 0, bbSig, &dwSig ) )
                        selftest = 1;
                }

                break;
            }

            if( hUserKey )
                CryptDestroyKey( hUserKey );

            if( hTestKey )
                CryptDestroyKey( hTestKey );

            if( hTestHash )
                CryptDestroyHash( hTestHash );

            if( hProv )
                CryptReleaseContext( hProv, 0 );

            if( !selftest )
                break;
        }

        isOK = 1;
        break;
    }

    if( provinfo )
        delete[]( char * )provinfo;

    if( isOK && h->is.can_append )
        credentials_api( h );

    return isOK;

    MSSPIEHCATCH_HERRRET( 0 );
}

void msspi_set_certstore( MSSPI_HANDLE h, const char * certstore )
{
    MSSPIEHTRY;

    h->certstore = certstore;

    MSSPIEHCATCH_0;
}

static PCCERT_CONTEXT pfx2cert( const char * pfx, int len, const char * password )
{
    std::wstring wpassword;
    wpassword.resize( strlen( password ) );
    for( size_t i = 0; i < wpassword.length(); ++i )
        wpassword[i] = (WCHAR)password[i];

    CRYPT_DATA_BLOB pfxBlob = { (DWORD)len, (BYTE *)pfx };
    HCERTSTORE hStore = PFXImportCertStore( &pfxBlob, wpassword.data(), PKCS12_NO_PERSIST_KEY );
    if( !hStore )
    {
        std::vector<BYTE> PFXDer;
        DWORD dwData;
        if( CryptStringToBinaryA( pfx, (DWORD)len, CRYPT_STRING_BASE64_ANY, NULL, &dwData, NULL, NULL ) )
        {
            PFXDer.resize( dwData );
            if( CryptStringToBinaryA( pfx, (DWORD)len, CRYPT_STRING_BASE64_ANY, &PFXDer[0], &dwData, NULL, NULL ) )
            {
                pfxBlob.cbData = dwData;
                pfxBlob.pbData = &PFXDer[0];
                hStore = PFXImportCertStore( &pfxBlob, wpassword.data(), PKCS12_NO_PERSIST_KEY );
            }
        }

        if( !hStore )
            return NULL;
    }

    PCCERT_CONTEXT pfxcert, prevcert = NULL;
    for( ;; )
    {
        pfxcert = CertEnumCertificatesInStore( hStore, prevcert );
        if( !pfxcert )
            break;

        DWORD dw = 0;
        if( CertGetCertificateContextProperty( pfxcert, CERT_KEY_CONTEXT_PROP_ID, NULL, &dw ) )
            break;

        prevcert = pfxcert;
    }

    CertCloseStore( hStore, 0 );
    return pfxcert;
}

static bool msspi_set_mycert_finalize( MSSPI_HANDLE h, PCCERT_CONTEXT certfound, bool pfx, bool can_append )
{
    bool isOK = false;
    PCCERT_CONTEXT cleancert = NULL;
    PCRYPT_KEY_PROV_INFO provinfo = NULL;
    DWORD dw = 0;

    for( ;; )
    {
        if( pfx )
            cleancert = CertDuplicateCertificateContext( certfound );
        else
            cleancert = CertCreateCertificateContext( X509_ASN_ENCODING, certfound->pbCertEncoded, certfound->cbCertEncoded );

        if( !cleancert )
            break;

        if( !pfx )
        {
            if( !CertGetCertificateContextProperty( certfound, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dw ) )
                break;

            provinfo = (PCRYPT_KEY_PROV_INFO)( new char[dw] );

            if( !CertGetCertificateContextProperty( certfound, CERT_KEY_PROV_INFO_PROP_ID, provinfo, &dw ) )
                break;

            if( !h->is.pin_cache ) // default: reset pin cache in case of different users working
            {
                CRYPT_KEY_PROV_PARAM pinparam;
                CRYPT_PIN_PARAM pinParam = { 0 };
                pinParam.type = CRYPT_PIN_CLEAR;
                pinParam.dest.passwd = NULL;
                pinparam.dwParam = PP_SET_PIN;
                pinparam.dwFlags = 0;
                pinparam.pbData = (BYTE*)&pinParam;
                pinparam.cbData = sizeof( CRYPT_PIN_PARAM );

                provinfo->dwFlags |= CERT_SET_KEY_CONTEXT_PROP_ID;
                provinfo->cProvParam = 1;
                provinfo->rgProvParam = &pinparam;

                if( !CertSetCertificateContextProperty( cleancert, CERT_KEY_PROV_INFO_PROP_ID, 0, provinfo ) )
                    break;
            }
            else // some cases set prov pin outside of msspi
            {
                provinfo->dwFlags |= CERT_SET_KEY_CONTEXT_PROP_ID;
                provinfo->cProvParam = 0;
                provinfo->rgProvParam = NULL;

                if( !CertSetCertificateContextProperty( cleancert, CERT_KEY_PROV_INFO_PROP_ID, 0, provinfo ) )
                    break;
            }
        }

        isOK = true;
        break;
    }

    if( provinfo )
        delete[]( char * )provinfo;

    if( isOK )
    {
        if( h->certs.size() && !can_append )
        {
            for( size_t i = 0; i < h->certs.size(); i++ )
                CertFreeCertificateContext( h->certs[i] );
            h->certs.clear();
        }

        h->certs.push_back( cleancert );
    }
    else if( cleancert )
        CertFreeCertificateContext( cleancert );

    return isOK;
}

static PCCERT_CONTEXT findcert( const char * certData, int len, const char * certstore )
{
    PCCERT_CONTEXT certprobe = NULL;

    if( len )
    {
        certprobe = CertCreateCertificateContext( X509_ASN_ENCODING, (BYTE *)certData, (DWORD)len );
        if( !certprobe )
        {
            std::vector<BYTE> clientCertDer;
            DWORD dwData;
            if( CryptStringToBinaryA( certData, (DWORD)len, CRYPT_STRING_BASE64_ANY, NULL, &dwData, NULL, NULL ) )
            {
                clientCertDer.resize( dwData );
                if( CryptStringToBinaryA( certData, (DWORD)len, CRYPT_STRING_BASE64_ANY, &clientCertDer[0], &dwData, NULL, NULL ) )
                    certprobe = CertCreateCertificateContext( X509_ASN_ENCODING, &clientCertDer[0], dwData );
            }

            if( !certprobe )
                return NULL;
        }
    }

    PCCERT_CONTEXT certfound = NULL;
    HCERTSTORE hStore = 0;

    DWORD dwStoreFlags[2] = {
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };

    for( size_t i = 0; i < sizeof( dwStoreFlags ) / sizeof( dwStoreFlags[0] ); i++ )
    {
        hStore = CertOpenStore( CERT_STORE_PROV_SYSTEM_A, 0, 0, dwStoreFlags[i], certstore );

        if( !hStore )
            continue;

        if( certprobe )
        {
            certfound = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, certprobe, 0 );
            if( certfound )
                break;
        }
        else
        {
            BYTE bb[64/*MAX_OID_LEN*/];
            int bblen = sizeof( bb );
            int sslen = (int)strlen( certData );

            if( sslen < bblen * 2 )
            {
                bblen = str2bin( certData, (char *)bb );
                if( bblen != -1 )
                {
                    CERT_ID id;

                    id.dwIdChoice = CERT_ID_SHA1_HASH;
                    id._UN HashId.pbData = bb;
                    id._UN HashId.cbData = (DWORD)bblen;

                    certfound = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL );
                    if( certfound )
                        break;

                    id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
                    id._UN KeyId.pbData = bb;
                    id._UN KeyId.cbData = (DWORD)bblen;

                    certfound = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL );
                    if( certfound )
                        break;
                }
            }

            certfound = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_A, certData, NULL );
            if( certfound )
                break;
        }

        CertCloseStore( hStore, 0 );
        hStore = 0;
    }

    if( hStore )
        CertCloseStore( hStore, 0 );

    if( certprobe )
        CertFreeCertificateContext( certprobe );

    return certfound;
}

static char msspi_set_mycert_common( MSSPI_HANDLE h, const char * certData, int len, const char * password, bool pfx, bool can_append )
{
    MSSPIEHTRY;

    bool is_append = can_append && h->credstring.length() != 0;
    std::string saved_credstring;

    if( is_append )
        saved_credstring = h->credstring;
    else
        h->credstring = credstring( h );

    h->credstring += pfx ? "::pfx::" : "::cert::";

    if( len )
        h->credstring.append( certData, (unsigned)len );
    else
        h->credstring.append( certData );

    if( credentials_api( h, true ) )
        return 1;

    char isOK = 0;
    PCCERT_CONTEXT cert = NULL;

    if( pfx )
        cert = pfx2cert( certData, len, password );
    else
        cert = findcert( certData, len, h->certstore.data() );

    if( cert )
    {
        isOK = msspi_set_mycert_finalize( h, cert, pfx, can_append );
        CertFreeCertificateContext( cert );
    }

    if( isOK )
        h->is.can_append = (unsigned)can_append;
    else
        h->credstring = saved_credstring;

    return isOK;

    MSSPIEHCATCH_HERRRET( 0 );
}

char msspi_set_mycert( MSSPI_HANDLE h, const char * clientCert, int len )
{
    return msspi_set_mycert_common( h, clientCert, len, NULL, false, false );
}

char msspi_add_mycert( MSSPI_HANDLE h, const char * clientCert, int len )
{
    return msspi_set_mycert_common( h, clientCert, len, NULL, false, true );
}

char msspi_set_mycert_pfx( MSSPI_HANDLE h, const char * pfx, int len, const char * password )
{
    return msspi_set_mycert_common( h, pfx, len, password, true, false );
}

char msspi_add_mycert_pfx( MSSPI_HANDLE h, const char * pfx, int len, const char * password )
{
    return msspi_set_mycert_common( h, pfx, len, password, true, true );
}

void msspi_close( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    delete h;

    MSSPIEHCATCH_0;
}

PSecPkgContext_CipherInfo msspi_get_cipherinfo( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    if( h->is.cipherinfo )
        return &h->cipherinfo;

    SECURITY_STATUS scRet;
    EXTERCALL( scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_CIPHER_INFO, (PVOID)&h->cipherinfo ) );

    msspi_logger_info( "QueryContextAttributes( hCtx = %016llX:%016llX, SECPKG_ATTR_CIPHER_INFO ) returned %08X", (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower, (uint32_t)scRet );

    if( scRet != SEC_E_OK )
        return NULL;

    h->is.cipherinfo = 1;
    return &h->cipherinfo;

    MSSPIEHCATCH_HERRRET( NULL );
}

const char * msspi_get_alpn( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    if( h->is.alpn )
        return h->alpn.length() ? h->alpn.data() : NULL;

    SecPkgContext_ApplicationProtocol alpn;

    SECURITY_STATUS scRet;
    EXTERCALL( scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_APPLICATION_PROTOCOL, (PVOID)&alpn ) );

    msspi_logger_info( "QueryContextAttributes( hCtx = %016llX:%016llX, SECPKG_ATTR_APPLICATION_PROTOCOL ) returned %08X", (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower, (uint32_t)scRet );

    if( scRet != SEC_E_OK )
        return NULL;

    if( alpn.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success &&
        alpn.ProtoNegoExt == SecApplicationProtocolNegotiationExt_ALPN &&
        alpn.ProtocolIdSize &&
        alpn.ProtocolIdSize < h->alpn.length() )
    {
        memset( &h->alpn[0], 0, h->alpn.length() );
        memcpy( &h->alpn[0], alpn.ProtocolId, alpn.ProtocolIdSize );
    }
    else
    {
        h->alpn.clear();
    }

    h->is.alpn = 1;
    return h->alpn.length() ? h->alpn.data() : NULL;

    MSSPIEHCATCH_HERRRET( NULL );
}

const char * msspi_get_version( MSSPI_HANDLE h )
{
    const char * tlsproto = "Unknown";

    MSSPIEHTRY;

    if( h->is.cipherinfo || msspi_get_cipherinfo( h ) )
    {
        switch( h->cipherinfo.dwProtocol )
        {
            case TLS1_VERSION:
            case SP_PROT_TLS1_SERVER:
            case SP_PROT_TLS1_CLIENT:
                tlsproto = "TLSv1";
                break;
            case TLS1_1_VERSION:
            case SP_PROT_TLS1_1_SERVER:
            case SP_PROT_TLS1_1_CLIENT:
                tlsproto = "TLSv1.1";
                break;
            case TLS1_2_VERSION:
            case SP_PROT_TLS1_2_SERVER:
            case SP_PROT_TLS1_2_CLIENT:
                tlsproto = "TLSv1.2";
                break;
            case TLS1_3_VERSION:
            case SP_PROT_TLS1_3_SERVER:
            case SP_PROT_TLS1_3_CLIENT:
                tlsproto = "TLSv1.3";
                break;
            default:
                break;
        }
    }

    return tlsproto;

    MSSPIEHCATCH_HERRRET( tlsproto );
}

char msspi_is_version_supported( int version )
{
    MSSPI_HANDLE h = msspi_open( NULL, (msspi_read_cb)(uintptr_t)-1, (msspi_write_cb)(uintptr_t)-1 );
    if( !h )
        return 0;

    msspi_set_client( h );
    msspi_set_version( h, version, version );
    char supported = h->grbitEnabledProtocols == 0 ? 0 : credentials_api( h );
    msspi_close( h );

    return supported;
}

char msspi_is_cipher_supported( int cipher )
{
    MSSPI_HANDLE h = msspi_open( NULL, (msspi_read_cb)(uintptr_t)-1, (msspi_write_cb)(uintptr_t)-1 );
    if( !h )
        return 0;

    msspi_set_client( h );
    h->ciphers.push_back( ALG_TYPE_CIPHER_SUITE | cipher );
    char supported = credentials_api( h );
    msspi_close( h );

    return supported;
}

char msspi_get_mycert( MSSPI_HANDLE h, const char ** buf, int * len )
{
    MSSPIEHTRY;

    PCCERT_CONTEXT cert = NULL;

    if( h->certs.size() )
        cert = h->certs[0];
    else if( h->cred && h->cred->certs.size() )
        cert = h->cred->certs[0];

    if( !cert )
        return 0;

    *buf = (char *)cert->pbCertEncoded;
    *len = (int)cert->cbCertEncoded;

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

char msspi_get_peercerts( MSSPI_HANDLE h, const char ** bufs, int * lens, size_t * count )
{
    MSSPIEHTRY;

    if( !h->peercerts.size() )
    {
        if( h->peercert )
        {
            CertFreeCertificateContext( h->peercert );
            h->peercert = NULL;
        }

        SECURITY_STATUS scRet;
        EXTERCALL( scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&h->peercert ) );

        msspi_logger_info( "QueryContextAttributes( hCtx = %016llX:%016llX, SECPKG_ATTR_REMOTE_CERT_CONTEXT ) returned %08X", (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower, (uint32_t)scRet );

        if( scRet != SEC_E_OK )
            return 0;

        PCCERT_CONTEXT cert;

        for( cert = h->peercert; cert; )
        {
            PCCERT_CONTEXT IssuerCert = NULL;
            DWORD dwVerificationFlags = 0;

            h->peercerts.push_back( std::string( (char *)cert->pbCertEncoded, cert->cbCertEncoded ) );

            IssuerCert = CertGetIssuerCertificateFromStore( h->peercert->hCertStore, cert, NULL, &dwVerificationFlags );

            if( cert != h->peercert )
                CertFreeCertificateContext( cert );

            cert = IssuerCert;
        }
    }

    if( !h->peercerts.size() )
        return 0;

    if( !count && !bufs )
        return 1;

    if( !count )
        return 0;

    if( !bufs )
    {
        *count = h->peercerts.size();
        return 1;
    }

    if( *count < h->peercerts.size() )
        return 0;

    *count = h->peercerts.size();

    for( size_t i = 0; i < h->peercerts.size(); i++ )
    {
        bufs[i] = h->peercerts[i].data();
        lens[i] = (int)h->peercerts[i].size();
    }

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

char msspi_get_peerchain( MSSPI_HANDLE h, char online, const char ** bufs, int * lens, size_t * count )
{
    MSSPIEHTRY;

    if( !h->peerchain.size() )
    {
        if( !h->peercert && !msspi_get_peercerts( h, NULL, NULL, NULL ) )
            return 0;

        PCCERT_CHAIN_CONTEXT PeerChain;
        CERT_CHAIN_PARA ChainPara;
        memset( &ChainPara, 0, sizeof( ChainPara ) );
        ChainPara.cbSize = sizeof( ChainPara );

        if( CertGetCertificateChain(
            NULL,
            h->peercert,
            NULL,
            h->peercert->hCertStore,
            &ChainPara,
            CERT_CHAIN_CACHE_END_CERT | ( online ? (DWORD)0 : CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL ),
            NULL,
            &PeerChain ) )
        {
            if( PeerChain->cChain > 0 )
                for( DWORD i = 0; i < PeerChain->rgpChain[0]->cElement; i++ )
                {
                    PCCERT_CONTEXT cert = PeerChain->rgpChain[0]->rgpElement[i]->pCertContext;
                    h->peerchain.push_back( std::string( (char *)cert->pbCertEncoded, cert->cbCertEncoded ) );
                }

            CertFreeCertificateChain( PeerChain );
        }
    }

    if( !h->peerchain.size() )
        return 0;

    if( !count && !bufs )
        return 1;

    if( !count )
        return 0;

    if( !bufs )
    {
        *count = h->peerchain.size();
        return 1;
    }

    if( *count < h->peerchain.size() )
        return 0;

    *count = h->peerchain.size();

    for( size_t i = 0; i < h->peerchain.size(); i++ )
    {
        bufs[i] = h->peerchain[i].data();
        lens[i] = (int)h->peerchain[i].size();
    }

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

static std::string certname( PCERT_NAME_BLOB name, bool quotes = true )
{
    DWORD dwLen = CertNameToStrW( X509_ASN_ENCODING, name, (DWORD)( CERT_X500_NAME_STR | ( quotes ? 0 : CERT_NAME_STR_NO_QUOTING_FLAG ) ), NULL, 0 );
    if( dwLen > 1 )
    {
        std::vector<WCHAR> w_str( dwLen );
        dwLen = CertNameToStrW( X509_ASN_ENCODING, name, (DWORD)( CERT_X500_NAME_STR | ( quotes ? 0 : CERT_NAME_STR_NO_QUOTING_FLAG ) ), &w_str[0], dwLen );
        if( dwLen == w_str.size() )
        {
            dwLen = (DWORD)WideCharToMultiByte( CP_UTF8, 0, &w_str[0], -1, NULL, 0, NULL, NULL );
            if( dwLen )
            {
                std::string c_str;
                c_str.resize( dwLen );
                dwLen = (DWORD)WideCharToMultiByte( CP_UTF8, 0, &w_str[0], -1, &c_str[0], (int)dwLen, NULL, NULL );
                if( dwLen == c_str.size() )
                    return c_str.c_str();
            }
        }
    }

    return "";
}

char msspi_get_peernames( MSSPI_HANDLE h, const char ** subject, size_t * slen, const char ** issuer, size_t * ilen )
{
    MSSPIEHTRY;

    if( !h->peercert )
        return 0;

    if( !h->is.names )
    {
        h->peercert_subject = certname( &h->peercert->pCertInfo->Subject );
        h->peercert_issuer = certname( &h->peercert->pCertInfo->Issuer );
        h->is.names = 1;
    }

    if( subject && slen )
    {
        *subject = &h->peercert_subject[0];
        *slen = h->peercert_subject.size();
    }

    if( issuer && ilen )
    {
        *issuer = &h->peercert_issuer[0];
        *ilen = h->peercert_issuer.size();
    }

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

char msspi_get_issuerlist( MSSPI_HANDLE h, const char ** bufs, int * lens, size_t * count )
{
    MSSPIEHTRY;

    if( !h->issuerlist.size() )
    {
        SecPkgContext_IssuerListInfoEx issuerlist = { NULL, 0 };

        SECURITY_STATUS scRet;
        EXTERCALL( scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_ISSUER_LIST_EX, (PVOID)&issuerlist ) );

        msspi_logger_info( "QueryContextAttributes( hCtx = %016llX:%016llX, SECPKG_ATTR_ISSUER_LIST_EX ) returned %08X", (uint64_t)(uintptr_t)h->hCtx.dwUpper, (uint64_t)(uintptr_t)h->hCtx.dwLower, (uint32_t)scRet );

        if( scRet != SEC_E_OK )
            return 0;

        for( DWORD i = 0; i < issuerlist.cIssuers; i++ )
            h->issuerlist.push_back( std::string( (char *)issuerlist.aIssuers[i].pbData, issuerlist.aIssuers[i].cbData ) );

        if( issuerlist.aIssuers )
        {
            msspi_logger_info( "FreeContextBuffer( pvBuffer = %016llX )", (uint64_t)(uintptr_t)issuerlist.aIssuers );
            EXTERCALL( sspi->FreeContextBuffer( issuerlist.aIssuers ) );
        }
    }

    if( !h->issuerlist.size() )
        return 0;

    if( !count && !bufs )
        return 1;

    if( !count )
        return 0;

    if( !bufs )
    {
        *count = h->issuerlist.size();
        return 1;
    }

    if( *count < h->issuerlist.size() )
        return 0;

    *count = h->issuerlist.size();

    for( size_t i = 0; i < h->issuerlist.size(); i++ )
    {
        bufs[i] = h->issuerlist[i].data();
        lens[i] = (int)h->issuerlist[i].size();
    }

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

unsigned msspi_verify( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    DWORD dwVerify = MSSPI_VERIFY_ERROR;
    PCCERT_CHAIN_CONTEXT PeerChain = NULL;

    if( !h->peercert && !msspi_get_peercerts( h, NULL, NULL, NULL ) )
        return dwVerify;

    if( !h->peercert )
        return dwVerify;

    for( ;; )
    {
        CERT_CHAIN_PARA ChainPara;
        memset( &ChainPara, 0, sizeof( ChainPara ) );
        ChainPara.cbSize = sizeof( ChainPara );

        if( !CertGetCertificateChain(
            NULL,
            h->peercert,
            NULL,
            h->peercert->hCertStore,
            &ChainPara,
            CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
            NULL,
            &PeerChain ) )
            break;

        std::wstring whost;
        HTTPSPolicyCallbackData polHttps;
        memset( &polHttps, 0, sizeof( HTTPSPolicyCallbackData ) );
        polHttps.cbStruct = sizeof( HTTPSPolicyCallbackData );
        polHttps.dwAuthType = (DWORD)( h->is.client ? AUTHTYPE_SERVER : AUTHTYPE_CLIENT );
        if( h->is.client && h->hostname.length() )
        {
            whost.resize( h->hostname.length() );
            for ( size_t i = 0; i < whost.length(); ++i )
                whost[i] = (WCHAR)h->hostname[i];

            polHttps.pwszServerName = (WCHAR *)whost.data();
        }

        // mitigate capilite CN validation without hostname
        if( polHttps.dwAuthType == AUTHTYPE_SERVER && !polHttps.pwszServerName )
            polHttps.fdwChecks |= 0x00001000; // SECURITY_FLAG_IGNORE_CERT_CN_INVALID

        CERT_CHAIN_POLICY_PARA PolicyPara;
        memset( &PolicyPara, 0, sizeof( PolicyPara ) );
        PolicyPara.cbSize = sizeof( PolicyPara );
        PolicyPara.pvExtraPolicyPara = &polHttps;

        CERT_CHAIN_POLICY_STATUS PolicyStatus;
        memset( &PolicyStatus, 0, sizeof( PolicyStatus ) );
        PolicyStatus.cbSize = sizeof( PolicyStatus );

        if( !CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_SSL,
            PeerChain,
            &PolicyPara,
            &PolicyStatus ) )
            break;

        dwVerify = MSSPI_VERIFY_OK;

        if( PolicyStatus.dwError )
            dwVerify = PolicyStatus.dwError;

        break;
    }

    if( PeerChain )
        CertFreeCertificateChain( PeerChain );

    return (unsigned)dwVerify;

    MSSPIEHCATCH_HERRRET( MSSPI_VERIFY_ERROR );
}

char msspi_verifypeer( MSSPI_HANDLE h, const char * store )
{
    MSSPIEHTRY;

    HCERTSTORE hStore = 0;
    PCCERT_CONTEXT certfound = NULL;
    unsigned int i;

    DWORD dwStoreFlags[2] = {
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };

    for( i = 0; i < sizeof( dwStoreFlags ) / sizeof( dwStoreFlags[0] ); i++ )
    {
        hStore = CertOpenStore( CERT_STORE_PROV_SYSTEM_A, 0, 0, dwStoreFlags[i], store );

        if( !hStore )
            continue;

        certfound = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, h->peercert, 0 );

        CertCloseStore( hStore, 0 );
        hStore = 0;

        if( certfound )
            break;
    }

    if( certfound )
        CertFreeCertificateContext( certfound );

    return certfound ? 1 : 0;

    MSSPIEHCATCH_HERRRET( 0 );
}

char msspi_random( void * buf, int len, char safe )
{
    MSSPIEHTRY;

    UNIQUE_LOCK( g_mtx );

    if( safe )
        return g_prov.Random( (BYTE *)buf, (DWORD)len );
    else
#ifdef USE_BOOST
    {
        static bool inited = false;

        if( !inited )
        {
            srand( GetTickCount() );
            inited = true;
        }

        for( int i = 0; i < len; i++ )
            ( (BYTE *)buf )[i] = (BYTE)rand();

        return 1;
    }
#else /* USE_BOOST */
    {
        static std::random_device & random_device = *( new std::random_device() );
        static std::default_random_engine & default_random_engine = *( new std::default_random_engine{ random_device() } );
        static std::uniform_int_distribution<> & random = *( new std::uniform_int_distribution<>( 0, 255 ) );

        for( int i = 0; i < len; i++ )
            ( (BYTE *)buf )[i] = (BYTE)random( default_random_engine );

        return 1;
    }
#endif /* USE_BOOST */

    MSSPIEHCATCH_RET( 0 );
}

#ifndef NO_MSSPI_CERT

#define B2C( b ) ( ( ( b ) < 10 ? '0' : 'A' - 10 ) + ( b ) )

static std::string to_hex_string( const uint8_t * bytes, size_t len )
{
    std::string c_str;
    for( size_t i = 0; i < len; i++ )
    {
        uint8_t b = bytes[i];
        c_str += B2C( b >> 4 );
        c_str += B2C( b & 15 );
    }
    return c_str;
}

static std::string to_hex_string( std::string b )
{
    return to_hex_string( (const uint8_t *)&b[0], b.length() );
}

static std::string to_string( LPCWSTR w_str )
{
    DWORD dwLen = (DWORD)WideCharToMultiByte( CP_UTF8, 0, w_str, -1, NULL, 0, NULL, NULL );
    if( dwLen )
    {
        std::string c_str;
        c_str.resize( dwLen );
        dwLen = (DWORD)WideCharToMultiByte( CP_UTF8, 0, w_str, -1, &c_str[0], (int)dwLen, NULL, NULL );
        if( dwLen == c_str.size() )
            return c_str.c_str();
    }

    return "";
}

static std::string certprop( PCCERT_CONTEXT cert, DWORD id )
{
    std::string prop;

    DWORD dw;
    if( CertGetCertificateContextProperty( cert, id, NULL, &dw ) )
    {
        prop.resize( dw );
        if( CertGetCertificateContextProperty( cert, id, &prop[0], &dw ) )
        {
            if( dw < prop.length() )
                prop.resize( dw );
        }
    }

    return prop;
}

static std::string algstr( LPSTR oid )
{
    std::string keyalg;

    PCCRYPT_OID_INFO pInfo;
    pInfo = CryptFindOIDInfo( CRYPT_OID_INFO_OID_KEY, (void *)oid, 0 );
    if( !pInfo )
        keyalg = oid;
    else
        keyalg = to_string( pInfo->pwszName );

    return keyalg;
}

static std::string alglenstr( CERT_PUBLIC_KEY_INFO * keyinfo )
{
    std::string keylen;

    DWORD dwPublicKeyLength = CertGetPublicKeyLength( X509_ASN_ENCODING, keyinfo );
    if( dwPublicKeyLength )
        keylen = to_dec_string( (uint32_t)dwPublicKeyLength );

    return keylen;
}

struct MSSPI_CERT
{
    PCCERT_CONTEXT cert;
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string keyid;
    std::string sha1;
    std::string alg_sig;
    std::string alg_key;

    MSSPI_CERT( PCCERT_CONTEXT certin )
    {
        cert = certin;
    }

    ~MSSPI_CERT()
    {
        if( cert )
            CertFreeCertificateContext( cert );
    }
};

MSSPI_CERT_HANDLE msspi_cert_open( const char * certbuf, size_t len )
{
    MSSPIEHTRY;

    PCCERT_CONTEXT cert = NULL;

    if( !len )
        return NULL;

    cert = CertCreateCertificateContext( X509_ASN_ENCODING, (BYTE *)certbuf, (DWORD)len );
    if( !cert )
    {
        std::vector<BYTE> certbufder;
        DWORD dwData;
        if( CryptStringToBinaryA( certbuf, (DWORD)len, CRYPT_STRING_BASE64_ANY, NULL, &dwData, NULL, NULL ) )
        {
            certbufder.resize( dwData );
            if( CryptStringToBinaryA( certbuf, (DWORD)len, CRYPT_STRING_BASE64_ANY, &certbufder[0], &dwData, NULL, NULL ) )
                cert = CertCreateCertificateContext( X509_ASN_ENCODING, &certbufder[0], dwData );
        }

        if( !cert )
            return NULL;
    }

    return new MSSPI_CERT( cert );

    MSSPIEHCATCH_RET( NULL );
}

MSSPI_CERT_HANDLE msspi_cert_next( MSSPI_CERT_HANDLE ch )
{
    MSSPIEHTRY;

    MSSPI_CERT_HANDLE ch_next = NULL;

    PCCERT_CHAIN_CONTEXT PeerChain;
    CERT_CHAIN_PARA ChainPara;
    memset( &ChainPara, 0, sizeof( ChainPara ) );
    ChainPara.cbSize = sizeof( ChainPara );

    if( CertGetCertificateChain(
        NULL,
        ch->cert,
        NULL,
        ch->cert->hCertStore,
        &ChainPara,
        CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
        NULL,
        &PeerChain ) )
    {
        if( PeerChain->cChain > 0 && PeerChain->rgpChain[0]->cElement > 1 )
        {
            PCCERT_CONTEXT cert = PeerChain->rgpChain[0]->rgpElement[1]->pCertContext;
            ch_next = msspi_cert_open( (const char *)cert->pbCertEncoded, (size_t)cert->cbCertEncoded );
        }

        CertFreeCertificateChain( PeerChain );
    }

    return ch_next;

    MSSPIEHCATCH_RET( NULL );
}

void msspi_cert_close( MSSPI_CERT_HANDLE ch )
{
    MSSPIEHTRY;

    delete ch;

    MSSPIEHCATCH_0;
}

char msspi_cert_subject( MSSPI_CERT_HANDLE ch, const char ** buf, size_t * len, char quotes )
{
    MSSPIEHTRY;

    ch->subject = certname( &ch->cert->pCertInfo->Subject, quotes != 0 ).c_str();
    if( !ch->subject.length() )
        return 0;

    *buf = ch->subject.c_str();
    *len = ch->subject.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

char msspi_cert_issuer( MSSPI_CERT_HANDLE ch, const char ** buf, size_t * len, char quotes )
{
    MSSPIEHTRY;

    ch->issuer = certname( &ch->cert->pCertInfo->Issuer, quotes != 0 ).c_str();
    if( !ch->issuer.length() )
        return 0;

    *buf = ch->issuer.c_str();
    *len = ch->issuer.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

char msspi_cert_serial( MSSPI_CERT_HANDLE ch, const char ** buf, size_t * len )
{
    MSSPIEHTRY;

    if( !ch->cert->pCertInfo->SerialNumber.pbData || !ch->cert->pCertInfo->SerialNumber.cbData )
        return 0;

    ch->serial = to_hex_string( ch->cert->pCertInfo->SerialNumber.pbData, ch->cert->pCertInfo->SerialNumber.cbData );
    if( !ch->serial.length() )
        return 0;

    *buf = ch->serial.c_str();
    *len = ch->serial.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

char msspi_cert_keyid( MSSPI_CERT_HANDLE ch, const char ** buf, size_t * len )
{
    MSSPIEHTRY;

    std::string prop = certprop( ch->cert, CERT_KEY_IDENTIFIER_PROP_ID );
    if( !prop.length() )
        return 0;

    ch->keyid = to_hex_string( prop );
    if( !ch->keyid.length() )
        return 0;

    *buf = ch->keyid.c_str();
    *len = ch->keyid.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

char msspi_cert_sha1( MSSPI_CERT_HANDLE ch, const char ** buf, size_t * len )
{
    MSSPIEHTRY;

    std::string prop = certprop( ch->cert, CERT_SHA1_HASH_PROP_ID );
    if( !prop.length() )
        return 0;

    ch->sha1 = to_hex_string( prop );
    if( !ch->sha1.length() )
        return 0;

    *buf = ch->sha1.c_str();
    *len = ch->sha1.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

char msspi_cert_alg_sig( MSSPI_CERT_HANDLE ch, const char ** buf, size_t * len )
{
    MSSPIEHTRY;

    if( !ch->cert->pCertInfo->SignatureAlgorithm.pszObjId )
        return 0;

    ch->alg_sig = algstr( ch->cert->pCertInfo->SignatureAlgorithm.pszObjId );
    if( !ch->alg_sig.length() )
        return 0;

    *buf = ch->alg_sig.c_str();
    *len = ch->alg_sig.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

char msspi_cert_alg_key( MSSPI_CERT_HANDLE ch, const char ** buf, size_t * len )
{
    MSSPIEHTRY;

    if( !ch->cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId )
        return 0;

    ch->alg_key = algstr( ch->cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId );
    if( !ch->alg_key.length() )
        return 0;

    std::string bitlen = alglenstr( &ch->cert->pCertInfo->SubjectPublicKeyInfo );
    if( bitlen.length() > 0 )
        ch->alg_key += " (" + bitlen + " бит)";

    *buf = ch->alg_key.c_str();
    *len = ch->alg_key.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

char msspi_cert_time_issued( MSSPI_CERT_HANDLE ch, struct tm * time )
{
    MSSPIEHTRY;

    SYSTEMTIME stime;
    if( !FileTimeToSystemTime( &ch->cert->pCertInfo->NotBefore, &stime ) )
        return 0;

    time->tm_year = stime.wYear;
    time->tm_mon = stime.wMonth;
    time->tm_mday = stime.wDay;
    time->tm_hour = stime.wHour;
    time->tm_min = stime.wMinute;
    time->tm_sec = stime.wSecond;
    time->tm_wday = -1;
    time->tm_yday = -1;
    time->tm_isdst = -1;

    return 1;

    MSSPIEHCATCH_RET( 0 );
}

char msspi_cert_time_expired( MSSPI_CERT_HANDLE ch, struct tm * time )
{
    MSSPIEHTRY;

    SYSTEMTIME stime;
    if( !FileTimeToSystemTime( &ch->cert->pCertInfo->NotAfter, &stime ) )
        return 0;

    time->tm_year = stime.wYear;
    time->tm_mon = stime.wMonth;
    time->tm_mday = stime.wDay;
    time->tm_hour = stime.wHour;
    time->tm_min = stime.wMinute;
    time->tm_sec = stime.wSecond;
    time->tm_wday = -1;
    time->tm_yday = -1;
    time->tm_isdst = -1;

    return 1;

    MSSPIEHCATCH_RET( 0 );
}

#endif /* NO_MSSPI_CERT */
