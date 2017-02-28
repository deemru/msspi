// microsspi

#ifdef _WIN32
#   pragma warning( disable:4820 )
#   pragma warning( disable:4710 )
#   pragma warning( disable:4668 )
#   include <Windows.h>
#endif

#if defined( __cplusplus )
extern "C" {
#endif
#ifdef _WIN32
#define LIBLOAD( name ) LoadLibraryA( name )
#define LIBFUNC( lib, name ) (UINT_PTR)GetProcAddress( lib, name )
#else
#define LIBLOAD( name ) dlopen( name, RTLD_LAZY )
#define LIBFUNC( lib, name ) dlsym( lib, name )
#endif
#if defined( __cplusplus )
}
#endif

#ifdef QT_NO_EXCEPTIONS
#define MSSPIEHTRY
#define MSSPIEHCATCH
#define MSSPIEHCATCH_HERRRET( ret )
#define MSSPIEHCATCH_RET( ret )
#define MSSPIEHCATCH_0 MSSPIEHCATCH
#else // QT_NO_EXCEPTIONS
#define MSSPIEHTRY try {
#define MSSPIEHCATCH } catch( ... ) {
#define MSSPIEHCATCH_HERRRET( ret ) MSSPIEHCATCH; h->state = MSSPI_ERROR; return ret; }
#define MSSPIEHCATCH_RET( ret ) MSSPIEHCATCH; return ret; }
#define MSSPIEHCATCH_0 MSSPIEHCATCH; }
#endif // QT_NO_EXCEPTIONS

#include <stdio.h>
#include <string.h>
#define SECURITY_WIN32
#ifdef _WIN32
#include <schannel.h>
#include <sspi.h>
#else
#   include "CSP_WinDef.h"
#   include "CSP_WinCrypt.h"
#   include "CSP_Sspi.h"
#   include "CSP_SChannel.h"
#include <dlfcn.h>
#include <sys/time.h>

unsigned GetTickCount()
{
    struct timeval tv;
    if( gettimeofday( &tv, NULL ) != 0 )
        return 0;

    return ( tv.tv_sec * 1000 ) + ( tv.tv_usec / 1000 );
}
#endif // _WIN32

#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS
#include <map>
#include <unordered_map>
#include <string>
#include <vector>

#define SSPI_CREDSCACHE_DEFAULT_TIMEOUT 600000 // 10 minutes
#define SSPI_BUFFER_SIZE 65536
#ifdef _WIN32
#define SECURITY_DLL_NAME "Security.dll"
#else
#ifndef SECURITY_DLL_NAME_LINUX
#define SECURITY_DLL_NAME_LINUX "/opt/cprocsp/lib/amd64/libssp.so"
#endif
#define SECURITY_DLL_NAME SECURITY_DLL_NAME_LINUX
#endif

#include "msspi.h"

// credentials_api
#include <mutex>
static std::recursive_mutex mtx;
struct MSSPI_CredCache;
typedef std::unordered_map< std::string, MSSPI_CredCache * > CREDENTIALS_DB;
static CREDENTIALS_DB credentials_db;
static char credentials_api( MSSPI_HANDLE h, bool is_free );

// sspi
static PSecurityFunctionTableA sspi = NULL;

static char msspi_sspi_init( void )
{
    if( sspi )
        return 1;

    INIT_SECURITY_INTERFACE_A pInitSecurityInterface;
    HMODULE hSecurity = (HMODULE)LIBLOAD( SECURITY_DLL_NAME );

    if( hSecurity == NULL )
        return 0;

    pInitSecurityInterface = (INIT_SECURITY_INTERFACE_A)LIBFUNC( hSecurity, "InitSecurityInterfaceA" );

    if( pInitSecurityInterface == NULL )
        return 0;

    sspi = pInitSecurityInterface();

    if( sspi == NULL )
        return 0;

    return 1;
}

struct MSSPI_CredCache
{
    CredHandle hCred;
    DWORD dwLastActive;
    DWORD dwRefs;

    MSSPI_CredCache( CredHandle h )
    {
        hCred = h;
        dwLastActive = GetTickCount();
        dwRefs = 1;
    }

    ~MSSPI_CredCache()
    {
        if( hCred.dwLower || hCred.dwUpper )
            sspi->FreeCredentialsHandle( &hCred );
    }

    void Ping()
    {
        dwLastActive = GetTickCount();
    }

    bool isActive()
    {
        return GetTickCount() - dwLastActive < SSPI_CREDSCACHE_DEFAULT_TIMEOUT;
    }
};

struct MSSPI
{
    MSSPI( void * arg, msspi_read_cb read, msspi_write_cb write )
    {
        is_client = 0;
        is_connected = 0;
        is_peerauth = 0;
        is_cipherinfo = 0;
        is_shutingdown = 0;
        is_renegotiate = 0;
        state = MSSPI_OK;
        rwstate = MSSPI_NOTHING;
        hCtx.dwLower = 0;
        hCtx.dwUpper = 0;
        cred = NULL;
        cert = NULL;
        in_len = 0;
        dec_len = 0;
        out_hdr_len = 0;
        out_msg_max = 0;
        out_trl_max = 0;
        out_len = 0;
        cb_arg = arg;
        read_cb = read;
        write_cb = write;
        cert_cb = NULL;
    }

    ~MSSPI()
    {
        if( cred )
            credentials_api( this, true );

        if( hCtx.dwLower || hCtx.dwUpper )
            sspi->DeleteSecurityContext( &hCtx );

        if( cert )
            CertFreeCertificateContext( cert );
    }

    char is_client;
    char is_connected;
    char is_peerauth;
    char is_cipherinfo;
    char is_shutingdown;
    char is_renegotiate;
    char reserved[2];
    MSSPI_STATE state;
    MSSPI_STATE rwstate;
    std::string hostname;
    SecPkgContext_CipherInfo cipherinfo;
    std::vector<std::string> peercerts;

    CtxtHandle hCtx;
    MSSPI_CredCache * cred;
    PCCERT_CONTEXT cert;

    int in_len;
    int dec_len;
    unsigned long out_hdr_len;
    unsigned long out_msg_max;
    unsigned long out_trl_max;
    int out_len;
    char in_buf[SSPI_BUFFER_SIZE];
    char dec_buf[SSPI_BUFFER_SIZE];
    char out_buf[SSPI_BUFFER_SIZE];

    void * cb_arg;
    msspi_read_cb read_cb;
    msspi_write_cb write_cb;
    msspi_cert_cb cert_cb;
};

static char credentials_api( MSSPI_HANDLE h, bool is_free )
{
    PCCERT_CONTEXT cert = h->cert;

    // release creds without certs
    if( is_free && !cert )
    {
        delete h->cred;
        h->cred = NULL;
        return 1;
    }

    std::string cred_record;

    if( cert )
    {
        cred_record = h->hostname.size() ? h->hostname : "*";
        cred_record.append( (char *)cert->pbCertEncoded, cert->cbCertEncoded );
    }

    std::unique_lock<std::recursive_mutex> lck( mtx );

    CREDENTIALS_DB::iterator it;

    // release creds > SSPI_CREDSCACHE_DEFAULT_TIMEOUT
    for( it = credentials_db.begin(); it != credentials_db.end(); )
    {
        if( it->second->dwRefs || it->second->isActive() )
        {
            it++;
        }
        else
        {
            delete it->second;
            it = credentials_db.erase( it );
        }
    }

    // credentials_db for records with certs only
    if( cert )
        it = credentials_db.find( cred_record );

    // dereference or ping found
    if( it != credentials_db.end() )
    {
        if( is_free )
        {
            h->cred = NULL;
            it->second->dwRefs--;
            return 1;
        }
        else
        {
            it->second->Ping();
            it->second->dwRefs++;
            h->cred = it->second;
            return 1;
        }
    }

    // new record
    else if( !is_free )
    {
        CredHandle      hCred;
        SECURITY_STATUS Status;
        TimeStamp       tsExpiry;
        SCHANNEL_CRED   SchannelCred;
        unsigned long   usage;

        ZeroMemory( &SchannelCred, sizeof( SchannelCred ) );

        SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
        SchannelCred.grbitEnabledProtocols = 0;
        if( h->is_client )
        {
            usage = SECPKG_CRED_OUTBOUND;
            SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
            SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
        }
        else
        {
            usage = SECPKG_CRED_INBOUND;
            SchannelCred.dwFlags |= SCH_CRED_NO_SYSTEM_MAPPER;
        }

        if( cert )
        {
            SchannelCred.cCreds = 1;
            SchannelCred.paCred = &cert;
        }

        Status = sspi->AcquireCredentialsHandleA(
            NULL,
            (char *)UNISP_NAME_A,
            usage,
            NULL,
            &SchannelCred,
            NULL,
            NULL,
            &hCred,
            &tsExpiry );

        if( Status == SEC_E_OK )
        {
            h->cred = new MSSPI_CredCache( hCred );

            // credentials_db for records with certs only
            if( cert )
                credentials_db.insert( it, CREDENTIALS_DB::value_type( cred_record, h->cred ) );

            return 1;
        }
    }

    return 0;
}

int msspi_read( MSSPI_HANDLE h, void * buf, int len )
{
    MSSPIEHTRY;

    if( !h->is_connected )
    {
        int i = h->is_client ? msspi_connect( h ) : msspi_accept( h );

        if( i != 1 )
            return i;
    }

    if( h->dec_len )
    {
        int decrypted = h->dec_len;

        if( decrypted > len )
            decrypted = len;

        memcpy( buf, h->dec_buf, (size_t)decrypted );
        h->dec_len -= decrypted;

        if( h->dec_len )
            memmove( h->dec_buf, h->dec_buf + decrypted, (size_t)h->dec_len );

        return decrypted;
    }

    if( h->rwstate == MSSPI_NOTHING && h->in_len == 0 )
        h->rwstate = MSSPI_READING;

    for( ;; )
    {
        SECURITY_STATUS scRet;
        SecBufferDesc   Message;
        SecBuffer       Buffers[4];

        int i;
        int decrypted = 0;
        int extra = 0;

        if( h->rwstate == MSSPI_READING )
        {
            int io = h->read_cb( h->cb_arg, h->in_buf + h->in_len, SSPI_BUFFER_SIZE - h->in_len );

            if( io < 0 )
                return io;

            if( io == 0 )
            {
                h->state = MSSPI_SHUTDOWN;
                return 0;
            }

            h->in_len = h->in_len + io;

            h->rwstate = MSSPI_NOTHING;
        }

        Buffers[0].pvBuffer = h->in_buf;
        Buffers[0].cbBuffer = (unsigned long)h->in_len;
        Buffers[0].BufferType = SECBUFFER_DATA;

        Buffers[1].BufferType = SECBUFFER_EMPTY;
        Buffers[2].BufferType = SECBUFFER_EMPTY;
        Buffers[3].BufferType = SECBUFFER_EMPTY;

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        scRet = sspi->DecryptMessage( &h->hCtx, &Message, 0, NULL );

        if( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            h->rwstate = MSSPI_READING;
            continue;
        }

        if( scRet != SEC_E_OK &&
            scRet != SEC_I_RENEGOTIATE &&
            scRet != SEC_I_CONTEXT_EXPIRED &&
            scRet != (SECURITY_STATUS)0x80090317 /*SEC_I_CONTEXT_EXPIRED*/ )
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_I_CONTEXT_EXPIRED ||
            scRet == (SECURITY_STATUS)0x80090317 /*SEC_I_CONTEXT_EXPIRED*/ )
        {
            return msspi_shutdown( h );
        }

        for( i = 1; i < 4; i++ )
        {
            if( !decrypted && Buffers[i].BufferType == SECBUFFER_DATA )
            {
                decrypted = (int)Buffers[i].cbBuffer;

                if( decrypted > len )
                {
                    memcpy( h->dec_buf, (char *)Buffers[i].pvBuffer + len, (size_t)decrypted - len );
                    h->dec_len = decrypted - len;
                    decrypted = len;
                }

                memcpy( buf, Buffers[i].pvBuffer, (size_t)decrypted );
                continue;
            }

            if( !extra && Buffers[i].BufferType == SECBUFFER_EXTRA )
            {
                extra = (int)Buffers[i].cbBuffer;
                memmove( h->in_buf, Buffers[i].pvBuffer, (size_t)extra );
            }

            if( decrypted && extra )
                break;
        }

        h->in_len = extra;

        if( scRet == SEC_E_OK && decrypted )
            return decrypted;

        if( scRet == SEC_I_RENEGOTIATE )
        {
            h->is_connected = 0;
            h->is_renegotiate = 1;
            return msspi_read( h, buf, len );
        }
    }

    MSSPIEHCATCH_HERRRET( 0 );
}

int msspi_write( MSSPI_HANDLE h, const void * buf, int len )
{
    MSSPIEHTRY;

    if( !h->is_connected )
    {
        int i = h->is_client ? msspi_connect( h ) : msspi_accept( h );

        if( i != 1 )
            return i;
    }

    if( !h->out_msg_max )
    {
        SECURITY_STATUS           scRet;
        SecPkgContext_StreamSizes Sizes;

        scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_STREAM_SIZES, &Sizes );

        if( scRet != SEC_E_OK )
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        if( Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer > SSPI_BUFFER_SIZE )
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        h->out_hdr_len = Sizes.cbHeader;
        h->out_msg_max = Sizes.cbMaximumMessage;
        h->out_trl_max = Sizes.cbTrailer;
    }

    if( len > (int)h->out_msg_max )
        len = (int)h->out_msg_max;

    if( !h->out_len )
    {
        SECURITY_STATUS           scRet;
        SecBufferDesc             Message;
        SecBuffer                 Buffers[4];

        Buffers[0].pvBuffer = h->out_buf;
        Buffers[0].cbBuffer = h->out_hdr_len;
        Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

        Buffers[1].pvBuffer = h->out_buf + h->out_hdr_len;
        Buffers[1].cbBuffer = (unsigned long)len;
        Buffers[1].BufferType = SECBUFFER_DATA;

        Buffers[2].pvBuffer = h->out_buf + h->out_hdr_len + len;
        Buffers[2].cbBuffer = h->out_trl_max;
        Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

        Buffers[3].BufferType = SECBUFFER_EMPTY;

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        memcpy( Buffers[1].pvBuffer, buf, (size_t)len );

        scRet = sspi->EncryptMessage( &h->hCtx, 0, &Message, 0 );

        if( scRet != SEC_E_OK &&
            scRet != SEC_I_CONTEXT_EXPIRED &&
            scRet != (SECURITY_STATUS)0x80090317 /*SEC_I_CONTEXT_EXPIRED*/ )
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_I_CONTEXT_EXPIRED ||
            scRet == (SECURITY_STATUS)0x80090317 /*SEC_I_CONTEXT_EXPIRED*/ )
        {
            return msspi_shutdown( h );
        }

        h->out_len = (int)h->out_hdr_len + len + (int)Buffers[2].cbBuffer;
    }

    while( h->out_len )
    {
        int io = h->write_cb( h->cb_arg, h->out_buf, h->out_len );

        if( io == h->out_len )
        {
            h->out_len = 0;
            if( h->rwstate == MSSPI_WRITING )
                h->rwstate = MSSPI_NOTHING;
            break;
        }

        if( io < 0 )
        {
            h->rwstate = MSSPI_WRITING;
            return io;
        }

        if( io == 0 )
        {
            h->state = MSSPI_SHUTDOWN;
            return 0;
        }

        if( io > h->out_len )
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        h->out_len -= io;
        memmove( h->out_buf, h->out_buf + io, (size_t)h->out_len );
    }

    return len;

    MSSPIEHCATCH_HERRRET( 0 );
}

MSSPI_STATE msspi_state( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    return h->state ? h->state : h->rwstate;

    MSSPIEHCATCH_RET( MSSPI_ERROR );
}

int msspi_pending( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    return h->in_len;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_shutdown( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    char is_ret = h->state != MSSPI_OK;

    h->is_connected = 0;
    h->in_len = 0;
    h->out_len = 0;
    h->rwstate = MSSPI_NOTHING;
    h->is_shutingdown = 1;

    if( is_ret )
    {
        h->state = MSSPI_SHUTDOWN;
        return 0;
    }

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

        if( FAILED( sspi->ApplyControlToken( &h->hCtx, &OutBuffer ) ) )
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        return h->is_client ? msspi_connect( h ) : msspi_accept( h );
    }

    return 0;

    MSSPIEHCATCH_HERRRET( 0 );
}

int msspi_accept( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    if( h->state == MSSPI_ERROR )
        return 0;

    for( ;; )
    {
        SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;

        if( h->rwstate == MSSPI_READING )
        {
            int io = h->read_cb( h->cb_arg, h->in_buf + h->in_len, SSPI_BUFFER_SIZE - h->in_len );

            if( io < 0 )
                return io;

            if( io == 0 )
            {
                h->state = MSSPI_SHUTDOWN;
                return 0;
            }

            h->in_len = h->in_len + io;

            h->rwstate = MSSPI_NOTHING;
        }

        if( !h->out_len )
        {
            SecBufferDesc   InBuffer;
            SecBuffer       InBuffers[2];
            SecBufferDesc   OutBuffer;
            SecBuffer       OutBuffers[1];
            unsigned long   dwSSPIOutFlags;
            TimeStamp       tsExpiry;

            static DWORD dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT |
                ASC_REQ_REPLAY_DETECT |
                ASC_REQ_CONFIDENTIALITY |
                ASC_REQ_EXTENDED_ERROR |
                ASC_REQ_ALLOCATE_MEMORY |
                ASC_REQ_STREAM;

            if( !h->cred )
            {
                if( !credentials_api( h, false ) )
                {
                    h->state = MSSPI_ERROR;
                    return 0;
                }
            }

            OutBuffers[0].pvBuffer = NULL;
            OutBuffers[0].BufferType = SECBUFFER_TOKEN;
            OutBuffers[0].cbBuffer = 0;

            OutBuffer.cBuffers = 1;
            OutBuffer.pBuffers = OutBuffers;
            OutBuffer.ulVersion = SECBUFFER_VERSION;

            if( h->in_len )
            {
                InBuffers[0].pvBuffer = h->in_buf;
                InBuffers[0].cbBuffer = (unsigned long)h->in_len;
                InBuffers[0].BufferType = SECBUFFER_TOKEN;

                InBuffers[1].pvBuffer = NULL;
                InBuffers[1].cbBuffer = 0;
                InBuffers[1].BufferType = SECBUFFER_EMPTY;

                InBuffer.cBuffers = 2;
                InBuffer.pBuffers = InBuffers;
                InBuffer.ulVersion = SECBUFFER_VERSION;
            }

            scRet = sspi->AcceptSecurityContext(
                &h->cred->hCred,
                ( h->hCtx.dwLower || h->hCtx.dwUpper ) ? &h->hCtx : NULL,
                h->in_len ? &InBuffer : NULL,
                dwSSPIFlags | ( h->is_peerauth ? ASC_REQ_MUTUAL_AUTH : 0 ),
                SECURITY_NATIVE_DREP,
                ( h->hCtx.dwLower || h->hCtx.dwUpper ) ? NULL : &h->hCtx,
                &OutBuffer,
                &dwSSPIOutFlags,
                &tsExpiry );

            if( h->in_len )
            {
                if( InBuffers[1].BufferType == SECBUFFER_EXTRA )
                {
                    memmove( h->in_buf, h->in_buf + ( h->in_len - InBuffers[1].cbBuffer ), InBuffers[1].cbBuffer );
                    h->in_len = (int)InBuffers[1].cbBuffer;
                }
                else if( !FAILED( scRet ) )
                    h->in_len = 0;
            }

            if( scRet == SEC_E_OK ||
                scRet == SEC_I_CONTINUE_NEEDED ||
                ( FAILED( scRet ) && ( dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR ) ) )
            {
                if( OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL )
                {
                    memcpy( h->out_buf, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer );
                    h->out_len = (int)OutBuffers[0].cbBuffer;

                    sspi->FreeContextBuffer( OutBuffers[0].pvBuffer );
                }
            }
        }

        while( h->out_len )
        {
            int io = h->write_cb( h->cb_arg, h->out_buf, h->out_len );

            if( io == h->out_len )
            {
                h->out_len = 0;
                if( h->rwstate == MSSPI_WRITING )
                    h->rwstate = MSSPI_NOTHING;
                break;
            }

            if( io < 0 )
            {
                h->rwstate = MSSPI_WRITING;
                return io;
            }

            if( io == 0 )
            {
                h->state = MSSPI_SHUTDOWN;
                return 0;
            }

            if( io > h->out_len )
            {
                h->state = MSSPI_ERROR;
                return 0;
            }

            h->out_len -= io;
            memmove( h->out_buf, h->out_buf + io, (size_t)h->out_len );
        }

        if( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            h->rwstate = MSSPI_READING;
            continue;
        }

        // shutdown OK
        if( h->is_shutingdown )
        {
            if( scRet == SEC_E_OK ||
                scRet == SEC_I_CONTEXT_EXPIRED ||
                scRet == (SECURITY_STATUS)0x80090317 /*SEC_I_CONTEXT_EXPIRED*/ )
            {
                h->state = MSSPI_SHUTDOWN;
                return 0;
            }
        }

        // handshake OK
        if( scRet == SEC_E_OK )
        {
            h->is_connected = 1;
            return 1;
        }

        if( scRet == SEC_E_UNKNOWN_CREDENTIALS ) // GOST, but RSA cert
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_E_INTERNAL_ERROR ) // RSA, but GOST cert (or license expired)
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        if( FAILED( scRet ) )
            break;
    }

    h->state = MSSPI_ERROR;
    return 0;

    MSSPIEHCATCH_HERRRET( 0 );
}

static char is_new_session_unmodified( MSSPI_HANDLE h )
{
    std::string old_session;
    std::string new_session;

    // if a user does not check params - modifications are not important
    if( !h->is_cipherinfo && !h->peercerts.size() )
        return 1;

    old_session.append( (char *)&h->cipherinfo, sizeof( h->cipherinfo ) );
    for( size_t i = 0; i < h->peercerts.size(); i++ )
        old_session.append( h->peercerts[i] );

    h->is_cipherinfo = 0;
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

int msspi_connect( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    if( h->state == MSSPI_ERROR )
        return 0;

    if( h->is_client == 0 )
        h->is_client = 1;

    for( ;; )
    {
        SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;

        if( h->rwstate == MSSPI_X509_LOOKUP )
        {
            if( h->cred )
                credentials_api( h, true );

            if( h->cert_cb )
            {
                int io = h->cert_cb( h->cb_arg );

                if( io != 1 )
                    return io;

                h->rwstate = MSSPI_NOTHING;
            }
        }

        if( h->rwstate == MSSPI_READING )
        {
            int io = h->read_cb( h->cb_arg, h->in_buf + h->in_len, SSPI_BUFFER_SIZE - h->in_len );

            if( io < 0 )
                return io;

            if( io == 0 )
            {
                h->state = MSSPI_SHUTDOWN;
                return 0;
            }

            h->in_len = h->in_len + io;

            h->rwstate = MSSPI_NOTHING;
        }

        if( !h->out_len )
        {
            SecBufferDesc   InBuffer;
            SecBuffer       InBuffers[2];
            SecBufferDesc   OutBuffer;
            SecBuffer       OutBuffers[1];
            unsigned long   dwSSPIOutFlags;
            TimeStamp       tsExpiry;

            static DWORD dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_REPLAY_DETECT |
                ISC_REQ_CONFIDENTIALITY |
                ISC_RET_EXTENDED_ERROR |
                ISC_REQ_ALLOCATE_MEMORY |
                ISC_REQ_STREAM;

            if( !h->cred )
            {
                if( !credentials_api( h, false ) )
                {
                    h->state = MSSPI_ERROR;
                    return 0;
                }
            }

            OutBuffers[0].pvBuffer = NULL;
            OutBuffers[0].BufferType = SECBUFFER_TOKEN;
            OutBuffers[0].cbBuffer = 0;

            OutBuffer.cBuffers = 1;
            OutBuffer.pBuffers = OutBuffers;
            OutBuffer.ulVersion = SECBUFFER_VERSION;

            if( h->in_len )
            {
                InBuffers[0].pvBuffer = h->in_buf;
                InBuffers[0].cbBuffer = (unsigned long)h->in_len;
                InBuffers[0].BufferType = SECBUFFER_TOKEN;

                InBuffers[1].pvBuffer = NULL;
                InBuffers[1].cbBuffer = 0;
                InBuffers[1].BufferType = SECBUFFER_EMPTY;

                InBuffer.cBuffers = 2;
                InBuffer.pBuffers = InBuffers;
                InBuffer.ulVersion = SECBUFFER_VERSION;
            }

            scRet = sspi->InitializeSecurityContextA(
                &h->cred->hCred,
                ( h->hCtx.dwLower || h->hCtx.dwUpper ) ? &h->hCtx : NULL,
                h->hostname.length() ? (char *)h->hostname.data() : NULL,
                dwSSPIFlags,
                0,
                SECURITY_NATIVE_DREP,
                h->in_len ? &InBuffer : NULL,
                0,
                ( h->hCtx.dwLower || h->hCtx.dwUpper ) ? NULL : &h->hCtx,
                &OutBuffer,
                &dwSSPIOutFlags,
                &tsExpiry );

            if( h->in_len )
            {
                if( InBuffers[1].BufferType == SECBUFFER_EXTRA )
                {
                    memmove( h->in_buf, h->in_buf + ( h->in_len - InBuffers[1].cbBuffer ), InBuffers[1].cbBuffer );
                    h->in_len = (int)InBuffers[1].cbBuffer;
                }
                else if( !FAILED( scRet ) )
                    h->in_len = 0;
            }

            if( scRet == SEC_E_OK ||
                scRet == SEC_I_CONTINUE_NEEDED ||
                ( FAILED( scRet ) && ( dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR ) ) )
            {
                if( OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL )
                {
                    memcpy( h->out_buf, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer );
                    h->out_len = (int)OutBuffers[0].cbBuffer;

                    sspi->FreeContextBuffer( OutBuffers[0].pvBuffer );
                }
            }
        }

        while( h->out_len )
        {
            int io = h->write_cb( h->cb_arg, h->out_buf, h->out_len );

            if( io == h->out_len )
            {
                h->out_len = 0;
                if( h->rwstate == MSSPI_WRITING )
                    h->rwstate = MSSPI_NOTHING;
                break;
            }

            if( io < 0 )
            {
                h->rwstate = MSSPI_WRITING;
                return io;
            }

            if( io == 0 )
            {
                h->state = MSSPI_SHUTDOWN;
                return 0;
            }

            if( io > h->out_len )
            {
                h->state = MSSPI_ERROR;
                return 0;
            }

            h->out_len -= io;
            memmove( h->out_buf, h->out_buf + io, (size_t)h->out_len );
        }

        if( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            h->rwstate = MSSPI_READING;
            continue;
        }

        // shutdown OK
        if( h->is_shutingdown )
        {
            if( scRet == SEC_E_OK ||
                scRet == SEC_I_CONTEXT_EXPIRED ||
                scRet == (SECURITY_STATUS)0x80090317 /*SEC_I_CONTEXT_EXPIRED*/ )
            {
                h->state = MSSPI_SHUTDOWN;
                return 0;
            }
        }

        // handshake OK
        if( scRet == SEC_E_OK )
        {
            // shutdown if params are changed in renegotiation
            if( h->is_renegotiate && !is_new_session_unmodified( h ) )
            {
                h->state = MSSPI_SHUTDOWN;
                return 0;
            }

            h->is_connected = 1;
            return 1;
        }

        if( scRet == SEC_E_UNKNOWN_CREDENTIALS ) // GOST, but RSA cert
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_E_INTERNAL_ERROR ) // RSA, but GOST cert (or license expired)
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_I_INCOMPLETE_CREDENTIALS )
        {
            h->rwstate = MSSPI_X509_LOOKUP;
            continue;
        }

        if( FAILED( scRet ) )
            break;
    }

    h->state = MSSPI_ERROR;
    return 0;

    MSSPIEHCATCH_HERRRET( 0 );
}

MSSPI_HANDLE msspi_open( void * cb_arg, msspi_read_cb read_cb, msspi_write_cb write_cb )
{
    MSSPIEHTRY;

    if( !msspi_sspi_init() )
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

#define C2B_IS_SKIP( c ) ( c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ':' )
#define C2B_VALUE( c ) ( ( '0' <= c && c <= '9' ) ? c - '0' : ( ( 'a' <= c && c <= 'f' ) ? c - 'a' + 10 : ( ( 'A' <= c && c <= 'F' ) ? c - 'A' + 10 : -1 ) ) )

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
            bin[n] = v << 4;
            is_filled = 1;
        }
        else
        {
            bin[n] += v;
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

    h->is_peerauth = is_peerauth;

    MSSPIEHCATCH_0;
}

void msspi_set_cert_cb( MSSPI_HANDLE h, msspi_cert_cb cert )
{
    MSSPIEHTRY;

    h->cert_cb = cert;

    MSSPIEHCATCH_0;
}

#ifndef _UN
#ifdef _WIN32
#define _UN
#else
#define _UN f_name.
#endif // _WIN32
#endif // _UN

char msspi_set_mycert_silent( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    PCRYPT_KEY_PROV_INFO provinfo = NULL;
    HCRYPTPROV hProv = 0;
    char isok = 0;

    for( ;; )
    {
        DWORD dw;

        if( !h->cert )
            break;

        if( !CertGetCertificateContextProperty( h->cert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dw ) )
            break;

        provinfo = (PCRYPT_KEY_PROV_INFO)( new char[dw] );

        if( !CertGetCertificateContextProperty( h->cert, CERT_KEY_PROV_INFO_PROP_ID, provinfo, &dw ) )
            break;

        if( !CryptAcquireContextW( &hProv, provinfo->pwszContainerName, provinfo->pwszProvName, provinfo->dwProvType,
            ( provinfo->dwFlags & ~CERT_SET_KEY_CONTEXT_PROP_ID ) | CRYPT_SILENT ) )
            break;

        {
            CERT_KEY_CONTEXT keyctx;
            keyctx.cbSize = sizeof( keyctx );
            keyctx.hCryptProv = hProv;
            keyctx.dwKeySpec = provinfo->dwKeySpec;

            if( !CertSetCertificateContextProperty( h->cert, CERT_KEY_CONTEXT_PROP_ID, 0, &keyctx ) )
                break;
        }

        isok = 1;
        break;
    }

    if( provinfo )
        delete[]( char * )provinfo;

    if( !isok && hProv )
        CryptReleaseContext( hProv, 0 );

    return isok;

    MSSPIEHCATCH_HERRRET( 0 );
}

char msspi_set_mycert( MSSPI_HANDLE h, const char * clientCert, int len )
{
    MSSPIEHTRY;

    HCERTSTORE hStore = 0;
    PCCERT_CONTEXT certfound = NULL;
    PCCERT_CONTEXT certprobe = NULL;
    unsigned int i;

    if( len )
        certprobe = CertCreateCertificateContext( X509_ASN_ENCODING, (BYTE *)clientCert, (DWORD)len );

    if( len && !certprobe )
        return 0;

    DWORD dwStoreFlags[2] = {
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };

    for( i = 0; i < sizeof( dwStoreFlags ) / sizeof( dwStoreFlags[0] ); i++ )
    {
        hStore = CertOpenStore( CERT_STORE_PROV_SYSTEM_A, 0, 0, dwStoreFlags[i], "MY" );

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
            int sslen = (int)strlen( clientCert );

            if( sslen < bblen * 2 )
            {
                bblen = str2bin( clientCert, (char *)bb );

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

            certfound = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_A, clientCert, NULL );

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

    if( h->cert )
        CertFreeCertificateContext( h->cert );

    h->cert = certfound;

    return certfound ? 1 : 0;

    MSSPIEHCATCH_HERRRET( 0 );
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

    if( h->is_cipherinfo )
        return &h->cipherinfo;

    SECURITY_STATUS scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_CIPHER_INFO, (PVOID)&h->cipherinfo );

    if( scRet != SEC_E_OK )
        return NULL;

    h->is_cipherinfo = 1;
    return &h->cipherinfo;

    MSSPIEHCATCH_HERRRET( NULL );
}

const char * msspi_get_version( MSSPI_HANDLE h )
{
    const char * tlsproto = "Unknown";

    MSSPIEHTRY;

    if( h->is_cipherinfo || msspi_get_cipherinfo( h ) )
    {
        switch( h->cipherinfo.dwProtocol )
        {
            case 0x00000301:
            case SP_PROT_TLS1_SERVER:
            case SP_PROT_TLS1_CLIENT:
                tlsproto = "TLSv1";
                break;
            case 0x00000302:
            case SP_PROT_TLS1_1_SERVER:
            case SP_PROT_TLS1_1_CLIENT:
                tlsproto = "TLSv1.1";
                break;
            case 0x00000303:
            case SP_PROT_TLS1_2_SERVER:
            case SP_PROT_TLS1_2_CLIENT:
                tlsproto = "TLSv1.2";
                break;
            default:
                break;
        }
    }

    return tlsproto;

    MSSPIEHCATCH_HERRRET( tlsproto );
}

char msspi_get_peercerts( MSSPI_HANDLE h, const char ** bufs, int * lens, size_t * count )
{
    MSSPIEHTRY;

    if( !h->peercerts.size() )
    {
        PCCERT_CONTEXT PeerCert = NULL;
        PCCERT_CONTEXT RunnerCert;

        SECURITY_STATUS scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&PeerCert );

        if( scRet != SEC_E_OK )
            return 0;

        for( RunnerCert = PeerCert; RunnerCert; )
        {
            PCCERT_CONTEXT IssuerCert = NULL;
            DWORD dwVerificationFlags = 0;

            h->peercerts.push_back( std::string( (char *)RunnerCert->pbCertEncoded, RunnerCert->cbCertEncoded ) );

            IssuerCert = CertGetIssuerCertificateFromStore( PeerCert->hCertStore, RunnerCert, NULL, &dwVerificationFlags );

            if( RunnerCert != PeerCert )
                CertFreeCertificateContext( RunnerCert );

            RunnerCert = IssuerCert;
        }

        CertFreeCertificateContext( PeerCert );
    }

    if( !h->peercerts.size() )
        return 0;

    if( !count && !bufs )
        return 1;

    if( *count < h->peercerts.size() )
    {
        if( bufs )
            return 0;

        *count = h->peercerts.size();
        return 1;
    }

    *count = h->peercerts.size();

    for( size_t i = 0; i < h->peercerts.size(); i++ )
    {
        bufs[i] = h->peercerts[i].data();
        lens[i] = h->peercerts[i].size();
    }

    return 1;

    MSSPIEHCATCH_HERRRET( 0 );
}

unsigned msspi_verify( MSSPI_HANDLE h )
{
    MSSPIEHTRY;

    DWORD dwVerify = MSSPI_VERIFY_ERROR;
    PCCERT_CONTEXT PeerCert = NULL;
    PCCERT_CHAIN_CONTEXT PeerChain = NULL;

    for( ;; )
    {
        if( SEC_E_OK != sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&PeerCert ) )
            break;

        CERT_CHAIN_PARA ChainPara;
        memset( &ChainPara, 0, sizeof( ChainPara ) );
        ChainPara.cbSize = sizeof( ChainPara );

        if( !CertGetCertificateChain(
            NULL,
            PeerCert,
            NULL,
            NULL,
            &ChainPara,
            CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
            NULL,
            &PeerChain ) )
            break;

        std::wstring whost;
        HTTPSPolicyCallbackData polHttps;
        memset( &polHttps, 0, sizeof( HTTPSPolicyCallbackData ) );
        polHttps.cbStruct = sizeof( HTTPSPolicyCallbackData );
        polHttps.dwAuthType = (DWORD)( h->is_client ? AUTHTYPE_SERVER : AUTHTYPE_CLIENT );
        if( h->is_client )
        {
            whost.assign( h->hostname.begin(), h->hostname.end() );
            polHttps.pwszServerName = (WCHAR *)whost.data();
        }

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

    if( PeerCert )
        CertFreeCertificateContext( PeerCert );

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
    PCCERT_CONTEXT certprobe = NULL;
    unsigned int i;

    SECURITY_STATUS scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&certprobe );

    if( scRet != SEC_E_OK )
        return 0;

    DWORD dwStoreFlags[2] = {
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };

    for( i = 0; i < sizeof( dwStoreFlags ) / sizeof( dwStoreFlags[0] ); i++ )
    {
        hStore = CertOpenStore( CERT_STORE_PROV_SYSTEM_A, 0, 0, dwStoreFlags[i], store );

        if( !hStore )
            continue;

        certfound = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, certprobe, 0 );

        CertCloseStore( hStore, 0 );
        hStore = 0;

        if( certfound )
            break;
    }

    if( certprobe )
        CertFreeCertificateContext( certprobe );

    if( certfound )
        CertFreeCertificateContext( certfound );

    return certfound ? 1 : 0;

    MSSPIEHCATCH_HERRRET( 0 );
}
