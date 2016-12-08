// micro sspi

#ifdef WIN32
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

#include <stdio.h>
#include <string.h>
#define SECURITY_WIN32
#ifdef WIN32
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
#endif // WIN32

#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS
#include <map>
#include <unordered_map>
#include <string>
#include <vector>

#define SSPI_CREDSCACHE_DEFAULT_TIMEOUT 600000 // 10 minutes
#define SSPI_BUFFER_SIZE 65536
#ifdef WIN32
#define SECURITY_DLL_NAME "Security.dll"
#else
#define SECURITY_DLL_NAME "/opt/cprocsp/lib/amd64/libssp.so"
#endif

#include "msspi.h"

// credentials_api
#include <mutex>
static std::recursive_mutex mtx;
struct MSSPI_CredCache;
typedef std::unordered_map< std::string, MSSPI_CredCache * > CREDENTIALS_DB;
static CREDENTIALS_DB credentials_db;
static char credentials_api( MSSPI_HANDLE s, PCCERT_CONTEXT user_cert, bool is_free );

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
        dwRefs = 0;
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
    }

    ~MSSPI()
    {
        if( cred )
            credentials_api( this, cert, true );

        if( hCtx.dwLower || hCtx.dwUpper )
            sspi->DeleteSecurityContext( &hCtx );

        if( cert )
            CertFreeCertificateContext( cert );
    }

    char is_client;
    char is_connected;
    char is_peerauth;
    MSSPI_STATE state;
    MSSPI_STATE rwstate;
    std::string host;

    CtxtHandle hCtx;
    MSSPI_CredCache * cred;
    PCCERT_CONTEXT cert;

    int in_len;
    int dec_len;
    int out_hdr_len;
    int out_msg_max;
    int out_trl_max;
    int out_len;
    char in_buf[SSPI_BUFFER_SIZE];
    char dec_buf[SSPI_BUFFER_SIZE];
    char out_buf[SSPI_BUFFER_SIZE];

    void * cb_arg;
    msspi_read_cb read_cb;
    msspi_write_cb write_cb;
};

static char credentials_api( MSSPI_HANDLE h, PCCERT_CONTEXT cert, bool is_free )
{
    std::string cred_record( h->host.size() ? h->host : "*" );

    if( cert && cert->pCertInfo && cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData && cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData )
        cred_record.append( (char *)cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData );

    std::unique_lock<std::recursive_mutex> lck( mtx );

    CREDENTIALS_DB::iterator it;

    // 1. free > SSPI_CREDSCACHE_DEFAULT_TIMEOUT
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

    // 2. ping found
    it = credentials_db.find( cred_record );

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

    // 3. new record
    else if( !is_free )
    {
        CredHandle      hCred;
        HCERTSTORE      hStore = 0;
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

            {
                DWORD dw = 0;
                if( !CertGetCertificateContextProperty( cert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dw ) )
                {
                    hStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY" );

                    if( hStore )
                        cert = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, cert, 0 );
                }
            }
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

        if( hStore )
        {
            if( cert )
                CertFreeCertificateContext( cert );
            CertCloseStore( hStore, CERT_CLOSE_STORE_CHECK_FLAG );
        }

        if( Status == SEC_E_OK )
        {
            it = credentials_db.insert( it, CREDENTIALS_DB::value_type( cred_record, new MSSPI_CredCache( hCred ) ) );

            it->second->dwRefs++;
            h->cred = it->second;

            return 1;
        }
    }

    return 0;
}

int msspi_read( MSSPI_HANDLE h, void * buf, int len )
{
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

        memcpy( buf, h->dec_buf, decrypted );
        h->dec_len -= decrypted;

        if( h->dec_len )
            memmove( h->dec_buf, h->dec_buf + decrypted, h->dec_len );

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

            if( io == 0 && h->state != MSSPI_SHUTDOWN )
                return msspi_shutdown( h );

            h->in_len = h->in_len + io;

            h->rwstate = MSSPI_NOTHING;
        }

        Buffers[0].pvBuffer = h->in_buf;
        Buffers[0].cbBuffer = h->in_len;
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
            scRet != SEC_I_CONTEXT_EXPIRED )
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        if( scRet == SEC_I_CONTEXT_EXPIRED )
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        for( i = 1; i < 4; i++ )
        {
            if( !decrypted && Buffers[i].BufferType == SECBUFFER_DATA )
            {
                decrypted = Buffers[i].cbBuffer;

                if( decrypted > len )
                {
                    memcpy( h->dec_buf, (char *)Buffers[i].pvBuffer + len, decrypted - len );
                    h->dec_len = decrypted - len;
                    decrypted = len;
                }

                memcpy( buf, Buffers[i].pvBuffer, decrypted );
                continue;
            }

            if( !extra && Buffers[i].BufferType == SECBUFFER_EXTRA )
            {
                extra = Buffers[i].cbBuffer;
                memmove( h->in_buf, Buffers[i].pvBuffer, extra );
            }

            if( decrypted && extra )
                break;
        }

        h->in_len = extra;

        if( scRet == SEC_E_OK )
            return decrypted;

        if( scRet == SEC_I_RENEGOTIATE )
        {
            h->rwstate = MSSPI_X509_LOOKUP;
            h->is_connected = false;

            i = msspi_connect( h );

            if( i != 1 )
                return i;

            continue;
        }
    }
}

int msspi_write( MSSPI_HANDLE h, const void * buf, int len )
{
    if( !h->is_connected )
    {
        int i = h->is_client ? msspi_connect( h ) : msspi_accept( h );

        if( i != 1 )
            return i;
    }

    {
        SECURITY_STATUS           scRet;
        SecBufferDesc             Message;
        SecBuffer                 Buffers[4];

        if( !h->out_msg_max )
        {
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

        if( len > h->out_msg_max )
            len = h->out_msg_max;

        Buffers[0].pvBuffer = h->out_buf;
        Buffers[0].cbBuffer = h->out_hdr_len;
        Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

        Buffers[1].pvBuffer = h->out_buf + h->out_hdr_len;
        Buffers[1].cbBuffer = len;
        Buffers[1].BufferType = SECBUFFER_DATA;

        Buffers[2].pvBuffer = h->out_buf + h->out_hdr_len + len;
        Buffers[2].cbBuffer = h->out_trl_max;
        Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

        Buffers[3].BufferType = SECBUFFER_EMPTY;

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        memcpy( Buffers[1].pvBuffer, buf, len );

        scRet = sspi->EncryptMessage( &h->hCtx, 0, &Message, 0 );

        if( FAILED( scRet ) )
        {
            h->state = MSSPI_ERROR;
            return 0;
        }

        int out_bytes = h->out_hdr_len + len + Buffers[2].cbBuffer;

        int io = h->write_cb( h->cb_arg, h->out_buf, out_bytes );

        if( io == out_bytes )
            return len;

        h->state = MSSPI_ERROR;
        return 0;
    }
}

MSSPI_STATE msspi_state( MSSPI_HANDLE h )
{
    return h->state ? h->state : h->rwstate;
}

int msspi_pending( MSSPI_HANDLE h )
{
    return h->in_len;
}

int msspi_shutdown( MSSPI_HANDLE h )
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

    h->state = MSSPI_SHUTDOWN;
    int ret = h->is_client ? msspi_connect( h ) : msspi_accept( h );
    return ret;
}

int msspi_accept( MSSPI_HANDLE h )
{
    for( ;; )
    {
        SECURITY_STATUS scRet;

        if( h->rwstate == MSSPI_READING )
        {
            int io = h->read_cb( h->cb_arg, h->in_buf + h->in_len, SSPI_BUFFER_SIZE - h->in_len );

            if( io < 0 )
                return io;

            if( io == 0 && h->state != MSSPI_SHUTDOWN )
                return msspi_shutdown( h );

            h->in_len = h->in_len + io;

            h->rwstate = MSSPI_NOTHING;
        }

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
                if( !credentials_api( h, h->cert, false ) )
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
                InBuffers[0].cbBuffer = h->in_len;
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
                dwSSPIFlags,
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
                    h->in_len = InBuffers[1].cbBuffer;
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
                    h->out_len = OutBuffers[0].cbBuffer;

                    h->rwstate = MSSPI_WRITING;

                    sspi->FreeContextBuffer( OutBuffers[0].pvBuffer );
                }
            }
        }

        if( h->rwstate == MSSPI_WRITING )
        {
            if( h->write_cb( h->cb_arg, h->out_buf, h->out_len ) != h->out_len )
            {
                h->state = MSSPI_ERROR;
                return 0;
            }

            h->out_len = 0;

            h->rwstate = MSSPI_NOTHING;
        }

        if( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            h->rwstate = MSSPI_READING;
            continue;
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

        if( scRet == SEC_I_INCOMPLETE_CREDENTIALS )
        {
            h->rwstate = MSSPI_X509_LOOKUP;
            continue;
        }

        if( FAILED( scRet ) )
        {
            h->state = MSSPI_ERROR;
            break;
        }
    }

    h->state = MSSPI_ERROR;
    return 0;
}

int msspi_connect( MSSPI_HANDLE h )
{
    h->is_client = 1;

    for( ;; )
    {
        SECURITY_STATUS scRet;

        if( h->rwstate == MSSPI_READING )
        {
            int io = h->read_cb( h->cb_arg, h->in_buf + h->in_len, SSPI_BUFFER_SIZE - h->in_len );

            if( io < 0 )
                return io;

            if( io == 0 && h->state != MSSPI_SHUTDOWN )
                return msspi_shutdown( h );

            h->in_len = h->in_len + io;

            h->rwstate = MSSPI_NOTHING;
        }

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
                if( !credentials_api( h, h->cert, false ) )
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
                InBuffers[0].cbBuffer = h->in_len;
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
                h->host.length() ? &h->host[0] : NULL,
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
                    h->in_len = InBuffers[1].cbBuffer;
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
                    h->out_len = OutBuffers[0].cbBuffer;

                    h->rwstate = MSSPI_WRITING;

                    sspi->FreeContextBuffer( OutBuffers[0].pvBuffer );
                }
            }
        }

        if( h->rwstate == MSSPI_WRITING )
        {
            if( h->write_cb( h->cb_arg, h->out_buf, h->out_len ) != h->out_len )
            {
                h->state = MSSPI_ERROR;
                return 0;
            }

            h->out_len = 0;

            h->rwstate = MSSPI_NOTHING;
        }

        if( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            h->rwstate = MSSPI_READING;
            continue;
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

        if( scRet == SEC_I_INCOMPLETE_CREDENTIALS )
        {
            h->rwstate = MSSPI_X509_LOOKUP;
            continue;
        }

        if( FAILED( scRet ) )
        {
            h->state = MSSPI_ERROR;
            break;
        }
    }

    h->state = MSSPI_ERROR;
    return 0;
}

MSSPI_HANDLE msspi_open( void * cb_arg, msspi_read_cb read_cb, msspi_write_cb write_cb )
{
    if( !msspi_sspi_init() )
        return NULL;

    if( !read_cb || !write_cb )
        return NULL;

    return new MSSPI( cb_arg, read_cb, write_cb );
}

char msspi_set_hostname( MSSPI_HANDLE h, const char * hostName )
{
    h->host = hostName;
    return 1;
}

#define C2B_IS_SKIP( c ) ( c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ':' )
#define C2B_VALUE( c ) ( ( '0' <= c && c <= '9' ) ? c - '0' : ( ( 'a' <= c && c <= 'f' ) ? c - 'a' + 10 : ( ( 'A' <= c && c <= 'F' ) ? c - 'A' + 10 : -1 ) ) )

static int str2bin( const char * str, BYTE * bin )
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
    h->is_peerauth = is_peerauth;
}

#ifndef _UN
#ifdef _WIN32
#define _UN
#else
#define _UN f_name.
#endif // _WIN32
#endif // _UN

char msspi_set_mycert( MSSPI_HANDLE h, const char * clientCert, int len )
{
    HCERTSTORE hStore = 0;
    PCCERT_CONTEXT cert = NULL;
    unsigned int i;

    if( len )
    {
        cert = CertCreateCertificateContext( X509_ASN_ENCODING, (BYTE *)clientCert, len );

        if( h->cert )
            CertFreeCertificateContext( h->cert );

        h->cert = cert;

        return cert ? 1 : 0;
    }

    DWORD dwStoreFlags[2] = {
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };

    for( i = 0; i < sizeof( dwStoreFlags ) / sizeof( dwStoreFlags[0] ); i++ )
    {
        hStore = CertOpenStore( CERT_STORE_PROV_SYSTEM_A, 0, 0, dwStoreFlags[i], "MY" );

        if( !hStore )
            continue;

        {
            BYTE bb[64/*MAX_OID_LEN*/];
            int bblen = sizeof( bb );
            int sslen = strlen( clientCert );

            if( sslen < bblen * 2 )
            {
                bblen = str2bin( clientCert, bb );

                if( bblen != -1 )
                {
                    CERT_ID id;

                    id.dwIdChoice = CERT_ID_SHA1_HASH;
                    id._UN HashId.pbData = bb;
                    id._UN HashId.cbData = bblen;

                    cert = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL );

                    if( cert )
                        break;

                    id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
                    id._UN KeyId.pbData = bb;
                    id._UN KeyId.cbData = bblen;

                    cert = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL );

                    if( cert )
                        break;
                }
            }

            cert = CertFindCertificateInStore( hStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_A, clientCert, NULL );

            if( cert )
                break;

            CertCloseStore( hStore, 0 );
            hStore = 0;
        }
    }

    if( hStore )
        CertCloseStore( hStore, 0 );

    if( h->cert )
        CertFreeCertificateContext( h->cert );

    h->cert = cert;
        
    return cert ? 1 : 0;
}

void msspi_close( MSSPI_HANDLE h )
{
    delete h;
}

char msspi_get_cipherinfo( MSSPI_HANDLE h, PSecPkgContext_CipherInfo cipherInfo )
{
    SECURITY_STATUS scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_CIPHER_INFO, (PVOID)cipherInfo );

    if( scRet != SEC_E_OK )
        return 0;

    return 1;
}

char msspi_get_peercerts( MSSPI_HANDLE h, void ** bufs, int * lens, int * count )
{
    int max = *count;
    int i;

    PCCERT_CONTEXT ServerCert = NULL;
    PCCERT_CONTEXT RunnerCert;

    SECURITY_STATUS scRet = sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&ServerCert );

    if( scRet != SEC_E_OK )
        return 0;

    RunnerCert = ServerCert;

    bool is_OK = false;

    for( i = 0; i < max && RunnerCert; i++ )
    {
        PCCERT_CONTEXT IssuerCert = NULL;
        DWORD dwVerificationFlags = 0;

        {
            lens[i] = RunnerCert->cbCertEncoded;
            bufs[i] = new char[RunnerCert->cbCertEncoded];
            memcpy( bufs[i], RunnerCert->pbCertEncoded, RunnerCert->cbCertEncoded );
        }

        IssuerCert = CertGetIssuerCertificateFromStore( ServerCert->hCertStore, RunnerCert, NULL, &dwVerificationFlags );

        if( RunnerCert != ServerCert )
            CertFreeCertificateContext( RunnerCert );

        RunnerCert = IssuerCert;

        if( IssuerCert == NULL )
            is_OK = true;
    }

    max = i;

    if( RunnerCert && RunnerCert != ServerCert )
        CertFreeCertificateContext( RunnerCert );

    if( ServerCert )
        CertFreeCertificateContext( ServerCert );

    if( !is_OK )
    {
        for( i = 0; i < max; i++ )
            delete[] (char *)bufs[i];

        return 0;
    }

    *count = max;
    return 1;
}

void msspi_get_peercerts_free( MSSPI_HANDLE h, void ** bufs, int count )
{
    int i;

    if( !h )
        return;

    for( i = 0; i < count; i++ )
        delete[] (char *)bufs[i];
}

unsigned msspi_verify( MSSPI_HANDLE h )
{
    DWORD dwVerify = MSSPI_VERIFY_ERROR;
    PCCERT_CONTEXT ServerCert = NULL;
    PCCERT_CHAIN_CONTEXT ServerChain = NULL;

    for( ;; )
    {
        if( SEC_E_OK != sspi->QueryContextAttributesA( &h->hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&ServerCert ) )
            break;

        CERT_CHAIN_PARA ChainPara;
        memset( &ChainPara, 0, sizeof( ChainPara ) );
        ChainPara.cbSize = sizeof( ChainPara );

        if( !CertGetCertificateChain(
            NULL,
            ServerCert,
            NULL,
            NULL,
            &ChainPara,
            CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
            NULL,
            &ServerChain ) )
            break;

        CERT_CHAIN_POLICY_PARA PolicyPara;
        memset( &PolicyPara, 0, sizeof( PolicyPara ) );
        PolicyPara.cbSize = sizeof( PolicyPara );

        CERT_CHAIN_POLICY_STATUS PolicyStatus;
        memset( &PolicyStatus, 0, sizeof( PolicyStatus ) );
        PolicyStatus.cbSize = sizeof( PolicyStatus );

        if( !CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_BASE,
            ServerChain,
            &PolicyPara,
            &PolicyStatus ) )
            break;

        dwVerify = MSSPI_VERIFY_OK;

        if( PolicyStatus.dwError )
            dwVerify = PolicyStatus.dwError;

        break;
    }

    if( ServerCert )
        CertFreeCertificateContext( ServerCert );

    if( ServerChain )
        CertFreeCertificateChain( ServerChain );

    return (unsigned)dwVerify;
}
