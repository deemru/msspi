#pragma once // microsspi

#ifndef SECPKGCONTEXT_CIPHERINFO_V1

#define SZ_ALG_MAX_SIZE 64
#define SECPKGCONTEXT_CIPHERINFO_V1 1

#ifndef WIN32
typedef unsigned int DWORD;
typedef wchar_t WCHAR;
#endif

typedef struct _SecPkgContext_CipherInfo
{
    DWORD dwVersion;
    DWORD dwProtocol;
    DWORD dwCipherSuite;
    DWORD dwBaseCipherSuite;
    WCHAR szCipherSuite[SZ_ALG_MAX_SIZE];
    WCHAR szCipher[SZ_ALG_MAX_SIZE];
    DWORD dwCipherLen;
    DWORD dwCipherBlockLen;    // in bytes
    WCHAR szHash[SZ_ALG_MAX_SIZE];
    DWORD dwHashLen;
    WCHAR szExchange[SZ_ALG_MAX_SIZE];
    DWORD dwMinExchangeLen;
    DWORD dwMaxExchangeLen;
    WCHAR szCertificate[SZ_ALG_MAX_SIZE];
    DWORD dwKeyType;
} SecPkgContext_CipherInfo, *PSecPkgContext_CipherInfo;

#endif // SECPKGCONTEXT_CIPHERINFO_V1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MSSPI * MSSPI_HANDLE;

typedef int ( * msspi_read_cb )( void * cb_arg, void * buf, int len );
typedef int ( * msspi_write_cb )( void * cb_arg, const void * buf, int len );

MSSPI_HANDLE msspi_open( void * cb_arg, msspi_read_cb, msspi_write_cb );

char msspi_set_hostname( MSSPI_HANDLE h, const char * hostName );
char msspi_set_mycert( MSSPI_HANDLE h, const char * clientCert, int len );
void msspi_set_peerauth( MSSPI_HANDLE h, char is_peerauth );

int msspi_connect( MSSPI_HANDLE h );
int msspi_accept( MSSPI_HANDLE h );
int msspi_read( MSSPI_HANDLE h, void * buf, int len );
int msspi_write( MSSPI_HANDLE h, const void * buf, int len );
int msspi_shutdown( MSSPI_HANDLE h );

typedef enum
{
    MSSPI_NOTHING,
    MSSPI_READING,
    MSSPI_WRITING,
    MSSPI_X509_LOOKUP,
    MSSPI_SHUTDOWN,
    MSSPI_ERROR
}
MSSPI_STATE;

MSSPI_STATE msspi_state( MSSPI_HANDLE h );
int msspi_pending( MSSPI_HANDLE h );

char msspi_get_cipherinfo( MSSPI_HANDLE h, PSecPkgContext_CipherInfo cipherInfo );
char msspi_get_peercerts( MSSPI_HANDLE h, void ** bufs, int * lens, int * count );
void msspi_get_peercerts_free( MSSPI_HANDLE h, void ** bufs, int count );

#define MSSPI_VERIFY_OK                 0x00000000L // NoError
#define MSSPI_VERIFY_ERROR              0x00000001L // UnspecifiedError
#ifndef TRUST_E_CERT_SIGNATURE
#define TRUST_E_CERT_SIGNATURE          0x80096004L // CertificateSignatureFailed
#define CRYPT_E_REVOKED                 0x80092010L // CertificateRevoked
#define CERT_E_UNTRUSTEDROOT            0x800B0109L // CertificateUntrusted
#define CERT_E_UNTRUSTEDTESTROOT        0x800B010DL // CertificateUntrusted
#define CERT_E_CHAINING                 0x800B010AL // UnableToGetIssuerCertificate
#define CERT_E_WRONG_USAGE              0x800B0110L // InvalidPurpose
#define CERT_E_EXPIRED                  0x800B0101L // CertificateExpired
#define CERT_E_INVALID_NAME             0x800B0114L // HostNameMismatch
#define CERT_E_INVALID_POLICY           0x800B0113L // InvalidPurpose
#define TRUST_E_BASIC_CONSTRAINTS       0x80096019L // UnspecifiedError
#define CERT_E_CRITICAL                 0x800B0105L // UnspecifiedError
#define CERT_E_VALIDITYPERIODNESTING    0x800B0102L // CertificateNotYetValid
#define CRYPT_E_NO_REVOCATION_CHECK     0x80092012L // UnableToGetIssuerCertificate
#define CRYPT_E_REVOCATION_OFFLINE      0x80092013L // UnableToGetIssuerCertificate
#endif

unsigned msspi_verify( MSSPI_HANDLE h );

void msspi_close( MSSPI_HANDLE h );

#ifdef __cplusplus
}
#endif
