#ifndef _MSSPI_H_INCLUDED_
#define _MSSPI_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>

#define MSSPI_VERSION_MAJOR 1
#define MSSPI_VERSION_MINOR 0
#define MSSPI_VERSION_PATCH 1

#define MSSPI_VERSION \
    ( ( MSSPI_VERSION_MAJOR << 16 ) | ( MSSPI_VERSION_MINOR << 8 ) | MSSPI_VERSION_PATCH )

#define MSSPI_MAKE_VERSION( major, minor, patch ) \
    ( ( ( major ) << 16 ) | ( ( minor ) << 8 ) | ( patch ) )

#ifdef __cplusplus
extern "C" {
#endif

uint32_t msspi_version( void );

#define TLS1_VERSION    0x0301
#define TLS1_1_VERSION  0x0302
#define TLS1_2_VERSION  0x0303
#define TLS1_3_VERSION  0x0304

int msspi_is_version_supported( int version );
int msspi_is_cipher_supported( int cipher );

typedef struct MSSPI * MSSPI_HANDLE;

typedef int ( * msspi_read_cb )( void * cb_arg, void * buf, int len );
typedef int ( * msspi_write_cb )( void * cb_arg, const void * buf, int len );
typedef int ( * msspi_cert_cb )( void * cb_arg );

MSSPI_HANDLE msspi_open( void * cb_arg, msspi_read_cb read_cb, msspi_write_cb write_cb );

int msspi_set_hostname( MSSPI_HANDLE h, const uint8_t * hostname, size_t hostname_len );
int msspi_set_cachestring( MSSPI_HANDLE h, const uint8_t * cachestring, size_t cachestring_len );
int msspi_set_alpn( MSSPI_HANDLE h, const uint8_t * alpn, size_t alpn_len );
int msspi_set_certstore( MSSPI_HANDLE h, const uint8_t * store, size_t store_len );
int msspi_set_mycert( MSSPI_HANDLE h, const uint8_t * cert, size_t cert_len );
int msspi_add_mycert( MSSPI_HANDLE h, const uint8_t * cert, size_t cert_len );
int msspi_set_mycert_pfx( MSSPI_HANDLE h, const uint8_t * pfx, size_t pfx_len, const uint8_t * password, size_t password_len );
int msspi_add_mycert_pfx( MSSPI_HANDLE h, const uint8_t * pfx, size_t pfx_len, const uint8_t * password, size_t password_len );
int msspi_set_mycert_options( MSSPI_HANDLE h, int silent, const uint8_t * pin, size_t pin_len, int selftest );
int msspi_set_peerauth( MSSPI_HANDLE h, int enable );
int msspi_set_cert_cb( MSSPI_HANDLE h, msspi_cert_cb cert );
int msspi_set_client( MSSPI_HANDLE h, int enable );
int msspi_set_dtls( MSSPI_HANDLE h, int enable );
int msspi_set_pin_cache( MSSPI_HANDLE h, int enable );
int msspi_set_version( MSSPI_HANDLE h, int min, int max );
int msspi_set_cipherlist( MSSPI_HANDLE h, const uint8_t * cipherlist, size_t cipherlist_len );
int msspi_set_credprovider( MSSPI_HANDLE h, const uint8_t * credprovider, size_t credprovider_len );
int msspi_set_input( MSSPI_HANDLE h, const uint8_t * input, size_t input_len );
int msspi_set_verify_offline( MSSPI_HANDLE h, int enable );
int msspi_set_verify_revocation( MSSPI_HANDLE h, int enable );
int msspi_set_dtls_peeraddr( MSSPI_HANDLE h, const uint8_t * peeraddr, size_t peeraddr_len );
int msspi_set_dtls_mtu( MSSPI_HANDLE h, size_t mtu );

int msspi_connect( MSSPI_HANDLE h );
int msspi_accept( MSSPI_HANDLE h );
int msspi_pending( MSSPI_HANDLE h );
int msspi_read( MSSPI_HANDLE h, void * buf, int len );
int msspi_peek( MSSPI_HANDLE h, void * buf, int len );
int msspi_write( MSSPI_HANDLE h, const void * buf, int len );
int msspi_shutdown( MSSPI_HANDLE h );

int msspi_random( void * buf, int len );

#define MSSPI_EMPTY ( 0 )
#define MSSPI_ERROR ( 1 << 30 )

#define MSSPI_READING ( 1 << 1 )
#define MSSPI_WRITING ( 1 << 2 )
#define MSSPI_X509_LOOKUP ( 1 << 3 )
#define MSSPI_SHUTDOWN_PROC ( 1 << 4 )
#define MSSPI_SENT_SHUTDOWN ( 1 << 5 )
#define MSSPI_RECEIVED_SHUTDOWN ( 1 << 6 )
#define MSSPI_LAST_PROC_WRITE ( 1 << 7 )

int msspi_state( MSSPI_HANDLE h );
uint32_t msspi_last_error( void );

#ifndef SECPKGCONTEXT_CIPHERINFO_V1

#define SECPKGCONTEXT_CIPHERINFO_V1 1
#define SZ_ALG_MAX_SIZE 64

#ifndef WIN32
typedef unsigned int DWORD;
#else
typedef unsigned long DWORD;
#endif

typedef wchar_t WCHAR;

typedef struct _SecPkgContext_CipherInfo
{
    DWORD dwVersion;
    DWORD dwProtocol;
    DWORD dwCipherSuite;
    DWORD dwBaseCipherSuite;
    WCHAR szCipherSuite[SZ_ALG_MAX_SIZE];
    WCHAR szCipher[SZ_ALG_MAX_SIZE];
    DWORD dwCipherLen;
    DWORD dwCipherBlockLen;
    WCHAR szHash[SZ_ALG_MAX_SIZE];
    DWORD dwHashLen;
    WCHAR szExchange[SZ_ALG_MAX_SIZE];
    DWORD dwMinExchangeLen;
    DWORD dwMaxExchangeLen;
    WCHAR szCertificate[SZ_ALG_MAX_SIZE];
    DWORD dwKeyType;
} SecPkgContext_CipherInfo, *PSecPkgContext_CipherInfo;

#endif /* SECPKGCONTEXT_CIPHERINFO_V1 */

int msspi_get_cipherinfo( MSSPI_HANDLE h, const SecPkgContext_CipherInfo ** cipherinfo );
int msspi_get_version( MSSPI_HANDLE h, uint32_t * version_num, const uint8_t ** version_str, size_t * version_str_len );
int msspi_get_mycert( MSSPI_HANDLE h, const uint8_t ** cert, size_t * cert_len );
int msspi_get_peercerts( MSSPI_HANDLE h, const uint8_t ** certs, size_t * certs_lens, size_t * certs_count );
int msspi_get_peerchain( MSSPI_HANDLE h, int online, const uint8_t ** certs, size_t * certs_lens, size_t * certs_count );
int msspi_get_peernames( MSSPI_HANDLE h, const uint8_t ** subject, size_t * subject_len, const uint8_t ** issuer, size_t * issuer_len );
int msspi_get_issuerlist( MSSPI_HANDLE h, const uint8_t ** certs, size_t * certs_lens, size_t * certs_count );
int msspi_get_alpn( MSSPI_HANDLE h, const uint8_t ** alpn, size_t * alpn_len );

#ifndef TRUST_E_CERT_SIGNATURE
#define TRUST_E_CERT_SIGNATURE          (uint32_t)0x80096004L
#define CRYPT_E_REVOKED                 (uint32_t)0x80092010L
#define CERT_E_UNTRUSTEDROOT            (uint32_t)0x800B0109L
#define CERT_E_UNTRUSTEDTESTROOT        (uint32_t)0x800B010DL
#define CERT_E_CHAINING                 (uint32_t)0x800B010AL
#define CERT_E_REVOCATION_FAILURE       (uint32_t)0x800B010EL
#define CERT_E_WRONG_USAGE              (uint32_t)0x800B0110L
#define CERT_E_EXPIRED                  (uint32_t)0x800B0101L
#define CERT_E_INVALID_NAME             (uint32_t)0x800B0114L
#define CERT_E_CN_NO_MATCH              (uint32_t)0x800B010FL
#define CERT_E_INVALID_POLICY           (uint32_t)0x800B0113L
#define TRUST_E_BASIC_CONSTRAINTS       (uint32_t)0x80096019L
#define CERT_E_CRITICAL                 (uint32_t)0x800B0105L
#define CERT_E_VALIDITYPERIODNESTING    (uint32_t)0x800B0102L
#define CRYPT_E_NO_REVOCATION_CHECK     (uint32_t)0x80092012L
#define CRYPT_E_REVOCATION_OFFLINE      (uint32_t)0x80092013L
#define CERT_E_ROLE                     (uint32_t)0x800B0103L
#endif

#ifndef SECBUFFER_ALERT
#define SECBUFFER_ALERT 17
#endif

int msspi_verify( MSSPI_HANDLE h, uint32_t * verify_result );
int msspi_verify_peer_in_store( MSSPI_HANDLE h, const uint8_t * store, size_t store_len );

int msspi_close( MSSPI_HANDLE h );

#ifdef MSSPI_USE_MSSPI_CERT

typedef struct MSSPI_CERT * MSSPI_CERT_HANDLE;

MSSPI_CERT_HANDLE msspi_cert_open( const uint8_t * cert, size_t cert_len );
MSSPI_CERT_HANDLE msspi_cert_next( MSSPI_CERT_HANDLE h );

int msspi_cert_subject( MSSPI_CERT_HANDLE ch, const uint8_t ** data, size_t * data_len, int quotes );
int msspi_cert_issuer( MSSPI_CERT_HANDLE ch, const uint8_t ** data, size_t * data_len, int quotes );
int msspi_cert_serial( MSSPI_CERT_HANDLE ch, const uint8_t ** data, size_t * data_len );
int msspi_cert_keyid( MSSPI_CERT_HANDLE ch, const uint8_t ** data, size_t * data_len );
int msspi_cert_sha1( MSSPI_CERT_HANDLE ch, const uint8_t ** data, size_t * data_len );
int msspi_cert_alg_sig( MSSPI_CERT_HANDLE ch, const uint8_t ** data, size_t * data_len );
int msspi_cert_alg_key( MSSPI_CERT_HANDLE ch, const uint8_t ** data, size_t * data_len );
int msspi_cert_time_issued( MSSPI_CERT_HANDLE ch, struct tm * time );
int msspi_cert_time_expired( MSSPI_CERT_HANDLE ch, struct tm * time );

int msspi_cert_close( MSSPI_CERT_HANDLE ch );

#endif /* MSSPI_USE_MSSPI_CERT */

#ifdef __cplusplus
}
#endif

#endif /* _MSSPI_H_INCLUDED_ */
