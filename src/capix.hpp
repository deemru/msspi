#ifndef _CAPIX_H_INCLUDED_
#define _CAPIX_H_INCLUDED_

#if defined( __cplusplus )
extern "C" {
#endif

#ifdef _WIN32
#define LIBLOAD( name ) LoadLibraryA( name )
#define LIBFUNC( lib, name ) (void *)GetProcAddress( (HMODULE)lib, name )
#else
#include <dlfcn.h>
#define LIBLOAD( name ) dlopen( name, RTLD_LAZY )
#define LIBFUNC( lib, name ) dlsym( lib, name )
#endif

#ifdef _WIN32
#define CAPI10_LIB "capi10_win.dll"
#define CAPI20_LIB "capi20_win.dll"
#define RDRSUP_LIB "cpsuprt.dll"
#elif defined( __APPLE__ )
#define CAPI10_LIB "/opt/cprocsp/lib/libcapi10.dylib"
#define CAPI20_LIB "/opt/cprocsp/lib/libcapi20.dylib"
#define RDRSUP_LIB "/opt/cprocsp/lib/librdrsup.dylib"
#include <TargetConditionals.h>
#else // other LINUX
#if defined( __mips__ ) // archs
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        #define CAPI10_LIB "/opt/cprocsp/lib/mipsel/libcapi10.so"
        #define CAPI20_LIB "/opt/cprocsp/lib/mipsel/libcapi20.so"
        #define RDRSUP_LIB "/opt/cprocsp/lib/mipsel/librdrsup.so"
    #else // byte order
        #define CAPI10_LIB "/opt/cprocsp/lib/mips/libcapi10.so"
        #define CAPI20_LIB "/opt/cprocsp/lib/mips/libcapi20.so"
        #define RDRSUP_LIB "/opt/cprocsp/lib/mips/librdrsup.so"
    #endif // byte order
#elif defined( __arm__ )
    #define CAPI10_LIB "/opt/cprocsp/lib/arm/libcapi10.so"
    #define CAPI20_LIB "/opt/cprocsp/lib/arm/libcapi20.so"
    #define RDRSUP_LIB "/opt/cprocsp/lib/arm/librdrsup.so"
#elif defined( __aarch64__ ) // archs
    #define CAPI10_LIB "/opt/cprocsp/lib/aarch64/libcapi10.so"
    #define CAPI20_LIB "/opt/cprocsp/lib/aarch64/libcapi20.so"
    #define RDRSUP_LIB "/opt/cprocsp/lib/aarch64/librdrsup.so"
#elif defined( __i386__ ) // archs
    #define CAPI10_LIB "/opt/cprocsp/lib/ia32/libcapi10.so"
    #define CAPI20_LIB "/opt/cprocsp/lib/ia32/libcapi20.so"
    #define RDRSUP_LIB "/opt/cprocsp/lib/ia32/librdrsup.so"
#else // archs
#define CAPI10_LIB "/opt/cprocsp/lib/amd64/libcapi10.so"
#define CAPI20_LIB "/opt/cprocsp/lib/amd64/libcapi20.so"
#define RDRSUP_LIB "/opt/cprocsp/lib/amd64/librdrsup.so"
#endif // archs
#endif // _WIN32 or __APPLE__ or LINUX

#if defined( __clang__ ) && defined( __has_attribute ) // NOCFI
#define EXTERCALL( call ) [&]()__attribute__((no_sanitize("cfi-icall"))){ call; }()
#else
#define EXTERCALL( call ) call
#endif

static void * get_capi10x( LPCSTR name )
{
    static void * capi10 = (void *)(uintptr_t)-1;
    if( capi10 == (void *)(uintptr_t)-1 )
        capi10 = LIBLOAD( CAPI10_LIB );
    return capi10 ? LIBFUNC( capi10, name ) : NULL;
}

static void * get_capi20x( LPCSTR name )
{
    static void * capi20 = (void *)(uintptr_t)-1;
    if( capi20 == (void *)(uintptr_t)-1 )
        capi20 = LIBLOAD( CAPI20_LIB );
    return capi20 ? LIBFUNC( capi20, name ) : NULL;
}

static void * get_rdrsupx( LPCSTR name )
{
    static void * rdrsup = (void *)(uintptr_t)-1;
    if( rdrsup == (void *)(uintptr_t)-1 )
        rdrsup = LIBLOAD( RDRSUP_LIB );
    return rdrsup ? LIBFUNC( rdrsup, name ) : NULL;
}

#define DECLARE_CAPI10X_FUNCTION( rettype, name, args, callargs, reterr ) \
typedef rettype ( WINAPI * t_##name ) args; \
rettype WINAPI name args \
{ \
    rettype result; \
    static t_##name capix = NULL; \
    if( !capix ) \
        *(void **)&capix = get_capi10x( #name ); \
    if( !capix ) \
        return reterr; \
    EXTERCALL( result = capix callargs; ); \
    return result; \
}

#define DECLARE_CAPI20X_FUNCTION( rettype, name, args, callargs, reterr ) \
typedef rettype ( WINAPI * t_##name ) args; \
rettype WINAPI name args \
{ \
    rettype result; \
    static t_##name capix = NULL; \
    if( !capix ) \
        *(void **)&capix = get_capi20x( #name ); \
    if( !capix ) \
        return reterr; \
    EXTERCALL( result = capix callargs; ); \
    return result; \
}

#define DECLARE_CAPI20X_FUNCTION_VOID( name, args, callargs ) \
typedef void ( WINAPI * t_##name ) args; \
void WINAPI name args \
{ \
    static t_##name capix = NULL; \
    if( !capix ) \
        *(void **)&capix = get_capi20x( #name ); \
    if( !capix ) \
        return; \
    EXTERCALL( capix callargs; ); \
}

#define DECLARE_RDRSUPX_FUNCTION( rettype, name, args, callargs, reterr ) \
typedef rettype ( WINAPI * t_##name ) args; \
rettype WINAPI name args \
{ \
    rettype result; \
    static t_##name capix = NULL; \
    if( !capix ) \
        *(void **)&capix = get_rdrsupx( #name ); \
    if( !capix ) \
        return reterr; \
    EXTERCALL( result = capix callargs; ); \
    return result; \
}

DECLARE_CAPI10X_FUNCTION( BOOL, CryptAcquireContextA,
    ( HCRYPTPROV * phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags ),
    ( phProv, szContainer, szProvider, dwProvType, dwFlags ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptAcquireContextW,
    ( HCRYPTPROV * phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags ),
    ( phProv, szContainer, szProvider, dwProvType, dwFlags ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptReleaseContext,
    ( HCRYPTPROV hProv, DWORD dwFlags ),
    ( hProv, dwFlags ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptSetProvParam,
    ( HCRYPTPROV hProv, DWORD dwParam, const BYTE * pbData, DWORD dwFlags ),
    ( hProv, dwParam, pbData, dwFlags ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptGetUserKey,
    ( HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY * phUserKey ),
    ( hProv, dwKeySpec, phUserKey ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptExportKey,
    ( HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags, BYTE * pbData, DWORD * pdwDataLen ),
    ( hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptImportKey,
    ( HCRYPTPROV hProv, const BYTE * pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY * phKey ),
    ( hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptSetKeyParam,
    ( HCRYPTKEY hKey, DWORD dwParam, const BYTE * pbData, DWORD dwFlags ),
    ( hKey, dwParam, pbData, dwFlags ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptEncrypt,
    ( HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE * pbData, DWORD * pdwDataLen, DWORD dwBufLen ),
    ( hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptDestroyKey,
    ( HCRYPTKEY hKey ),
    ( hKey ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptCreateHash,
    ( HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH * phHash ),
    ( hProv, Algid, hKey, dwFlags, phHash ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptDestroyHash,
    ( HCRYPTHASH hHash ),
    ( hHash ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptGetHashParam,
    ( HCRYPTHASH hHash, DWORD dwParam, BYTE * pbData, DWORD * pdwDataLen, DWORD dwFlags ),
    ( hHash, dwParam, pbData, pdwDataLen, dwFlags ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptHashData,
    ( HCRYPTHASH hHash, const BYTE * pbData, DWORD dwDataLen, DWORD dwFlags ),
    ( hHash, pbData, dwDataLen, dwFlags ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptSignHash,
    ( HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR szDescription, DWORD dwFlags, BYTE * pbSignature, DWORD * pdwSigLen ),
    ( hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptGetProvParam,
    ( HCRYPTPROV hProv, DWORD dwParam, BYTE * pbData, DWORD * pdwDataLen, DWORD dwFlags ),
    ( hProv, dwParam, pbData, pdwDataLen, dwFlags ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptGenKey,
    ( HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY * phKey ),
    ( hProv, Algid, dwFlags, phKey ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptEnumProvidersA,
    ( DWORD dwIndex, DWORD * pdwReserved, DWORD dwFlags, DWORD * pdwProvType, LPSTR szProvName, DWORD * pcbProvName ),
    ( dwIndex, pdwReserved, dwFlags, pdwProvType, szProvName, pcbProvName ), FALSE )

DECLARE_CAPI10X_FUNCTION( BOOL, CryptGetKeyParam,
    ( HCRYPTKEY hKey, DWORD dwParam, BYTE * pbData, DWORD * pdwDataLen, DWORD dwFlags ),
    ( hKey, dwParam, pbData, pdwDataLen, dwFlags ), FALSE )

DECLARE_CAPI20X_FUNCTION( PCCERT_CONTEXT, CertCreateCertificateContext,
    ( DWORD dwCertEncodingType, const BYTE * pbCertEncoded, DWORD cbCertEncoded ),
    ( dwCertEncodingType, pbCertEncoded, cbCertEncoded ), NULL )

DECLARE_CAPI20X_FUNCTION( BOOL, CertFreeCertificateContext,
    ( PCCERT_CONTEXT pCertContext ),
    ( pCertContext ), FALSE )

DECLARE_CAPI20X_FUNCTION( PCCERT_CONTEXT, CertDuplicateCertificateContext,
    ( PCCERT_CONTEXT pCertContext ),
    ( pCertContext ), NULL )

DECLARE_CAPI20X_FUNCTION( HCERTSTORE, CertOpenStore,
    ( LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV hCryptProv, DWORD dwFlags, const void * pvPara ),
    ( lpszStoreProvider, dwEncodingType, hCryptProv, dwFlags, pvPara ), NULL )

DECLARE_CAPI20X_FUNCTION( PCCERT_CONTEXT, CertFindCertificateInStore,
    ( HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, const void * pvFindPara, PCCERT_CONTEXT pPrevCertContext ),
    ( hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext ), NULL )

DECLARE_CAPI20X_FUNCTION( BOOL, CertVerifyCertificateChainPolicy,
    ( LPCSTR pszPolicyOID, PCCERT_CHAIN_CONTEXT pChainContext, PCERT_CHAIN_POLICY_PARA pPolicyPara, PCERT_CHAIN_POLICY_STATUS pPolicyStatus ),
    ( pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CertGetIntendedKeyUsage,
    ( DWORD dwCertEncodingType, PCERT_INFO pCertInfo, BYTE * pbKeyUsage, DWORD cbKeyUsage ),
    ( dwCertEncodingType, pCertInfo, pbKeyUsage, cbKeyUsage ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CertGetEnhancedKeyUsage,
    ( PCCERT_CONTEXT pCertContext, DWORD dwFlags, PCERT_ENHKEY_USAGE pUsage, DWORD * pcbUsage ),
    ( pCertContext, dwFlags, pUsage, pcbUsage ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CertGetCertificateContextProperty,
    ( PCCERT_CONTEXT pCertContext, DWORD dwPropId, void * pvData, DWORD * pcbData ),
    ( pCertContext, dwPropId, pvData, pcbData ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CertCloseStore,
    ( HCERTSTORE hCertStore, DWORD dwFlags ),
    ( hCertStore, dwFlags ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CertSetCertificateContextProperty,
    ( PCCERT_CONTEXT pCertContext, DWORD dwPropId, DWORD dwFlags, const void * pvData ),
    ( pCertContext, dwPropId, dwFlags, pvData ), FALSE )

DECLARE_CAPI20X_FUNCTION( DWORD, CertGetNameStringW,
    ( PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void * pvTypePara, LPWSTR pszNameString, DWORD cchNameString ),
    ( pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString ), 0 )

DECLARE_CAPI20X_FUNCTION( LONG, CertVerifyTimeValidity,
    ( LPFILETIME pTimeToVerify, PCERT_INFO pCertInfo ),
    ( pTimeToVerify, pCertInfo ), -1 )

DECLARE_CAPI20X_FUNCTION( PCCERT_CONTEXT, CertGetIssuerCertificateFromStore,
    ( HCERTSTORE hCertStore, PCCERT_CONTEXT pSubjectContext, PCCERT_CONTEXT pPrevIssuerContext, DWORD * pdwFlags ),
    ( hCertStore, pSubjectContext, pPrevIssuerContext, pdwFlags ), NULL )

DECLARE_CAPI20X_FUNCTION( BOOL, CertGetCertificateChain,
    ( HCERTCHAINENGINE hChainEngine, PCCERT_CONTEXT pCertContext, LPFILETIME pTime, HCERTSTORE hAdditionalStore, PCERT_CHAIN_PARA pChainPara, DWORD dwFlags, LPVOID pvReserved, PCCERT_CHAIN_CONTEXT * ppChainContext ),
    ( hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext ), FALSE )

DECLARE_CAPI20X_FUNCTION_VOID( CertFreeCertificateChain,
    ( PCCERT_CHAIN_CONTEXT pChainContext ),
    ( pChainContext ) )

DECLARE_CAPI20X_FUNCTION( BOOL, CryptGenRandom,
    ( HCRYPTPROV hProv, DWORD dwLen, BYTE * pbBuffer ),
    ( hProv, dwLen, pbBuffer ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CryptBinaryToStringA,
    ( const BYTE * pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD * pcchString ),
    ( pbBinary, cbBinary, dwFlags, pszString, pcchString ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CryptStringToBinaryA,
    ( LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE * pbBinary, DWORD * pcbBinary, DWORD * pdwSkip, DWORD * pdwFlags ),
    ( pszString, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags ), FALSE )

DECLARE_CAPI20X_FUNCTION( DWORD, CertNameToStrW,
    ( DWORD dwCertEncodingType, PCERT_NAME_BLOB pName, DWORD dwStrType, LPWSTR psz, DWORD csz ),
    ( dwCertEncodingType, pName, dwStrType, psz, csz ), 0 )

DECLARE_CAPI20X_FUNCTION( BOOL, CryptEncodeObject,
    ( DWORD dwCertEncodingType, LPCSTR lpszStructType, const void * pvStructInfo, BYTE * pbEncoded, DWORD * pcbEncoded ),
    ( dwCertEncodingType, lpszStructType, pvStructInfo, pbEncoded, pcbEncoded ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CryptExportPublicKeyInfo,
    ( HCRYPTPROV hCryptProv, DWORD dwKeySpec, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, DWORD * pcbInfo ),
    ( hCryptProv, dwKeySpec, dwCertEncodingType, pInfo, pcbInfo ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CryptSignAndEncodeCertificate,
    ( HCRYPTPROV hCryptProv, DWORD dwKeySpec, DWORD dwCertEncodingType, LPCSTR lpszStructType, const void * pvStructInfo, PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm, const void * pvHashAuxInfo, PBYTE pbEncoded, DWORD * pcbEncoded ),
    ( hCryptProv, dwKeySpec, dwCertEncodingType, lpszStructType, pvStructInfo, pSignatureAlgorithm, pvHashAuxInfo, pbEncoded, pcbEncoded ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CertAddCertificateContextToStore,
    ( HCERTSTORE hCertStore, PCCERT_CONTEXT pCertContext, DWORD dwAddDisposition, PCCERT_CONTEXT * ppStoreContext ),
    ( hCertStore, pCertContext, dwAddDisposition, ppStoreContext ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CertDeleteCertificateFromStore,
    ( PCCERT_CONTEXT pCertContext ),
    ( pCertContext ), FALSE )

DECLARE_CAPI20X_FUNCTION( PCCERT_CONTEXT, CertEnumCertificatesInStore,
    ( HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext ),
    ( hCertStore, pPrevCertContext ), NULL )

DECLARE_CAPI20X_FUNCTION( PCCRL_CONTEXT, CertEnumCRLsInStore,
    ( HCERTSTORE hCertStore, PCCRL_CONTEXT pPrevCrlContext ),
    ( hCertStore, pPrevCrlContext ), NULL )

DECLARE_CAPI20X_FUNCTION( HCERTSTORE, PFXImportCertStore,
    ( CRYPT_DATA_BLOB * pPFX, LPCWSTR szPassword, DWORD dwFlags ),
    ( pPFX, szPassword, dwFlags ), 0 )

DECLARE_CAPI20X_FUNCTION( PCCRYPT_OID_INFO, CryptFindOIDInfo,
    ( DWORD dwKeyType, void * pvKey, DWORD dwGroupId ),
    ( dwKeyType, pvKey, dwGroupId ), NULL )

DECLARE_CAPI20X_FUNCTION( DWORD, CertGetPublicKeyLength,
    ( DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pPublicKey ),
    ( dwCertEncodingType, pPublicKey ), 0 )

DECLARE_RDRSUPX_FUNCTION( int, WideCharToMultiByte,
    ( UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar ),
    ( CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar ), 0 )

DECLARE_RDRSUPX_FUNCTION( BOOL, FileTimeToSystemTime,
    ( const FILETIME * lpFileTime, LPSYSTEMTIME lpSystemTime ),
    ( lpFileTime, lpSystemTime ), FALSE )

DECLARE_RDRSUPX_FUNCTION( DWORD, GetLastError,
    ( ),
    ( ), (DWORD)-1 )

#if defined( __cplusplus )
}
#endif

#endif /* _CAPIX_H_INCLUDED_ */
