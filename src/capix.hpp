#ifndef _CAPIX_H_INCLUDED_
#define _CAPIX_H_INCLUDED_

#if defined( __cplusplus )
extern "C" {
#endif

#ifndef LIBLOAD
#ifdef _WIN32
#define LIBLOAD( name ) LoadLibraryA( name )
#define LIBFUNC( lib, name ) (void *)GetProcAddress( (HMODULE)lib, name )
#else
#include <dlfcn.h>
#define LIBLOAD( name ) dlopen( name, RTLD_LAZY )
#define LIBFUNC( lib, name ) dlsym( lib, name )
#endif
#endif // LIBLOAD

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
#define LIBCAPI10_NAME "capi10_win.dll"
#define LIBCAPI20_NAME "capi20_win.dll"
#define LIBRDRSUP_NAME "cpsuprt.dll"
#elif defined( __APPLE__ )
#define LIBCAPI10_NAME "libcapi10.dylib"
#define LIBCAPI20_NAME "libcapi20.dylib"
#define LIBRDRSUP_NAME "librdrsup.dylib"
#else // other LINUX
#define LIBCAPI10_NAME "libcapi10.so"
#define LIBCAPI20_NAME "libcapi20.so"
#define LIBRDRSUP_NAME "librdrsup.so"
#endif // LIBXXXXXX_NAME
#define LIBCAPI10_PATH_NAME CPROLIBS_PATH LIBCAPI10_NAME
#define LIBCAPI20_PATH_NAME CPROLIBS_PATH LIBCAPI20_NAME
#define LIBRDRSUP_PATH_NAME CPROLIBS_PATH LIBRDRSUP_NAME

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

static void * get_capi10x( LPCSTR name )
{
    static void * capi10 = (void *)(uintptr_t)-1;
    if( capi10 == (void *)(uintptr_t)-1 )
    {
        capi10 = LIBLOAD( LIBCAPI10_PATH_NAME );
        if( capi10 == NULL )
            capi10 = LIBLOAD( LIBCAPI10_NAME );
    }
    return capi10 ? LIBFUNC( capi10, name ) : NULL;
}

static void * get_capi20x( LPCSTR name )
{
    static void * capi20 = (void *)(uintptr_t)-1;
    if( capi20 == (void *)(uintptr_t)-1 )
    {
        capi20 = LIBLOAD( LIBCAPI20_PATH_NAME );
        if( capi20 == NULL )
            capi20 = LIBLOAD( LIBCAPI20_NAME );
    }
    return capi20 ? LIBFUNC( capi20, name ) : NULL;
}

static void * get_rdrsupx( LPCSTR name )
{
    static void * rdrsup = (void *)(uintptr_t)-1;
    if( rdrsup == (void *)(uintptr_t)-1 )
    {
        rdrsup = LIBLOAD( LIBRDRSUP_PATH_NAME );
        if( rdrsup == NULL )
            rdrsup = LIBLOAD( LIBRDRSUP_NAME );
    }
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

#define DECLARE_RDRSUPX_FUNCTION_VOID( name, args, callargs ) \
typedef void ( WINAPI * t_##name ) args; \
void WINAPI name args \
{ \
    static t_##name capix = NULL; \
    if( !capix ) \
        *(void **)&capix = get_rdrsupx( #name ); \
    if( !capix ) \
        return; \
    EXTERCALL( capix callargs; ); \
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

DECLARE_CAPI10X_FUNCTION( BOOL, CryptSignHashW,
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
    ( pPFX, szPassword, dwFlags ), NULL )

DECLARE_CAPI20X_FUNCTION( PCCRYPT_OID_INFO, CryptFindOIDInfo,
    ( DWORD dwKeyType, void * pvKey, DWORD dwGroupId ),
    ( dwKeyType, pvKey, dwGroupId ), NULL )

DECLARE_CAPI20X_FUNCTION( DWORD, CertGetPublicKeyLength,
    ( DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pPublicKey ),
    ( dwCertEncodingType, pPublicKey ), 0 )

DECLARE_CAPI20X_FUNCTION( PCERT_EXTENSION, CertFindExtension,
    ( LPCSTR pszObjId, DWORD cExtensions, CERT_EXTENSION * rgExtensions ),
    ( pszObjId, cExtensions, rgExtensions ), NULL )

DECLARE_CAPI20X_FUNCTION( BOOL, CryptDecodeObjectEx,
    ( DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE * pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void * pvStructInfo, DWORD * pcbStructInfo ),
    ( dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pDecodePara, pvStructInfo, pcbStructInfo ), FALSE )

DECLARE_CAPI20X_FUNCTION( BOOL, CryptAcquireCertificatePrivateKey,
                         ( PCCERT_CONTEXT pCert, DWORD dwFlags, void * pvParameters, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE * phCryptProvOrNCryptKey, DWORD * pdwKeySpec, BOOL * pfCallerFreeProvOrNCryptKey ),
                         ( pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey ), FALSE )

DECLARE_RDRSUPX_FUNCTION( int, WideCharToMultiByte,
    ( UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar ),
    ( CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar ), 0 )

DECLARE_RDRSUPX_FUNCTION( BOOL, FileTimeToSystemTime,
    ( const FILETIME * lpFileTime, LPSYSTEMTIME lpSystemTime ),
    ( lpFileTime, lpSystemTime ), FALSE )

DECLARE_RDRSUPX_FUNCTION( DWORD, GetLastError,
    ( ),
    ( ), (DWORD)-1 )

DECLARE_RDRSUPX_FUNCTION_VOID( SetLastError,
    ( DWORD dwErrCode ),
    ( dwErrCode ) )

#if defined( __cplusplus )
}
#endif

#endif /* _CAPIX_H_INCLUDED_ */
