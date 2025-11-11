#ifndef _MSSPI_CERT_HPP_INCLUDED_
#define _MSSPI_CERT_HPP_INCLUDED_

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

static std::vector<BYTE> certprop( PCCERT_CONTEXT cert, DWORD id )
{
    std::vector<BYTE> prop;

    DWORD dw;
    if( CertGetCertificateContextProperty( cert, id, NULL, &dw ) )
    {
        prop.resize( dw );
        if( CertGetCertificateContextProperty( cert, id, prop.data(), &dw ) )
        {
            if( dw < prop.size() )
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

#define MSSPI_CERT_MAGIC 0x4D434552 // MCER
#define MSSPI_CERT_MAGIC_VERSION ( MSSPI_CERT_MAGIC ^ MSSPI_VERSION )
#define MSSPI_CERT_MAGIC_DEAD MSSPI_CERT_MAGIC

struct MSSPI_CERT
{
    volatile uint32_t magic = MSSPI_CERT_MAGIC_VERSION;

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

        magic = MSSPI_CERT_MAGIC_DEAD;
    }
};

static MSSPI_CERT_HANDLE msspi_cert_handle( MSSPI_CERT_HANDLE ch )
{
    MSSPIEHTRY_ch;
    return ch;
    MSSPIEHCATCH_RET( NULL );
}

MSSPI_CERT_HANDLE msspi_cert_open( const uint8_t * certbuf, size_t len )
{
    MSSPIEHTRY_0;

    PCCERT_CONTEXT cert = NULL;

    if( !certbuf || !len )
    {
        SetLastError( ERROR_BAD_ARGUMENTS );
        return NULL;
    }

    cert = CertCreateCertificateContext( X509_ASN_ENCODING, (const BYTE *)certbuf, (DWORD)len );
    if( !cert )
    {
        std::vector<BYTE> certbufder;
        DWORD dwData;
        if( CryptStringToBinaryA( (const char *)certbuf, (DWORD)len, CRYPT_STRING_BASE64_ANY, NULL, &dwData, NULL, NULL ) )
        {
            certbufder.resize( dwData );
            if( CryptStringToBinaryA( (const char *)certbuf, (DWORD)len, CRYPT_STRING_BASE64_ANY, certbufder.data(), &dwData, NULL, NULL ) )
                cert = CertCreateCertificateContext( X509_ASN_ENCODING, certbufder.data(), dwData );
        }

        if( !cert )
            return NULL; // last error included
    }

    return msspi_cert_handle( new MSSPI_CERT( cert ) );

    MSSPIEHCATCH_RET( NULL );
}

MSSPI_CERT_HANDLE msspi_cert_next( MSSPI_CERT_HANDLE ch )
{
    MSSPIEHTRY_ch;

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
            ch_next = msspi_cert_open( (const uint8_t *)cert->pbCertEncoded, (size_t)cert->cbCertEncoded );
        }

        CertFreeCertificateChain( PeerChain );
    }

    return ch_next;

    MSSPIEHCATCH_RET( NULL );
}

int msspi_cert_close( MSSPI_CERT_HANDLE ch )
{
    MSSPIEHTRY_ch;

    delete ch;
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_cert_subject( MSSPI_CERT_HANDLE ch, const uint8_t ** buf, size_t * len, int quotes )
{
    MSSPIEHTRY_ch;

    ch->subject = certname( &ch->cert->pCertInfo->Subject, quotes != 0 ).c_str();
    // cppcheck-suppress danglingTemporaryLifetime
    if( !ch->subject.length() )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    *buf = (const uint8_t *)ch->subject.c_str();
    *len = ch->subject.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_cert_issuer( MSSPI_CERT_HANDLE ch, const uint8_t ** buf, size_t * len, int quotes )
{
    MSSPIEHTRY_ch;

    ch->issuer = certname( &ch->cert->pCertInfo->Issuer, quotes != 0 ).c_str();
    // cppcheck-suppress danglingTemporaryLifetime
    if( !ch->issuer.length() )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    *buf = (const uint8_t *)ch->issuer.c_str();
    *len = ch->issuer.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_cert_serial( MSSPI_CERT_HANDLE ch, const uint8_t ** buf, size_t * len )
{
    MSSPIEHTRY_ch;

    if( !ch->cert->pCertInfo->SerialNumber.pbData || !ch->cert->pCertInfo->SerialNumber.cbData )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    ch->serial = to_hex_string( ch->cert->pCertInfo->SerialNumber.pbData, ch->cert->pCertInfo->SerialNumber.cbData );
    if( !ch->serial.length() )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    *buf = (const uint8_t *)ch->serial.c_str();
    *len = ch->serial.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_cert_keyid( MSSPI_CERT_HANDLE ch, const uint8_t ** buf, size_t * len )
{
    MSSPIEHTRY_ch;

    std::vector<BYTE> prop = certprop( ch->cert, CERT_KEY_IDENTIFIER_PROP_ID );
    if( !prop.size() )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    ch->keyid = to_hex_string( prop.data(), prop.size() );
    if( !ch->keyid.length() )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    *buf = (const uint8_t *)ch->keyid.c_str();
    *len = ch->keyid.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_cert_sha1( MSSPI_CERT_HANDLE ch, const uint8_t ** buf, size_t * len )
{
    MSSPIEHTRY_ch;

    std::vector<BYTE> prop = certprop( ch->cert, CERT_SHA1_HASH_PROP_ID );
    if( !prop.size() )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    ch->sha1 = to_hex_string( prop.data(), prop.size() );
    if( !ch->sha1.length() )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    *buf = (const uint8_t *)ch->sha1.c_str();
    *len = ch->sha1.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_cert_alg_sig( MSSPI_CERT_HANDLE ch, const uint8_t ** buf, size_t * len )
{
    MSSPIEHTRY_ch;

    if( !ch->cert->pCertInfo->SignatureAlgorithm.pszObjId )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    ch->alg_sig = algstr( ch->cert->pCertInfo->SignatureAlgorithm.pszObjId );
    if( !ch->alg_sig.length() )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    *buf = (const uint8_t *)ch->alg_sig.c_str();
    *len = ch->alg_sig.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_cert_alg_key( MSSPI_CERT_HANDLE ch, const uint8_t ** buf, size_t * len )
{
    MSSPIEHTRY_ch;

    if( !ch->cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    ch->alg_key = algstr( ch->cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId );
    if( !ch->alg_key.length() )
    {
        SetLastError( ERROR_NOT_FOUND );
        return 0;
    }

    std::string bitlen = alglenstr( &ch->cert->pCertInfo->SubjectPublicKeyInfo );
    if( bitlen.length() > 0 )
        ch->alg_key += " (" + bitlen + " бит)";

    *buf = (const uint8_t *)ch->alg_key.c_str();
    *len = ch->alg_key.length();
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

int msspi_cert_time_issued( MSSPI_CERT_HANDLE ch, struct tm * time )
{
    MSSPIEHTRY_ch;

    SYSTEMTIME stime;
    if( !FileTimeToSystemTime( &ch->cert->pCertInfo->NotBefore, &stime ) )
        return 0; // last error included

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

int msspi_cert_time_expired( MSSPI_CERT_HANDLE ch, struct tm * time )
{
    MSSPIEHTRY_ch;

    SYSTEMTIME stime;
    if( !FileTimeToSystemTime( &ch->cert->pCertInfo->NotAfter, &stime ) )
        return 0; // last error included

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

#endif /* _MSSPI_CERT_HPP_INCLUDED_ */
