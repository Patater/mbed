/*
 *  X.509 common functions for parsing and verification
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_USE_C)

#include "mbedtls/x509.h"
#include "mbedtls/x509_internal.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"

/* XXX We have to avoid doing this optimization like this for now, because Mbed
 * OS finds the C files and forces them to get build, even though we only want
 * to include them. We can manually inline them, or enhance our importer script
 * to do the inlining for us. */
#if 0
/* We include x509xxx.c files here so that x509.c is one compilation unit including
 * all the x509 files. This is done because some of the internal functions are shared.
 * For code size savings internal functions should be static so that compiler can do better job
 * when optimizing. We don't wan't x509.c file to get too big so including .c files.
 */
#include "x509_crl.c"
#include "x509_crt.c"
#include "x509_csr.c"
#include "x509_create.c"
#include "x509write_crt.c"
#include "x509write_csr.c"
#else

/*
 *  X.509 Certidicate Revocation List (CRL) parsing
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CRL_PARSE_C)

#include "mbedtls/x509_crl.h"
#include "mbedtls/x509_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf
#endif

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
#include <windows.h>
#else
#include <time.h>
#endif

#if defined(MBEDTLS_FS_IO) || defined(EFIX64) || defined(EFI32)
#include <stdio.h>
#endif

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1)  }
 */
static int x509_crl_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret );
    }

    return( 0 );
}

/*
 * X.509 CRL v2 extensions
 *
 * We currently don't parse any extension's content, but we do check that the
 * list of extensions is well-formed and abort on critical extensions (that
 * are unsupported as we don't support any extension so far)
 */
static int x509_get_crl_ext( unsigned char **p,
                             const unsigned char *end,
                             mbedtls_x509_buf *ext )
{
    int ret;

    if( *p == end )
        return( 0 );

    /*
     * crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
     *                              -- if present, version MUST be v2
     */
    if( ( ret = mbedtls_x509_get_ext( p, end, ext, 0 ) ) != 0 )
        return( ret );

    end = ext->p + ext->len;

    while( *p < end )
    {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        int is_critical = 0;
        const unsigned char *end_ext_data;
        size_t len;

        /* Get enclosing sequence tag */
        if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        end_ext_data = *p + len;

        /* Get OID (currently ignored) */
        if( ( ret = mbedtls_asn1_get_tag( p, end_ext_data, &len,
                                          MBEDTLS_ASN1_OID ) ) != 0 )
        {
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
        }
        *p += len;

        /* Get optional critical */
        if( ( ret = mbedtls_asn1_get_bool( p, end_ext_data,
                                           &is_critical ) ) != 0 &&
            ( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) )
        {
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
        }

        /* Data should be octet string type */
        if( ( ret = mbedtls_asn1_get_tag( p, end_ext_data, &len,
                MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        /* Ignore data so far and just check its length */
        *p += len;
        if( *p != end_ext_data )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

        /* Abort on (unsupported) critical extensions */
        if( is_critical )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                    MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
    }

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * X.509 CRL v2 entry extensions (no extensions parsed yet.)
 */
static int x509_get_crl_entry_ext( unsigned char **p,
                             const unsigned char *end,
                             mbedtls_x509_buf *ext )
{
    int ret;
    size_t len = 0;

    /* OPTIONAL */
    if( end <= *p )
        return( 0 );

    ext->tag = **p;
    ext->p = *p;

    /*
     * Get CRL-entry extension sequence header
     * crlEntryExtensions      Extensions OPTIONAL  -- if present, MUST be v2
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &ext->len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            ext->p = NULL;
            return( 0 );
        }
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
    }

    end = *p + ext->len;

    if( end != *p + ext->len )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    while( *p < end )
    {
        if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        *p += len;
    }

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * X.509 CRL Entries
 */
static int x509_get_entries( unsigned char **p,
                             const unsigned char *end,
                             mbedtls_x509_crl_entry *entry )
{
    int ret;
    size_t entry_len;
    mbedtls_x509_crl_entry *cur_entry = entry;

    if( *p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_tag( p, end, &entry_len,
            MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( ret );
    }

    end = *p + entry_len;

    while( *p < end )
    {
        size_t len2;
        const unsigned char *end2;

        if( ( ret = mbedtls_asn1_get_tag( p, end, &len2,
                MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED ) ) != 0 )
        {
            return( ret );
        }

        cur_entry->raw.tag = **p;
        cur_entry->raw.p = *p;
        cur_entry->raw.len = len2;
        end2 = *p + len2;

        if( ( ret = mbedtls_x509_get_serial( p, end2, &cur_entry->serial ) ) != 0 )
            return( ret );

        if( ( ret = mbedtls_x509_get_time( p, end2,
                                   &cur_entry->revocation_date ) ) != 0 )
            return( ret );

        if( ( ret = x509_get_crl_entry_ext( p, end2,
                                            &cur_entry->entry_ext ) ) != 0 )
            return( ret );

        if( *p < end )
        {
            cur_entry->next = mbedtls_calloc( 1, sizeof( mbedtls_x509_crl_entry ) );

            if( cur_entry->next == NULL )
                return( MBEDTLS_ERR_X509_ALLOC_FAILED );

            cur_entry = cur_entry->next;
        }
    }

    return( 0 );
}

/*
 * Parse one  CRLs in DER format and append it to the chained list
 */
int mbedtls_x509_crl_parse_der( mbedtls_x509_crl *chain,
                        const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p = NULL, *end = NULL;
    mbedtls_x509_buf sig_params1, sig_params2, sig_oid2;
    mbedtls_x509_crl *crl = chain;

    /*
     * Check for valid input
     */
    if( crl == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    mbedtls_platform_memset( &sig_params1, 0, sizeof( mbedtls_x509_buf ) );
    mbedtls_platform_memset( &sig_params2, 0, sizeof( mbedtls_x509_buf ) );
    mbedtls_platform_memset( &sig_oid2, 0, sizeof( mbedtls_x509_buf ) );

    /*
     * Add new CRL on the end of the chain if needed.
     */
    while( crl->version != 0 && crl->next != NULL )
        crl = crl->next;

    if( crl->version != 0 && crl->next == NULL )
    {
        crl->next = mbedtls_calloc( 1, sizeof( mbedtls_x509_crl ) );

        if( crl->next == NULL )
        {
            mbedtls_x509_crl_free( crl );
            return( MBEDTLS_ERR_X509_ALLOC_FAILED );
        }

        mbedtls_x509_crl_init( crl->next );
        crl = crl->next;
    }

    /*
     * Copy raw DER-encoded CRL
     */
    if( buflen == 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    p = mbedtls_calloc( 1, buflen );
    if( p == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    mbedtls_platform_memcpy( p, buf, buflen );

    crl->raw.p = p;
    crl->raw.len = buflen;

    end = p + buflen;

    /*
     * CertificateList  ::=  SEQUENCE  {
     *      tbsCertList          TBSCertList,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }

    if( len != (size_t) ( end - p ) )
    {
        mbedtls_x509_crl_free( crl );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     * TBSCertList  ::=  SEQUENCE  {
     */
    crl->tbs.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = p + len;
    crl->tbs.len = end - crl->tbs.p;

    /*
     * Version  ::=  INTEGER  OPTIONAL {  v1(0), v2(1)  }
     *               -- if present, MUST be v2
     *
     * signature            AlgorithmIdentifier
     */
    if( ( ret = x509_crl_get_version( &p, end, &crl->version ) ) != 0 ||
        ( ret = mbedtls_x509_get_alg( &p, end, &crl->sig_oid, &sig_params1 ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( ret );
    }

    if( crl->version < 0 || crl->version > 1 )
    {
        mbedtls_x509_crl_free( crl );
        return( MBEDTLS_ERR_X509_UNKNOWN_VERSION );
    }

    crl->version++;

    if( ( ret = mbedtls_x509_get_sig_alg( &crl->sig_oid, &sig_params1,
                                  &crl->sig_md, &crl->sig_pk,
                                  &crl->sig_opts ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG );
    }

    /*
     * issuer               Name
     */
    crl->issuer_raw.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }
    p += len;
    crl->issuer_raw.len = p - crl->issuer_raw.p;

    if( ( ret = mbedtls_x509_get_name( crl->issuer_raw.p,
                                       crl->issuer_raw.len,
                                       &crl->issuer ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( ret );
    }

    /*
     * thisUpdate          Time
     * nextUpdate          Time OPTIONAL
     */
    if( ( ret = mbedtls_x509_get_time( &p, end, &crl->this_update ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( ret );
    }

    if( ( ret = mbedtls_x509_get_time( &p, end, &crl->next_update ) ) != 0 )
    {
        if( ret != ( MBEDTLS_ERR_X509_INVALID_DATE +
                        MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) &&
            ret != ( MBEDTLS_ERR_X509_INVALID_DATE +
                        MBEDTLS_ERR_ASN1_OUT_OF_DATA ) )
        {
            mbedtls_x509_crl_free( crl );
            return( ret );
        }
    }

    /*
     * revokedCertificates    SEQUENCE OF SEQUENCE   {
     *      userCertificate        CertificateSerialNumber,
     *      revocationDate         Time,
     *      crlEntryExtensions     Extensions OPTIONAL
     *                                   -- if present, MUST be v2
     *                        } OPTIONAL
     */
    if( ( ret = x509_get_entries( &p, end, &crl->entry ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( ret );
    }

    /*
     * crlExtensions          EXPLICIT Extensions OPTIONAL
     *                              -- if present, MUST be v2
     */
    if( crl->version == 2 )
    {
        ret = x509_get_crl_ext( &p, end, &crl->crl_ext );

        if( ret != 0 )
        {
            mbedtls_x509_crl_free( crl );
            return( ret );
        }
    }

    if( p != end )
    {
        mbedtls_x509_crl_free( crl );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    end = crl->raw.p + crl->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signatureValue       BIT STRING
     */
    if( ( ret = mbedtls_x509_get_alg( &p, end, &sig_oid2, &sig_params2 ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( ret );
    }

    if( crl->sig_oid.len != sig_oid2.len ||
        mbedtls_platform_memcmp( crl->sig_oid.p, sig_oid2.p, crl->sig_oid.len ) != 0 ||
        sig_params1.len != sig_params2.len ||
        ( sig_params1.len != 0 &&
          mbedtls_platform_memcmp( sig_params1.p, sig_params2.p, sig_params1.len ) != 0 ) )
    {
        mbedtls_x509_crl_free( crl );
        return( MBEDTLS_ERR_X509_SIG_MISMATCH );
    }

    if( ( ret = mbedtls_x509_get_sig( &p, end, &crl->sig ) ) != 0 )
    {
        mbedtls_x509_crl_free( crl );
        return( ret );
    }

    if( p != end )
    {
        mbedtls_x509_crl_free( crl );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

/*
 * Parse one or more CRLs and add them to the chained list
 */
int mbedtls_x509_crl_parse( mbedtls_x509_crl *chain, const unsigned char *buf, size_t buflen )
{
#if defined(MBEDTLS_PEM_PARSE_C)
    int ret;
    size_t use_len;
    mbedtls_pem_context pem;
    int is_pem = 0;

    if( chain == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    do
    {
        mbedtls_pem_init( &pem );

        // Avoid calling mbedtls_pem_read_buffer() on non-null-terminated
        // string
        if( buflen == 0 || buf[buflen - 1] != '\0' )
            ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
        else
            ret = mbedtls_pem_read_buffer( &pem,
                                           "-----BEGIN X509 CRL-----",
                                           "-----END X509 CRL-----",
                                            buf, NULL, 0, &use_len );

        if( ret == 0 )
        {
            /*
             * Was PEM encoded
             */
            is_pem = 1;

            buflen -= use_len;
            buf += use_len;

            if( ( ret = mbedtls_x509_crl_parse_der( chain,
                                            pem.buf, pem.buflen ) ) != 0 )
            {
                mbedtls_pem_free( &pem );
                return( ret );
            }
        }
        else if( is_pem )
        {
            mbedtls_pem_free( &pem );
            return( ret );
        }

        mbedtls_pem_free( &pem );
    }
    /* In the PEM case, buflen is 1 at the end, for the terminated NULL byte.
     * And a valid CRL cannot be less than 1 byte anyway. */
    while( is_pem && buflen > 1 );

    if( is_pem )
        return( 0 );
    else
#endif /* MBEDTLS_PEM_PARSE_C */
        return( mbedtls_x509_crl_parse_der( chain, buf, buflen ) );
}

#if defined(MBEDTLS_FS_IO)
/*
 * Load one or more CRLs and add them to the chained list
 */
int mbedtls_x509_crl_parse_file( mbedtls_x509_crl *chain, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_crl_parse( chain, buf, n );

    mbedtls_platform_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
#endif /* MBEDTLS_FS_IO */

#if !defined(MBEDTLS_X509_REMOVE_INFO)
/*
 * Return an informational string about the CRL.
 */
int mbedtls_x509_crl_info( char *buf, size_t size, const char *prefix,
                   const mbedtls_x509_crl *crl )
{
    int ret;
    size_t n;
    char *p;
    const mbedtls_x509_crl_entry *entry;

    p = buf;
    n = size;

    ret = mbedtls_snprintf( p, n, "%sCRL version   : %d",
                               prefix, crl->version );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%sissuer name   : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_dn_gets( p, n, &crl->issuer );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%sthis update   : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crl->this_update.year, crl->this_update.mon,
                   crl->this_update.day,  crl->this_update.hour,
                   crl->this_update.min,  crl->this_update.sec );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%snext update   : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crl->next_update.year, crl->next_update.mon,
                   crl->next_update.day,  crl->next_update.hour,
                   crl->next_update.min,  crl->next_update.sec );
    MBEDTLS_X509_SAFE_SNPRINTF;

    entry = &crl->entry;

    ret = mbedtls_snprintf( p, n, "\n%sRevoked certificates:",
                               prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;

    while( entry != NULL && entry->raw.len != 0 )
    {
        ret = mbedtls_snprintf( p, n, "\n%sserial number: ",
                               prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;

        ret = mbedtls_x509_serial_gets( p, n, &entry->serial );
        MBEDTLS_X509_SAFE_SNPRINTF;

        ret = mbedtls_snprintf( p, n, " revocation date: " \
                   "%04d-%02d-%02d %02d:%02d:%02d",
                   entry->revocation_date.year, entry->revocation_date.mon,
                   entry->revocation_date.day,  entry->revocation_date.hour,
                   entry->revocation_date.min,  entry->revocation_date.sec );
        MBEDTLS_X509_SAFE_SNPRINTF;

        entry = entry->next;
    }

    ret = mbedtls_snprintf( p, n, "\n%ssigned using  : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_sig_alg_gets( p, n, crl->sig_pk,
                                     crl->sig_md, crl->sig_opts );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n" );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( (int) ( size - n ) );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */

/*
 * Initialize a CRL chain
 */
void mbedtls_x509_crl_init( mbedtls_x509_crl *crl )
{
    mbedtls_platform_memset( crl, 0, sizeof(mbedtls_x509_crl) );
}

/*
 * Unallocate all CRL data
 */
void mbedtls_x509_crl_free( mbedtls_x509_crl *crl )
{
    mbedtls_x509_crl *crl_cur = crl;
    mbedtls_x509_crl *crl_prv;
    mbedtls_x509_name *name_cur;
    mbedtls_x509_name *name_prv;
    mbedtls_x509_crl_entry *entry_cur;
    mbedtls_x509_crl_entry *entry_prv;

    if( crl == NULL )
        return;

    do
    {
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
        mbedtls_free( crl_cur->sig_opts );
#endif

        name_cur = crl_cur->issuer.next;
        while( name_cur != NULL )
        {
            name_prv = name_cur;
            name_cur = name_cur->next;
            mbedtls_platform_zeroize( name_prv, sizeof( mbedtls_x509_name ) );
            mbedtls_free( name_prv );
        }

        entry_cur = crl_cur->entry.next;
        while( entry_cur != NULL )
        {
            entry_prv = entry_cur;
            entry_cur = entry_cur->next;
            mbedtls_platform_zeroize( entry_prv,
                                      sizeof( mbedtls_x509_crl_entry ) );
            mbedtls_free( entry_prv );
        }

        if( crl_cur->raw.p != NULL )
        {
            mbedtls_platform_zeroize( crl_cur->raw.p, crl_cur->raw.len );
            mbedtls_free( crl_cur->raw.p );
        }

        crl_cur = crl_cur->next;
    }
    while( crl_cur != NULL );

    crl_cur = crl;
    do
    {
        crl_prv = crl_cur;
        crl_cur = crl_cur->next;

        mbedtls_platform_zeroize( crl_prv, sizeof( mbedtls_x509_crl ) );
        if( crl_prv != crl )
            mbedtls_free( crl_prv );
    }
    while( crl_cur != NULL );
}

#endif /* MBEDTLS_X509_CRL_PARSE_C */
/*
 *  X.509 certificate parsing and verification
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 *  [SIRO] https://cabforum.org/wp-content/uploads/Chunghwatelecom201503cabforumV4.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
#include <windows.h>
#else
#include <time.h>
#endif

#if defined(MBEDTLS_FS_IO)
#include <stdio.h>
#if !defined(_WIN32) || defined(EFIX64) || defined(EFI32)
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#endif /* !_WIN32 || EFIX64 || EFI32 */
#endif

#if !defined(MBEDTLS_X509_ON_DEMAND_PARSING)
static void x509_buf_to_buf_raw( mbedtls_x509_buf_raw *dst,
                                 mbedtls_x509_buf const *src )
{
    dst->p = src->p;
    dst->len = src->len;
}

static void x509_buf_raw_to_buf( mbedtls_x509_buf *dst,
                                 mbedtls_x509_buf_raw const *src )
{
    dst->p = src->p;
    dst->len = src->len;
}
#endif /* MBEDTLS_X509_ON_DEMAND_PARSING */

static int x509_crt_parse_frame( unsigned char *start,
                                 unsigned char *end,
                                 mbedtls_x509_crt_frame *frame );
static int x509_crt_subject_from_frame( mbedtls_x509_crt_frame const *frame,
                                        mbedtls_x509_name *subject );
static int x509_crt_issuer_from_frame( mbedtls_x509_crt_frame const *frame,
                                       mbedtls_x509_name *issuer );
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
static int x509_crt_subject_alt_from_frame( mbedtls_x509_crt_frame const *frame,
                                        mbedtls_x509_sequence *subject_alt );
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */
static int x509_crt_ext_key_usage_from_frame( mbedtls_x509_crt_frame const *frame,
                                        mbedtls_x509_sequence *ext_key_usage );

static int mbedtls_x509_crt_flush_cache_pk( mbedtls_x509_crt const *crt )
{
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &crt->cache->pk_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
    /* Can only free the PK context if nobody is using it.
     * If MBEDTLS_X509_ALWAYS_FLUSH is set, nested uses
     * of xxx_acquire() are prohibited, and no reference
     * counting is needed. Also, notice that the code-path
     * below is safe if the cache isn't filled. */
    if( crt->cache->pk_readers == 0 )
#endif /* !MBEDTLS_X509_ALWAYS_FLUSH ||
          MBEDTLS_THREADING_C */
    {
#if !defined(MBEDTLS_X509_ON_DEMAND_PARSING)
        /* The cache holds a shallow copy of the PK context
         * in the legacy struct, so don't free PK context. */
        mbedtls_free( crt->cache->pk );
#else
        mbedtls_pk_free( crt->cache->pk );
        mbedtls_free( crt->cache->pk );
#endif /* MBEDTLS_X509_ON_DEMAND_PARSING */
        crt->cache->pk = NULL;
    }

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &crt->cache->pk_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif
    return( 0 );
}

static int mbedtls_x509_crt_flush_cache_frame( mbedtls_x509_crt const *crt )
{
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &crt->cache->frame_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
    /* Can only free the PK context if nobody is using it.
     * If MBEDTLS_X509_ALWAYS_FLUSH is set, nested uses
     * of xxx_acquire() are prohibited, and no reference
     * counting is needed. Also, notice that the code-path
     * below is safe if the cache isn't filled. */
    if( crt->cache->frame_readers == 0 )
#endif /* !MBEDTLS_X509_ALWAYS_FLUSH ||
          MBEDTLS_THREADING_C */
    {
        mbedtls_free( crt->cache->frame );
        crt->cache->frame = NULL;
    }

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &crt->cache->frame_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif
    return( 0 );
}

int mbedtls_x509_crt_flush_cache( mbedtls_x509_crt const *crt )
{
    int ret;
    ret = mbedtls_x509_crt_flush_cache_frame( crt );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_x509_crt_flush_cache_pk( crt );
    if( ret != 0 )
        return( ret );
    return( 0 );
}

static int x509_crt_frame_parse_ext( mbedtls_x509_crt_frame *frame );

static int mbedtls_x509_crt_cache_provide_frame( mbedtls_x509_crt const *crt )
{
    mbedtls_x509_crt_cache *cache = crt->cache;
    mbedtls_x509_crt_frame *frame;

    if( cache->frame != NULL )
    {
#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
        return( 0 );
#else
        /* If MBEDTLS_X509_ALWAYS_FLUSH is set, we don't
         * allow nested uses of acquire. */
        return( MBEDTLS_ERR_X509_FATAL_ERROR );
#endif
    }

    frame = mbedtls_calloc( 1, sizeof( mbedtls_x509_crt_frame ) );
    if( frame == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );
    cache->frame = frame;

#if defined(MBEDTLS_X509_ON_DEMAND_PARSING)
    /* This would work with !MBEDTLS_X509_ON_DEMAND_PARSING, too,
     * but is inefficient compared to copying the respective fields
     * from the legacy mbedtls_x509_crt. */
    return( x509_crt_parse_frame( crt->raw.p,
                                  crt->raw.p + crt->raw.len,
                                  frame ) );
#else /* MBEDTLS_X509_ON_DEMAND_PARSING */
    /* Make sure all extension related fields are properly initialized. */
    frame->ca_istrue = 0;
    frame->max_pathlen = 0;
    frame->ext_types = 0;
    frame->version = crt->version;
    frame->sig_md = crt->sig_md;
    frame->sig_pk = crt->sig_pk;

#if !defined(MBEDTLS_X509_CRT_REMOVE_TIME)
    frame->valid_from = crt->valid_from;
    frame->valid_to = crt->valid_to;
#endif /* !MBEDTLS_X509_CRT_REMOVE_TIME */

    x509_buf_to_buf_raw( &frame->raw, &crt->raw );
    x509_buf_to_buf_raw( &frame->tbs, &crt->tbs );
    x509_buf_to_buf_raw( &frame->serial, &crt->serial );
    x509_buf_to_buf_raw( &frame->pubkey_raw, &crt->pk_raw );
    x509_buf_to_buf_raw( &frame->issuer_raw, &crt->issuer_raw );
    x509_buf_to_buf_raw( &frame->subject_raw, &crt->subject_raw );
#if !defined(MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID)
    x509_buf_to_buf_raw( &frame->subject_id, &crt->subject_id );
    x509_buf_to_buf_raw( &frame->issuer_id, &crt->issuer_id );
#endif /* !MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID */
    x509_buf_to_buf_raw( &frame->sig, &crt->sig );
    x509_buf_to_buf_raw( &frame->v3_ext, &crt->v3_ext );

    /* The legacy CRT structure doesn't explicitly contain
     * the `AlgorithmIdentifier` bounds; however, those can
     * be inferred from the surrounding (mandatory) `SerialNumber`
     * and `Issuer` fields. */
    frame->sig_alg.p = crt->serial.p + crt->serial.len;
    frame->sig_alg.len = crt->issuer_raw.p - frame->sig_alg.p;

    return( x509_crt_frame_parse_ext( frame ) );
#endif /* !MBEDTLS_X509_ON_DEMAND_PARSING */
}

static int mbedtls_x509_crt_cache_provide_pk( mbedtls_x509_crt const *crt )
{
    mbedtls_x509_crt_cache *cache = crt->cache;
    mbedtls_pk_context *pk;

    if( cache->pk != NULL )
    {
#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
        return( 0 );
#else
        /* If MBEDTLS_X509_ALWAYS_FLUSH is set, we don't
         * allow nested uses of acquire. */
        return( MBEDTLS_ERR_X509_FATAL_ERROR );
#endif
    }

    pk = mbedtls_calloc( 1, sizeof( mbedtls_pk_context ) );
    if( pk == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );
    cache->pk = pk;

#if !defined(MBEDTLS_X509_ON_DEMAND_PARSING)
    *pk = crt->pk;
    return( 0 );
#else
    {
        mbedtls_x509_buf_raw pk_raw = cache->pk_raw;
        return( mbedtls_pk_parse_subpubkey( &pk_raw.p,
                                            pk_raw.p + pk_raw.len,
                                            pk ) );
    }
#endif /* MBEDTLS_X509_ON_DEMAND_PARSING */
}

static void x509_crt_cache_init( mbedtls_x509_crt_cache *cache )
{
    memset( cache, 0, sizeof( *cache ) );
#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_init( &cache->frame_mutex );
    mbedtls_mutex_init( &cache->pk_mutex );
#endif
}

static void x509_crt_cache_clear_pk( mbedtls_x509_crt_cache *cache )
{
#if !defined(MBEDTLS_X509_ON_DEMAND_PARSING)
    /* The cache holds a shallow copy of the PK context
     * in the legacy struct, so don't free PK context. */
    mbedtls_free( cache->pk );
#else
    mbedtls_pk_free( cache->pk );
    mbedtls_free( cache->pk );
#endif /* MBEDTLS_X509_ON_DEMAND_PARSING */

    cache->pk = NULL;
}

static void x509_crt_cache_clear_frame( mbedtls_x509_crt_cache *cache )
{
    mbedtls_free( cache->frame );
    cache->frame = NULL;
}

static void x509_crt_cache_free( mbedtls_x509_crt_cache *cache )
{
    if( cache == NULL )
        return;

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_free( &cache->frame_mutex );
    mbedtls_mutex_free( &cache->pk_mutex );
#endif

    x509_crt_cache_clear_frame( cache );
    x509_crt_cache_clear_pk( cache );

    mbedtls_platform_memset( cache, 0, sizeof( *cache ) );
}

#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
int mbedtls_x509_crt_get_subject_alt_names( mbedtls_x509_crt const *crt,
                                            mbedtls_x509_sequence **subj_alt )
{
    int ret;
    mbedtls_x509_crt_frame const *frame;
    mbedtls_x509_sequence *seq;

    ret = mbedtls_x509_crt_frame_acquire( crt, &frame );
    if( ret != 0 )
        return( ret );

    seq = mbedtls_calloc( 1, sizeof( mbedtls_x509_sequence ) );
    if( seq == NULL )
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
    else
        ret = x509_crt_subject_alt_from_frame( frame, seq );

    mbedtls_x509_crt_frame_release( crt );

    *subj_alt = seq;
    return( ret );
}
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

int mbedtls_x509_crt_get_ext_key_usage( mbedtls_x509_crt const *crt,
                                        mbedtls_x509_sequence **ext_key_usage )
{
    int ret;
    mbedtls_x509_crt_frame const *frame;
    mbedtls_x509_sequence *seq;

    ret = mbedtls_x509_crt_frame_acquire( crt, &frame );
    if( ret != 0 )
        return( ret );

    seq = mbedtls_calloc( 1, sizeof( mbedtls_x509_sequence ) );
    if( seq == NULL )
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
    else
        ret = x509_crt_ext_key_usage_from_frame( frame, seq );

    mbedtls_x509_crt_frame_release( crt );

    *ext_key_usage = seq;
    return( ret );
}

int mbedtls_x509_crt_get_subject( mbedtls_x509_crt const *crt,
                                  mbedtls_x509_name **subject )
{
    int ret;
    mbedtls_x509_crt_frame const *frame;
    mbedtls_x509_name *name;

    ret = mbedtls_x509_crt_frame_acquire( crt, &frame );
    if( ret != 0 )
        return( ret );

    name = mbedtls_calloc( 1, sizeof( mbedtls_x509_name ) );
    if( name == NULL )
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
    else
        ret = x509_crt_subject_from_frame( frame, name );

    mbedtls_x509_crt_frame_release( crt );

    *subject = name;
    return( ret );
}

int mbedtls_x509_crt_get_issuer( mbedtls_x509_crt const *crt,
                                 mbedtls_x509_name **issuer )
{
    int ret;
    mbedtls_x509_crt_frame const *frame;
    mbedtls_x509_name *name;

    ret = mbedtls_x509_crt_frame_acquire( crt, &frame );
    if( ret != 0 )
        return( ret );

    name = mbedtls_calloc( 1, sizeof( mbedtls_x509_name ) );
    if( name == NULL )
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
    else
        ret = x509_crt_issuer_from_frame( frame, name );

    mbedtls_x509_crt_frame_release( crt );

    *issuer = name;
    return( ret );
}

int mbedtls_x509_crt_get_frame( mbedtls_x509_crt const *crt,
                                mbedtls_x509_crt_frame *dst )
{
    int ret;
    mbedtls_x509_crt_frame const *frame;
    ret = mbedtls_x509_crt_frame_acquire( crt, &frame );
    if( ret != 0 )
        return( ret );
    *dst = *frame;
    mbedtls_x509_crt_frame_release( crt );
    return( 0 );
}

int mbedtls_x509_crt_get_pk( mbedtls_x509_crt const *crt,
                             mbedtls_pk_context *dst )
{
#if !defined(MBEDTLS_X509_ON_DEMAND_PARSING)
    mbedtls_x509_buf_raw pk_raw = crt->cache->pk_raw;
    return( mbedtls_pk_parse_subpubkey( &pk_raw.p,
                                        pk_raw.p + pk_raw.len,
                                        dst ) );
#else /* !MBEDTLS_X509_ON_DEMAND_PARSING */
    int ret;
    mbedtls_pk_context *pk;
    ret = mbedtls_x509_crt_pk_acquire( crt, &pk );
    if( ret != 0 )
        return( ret );

    /* Move PK from CRT cache to destination pointer
     * to avoid a copy. */
    *dst = *pk;
    mbedtls_free( crt->cache->pk );
    crt->cache->pk = NULL;

    mbedtls_x509_crt_pk_release( crt );
    return( 0 );
#endif /* MBEDTLS_X509_ON_DEMAND_PARSING */
}

/*
 * Item in a verification chain: cert and flags for it
 */
typedef struct {
    mbedtls_x509_crt *crt;
    uint32_t flags;
} x509_crt_verify_chain_item;

/*
 * Max size of verification chain: end-entity + intermediates + trusted root
 */
#define X509_MAX_VERIFY_CHAIN_SIZE    ( MBEDTLS_X509_MAX_INTERMEDIATE_CA + 2 )

/*
 * Default profile
 */
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_default =
{
#if defined(MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES)
    /* Allow SHA-1 (weak, but still safe in controlled environments) */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA1 ) |
#endif
    /* Only SHA-2 hashes */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    2048,
};

/*
 * Next-default profile
 */
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_next =
{
    /* Hashes from SHA-256 and above */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
#if defined(MBEDTLS_USE_TINYCRYPT)
    MBEDTLS_X509_ID_FLAG( MBEDTLS_UECC_DP_SECP256R1 ),
#elif defined(MBEDTLS_ECP_C)
    /* Curves at or above 128-bit security level */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP384R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP521R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_BP256R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_BP384R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_BP512R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256K1 ),
#else
    0,
#endif
    2048,
};

/*
 * NSA Suite B Profile
 */
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_suiteb =
{
    /* Only SHA-256 and 384 */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ),
    /* Only ECDSA */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECDSA ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECKEY ),
#if defined(MBEDTLS_USE_TINYCRYPT)
    MBEDTLS_X509_ID_FLAG( MBEDTLS_UECC_DP_SECP256R1 ),
#elif defined(MBEDTLS_ECP_C)
    /* Only NIST P-256 and P-384 */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP384R1 ),
#else
    0,
#endif
    0,
};

/*
 * Check md_alg against profile
 * Return 0 if md_alg is acceptable for this profile, -1 otherwise
 */
static int x509_profile_check_md_alg( const mbedtls_x509_crt_profile *profile,
                                      mbedtls_md_type_t md_alg )
{
    if( md_alg == MBEDTLS_MD_NONE )
        return( -1 );

    if( ( profile->allowed_mds & MBEDTLS_X509_ID_FLAG( md_alg ) ) != 0 )
        return( 0 );

    return( -1 );
}

/*
 * Check pk_alg against profile
 * Return 0 if pk_alg is acceptable for this profile, -1 otherwise
 */
static int x509_profile_check_pk_alg( const mbedtls_x509_crt_profile *profile,
                                      mbedtls_pk_type_t pk_alg )
{
    if( pk_alg == MBEDTLS_PK_NONE )
        return( -1 );

    if( ( profile->allowed_pks & MBEDTLS_X509_ID_FLAG( pk_alg ) ) != 0 )
        return( 0 );

    return( -1 );
}

/*
 * Check key against profile
 * Return 0 if pk is acceptable for this profile, -1 otherwise
 */
static int x509_profile_check_key( const mbedtls_x509_crt_profile *profile,
                                   const mbedtls_pk_context *pk )
{
    const mbedtls_pk_type_t pk_alg = mbedtls_pk_get_type( pk );

#if defined(MBEDTLS_RSA_C)
    if( pk_alg == MBEDTLS_PK_RSA || pk_alg == MBEDTLS_PK_RSASSA_PSS )
    {
        if( mbedtls_pk_get_bitlen( pk ) >= profile->rsa_min_bitlen )
            return( 0 );

        return( -1 );
    }
#endif

#if defined(MBEDTLS_USE_TINYCRYPT)
    if( pk_alg == MBEDTLS_PK_ECKEY )
    {
        if( ( profile->allowed_curves & MBEDTLS_UECC_DP_SECP256R1 ) != 0 )
            return( 0 );

        return( -1 );
    }
#endif /* MBEDTLS_USE_TINYCRYPT */

#if defined(MBEDTLS_ECP_C)
    if( pk_alg == MBEDTLS_PK_ECDSA ||
        pk_alg == MBEDTLS_PK_ECKEY ||
        pk_alg == MBEDTLS_PK_ECKEY_DH )
    {
        const mbedtls_ecp_group_id gid = mbedtls_pk_ec( *pk )->grp.id;

        if( gid == MBEDTLS_ECP_DP_NONE )
            return( -1 );

        if( ( profile->allowed_curves & MBEDTLS_X509_ID_FLAG( gid ) ) != 0 )
            return( 0 );

        return( -1 );
    }
#endif

    return( -1 );
}

#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
/*
 * Return 0 if name matches wildcard, -1 otherwise
 */
static int x509_check_wildcard( char const *cn,
                                size_t cn_len,
                                unsigned char const *buf,
                                size_t buf_len )
{
    size_t i;
    size_t cn_idx = 0;

    /* We can't have a match if there is no wildcard to match */
    if( buf_len < 3 || buf[0] != '*' || buf[1] != '.' )
        return( -1 );

    for( i = 0; i < cn_len; ++i )
    {
        if( cn[i] == '.' )
        {
            cn_idx = i;
            break;
        }
    }

    if( cn_idx == 0 )
        return( -1 );

    if( mbedtls_x509_memcasecmp( buf + 1, cn + cn_idx,
                                 buf_len - 1, cn_len - cn_idx ) == 0 )
    {
        return( 0 );
    }

    return( -1 );
}
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static int x509_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = *p + len;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_VERSION +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

#if !defined(MBEDTLS_X509_CRT_REMOVE_TIME)
/*
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 */
static int x509_get_dates( unsigned char **p,
                           const unsigned char *end,
                           mbedtls_x509_time *from,
                           mbedtls_x509_time *to )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_DATE + ret );

    end = *p + len;

    if( ( ret = mbedtls_x509_get_time( p, end, from ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_x509_get_time( p, end, to ) ) != 0 )
        return( ret );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_DATE +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}
#else /* !MBEDTLS_X509_CRT_REMOVE_TIME */
static int x509_skip_dates( unsigned char **p,
                           const unsigned char *end )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_DATE + ret );

    /* skip contents of the sequence */
    *p += len;

    return( 0 );
}
#endif /* MBEDTLS_X509_CRT_REMOVE_TIME */

#if !defined(MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID)
/*
 * X.509 v2/v3 unique identifier (not parsed)
 */
static int x509_get_uid( unsigned char **p,
                         const unsigned char *end,
                         mbedtls_x509_buf_raw *uid, int n )
{
    int ret;

    if( *p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_tag( p, end, &uid->len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | n ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    uid->p = *p;
    *p += uid->len;

    return( 0 );
}
#else /* !MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID */
static int x509_skip_uid( unsigned char **p,
                          const unsigned char *end,
                          int n )
{
    int ret;
    size_t len;

    if( *p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | n ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    *p += len;
    return( 0 );
}
#endif /* MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID */

static int x509_get_basic_constraints( unsigned char **p,
                                       const unsigned char *end,
                                       int *ca_istrue,
                                       int *max_pathlen )
{
    int ret;
    size_t len;

    /*
     * BasicConstraints ::= SEQUENCE {
     *      cA                      BOOLEAN DEFAULT FALSE,
     *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
     */
    *ca_istrue = 0; /* DEFAULT FALSE */
    *max_pathlen = 0; /* endless */

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    if( *p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_bool( p, end, ca_istrue ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            ret = mbedtls_asn1_get_int( p, end, ca_istrue );

        if( ret != 0 )
            return( ret );

        if( *ca_istrue != 0 )
            *ca_istrue = 1;
    }

    if( *p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_int( p, end, max_pathlen ) ) != 0 )
        return( ret );

    if( *p != end )
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    (*max_pathlen)++;

    return( 0 );
}

static int x509_get_ns_cert_type( unsigned char **p,
                                       const unsigned char *end,
                                       unsigned char *ns_cert_type)
{
    int ret;
    mbedtls_x509_bitstring bs = { 0, 0, NULL };

    if( ( ret = mbedtls_asn1_get_bitstring( p, end, &bs ) ) != 0 )
        return( ret );

    if( bs.len != 1 )
        return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );

    /* Get actual bitstring */
    *ns_cert_type = *bs.p;
    return( 0 );
}

static int x509_get_key_usage( unsigned char **p,
                               const unsigned char *end,
                               uint16_t *key_usage)
{
    int ret;
    size_t i;
    mbedtls_x509_bitstring bs = { 0, 0, NULL };

    if( ( ret = mbedtls_asn1_get_bitstring( p, end, &bs ) ) != 0 )
        return( ret );

    if( bs.len < 1 )
        return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );

    /* Get actual bitstring */
    *key_usage = 0;
    for( i = 0; i < bs.len && i < sizeof( *key_usage ); i++ )
    {
        *key_usage |= (uint16_t) bs.p[i] << ( 8*i );
    }

    return( 0 );
}

static int asn1_build_sequence_cb( void *ctx,
                                   int tag,
                                   unsigned char *data,
                                   size_t data_len )
{
    mbedtls_asn1_sequence **cur_ptr = (mbedtls_asn1_sequence **) ctx;
    mbedtls_asn1_sequence *cur = *cur_ptr;

    /* Allocate and assign next pointer */
    if( cur->buf.p != NULL )
    {
        cur->next = mbedtls_calloc( 1, sizeof( mbedtls_asn1_sequence ) );
        if( cur->next == NULL )
            return( MBEDTLS_ERR_ASN1_ALLOC_FAILED );
        cur = cur->next;
    }

    cur->buf.tag = tag;
    cur->buf.p = data;
    cur->buf.len = data_len;

    *cur_ptr = cur;
    return( 0 );
}

/*
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 */
static int x509_get_ext_key_usage( unsigned char **p,
                               const unsigned char *end,
                               mbedtls_x509_sequence *ext_key_usage)
{
    return( mbedtls_asn1_traverse_sequence_of( p, end,
                                               0xFF, MBEDTLS_ASN1_OID,
                                               0, 0,
                                               asn1_build_sequence_cb,
                                               (void *) &ext_key_usage ) );
}

#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
/*
 * SubjectAltName ::= GeneralNames
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER }
 *
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 * EDIPartyName ::= SEQUENCE {
 *      nameAssigner            [0]     DirectoryString OPTIONAL,
 *      partyName               [1]     DirectoryString }
 *
 * NOTE: we only parse and use dNSName at this point.
 */
static int x509_get_subject_alt_name( unsigned char *p,
                                      const unsigned char *end,
                                      mbedtls_x509_sequence *subject_alt_name )
{
    return( mbedtls_asn1_traverse_sequence_of( &p, end,
                                               MBEDTLS_ASN1_TAG_CLASS_MASK,
                                               MBEDTLS_ASN1_CONTEXT_SPECIFIC,
                                               MBEDTLS_ASN1_TAG_VALUE_MASK,
                                               2 /* SubjectAlt DNS */,
                                               asn1_build_sequence_cb,
                                               (void *) &subject_alt_name ) );
}
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

/*
 * X.509 v3 extensions
 *
 */
static int x509_crt_get_ext_cb( void *ctx,
                                int tag,
                                unsigned char *p,
                                size_t ext_len )
{
    int ret;
    mbedtls_x509_crt_frame *frame = (mbedtls_x509_crt_frame *) ctx;
    size_t len;
    unsigned char *end, *end_ext_octet;
    mbedtls_x509_buf extn_oid = { 0, 0, NULL };
    int is_critical = 0; /* DEFAULT FALSE */
    int ext_type = 0;

    ((void) tag);

    /*
     * Extension  ::=  SEQUENCE  {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING  }
     */

    end = p + ext_len;

    /* Get extension ID */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &extn_oid.len,
                                      MBEDTLS_ASN1_OID ) ) != 0 )
        goto err;

    extn_oid.tag = MBEDTLS_ASN1_OID;
    extn_oid.p = p;
    p += extn_oid.len;

    /* Get optional critical */
    if( ( ret = mbedtls_asn1_get_bool( &p, end, &is_critical ) ) != 0 &&
        ( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) )
        goto err;

    /* Data should be octet string type */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        goto err;

    end_ext_octet = p + len;
    if( end_ext_octet != end )
    {
        ret = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        goto err;
    }

    /*
     * Detect supported extensions
     */
    ret = mbedtls_oid_get_x509_ext_type( &extn_oid, &ext_type );
    if( ret != 0 )
    {
#if !defined(MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
        if( is_critical )
        {
            /* Data is marked as critical: fail */
            ret = MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            goto err;
        }
#endif /* MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION */
        return( 0 );
    }

    /* Forbid repeated extensions */
    if( ( frame->ext_types & ext_type ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS );

    frame->ext_types |= ext_type;
    switch( ext_type )
    {
        case MBEDTLS_X509_EXT_BASIC_CONSTRAINTS:
        {
            int ca_istrue;
            int max_pathlen;

            /* Parse basic constraints */
            ret = x509_get_basic_constraints( &p, end_ext_octet,
                                              &ca_istrue,
                                              &max_pathlen );
            if( ret != 0 )
                goto err;

            frame->ca_istrue   = ca_istrue;
            frame->max_pathlen = max_pathlen;
            break;
        }

        case MBEDTLS_X509_EXT_KEY_USAGE:
            /* Parse key usage */
            ret = x509_get_key_usage( &p, end_ext_octet,
                                      &frame->key_usage );
            if( ret != 0 )
                goto err;
            break;

        case MBEDTLS_X509_EXT_SUBJECT_ALT_NAME:
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
            /* Copy reference to raw subject alt name data. */
            frame->subject_alt_raw.p   = p;
            frame->subject_alt_raw.len = end_ext_octet - p;
            ret = mbedtls_asn1_traverse_sequence_of( &p, end_ext_octet,
                                      MBEDTLS_ASN1_TAG_CLASS_MASK,
                                      MBEDTLS_ASN1_CONTEXT_SPECIFIC,
                                      MBEDTLS_ASN1_TAG_VALUE_MASK,
                                      2 /* SubjectAlt DNS */,
                                      NULL, NULL );
            if( ret != 0 )
                goto err;
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */
            break;

        case MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE:
            /* Parse extended key usage */
            frame->ext_key_usage_raw.p   = p;
            frame->ext_key_usage_raw.len = end_ext_octet - p;
            if( frame->ext_key_usage_raw.len == 0 )
            {
                ret = MBEDTLS_ERR_ASN1_INVALID_LENGTH;
                goto err;
            }

            /* Check structural sanity of extension. */
            ret = mbedtls_asn1_traverse_sequence_of( &p, end_ext_octet,
                                                     0xFF, MBEDTLS_ASN1_OID,
                                                     0, 0, NULL, NULL );
            if( ret != 0 )
                goto err;

            break;

        case MBEDTLS_X509_EXT_NS_CERT_TYPE:
            /* Parse netscape certificate type */
            ret = x509_get_ns_cert_type( &p, end_ext_octet,
                                         &frame->ns_cert_type );
            if( ret != 0 )
                goto err;
            break;

        default:
            /*
             * If this is a non-critical extension, which the oid layer
             * supports, but there isn't an X.509 parser for it,
             * skip the extension.
             */
#if !defined(MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
            if( is_critical )
                return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );
#endif
            p = end_ext_octet;
    }

    return( 0 );

err:
    return( ret );
}

static int x509_crt_frame_parse_ext( mbedtls_x509_crt_frame *frame )
{
    int ret;
    unsigned char *p = frame->v3_ext.p;
    unsigned char *end = p + frame->v3_ext.len;

    if( p == end )
        return( 0 );

    ret = mbedtls_asn1_traverse_sequence_of( &p, end,
                 0xFF, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED,
                 0, 0, x509_crt_get_ext_cb, frame );

    if( ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE )
        return( ret );
    if( ret == MBEDTLS_ERR_X509_INVALID_EXTENSIONS )
        return( ret );

    if( ret != 0 )
        ret += MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    return( ret );
}

static int x509_crt_parse_frame( unsigned char *start,
                                 unsigned char *end,
                                 mbedtls_x509_crt_frame *frame )
{
    int ret;
    unsigned char *p;
    size_t len;

    mbedtls_x509_buf tmp;
    unsigned char *tbs_start;

    mbedtls_x509_buf outer_sig_alg;
    size_t inner_sig_alg_len;
    unsigned char *inner_sig_alg_start;

    mbedtls_platform_memset( frame, 0, sizeof( *frame ) );

    /*
     * Certificate  ::=  SEQUENCE {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING
     * }
     *
     */
    p = start;

    frame->raw.p = p;
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }

    /* NOTE: We are currently not checking that the `Certificate`
     * structure spans the entire buffer. */
    end = p + len;
    frame->raw.len = end - frame->raw.p;

    /*
     * TBSCertificate  ::=  SEQUENCE  { ...
     */
    frame->tbs.p = p;
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( ret + MBEDTLS_ERR_X509_INVALID_FORMAT );
    }
    tbs_start = p;

    /* Breadth-first parsing: Jump over TBS for now. */
    p += len;
    frame->tbs.len = p - frame->tbs.p;

    /*
     *  AlgorithmIdentifier ::= SEQUENCE { ...
     */
    outer_sig_alg.p = p;
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );
    }
    p += len;
    outer_sig_alg.len = p - outer_sig_alg.p;

    /*
     *  signatureValue       BIT STRING
     */
    ret = mbedtls_x509_get_sig( &p, end, &tmp );
    if( ret != 0 )
        return( ret );
    frame->sig.p   = tmp.p;
    frame->sig.len = tmp.len;

    /* Check that we consumed the entire `Certificate` structure. */
    if( p != end )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    /* Parse TBSCertificate structure
     *
     * TBSCertificate  ::=  SEQUENCE  {
     *             version         [0]  EXPLICIT Version DEFAULT v1,
     *             serialNumber         CertificateSerialNumber,
     *             signature            AlgorithmIdentifier,
     *             issuer               Name,
     *             validity             Validity,
     *             subject              Name,
     *             subjectPublicKeyInfo SubjectPublicKeyInfo,
     *             issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                                  -- If present, version MUST be v2 or v3
     *             subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                                  -- If present, version MUST be v2 or v3
     *             extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                                  -- If present, version MUST be v3
     *         }
     */
    end = frame->tbs.p + frame->tbs.len;
    p = tbs_start;

    /*
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    {
        int version;
        ret = x509_get_version( &p, end, &version );
        if( ret != 0 )
            return( ret );

        if( version < 0 || version > 2 )
            return( MBEDTLS_ERR_X509_UNKNOWN_VERSION );

        frame->version = version + 1;
    }

    /*
     * CertificateSerialNumber  ::=  INTEGER
     */
    ret = mbedtls_x509_get_serial( &p, end, &tmp );
    if( ret != 0 )
        return( ret );

    frame->serial.p   = tmp.p;
    frame->serial.len = tmp.len;

    /*
     * signature            AlgorithmIdentifier
     */
    inner_sig_alg_start = p;
    ret = mbedtls_x509_get_sig_alg_raw( &p, end, &frame->sig_md,
                                        &frame->sig_pk, NULL );
    if( ret != 0 )
        return( ret );
    inner_sig_alg_len = p - inner_sig_alg_start;

    frame->sig_alg.p   = inner_sig_alg_start;
    frame->sig_alg.len = inner_sig_alg_len;

    /* Consistency check:
     * Inner and outer AlgorithmIdentifier structures must coincide:
     *
     * Quoting RFC 5280, Section 4.1.1.2:
     *    This field MUST contain the same algorithm identifier as the
     *    signature field in the sequence tbsCertificate (Section 4.1.2.3).
     */
    if( outer_sig_alg.len != inner_sig_alg_len ||
        mbedtls_platform_memcmp( outer_sig_alg.p, inner_sig_alg_start, inner_sig_alg_len ) != 0 )
    {
        return( MBEDTLS_ERR_X509_SIG_MISMATCH );
    }

    /*
     * issuer               Name
     *
     * Name ::= CHOICE { -- only one possibility for now --
     *                      rdnSequence  RDNSequence }
     *
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     */
    frame->issuer_raw.p = p;

    ret = mbedtls_asn1_get_tag( &p, end, &len,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( ret + MBEDTLS_ERR_X509_INVALID_FORMAT );
    p += len;
    frame->issuer_raw.len = p - frame->issuer_raw.p;

    /* Comparing the raw buffer to itself amounts to structural validation. */
    ret = mbedtls_x509_name_cmp_raw( &frame->issuer_raw,
                                     &frame->issuer_raw,
                                     NULL, NULL );
    if( ret != 0 )
        return( ret );

    /*
     * Validity ::= SEQUENCE { ...
     */
#if !defined(MBEDTLS_X509_CRT_REMOVE_TIME)
    ret = x509_get_dates( &p, end, &frame->valid_from, &frame->valid_to );
    if( ret != 0 )
        return( ret );
#else /* !MBEDTLS_X509_CRT_REMOVE_TIME */
    ret = x509_skip_dates( &p, end );
    if( ret != 0 )
        return( ret );
#endif /* MBEDTLS_X509_CRT_REMOVE_TIME */

    /*
     * subject              Name
     *
     * Name ::= CHOICE { -- only one possibility for now --
     *                      rdnSequence  RDNSequence }
     *
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     */
    frame->subject_raw.p = p;

    ret = mbedtls_asn1_get_tag( &p, end, &len,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( ret + MBEDTLS_ERR_X509_INVALID_FORMAT );
    p += len;
    frame->subject_raw.len = p - frame->subject_raw.p;

    /* Comparing the raw buffer to itself amounts to structural validation. */
    ret = mbedtls_x509_name_cmp_raw( &frame->subject_raw,
                                     &frame->subject_raw,
                                     NULL, NULL );
    if( ret != 0 )
        return( ret );

    /*
     * SubjectPublicKeyInfo
     */
    frame->pubkey_raw.p = p;
    ret = mbedtls_asn1_get_tag( &p, end, &len,
                            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( ret + MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
    p += len;
    frame->pubkey_raw.len = p - frame->pubkey_raw.p;

    if( frame->version != 1 )
    {
#if !defined(MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID)
        /*
         *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
         *                       -- If present, version shall be v2 or v3
         */
        ret = x509_get_uid( &p, end, &frame->issuer_id, 1 /* implicit tag */ );
        if( ret != 0 )
            return( ret );

        /*
         *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
         *                       -- If present, version shall be v2 or v3
         */
        ret = x509_get_uid( &p, end, &frame->subject_id, 2 /* implicit tag */ );
        if( ret != 0 )
            return( ret );
#else /* !MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID */
        ret = x509_skip_uid( &p, end, 1 /* implicit tag */ );
        if( ret != 0 )
            return( ret );
        ret = x509_skip_uid( &p, end, 2 /* implicit tag */ );
        if( ret != 0 )
            return( ret );
#endif /* MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID */
    }

    /*
     *  extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                       -- If present, version shall be v3
     */
#if !defined(MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3)
    if( frame->version == 3 )
#endif
    {
        if( p != end )
        {
            ret = mbedtls_asn1_get_tag( &p, end, &len,
                                        MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                        MBEDTLS_ASN1_CONSTRUCTED | 3 );
            if( len == 0 )
                ret = MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            if( ret != 0 )
                return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

            frame->v3_ext.p = p;
            frame->v3_ext.len = len;

            p += len;
        }

        ret = x509_crt_frame_parse_ext( frame );
        if( ret != 0 )
            return( ret );
    }

    /* Wrapup: Check that we consumed the entire `TBSCertificate` structure. */
    if( p != end )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

static int x509_crt_subject_from_frame( mbedtls_x509_crt_frame const *frame,
                                        mbedtls_x509_name *subject )
{
    return( mbedtls_x509_get_name( frame->subject_raw.p,
                                   frame->subject_raw.len,
                                   subject ) );
}

static int x509_crt_issuer_from_frame( mbedtls_x509_crt_frame const *frame,
                                       mbedtls_x509_name *issuer )
{
    return( mbedtls_x509_get_name( frame->issuer_raw.p,
                                   frame->issuer_raw.len,
                                   issuer ) );
}

#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
static int x509_crt_subject_alt_from_frame( mbedtls_x509_crt_frame const *frame,
                                            mbedtls_x509_sequence *subject_alt )
{
    int ret;
    unsigned char *p   = frame->subject_alt_raw.p;
    unsigned char *end = p + frame->subject_alt_raw.len;

    mbedtls_platform_memset( subject_alt, 0, sizeof( *subject_alt ) );

    if( ( frame->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME ) == 0 )
        return( 0 );

    ret = x509_get_subject_alt_name( p, end, subject_alt );
    if( ret != 0 )
        ret += MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    return( ret );
}
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

static int x509_crt_ext_key_usage_from_frame( mbedtls_x509_crt_frame const *frame,
                                        mbedtls_x509_sequence *ext_key_usage )
{
    int ret;
    unsigned char *p   = frame->ext_key_usage_raw.p;
    unsigned char *end = p + frame->ext_key_usage_raw.len;

    mbedtls_platform_memset( ext_key_usage, 0, sizeof( *ext_key_usage ) );

    if( ( frame->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE ) == 0 )
        return( 0 );

    ret = x509_get_ext_key_usage( &p, end, ext_key_usage );
    if( ret != 0 )
    {
        ret += MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        return( ret );
    }

    return( 0 );
}

#if !defined(MBEDTLS_X509_ON_DEMAND_PARSING)
static int x509_crt_pk_from_frame( mbedtls_x509_crt_frame *frame,
                                   mbedtls_pk_context *pk )
{
    unsigned char *p   = frame->pubkey_raw.p;
    unsigned char *end = p + frame->pubkey_raw.len;
    return( mbedtls_pk_parse_subpubkey( &p, end, pk ) );
}
#endif /* !MBEDTLS_X509_ON_DEMAND_PARSING */

/*
 * Parse and fill a single X.509 certificate in DER format
 */
static int x509_crt_parse_der_core( mbedtls_x509_crt *crt,
                                    const unsigned char *buf,
                                    size_t buflen,
                                    int make_copy )
{
    int ret;
    mbedtls_x509_crt_frame *frame;
    mbedtls_x509_crt_cache *cache;

    if( crt == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    if( make_copy == 0 )
    {
        crt->raw.p = (unsigned char*) buf;
        crt->raw.len = buflen;
        crt->own_buffer = 0;
    }
    else
    {
        /* Call mbedtls_calloc with buflen + 1 in order to avoid potential
         * return of NULL in case of length 0 certificates, which we want
         * to cleanly fail with MBEDTLS_ERR_X509_INVALID_FORMAT in the
         * core parsing routine, but not here. */
        crt->raw.p = mbedtls_calloc( 1, buflen + 1 );
        if( crt->raw.p == NULL )
            return( MBEDTLS_ERR_X509_ALLOC_FAILED );
        crt->raw.len = buflen;
        mbedtls_platform_memcpy( crt->raw.p, buf, buflen );

        crt->own_buffer = 1;
    }

    cache = mbedtls_calloc( 1, sizeof( mbedtls_x509_crt_cache ) );
    if( cache == NULL )
    {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto exit;
    }
    crt->cache = cache;
    x509_crt_cache_init( cache );

#if defined(MBEDTLS_X509_ON_DEMAND_PARSING)

    ret = mbedtls_x509_crt_cache_provide_frame( crt );
    if( ret != 0 )
        goto exit;

    frame = crt->cache->frame;

#else /* MBEDTLS_X509_ON_DEMAND_PARSING */

    frame = mbedtls_calloc( 1, sizeof( mbedtls_x509_crt_frame ) );
    if( frame == NULL )
    {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto exit;
    }
    cache->frame = frame;

    ret = x509_crt_parse_frame( crt->raw.p,
                                crt->raw.p + crt->raw.len,
                                frame );
    if( ret != 0 )
        goto exit;

    /* Copy frame to legacy CRT structure -- that's inefficient, but if
     * memory matters, the new CRT structure should be used anyway. */
    x509_buf_raw_to_buf( &crt->tbs, &frame->tbs );
    x509_buf_raw_to_buf( &crt->serial, &frame->serial );
    x509_buf_raw_to_buf( &crt->issuer_raw, &frame->issuer_raw );
    x509_buf_raw_to_buf( &crt->subject_raw, &frame->subject_raw );
#if !defined(MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID)
    x509_buf_raw_to_buf( &crt->issuer_id, &frame->issuer_id );
    x509_buf_raw_to_buf( &crt->subject_id, &frame->subject_id );
#endif /* !MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID */
    x509_buf_raw_to_buf( &crt->pk_raw, &frame->pubkey_raw );
    x509_buf_raw_to_buf( &crt->sig, &frame->sig );
    x509_buf_raw_to_buf( &crt->v3_ext, &frame->v3_ext );

#if !defined(MBEDTLS_X509_CRT_REMOVE_TIME)
    crt->valid_from = frame->valid_from;
    crt->valid_to = frame->valid_to;
#endif /* !MBEDTLS_X509_CRT_REMOVE_TIME */

    crt->version      = frame->version;
    crt->ca_istrue    = frame->ca_istrue;
    crt->max_pathlen  = frame->max_pathlen;
    crt->ext_types    = frame->ext_types;
    crt->key_usage    = frame->key_usage;
    crt->ns_cert_type = frame->ns_cert_type;

    /*
     * Obtain the remaining fields from the frame.
     */

    {
        /* sig_oid: Previously, needed for convenience in
         * mbedtls_x509_crt_info(), now pure legacy burden. */
        unsigned char *tmp = frame->sig_alg.p;
        unsigned char *end = tmp + frame->sig_alg.len;
        mbedtls_x509_buf sig_oid, sig_params;

        ret = mbedtls_x509_get_alg( &tmp, end,
                                    &sig_oid, &sig_params );
        if( ret != 0 )
        {
            /* This should never happen, because we check
             * the sanity of the AlgorithmIdentifier structure
             * during frame parsing. */
            ret = MBEDTLS_ERR_X509_FATAL_ERROR;
            goto exit;
        }
        crt->sig_oid = sig_oid;

        /* Signature parameters */
        tmp = frame->sig_alg.p;
        ret = mbedtls_x509_get_sig_alg_raw( &tmp, end,
                                            &crt->sig_md, &crt->sig_pk,
                                            &crt->sig_opts );
        if( ret != 0 )
        {
            /* Again, this should never happen. */
            ret = MBEDTLS_ERR_X509_FATAL_ERROR;
            goto exit;
        }
    }

    ret = x509_crt_pk_from_frame( frame, &crt->pk );
    if( ret != 0 )
        goto exit;

    ret = x509_crt_subject_from_frame( frame, &crt->subject );
    if( ret != 0 )
        goto exit;

    ret = x509_crt_issuer_from_frame( frame, &crt->issuer );
    if( ret != 0 )
        goto exit;

#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
    ret = x509_crt_subject_alt_from_frame( frame, &crt->subject_alt_names );
    if( ret != 0 )
        goto exit;
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

    ret = x509_crt_ext_key_usage_from_frame( frame, &crt->ext_key_usage );
    if( ret != 0 )
        goto exit;
#endif /* !MBEDTLS_X509_ON_DEMAND_PARSING */

    /* Currently, we accept DER encoded CRTs with trailing garbage
     * and promise to not account for the garbage in the `raw` field.
     *
     * Note that this means that `crt->raw.len` is not necessarily the
     * full size of the heap buffer allocated at `crt->raw.p` in case
     * of copy-mode, but this is not a problem: freeing the buffer doesn't
     * need the size, and the garbage data doesn't need zeroization. */
    crt->raw.len = frame->raw.len;

    cache->pk_raw = frame->pubkey_raw;

    /* Free the frame before parsing the public key to
     * keep peak RAM usage low. This is slightly inefficient
     * because the frame will need to be parsed again on the
     * first usage of the CRT, but that seems acceptable.
     * As soon as the frame gets used multiple times, it
     * will be cached by default. */
    x509_crt_cache_clear_frame( crt->cache );

    /* The cache just references the PK structure from the legacy
     * implementation, so set up the latter first before setting up
     * the cache.
     *
     * We're not actually using the parsed PK context here;
     * we just parse it to check that it's well-formed. */
    ret = mbedtls_x509_crt_cache_provide_pk( crt );
    if( ret != 0 )
        goto exit;
    x509_crt_cache_clear_pk( crt->cache );

exit:
    if( ret != 0 )
        mbedtls_x509_crt_free( crt );

    return( ret );
}

/*
 * Parse one X.509 certificate in DER format from a buffer and add them to a
 * chained list
 */
static int mbedtls_x509_crt_parse_der_internal( mbedtls_x509_crt *chain,
                                                const unsigned char *buf,
                                                size_t buflen,
                                                int make_copy )
{
    int ret;
    mbedtls_x509_crt *crt = chain, *prev = NULL;

    /*
     * Check for valid input
     */
    if( crt == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    while( crt->raw.p != NULL && crt->next != NULL )
    {
        prev = crt;
        crt = crt->next;
    }

    /*
     * Add new certificate on the end of the chain if needed.
     */
    if( crt->raw.p != NULL && crt->next == NULL )
    {
        crt->next = mbedtls_calloc( 1, sizeof( mbedtls_x509_crt ) );

        if( crt->next == NULL )
            return( MBEDTLS_ERR_X509_ALLOC_FAILED );

        prev = crt;
        mbedtls_x509_crt_init( crt->next );
        crt = crt->next;
    }

    if( ( ret = x509_crt_parse_der_core( crt, buf, buflen, make_copy ) ) != 0 )
    {
        if( prev )
            prev->next = NULL;

        if( crt != chain )
            mbedtls_free( crt );

        return( ret );
    }

    return( 0 );
}

int mbedtls_x509_crt_parse_der_nocopy( mbedtls_x509_crt *chain,
                                       const unsigned char *buf,
                                       size_t buflen )
{
    return( mbedtls_x509_crt_parse_der_internal( chain, buf, buflen, 0 ) );
}

int mbedtls_x509_crt_parse_der( mbedtls_x509_crt *chain,
                                const unsigned char *buf,
                                size_t buflen )
{
    return( mbedtls_x509_crt_parse_der_internal( chain, buf, buflen, 1 ) );
}

/*
 * Parse one or more PEM certificates from a buffer and add them to the chained
 * list
 */
int mbedtls_x509_crt_parse( mbedtls_x509_crt *chain,
                            const unsigned char *buf,
                            size_t buflen )
{
#if defined(MBEDTLS_PEM_PARSE_C)
    int success = 0, first_error = 0, total_failed = 0;
    int buf_format = MBEDTLS_X509_FORMAT_DER;
#endif

    /*
     * Check for valid input
     */
    if( chain == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    /*
     * Determine buffer content. Buffer contains either one DER certificate or
     * one or more PEM certificates.
     */
#if defined(MBEDTLS_PEM_PARSE_C)
    if( buflen != 0 && buf[buflen - 1] == '\0' &&
        strstr( (const char *) buf, "-----BEGIN CERTIFICATE-----" ) != NULL )
    {
        buf_format = MBEDTLS_X509_FORMAT_PEM;
    }

    if( buf_format == MBEDTLS_X509_FORMAT_DER )
        return mbedtls_x509_crt_parse_der( chain, buf, buflen );
#else
    return mbedtls_x509_crt_parse_der( chain, buf, buflen );
#endif

#if defined(MBEDTLS_PEM_PARSE_C)
    if( buf_format == MBEDTLS_X509_FORMAT_PEM )
    {
        int ret;
        mbedtls_pem_context pem;

        /* 1 rather than 0 since the terminating NULL byte is counted in */
        while( buflen > 1 )
        {
            size_t use_len;
            mbedtls_pem_init( &pem );

            /* If we get there, we know the string is null-terminated */
            ret = mbedtls_pem_read_buffer( &pem,
                           "-----BEGIN CERTIFICATE-----",
                           "-----END CERTIFICATE-----",
                           buf, NULL, 0, &use_len );

            if( ret == 0 )
            {
                /*
                 * Was PEM encoded
                 */
                buflen -= use_len;
                buf += use_len;
            }
            else if( ret == MBEDTLS_ERR_PEM_BAD_INPUT_DATA )
            {
                return( ret );
            }
            else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
            {
                mbedtls_pem_free( &pem );

                /*
                 * PEM header and footer were found
                 */
                buflen -= use_len;
                buf += use_len;

                if( first_error == 0 )
                    first_error = ret;

                total_failed++;
                continue;
            }
            else
                break;

            ret = mbedtls_x509_crt_parse_der( chain, pem.buf, pem.buflen );

            mbedtls_pem_free( &pem );

            if( ret != 0 )
            {
                /*
                 * Quit parsing on a memory error
                 */
                if( ret == MBEDTLS_ERR_X509_ALLOC_FAILED )
                    return( ret );

                if( first_error == 0 )
                    first_error = ret;

                total_failed++;
                continue;
            }

            success = 1;
        }
    }

    if( success )
        return( total_failed );
    else if( first_error )
        return( first_error );
    else
        return( MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT );
#endif /* MBEDTLS_PEM_PARSE_C */
}

#if defined(MBEDTLS_FS_IO)
/*
 * Load one or more certificates and add them to the chained list
 */
int mbedtls_x509_crt_parse_file( mbedtls_x509_crt *chain, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_crt_parse( chain, buf, n );

    mbedtls_platform_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}

int mbedtls_x509_crt_parse_path( mbedtls_x509_crt *chain, const char *path )
{
    int ret = 0;
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
    int w_ret;
    WCHAR szDir[MAX_PATH];
    char filename[MAX_PATH];
    char *p;
    size_t len = strlen( path );

    WIN32_FIND_DATAW file_data;
    HANDLE hFind;

    if( len > MAX_PATH - 3 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    mbedtls_platform_memset( szDir, 0, sizeof(szDir) );
    mbedtls_platform_memset( filename, 0, MAX_PATH );
    mbedtls_platform_memcpy( filename, path, len );
    filename[len++] = '\\';
    p = filename + len;
    filename[len++] = '*';

    w_ret = MultiByteToWideChar( CP_ACP, 0, filename, (int)len, szDir,
                                 MAX_PATH - 3 );
    if( w_ret == 0 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    hFind = FindFirstFileW( szDir, &file_data );
    if( hFind == INVALID_HANDLE_VALUE )
        return( MBEDTLS_ERR_X509_FILE_IO_ERROR );

    len = MAX_PATH - len;
    do
    {
        mbedtls_platform_memset( p, 0, len );

        if( file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
            continue;

        w_ret = WideCharToMultiByte( CP_ACP, 0, file_data.cFileName,
                                     lstrlenW( file_data.cFileName ),
                                     p, (int) len - 1,
                                     NULL, NULL );
        if( w_ret == 0 )
        {
            ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
            goto cleanup;
        }

        w_ret = mbedtls_x509_crt_parse_file( chain, filename );
        if( w_ret < 0 )
            ret++;
        else
            ret += w_ret;
    }
    while( FindNextFileW( hFind, &file_data ) != 0 );

    if( GetLastError() != ERROR_NO_MORE_FILES )
        ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;

cleanup:
    FindClose( hFind );
#else /* _WIN32 */
    int t_ret;
    int snp_ret;
    struct stat sb;
    struct dirent *entry;
    char entry_name[MBEDTLS_X509_MAX_FILE_PATH_LEN];
    DIR *dir = opendir( path );

    if( dir == NULL )
        return( MBEDTLS_ERR_X509_FILE_IO_ERROR );

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &mbedtls_threading_readdir_mutex ) ) != 0 )
    {
        closedir( dir );
        return( ret );
    }
#endif /* MBEDTLS_THREADING_C */

    while( ( entry = readdir( dir ) ) != NULL )
    {
        snp_ret = mbedtls_snprintf( entry_name, sizeof entry_name,
                                    "%s/%s", path, entry->d_name );

        if( snp_ret < 0 || (size_t)snp_ret >= sizeof entry_name )
        {
            ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        else if( stat( entry_name, &sb ) == -1 )
        {
            ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
            goto cleanup;
        }

        if( !S_ISREG( sb.st_mode ) )
            continue;

        // Ignore parse errors
        //
        t_ret = mbedtls_x509_crt_parse_file( chain, entry_name );
        if( t_ret < 0 )
            ret++;
        else
            ret += t_ret;
    }

cleanup:
    closedir( dir );

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &mbedtls_threading_readdir_mutex ) != 0 )
        ret = MBEDTLS_ERR_THREADING_MUTEX_ERROR;
#endif /* MBEDTLS_THREADING_C */

#endif /* _WIN32 */

    return( ret );
}
#endif /* MBEDTLS_FS_IO */

typedef struct mbedtls_x509_crt_sig_info
{
    mbedtls_md_type_t sig_md;
    mbedtls_pk_type_t sig_pk;
    void *sig_opts;
    size_t crt_hash_len;
    mbedtls_x509_buf_raw sig;
    mbedtls_x509_buf_raw issuer_raw;
    uint8_t crt_hash[MBEDTLS_MD_MAX_SIZE];
} mbedtls_x509_crt_sig_info;

static void x509_crt_free_sig_info( mbedtls_x509_crt_sig_info *info )
{
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_free( info->sig_opts );
#else
    ((void) info);
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
}

static int x509_crt_get_sig_info( mbedtls_x509_crt_frame const *frame,
                                  mbedtls_x509_crt_sig_info *info )
{
    mbedtls_md_handle_t md_info;

    md_info = mbedtls_md_info_from_type( frame->sig_md );
    if( mbedtls_md( md_info, frame->tbs.p, frame->tbs.len,
                    info->crt_hash ) != 0 )
    {
        /* Note: this can't happen except after an internal error */
        return( -1 );
    }

    info->crt_hash_len = mbedtls_md_get_size( md_info );

    /* Make sure that this function leaves the target structure
     * ready to be freed, regardless of success of failure. */
    info->sig_opts = NULL;

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    {
        int ret;
        unsigned char *alg_start = frame->sig_alg.p;
        unsigned char *alg_end = alg_start + frame->sig_alg.len;

        /* Get signature options -- currently only
         * necessary for RSASSA-PSS. */
        ret = mbedtls_x509_get_sig_alg_raw( &alg_start, alg_end, &info->sig_md,
                                            &info->sig_pk, &info->sig_opts );
        if( ret != 0 )
        {
            /* Note: this can't happen except after an internal error */
            return( -1 );
        }
    }
#else /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
    info->sig_md   = frame->sig_md;
    info->sig_pk   = frame->sig_pk;
#endif /* !MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    info->issuer_raw = frame->issuer_raw;
    info->sig = frame->sig;
    return( 0 );
}

#if !defined(MBEDTLS_X509_REMOVE_INFO)
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
static int x509_info_subject_alt_name( char **buf, size_t *size,
                                       const mbedtls_x509_sequence *subject_alt_name )
{
    size_t i;
    size_t n = *size;
    char *p = *buf;
    const mbedtls_x509_sequence *cur = subject_alt_name;
    const char *sep = "";
    size_t sep_len = 0;

    while( cur != NULL )
    {
        if( cur->buf.len + sep_len >= n )
        {
            *p = '\0';
            return( MBEDTLS_ERR_X509_BUFFER_TOO_SMALL );
        }

        n -= cur->buf.len + sep_len;
        for( i = 0; i < sep_len; i++ )
            *p++ = sep[i];
        for( i = 0; i < cur->buf.len; i++ )
            *p++ = cur->buf.p[i];

        sep = ", ";
        sep_len = 2;

        cur = cur->next;
    }

    *p = '\0';

    *size = n;
    *buf = p;

    return( 0 );
}
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

#define PRINT_ITEM(i)                           \
    {                                           \
        ret = mbedtls_snprintf( p, n, "%s" i, sep );    \
        MBEDTLS_X509_SAFE_SNPRINTF;                        \
        sep = ", ";                             \
    }

#define CERT_TYPE(type,name)                    \
    if( ns_cert_type & (type) )                 \
        PRINT_ITEM( name );

static int x509_info_cert_type( char **buf, size_t *size,
                                unsigned char ns_cert_type )
{
    int ret;
    size_t n = *size;
    char *p = *buf;
    const char *sep = "";

    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT,         "SSL Client" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,         "SSL Server" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_EMAIL,              "Email" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING,     "Object Signing" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_RESERVED,           "Reserved" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_SSL_CA,             "SSL CA" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA,           "Email CA" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA,  "Object Signing CA" );

    *size = n;
    *buf = p;

    return( 0 );
}

#define KEY_USAGE(code,name)    \
    if( key_usage & (code) )    \
        PRINT_ITEM( name );

static int x509_info_key_usage( char **buf, size_t *size,
                                unsigned int key_usage )
{
    int ret;
    size_t n = *size;
    char *p = *buf;
    const char *sep = "";

    KEY_USAGE( MBEDTLS_X509_KU_DIGITAL_SIGNATURE,    "Digital Signature" );
    KEY_USAGE( MBEDTLS_X509_KU_NON_REPUDIATION,      "Non Repudiation" );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_ENCIPHERMENT,     "Key Encipherment" );
    KEY_USAGE( MBEDTLS_X509_KU_DATA_ENCIPHERMENT,    "Data Encipherment" );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_AGREEMENT,        "Key Agreement" );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_CERT_SIGN,        "Key Cert Sign" );
    KEY_USAGE( MBEDTLS_X509_KU_CRL_SIGN,             "CRL Sign" );
    KEY_USAGE( MBEDTLS_X509_KU_ENCIPHER_ONLY,        "Encipher Only" );
    KEY_USAGE( MBEDTLS_X509_KU_DECIPHER_ONLY,        "Decipher Only" );

    *size = n;
    *buf = p;

    return( 0 );
}

static int x509_info_ext_key_usage( char **buf, size_t *size,
                                    const mbedtls_x509_sequence *extended_key_usage )
{
    int ret;
    const char *desc;
    size_t n = *size;
    char *p = *buf;
    const mbedtls_x509_sequence *cur = extended_key_usage;
    const char *sep = "";

    while( cur != NULL )
    {
        if( mbedtls_oid_get_extended_key_usage( &cur->buf, &desc ) != 0 )
            desc = "???";

        ret = mbedtls_snprintf( p, n, "%s%s", sep, desc );
        MBEDTLS_X509_SAFE_SNPRINTF;

        sep = ", ";

        cur = cur->next;
    }

    *size = n;
    *buf = p;

    return( 0 );
}

/*
 * Return an informational string about the certificate.
 */
#define BEFORE_COLON_CRT    18
#define BC_CRT              "18"
int mbedtls_x509_crt_info( char *buf, size_t size, const char *prefix,
                           const mbedtls_x509_crt *crt )
{
    int ret;
    size_t n;
    char *p;
    char key_size_str[BEFORE_COLON_CRT];
    mbedtls_x509_crt_frame frame;
    mbedtls_pk_context pk;

    mbedtls_x509_name *issuer = NULL, *subject = NULL;
    mbedtls_x509_sequence *ext_key_usage = NULL;
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
    mbedtls_x509_sequence *subject_alt_names = NULL;
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

    mbedtls_x509_crt_sig_info sig_info;

    p = buf;
    n = size;

    memset( &sig_info, 0, sizeof( mbedtls_x509_crt_sig_info ) );
    mbedtls_pk_init( &pk );

    if( NULL == crt )
    {
        ret = mbedtls_snprintf( p, n, "\nCertificate is uninitialised!\n" );
        MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

        return( (int) ( size - n ) );
    }

    ret = mbedtls_x509_crt_get_frame( crt, &frame );
    if( ret != 0 )
    {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto cleanup;
    }

    ret = mbedtls_x509_crt_get_subject( crt, &subject );
    if( ret != 0 )
    {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto cleanup;
    }

    ret = mbedtls_x509_crt_get_issuer( crt, &issuer );
    if( ret != 0 )
    {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto cleanup;
    }

#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
    ret = mbedtls_x509_crt_get_subject_alt_names( crt, &subject_alt_names );
    if( ret != 0 )
    {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto cleanup;
    }
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

    ret = mbedtls_x509_crt_get_ext_key_usage( crt, &ext_key_usage );
    if( ret != 0 )
    {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto cleanup;
    }

    ret = mbedtls_x509_crt_get_pk( crt, &pk );
    if( ret != 0 )
    {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto cleanup;
    }

    ret = x509_crt_get_sig_info( &frame, &sig_info );
    if( ret != 0 )
    {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto cleanup;
    }

    ret = mbedtls_snprintf( p, n, "%scert. version     : %d\n",
                               prefix, frame.version );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

    {
        mbedtls_x509_buf serial;
        serial.p   = frame.serial.p;
        serial.len = frame.serial.len;
        ret = mbedtls_snprintf( p, n, "%sserial number     : ",
                                prefix );
        MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;
        ret = mbedtls_x509_serial_gets( p, n, &serial );
        MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;
    }

    ret = mbedtls_snprintf( p, n, "\n%sissuer name       : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;
    ret = mbedtls_x509_dn_gets( p, n, issuer  );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

    ret = mbedtls_snprintf( p, n, "\n%ssubject name      : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;
    ret = mbedtls_x509_dn_gets( p, n, subject );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

#if !defined(MBEDTLS_X509_CRT_REMOVE_TIME)
    ret = mbedtls_snprintf( p, n, "\n%sissued  on        : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   frame.valid_from.year, frame.valid_from.mon,
                   frame.valid_from.day,  frame.valid_from.hour,
                   frame.valid_from.min,  frame.valid_from.sec );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

    ret = mbedtls_snprintf( p, n, "\n%sexpires on        : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   frame.valid_to.year, frame.valid_to.mon,
                   frame.valid_to.day,  frame.valid_to.hour,
                   frame.valid_to.min,  frame.valid_to.sec );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;
#endif /* MBEDTLS_X509_CRT_REMOVE_TIME */

    ret = mbedtls_snprintf( p, n, "\n%ssigned using      : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

    ret = mbedtls_x509_sig_alg_gets( p, n, sig_info.sig_pk,
                                     sig_info.sig_md, sig_info.sig_opts );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

    /* Key size */
    if( ( ret = mbedtls_x509_key_size_helper( key_size_str, BEFORE_COLON_CRT,
                                      mbedtls_pk_get_name( &pk ) ) ) != 0 )
    {
        return( ret );
    }

    ret = mbedtls_snprintf( p, n, "\n%s%-" BC_CRT "s: %d bits", prefix, key_size_str,
                          (int) mbedtls_pk_get_bitlen( &pk ) );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

    /*
     * Optional extensions
     */

    if( frame.ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS )
    {
        ret = mbedtls_snprintf( p, n, "\n%sbasic constraints : CA=%s", prefix,
                        frame.ca_istrue ? "true" : "false" );
        MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

        if( frame.max_pathlen > 0 )
        {
            ret = mbedtls_snprintf( p, n, ", max_pathlen=%d", frame.max_pathlen - 1 );
            MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;
        }
    }

#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
    if( frame.ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME )
    {
        ret = mbedtls_snprintf( p, n, "\n%ssubject alt name  : ", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

        if( ( ret = x509_info_subject_alt_name( &p, &n,
                                            subject_alt_names ) ) != 0 )
            return( ret );
    }
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

    if( frame.ext_types & MBEDTLS_X509_EXT_NS_CERT_TYPE )
    {
        ret = mbedtls_snprintf( p, n, "\n%scert. type        : ", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

        if( ( ret = x509_info_cert_type( &p, &n, frame.ns_cert_type ) ) != 0 )
            return( ret );
    }

    if( frame.ext_types & MBEDTLS_X509_EXT_KEY_USAGE )
    {
        ret = mbedtls_snprintf( p, n, "\n%skey usage         : ", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

        if( ( ret = x509_info_key_usage( &p, &n, frame.key_usage ) ) != 0 )
            return( ret );
    }

    if( frame.ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE )
    {
        ret = mbedtls_snprintf( p, n, "\n%sext key usage     : ", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

        if( ( ret = x509_info_ext_key_usage( &p, &n,
                                             ext_key_usage ) ) != 0 )
            return( ret );
    }

    ret = mbedtls_snprintf( p, n, "\n" );
    MBEDTLS_X509_SAFE_SNPRINTF_WITH_CLEANUP;

    ret = (int) ( size - n );

cleanup:

    x509_crt_free_sig_info( &sig_info );
    mbedtls_pk_free( &pk );
    mbedtls_x509_name_free( issuer );
    mbedtls_x509_name_free( subject );
    mbedtls_x509_sequence_free( ext_key_usage );
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
    mbedtls_x509_sequence_free( subject_alt_names );
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

    return( ret );
}

struct x509_crt_verify_string {
    int code;
    const char *string;
};

static const struct x509_crt_verify_string x509_crt_verify_strings[] = {
    { MBEDTLS_X509_BADCERT_EXPIRED,       "The certificate validity has expired" },
    { MBEDTLS_X509_BADCERT_REVOKED,       "The certificate has been revoked (is on a CRL)" },
    { MBEDTLS_X509_BADCERT_CN_MISMATCH,   "The certificate Common Name (CN) does not match with the expected CN" },
    { MBEDTLS_X509_BADCERT_NOT_TRUSTED,   "The certificate is not correctly signed by the trusted CA" },
    { MBEDTLS_X509_BADCRL_NOT_TRUSTED,    "The CRL is not correctly signed by the trusted CA" },
    { MBEDTLS_X509_BADCRL_EXPIRED,        "The CRL is expired" },
    { MBEDTLS_X509_BADCERT_MISSING,       "Certificate was missing" },
    { MBEDTLS_X509_BADCERT_SKIP_VERIFY,   "Certificate verification was skipped" },
    { MBEDTLS_X509_BADCERT_OTHER,         "Other reason (can be used by verify callback)" },
    { MBEDTLS_X509_BADCERT_FUTURE,        "The certificate validity starts in the future" },
    { MBEDTLS_X509_BADCRL_FUTURE,         "The CRL is from the future" },
    { MBEDTLS_X509_BADCERT_KEY_USAGE,     "Usage does not match the keyUsage extension" },
    { MBEDTLS_X509_BADCERT_EXT_KEY_USAGE, "Usage does not match the extendedKeyUsage extension" },
    { MBEDTLS_X509_BADCERT_NS_CERT_TYPE,  "Usage does not match the nsCertType extension" },
    { MBEDTLS_X509_BADCERT_BAD_MD,        "The certificate is signed with an unacceptable hash." },
    { MBEDTLS_X509_BADCERT_BAD_PK,        "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA)." },
    { MBEDTLS_X509_BADCERT_BAD_KEY,       "The certificate is signed with an unacceptable key (eg bad curve, RSA too short)." },
    { MBEDTLS_X509_BADCRL_BAD_MD,         "The CRL is signed with an unacceptable hash." },
    { MBEDTLS_X509_BADCRL_BAD_PK,         "The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA)." },
    { MBEDTLS_X509_BADCRL_BAD_KEY,        "The CRL is signed with an unacceptable key (eg bad curve, RSA too short)." },
    { 0, NULL }
};

int mbedtls_x509_crt_verify_info( char *buf, size_t size, const char *prefix,
                          uint32_t flags )
{
    int ret;
    const struct x509_crt_verify_string *cur;
    char *p = buf;
    size_t n = size;

    for( cur = x509_crt_verify_strings; cur->string != NULL ; cur++ )
    {
        if( ( flags & cur->code ) == 0 )
            continue;

        ret = mbedtls_snprintf( p, n, "%s%s\n", prefix, cur->string );
        MBEDTLS_X509_SAFE_SNPRINTF;
        flags ^= cur->code;
    }

    if( flags != 0 )
    {
        ret = mbedtls_snprintf( p, n, "%sUnknown reason "
                                       "(this should not happen)\n", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;
    }

    return( (int) ( size - n ) );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */

#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
static int x509_crt_check_key_usage_frame( const mbedtls_x509_crt_frame *crt,
                                           unsigned int usage )
{
    unsigned int usage_must, usage_may;
    unsigned int may_mask = MBEDTLS_X509_KU_ENCIPHER_ONLY
                          | MBEDTLS_X509_KU_DECIPHER_ONLY;

    if( ( crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE ) == 0 )
        return( 0 );

    usage_must = usage & ~may_mask;

    if( ( ( crt->key_usage & ~may_mask ) & usage_must ) != usage_must )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    usage_may = usage & may_mask;

    if( ( ( crt->key_usage & may_mask ) | usage_may ) != usage_may )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    return( 0 );
}

int mbedtls_x509_crt_check_key_usage( const mbedtls_x509_crt *crt,
                                      unsigned int usage )
{
    int ret;
    mbedtls_x509_crt_frame const *frame;
    ret = mbedtls_x509_crt_frame_acquire( crt, &frame );
    if( ret != 0 )
        return( MBEDTLS_ERR_X509_FATAL_ERROR );

    ret = x509_crt_check_key_usage_frame( frame, usage );
    mbedtls_x509_crt_frame_release( crt );

    return( ret );
}
#endif

#if defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
typedef struct
{
    const char *oid;
    size_t oid_len;
} x509_crt_check_ext_key_usage_cb_ctx_t;

static int x509_crt_check_ext_key_usage_cb( void *ctx,
                                            int tag,
                                            unsigned char *data,
                                            size_t data_len )
{
    x509_crt_check_ext_key_usage_cb_ctx_t *cb_ctx =
        (x509_crt_check_ext_key_usage_cb_ctx_t *) ctx;
    ((void) tag);

    if( MBEDTLS_OID_CMP_RAW( MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE,
                             data, data_len ) == 0 )
    {
        return( 1 );
    }

    if( data_len == cb_ctx->oid_len && mbedtls_platform_memcmp( data, cb_ctx->oid,
                                               data_len ) == 0 )
    {
        return( 1 );
    }

    return( 0 );
}

int mbedtls_x509_crt_check_extended_key_usage( const mbedtls_x509_crt *crt,
                                               const char *usage_oid,
                                               size_t usage_len )
{
    int ret;
    mbedtls_x509_crt_frame const *frame;
    unsigned ext_types;
    unsigned char *p, *end;
    x509_crt_check_ext_key_usage_cb_ctx_t cb_ctx = { usage_oid, usage_len };

    ret = mbedtls_x509_crt_frame_acquire( crt, &frame );
    if( ret != 0 )
        return( MBEDTLS_ERR_X509_FATAL_ERROR );

    /* Extension is not mandatory, absent means no restriction */
    ext_types = frame->ext_types;
    if( ( ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE ) != 0 )
    {
        p = frame->ext_key_usage_raw.p;
        end = p + frame->ext_key_usage_raw.len;

        ret = mbedtls_asn1_traverse_sequence_of( &p, end,
                                                 0xFF, MBEDTLS_ASN1_OID, 0, 0,
                                                 x509_crt_check_ext_key_usage_cb,
                                                 &cb_ctx );
        if( ret == 1 )
            ret = 0;
        else
            ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    mbedtls_x509_crt_frame_release( crt );
    return( ret );
}
#endif /* MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE */

#if defined(MBEDTLS_X509_CRL_PARSE_C)
/*
 * Return 1 if the certificate is revoked, or 0 otherwise.
 */
static int x509_serial_is_revoked( unsigned char const *serial,
                                 size_t serial_len,
                                 const mbedtls_x509_crl *crl )
{
    const mbedtls_x509_crl_entry *cur = &crl->entry;

    while( cur != NULL && cur->serial.len != 0 )
    {
        if( serial_len == cur->serial.len &&
            mbedtls_platform_memcmp( serial, cur->serial.p, serial_len ) == 0 )
        {
            if( mbedtls_x509_time_is_past( &cur->revocation_date ) )
                return( 1 );
        }

        cur = cur->next;
    }

    return( 0 );
}

int mbedtls_x509_crt_is_revoked( const mbedtls_x509_crt *crt,
                                 const mbedtls_x509_crl *crl )
{
    int ret;
    mbedtls_x509_crt_frame const *frame;

    ret = mbedtls_x509_crt_frame_acquire( crt, &frame );
    if( ret != 0 )
        return( MBEDTLS_ERR_X509_FATAL_ERROR );

    ret = x509_serial_is_revoked( frame->serial.p,
                                  frame->serial.len,
                                  crl );
    mbedtls_x509_crt_frame_release( crt );
    return( ret );
}

/*
 * Check that the given certificate is not revoked according to the CRL.
 * Skip validation if no CRL for the given CA is present.
 */
static int x509_crt_verifycrl( unsigned char *crt_serial,
                               size_t crt_serial_len,
                               mbedtls_x509_crt *ca_crt,
                               mbedtls_x509_crl *crl_list,
                               const mbedtls_x509_crt_profile *profile )
{
    int ret;
    int flags = 0;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_handle_t md_info;
    mbedtls_x509_buf_raw ca_subject;
    mbedtls_pk_context *pk;
    int can_sign;

    if( ca_crt == NULL )
        return( flags );

    {
        mbedtls_x509_crt_frame const *ca;
        ret = mbedtls_x509_crt_frame_acquire( ca_crt, &ca );
        if( ret != 0 )
            return( MBEDTLS_X509_BADCRL_NOT_TRUSTED );

        ca_subject = ca->subject_raw;

        can_sign = 0;
        if( x509_crt_check_key_usage_frame( ca,
                                            MBEDTLS_X509_KU_CRL_SIGN ) == 0 )
        {
            can_sign = 1;
        }

        mbedtls_x509_crt_frame_release( ca_crt );
    }

    ret = mbedtls_x509_crt_pk_acquire( ca_crt, &pk );
    if( ret != 0 )
        return( MBEDTLS_X509_BADCRL_NOT_TRUSTED );

    while( crl_list != NULL )
    {
        if( crl_list->version == 0 ||
            mbedtls_x509_name_cmp_raw( &crl_list->issuer_raw,
                                       &ca_subject, NULL, NULL ) != 0 )
        {
            crl_list = crl_list->next;
            continue;
        }

        /*
         * Check if the CA is configured to sign CRLs
         */
#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
        if( !can_sign )
        {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }
#endif

        /*
         * Check if CRL is correctly signed by the trusted CA
         */
        if( x509_profile_check_md_alg( profile, crl_list->sig_md ) != 0 )
            flags |= MBEDTLS_X509_BADCRL_BAD_MD;

        if( x509_profile_check_pk_alg( profile, crl_list->sig_pk ) != 0 )
            flags |= MBEDTLS_X509_BADCRL_BAD_PK;

        md_info = mbedtls_md_info_from_type( crl_list->sig_md );
        if( mbedtls_md( md_info, crl_list->tbs.p, crl_list->tbs.len, hash ) != 0 )
        {
            /* Note: this can't happen except after an internal error */
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }

        if( x509_profile_check_key( profile, pk ) != 0 )
            flags |= MBEDTLS_X509_BADCERT_BAD_KEY;

        if( mbedtls_pk_verify_ext( crl_list->sig_pk, crl_list->sig_opts, pk,
                           crl_list->sig_md, hash, mbedtls_md_get_size( md_info ),
                           crl_list->sig.p, crl_list->sig.len ) != 0 )
        {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }

        /*
         * Check for validity of CRL (Do not drop out)
         */
        if( mbedtls_x509_time_is_past( &crl_list->next_update ) )
            flags |= MBEDTLS_X509_BADCRL_EXPIRED;

        if( mbedtls_x509_time_is_future( &crl_list->this_update ) )
            flags |= MBEDTLS_X509_BADCRL_FUTURE;

        /*
         * Check if certificate is revoked
         */
        if( x509_serial_is_revoked( crt_serial, crt_serial_len,
                                    crl_list ) )
        {
            flags |= MBEDTLS_X509_BADCERT_REVOKED;
            break;
        }

        crl_list = crl_list->next;
    }

    mbedtls_x509_crt_pk_release( ca_crt );
    return( flags );
}
#endif /* MBEDTLS_X509_CRL_PARSE_C */

/*
 * Check the signature of a certificate by its parent
 */
static int x509_crt_check_signature( const mbedtls_x509_crt_sig_info *sig_info,
                                     mbedtls_x509_crt *parent,
                                     mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_pk_context *pk;

    ret = mbedtls_x509_crt_pk_acquire( parent, &pk );
    if( ret != 0 )
        return( MBEDTLS_ERR_X509_FATAL_ERROR );

    /* Skip expensive computation on obvious mismatch */
    if( ! mbedtls_pk_can_do( pk, sig_info->sig_pk ) )
    {
        ret = -1;
        goto exit;
    }

#if !( defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE) )
    ((void) rs_ctx);
#else
    if( rs_ctx != NULL && sig_info->sig_pk == MBEDTLS_PK_ECDSA )
    {
        ret = mbedtls_pk_verify_restartable( pk,
                    sig_info->sig_md,
                    sig_info->crt_hash, sig_info->crt_hash_len,
                    sig_info->sig.p, sig_info->sig.len,
                    &rs_ctx->pk );
    }
    else
#endif
    {
        ret = mbedtls_pk_verify_ext( sig_info->sig_pk,
                                     sig_info->sig_opts,
                                     pk,
                                     sig_info->sig_md,
                                     sig_info->crt_hash, sig_info->crt_hash_len,
                                     sig_info->sig.p, sig_info->sig.len );
    }

exit:
    mbedtls_x509_crt_pk_release( parent );
    return( ret );
}

/*
 * Check if 'parent' is a suitable parent (signing CA) for 'child'.
 * Return 0 if yes, -1 if not.
 *
 * top means parent is a locally-trusted certificate
 */
static int x509_crt_check_parent( const mbedtls_x509_crt_sig_info *sig_info,
                                  const mbedtls_x509_crt_frame *parent,
                                  int top )
{
    int need_ca_bit;

    /* Parent must be the issuer */
    if( mbedtls_x509_name_cmp_raw( &sig_info->issuer_raw,
                                   &parent->subject_raw,
                                   NULL, NULL ) != 0 )
    {
        return( -1 );
    }

    /* Parent must have the basicConstraints CA bit set as a general rule */
    need_ca_bit = 1;

    /* Exception: v1/v2 certificates that are locally trusted. */
    if( top && parent->version < 3 )
        need_ca_bit = 0;

    if( need_ca_bit && ! parent->ca_istrue )
        return( -1 );

#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
    if( need_ca_bit &&
        x509_crt_check_key_usage_frame( parent,
                                        MBEDTLS_X509_KU_KEY_CERT_SIGN ) != 0 )
    {
        return( -1 );
    }
#endif

    return( 0 );
}

/*
 * Find a suitable parent for child in candidates, or return NULL.
 *
 * Here suitable is defined as:
 *  1. subject name matches child's issuer
 *  2. if necessary, the CA bit is set and key usage allows signing certs
 *  3. for trusted roots, the signature is correct
 *     (for intermediates, the signature is checked and the result reported)
 *  4. pathlen constraints are satisfied
 *
 * If there's a suitable candidate which is also time-valid, return the first
 * such. Otherwise, return the first suitable candidate (or NULL if there is
 * none).
 *
 * The rationale for this rule is that someone could have a list of trusted
 * roots with two versions on the same root with different validity periods.
 * (At least one user reported having such a list and wanted it to just work.)
 * The reason we don't just require time-validity is that generally there is
 * only one version, and if it's expired we want the flags to state that
 * rather than NOT_TRUSTED, as would be the case if we required it here.
 *
 * The rationale for rule 3 (signature for trusted roots) is that users might
 * have two versions of the same CA with different keys in their list, and the
 * way we select the correct one is by checking the signature (as we don't
 * rely on key identifier extensions). (This is one way users might choose to
 * handle key rollover, another relies on self-issued certs, see [SIRO].)
 *
 * Arguments:
 *  - [in] child: certificate for which we're looking for a parent
 *  - [in] candidates: chained list of potential parents
 *  - [out] r_parent: parent found (or NULL)
 *  - [out] r_signature_is_good: 1 if child signature by parent is valid, or 0
 *  - [in] top: 1 if candidates consists of trusted roots, ie we're at the top
 *         of the chain, 0 otherwise
 *  - [in] path_cnt: number of intermediates seen so far
 *  - [in] self_cnt: number of self-signed intermediates seen so far
 *         (will never be greater than path_cnt)
 *  - [in-out] rs_ctx: context for restarting operations
 *
 * Return value:
 *  - 0 on success
 *  - MBEDTLS_ERR_ECP_IN_PROGRESS otherwise
 */
static int x509_crt_find_parent_in(
                        mbedtls_x509_crt_sig_info const *child_sig,
                        mbedtls_x509_crt *candidates,
                        mbedtls_x509_crt **r_parent,
                        int *r_signature_is_good,
                        int top,
                        unsigned path_cnt,
                        unsigned self_cnt,
                        mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_x509_crt *parent_crt;
    int signature_is_good;

#if defined(MBEDTLS_HAVE_TIME_DATE)
    mbedtls_x509_crt *fallback_parent;
    int fallback_signature_is_good;
#endif /* MBEDTLS_HAVE_TIME_DATE */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* did we have something in progress? */
    if( rs_ctx != NULL && rs_ctx->parent != NULL )
    {
        /* restore saved state */
        parent_crt = rs_ctx->parent;
#if defined(MBEDTLS_HAVE_TIME_DATE)
        fallback_parent = rs_ctx->fallback_parent;
        fallback_signature_is_good = rs_ctx->fallback_signature_is_good;
#endif /* MBEDTLS_HAVE_TIME_DATE */

        /* clear saved state */
        rs_ctx->parent = NULL;
#if defined(MBEDTLS_HAVE_TIME_DATE)
        rs_ctx->fallback_parent = NULL;
        rs_ctx->fallback_signature_is_good = 0;
#endif /* MBEDTLS_HAVE_TIME_DATE */

        /* resume where we left */
        goto check_signature;
    }
#endif

#if defined(MBEDTLS_HAVE_TIME_DATE)
    fallback_parent = NULL;
    fallback_signature_is_good = 0;
#endif /* MBEDTLS_HAVE_TIME_DATE */

    for( parent_crt = candidates; parent_crt != NULL;
         parent_crt = parent_crt->next )
    {
        int parent_valid, parent_match, path_len_ok;

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
check_signature:
#endif

        parent_valid = parent_match = path_len_ok = 0;
        {
            mbedtls_x509_crt_frame const *parent;

            ret = mbedtls_x509_crt_frame_acquire( parent_crt, &parent );
            if( ret != 0 )
                return( MBEDTLS_ERR_X509_FATAL_ERROR );

#if !defined(MBEDTLS_X509_CRT_REMOVE_TIME)
            if( !mbedtls_x509_time_is_past( &parent->valid_to ) &&
                !mbedtls_x509_time_is_future( &parent->valid_from ) )
#endif /* !MBEDTLS_X509_CRT_REMOVE_TIME */
            {
                parent_valid = 1;
            }

            /* basic parenting skills (name, CA bit, key usage) */
            if( x509_crt_check_parent( child_sig, parent, top ) == 0 )
                parent_match = 1;

            /* +1 because the stored max_pathlen is 1 higher
             * than the actual value */
            if( !( parent->max_pathlen > 0 &&
                   (size_t) parent->max_pathlen < 1 + path_cnt - self_cnt ) )
            {
                path_len_ok = 1;
            }

            mbedtls_x509_crt_frame_release( parent_crt );
        }

        if( parent_match == 0 || path_len_ok == 0 )
            continue;

        /* Signature */
        ret = x509_crt_check_signature( child_sig, parent_crt, rs_ctx );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        if( rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS )
        {
            /* save state */
            rs_ctx->parent = parent_crt;
#if defined(MBEDTLS_HAVE_TIME_DATE)
            rs_ctx->fallback_parent = fallback_parent;
            rs_ctx->fallback_signature_is_good = fallback_signature_is_good;
#endif /* MBEDTLS_HAVE_TIME_DATE */

            return( ret );
        }
#else
        (void) ret;
#endif

        signature_is_good = ret == 0;
        if( top && ! signature_is_good )
            continue;

        /* optional time check */
        if( !parent_valid )
        {
#if defined(MBEDTLS_HAVE_TIME_DATE)
            if( fallback_parent == NULL )
            {
                fallback_parent = parent_crt;
                fallback_signature_is_good = signature_is_good;
            }
#endif /* MBEDTLS_HAVE_TIME_DATE */

            continue;
        }

        *r_parent = parent_crt;
        *r_signature_is_good = signature_is_good;

        break;
    }

    if( parent_crt == NULL )
    {
#if defined(MBEDTLS_HAVE_TIME_DATE)
        *r_parent = fallback_parent;
        *r_signature_is_good = fallback_signature_is_good;
#else /* MBEDTLS_HAVE_TIME_DATE */
        *r_parent = NULL;
#endif /* !MBEDTLS_HAVE_TIME_DATE */
    }

    return( 0 );
}

/*
 * Find a parent in trusted CAs or the provided chain, or return NULL.
 *
 * Searches in trusted CAs first, and return the first suitable parent found
 * (see find_parent_in() for definition of suitable).
 *
 * Arguments:
 *  - [in] child: certificate for which we're looking for a parent, followed
 *         by a chain of possible intermediates
 *  - [in] trust_ca: list of locally trusted certificates
 *  - [out] parent: parent found (or NULL)
 *  - [out] parent_is_trusted: 1 if returned `parent` is trusted, or 0
 *  - [out] signature_is_good: 1 if child signature by parent is valid, or 0
 *  - [in] path_cnt: number of links in the chain so far (EE -> ... -> child)
 *  - [in] self_cnt: number of self-signed certs in the chain so far
 *         (will always be no greater than path_cnt)
 *  - [in-out] rs_ctx: context for restarting operations
 *
 * Return value:
 *  - 0 on success
 *  - MBEDTLS_ERR_ECP_IN_PROGRESS otherwise
 */
static int x509_crt_find_parent(
                        mbedtls_x509_crt_sig_info const *child_sig,
                        mbedtls_x509_crt *rest,
                        mbedtls_x509_crt *trust_ca,
                        mbedtls_x509_crt **parent,
                        int *parent_is_trusted,
                        int *signature_is_good,
                        unsigned path_cnt,
                        unsigned self_cnt,
                        mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_x509_crt *search_list;

    *parent_is_trusted = 1;

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* restore then clear saved state if we have some stored */
    if( rs_ctx != NULL && rs_ctx->parent_is_trusted != -1 )
    {
        *parent_is_trusted = rs_ctx->parent_is_trusted;
        rs_ctx->parent_is_trusted = -1;
    }
#endif

    while( 1 ) {
        search_list = *parent_is_trusted ? trust_ca : rest;

        ret = x509_crt_find_parent_in( child_sig, search_list,
                                       parent, signature_is_good,
                                       *parent_is_trusted,
                                       path_cnt, self_cnt, rs_ctx );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        if( rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS )
        {
            /* save state */
            rs_ctx->parent_is_trusted = *parent_is_trusted;
            return( ret );
        }
#else
        (void) ret;
#endif

        /* stop here if found or already in second iteration */
        if( *parent != NULL || *parent_is_trusted == 0 )
            break;

        /* prepare second iteration */
        *parent_is_trusted = 0;
    }

    /* extra precaution against mistakes in the caller */
    if( *parent == NULL )
    {
        *parent_is_trusted = 0;
        *signature_is_good = 0;
    }

    return( 0 );
}

/*
 * Check if an end-entity certificate is locally trusted
 *
 * Currently we require such certificates to be self-signed (actually only
 * check for self-issued as self-signatures are not checked)
 */
static int x509_crt_check_ee_locally_trusted(
                    mbedtls_x509_crt_frame const *crt,
                    mbedtls_x509_crt const *trust_ca )
{
    mbedtls_x509_crt const *cur;

    /* look for an exact match with trusted cert */
    for( cur = trust_ca; cur != NULL; cur = cur->next )
    {
        if( crt->raw.len == cur->raw.len &&
            mbedtls_platform_memcmp( crt->raw.p, cur->raw.p, crt->raw.len ) == 0 )
        {
            return( 0 );
        }
    }

    /* too bad */
    return( -1 );
}

#if !defined(MBEDTLS_X509_REMOVE_VERIFY_CALLBACK)

/*
 * Reset (init or clear) a verify_chain
 */
static void x509_crt_verify_chain_reset(
    mbedtls_x509_crt_verify_chain *ver_chain )
{
    size_t i;

    for( i = 0; i < MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE; i++ )
    {
        ver_chain->items[i].crt = NULL;
        ver_chain->items[i].flags = (uint32_t) -1;
    }

    ver_chain->len = 0;
}

/*
 * Merge the flags for all certs in the chain, after calling callback
 */
static int x509_crt_verify_chain_get_flags(
           const mbedtls_x509_crt_verify_chain *ver_chain,
           uint32_t *flags,
           int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
           void *p_vrfy )
{
    int ret;
    unsigned i;
    uint32_t cur_flags;
    const mbedtls_x509_crt_verify_chain_item *cur;

    for( i = ver_chain->len; i != 0; --i )
    {
        cur = &ver_chain->items[i-1];
        cur_flags = cur->flags;

        if( NULL != f_vrfy )
            if( ( ret = f_vrfy( p_vrfy, cur->crt, (int) i-1, &cur_flags ) ) != 0 )
                return( ret );

        *flags |= cur_flags;
    }

    return( 0 );
}

static void x509_crt_verify_chain_add_ee_flags(
    mbedtls_x509_crt_verify_chain *chain,
    uint32_t ee_flags )
{
    chain->items[0].flags |= ee_flags;
}

static void x509_crt_verify_chain_add_crt(
    mbedtls_x509_crt_verify_chain *chain,
    mbedtls_x509_crt *crt )
{
    mbedtls_x509_crt_verify_chain_item *cur;
    cur = &chain->items[chain->len];
    cur->crt = crt;
    cur->flags = 0;
    chain->len++;
}

static uint32_t* x509_crt_verify_chain_get_cur_flags(
    mbedtls_x509_crt_verify_chain *chain )
{
    return( &chain->items[chain->len - 1].flags );
}

static unsigned x509_crt_verify_chain_len(
    mbedtls_x509_crt_verify_chain const *chain )
{
    return( chain->len );
}

#else /* !MBEDTLS_X509_REMOVE_VERIFY_CALLBACK */

/*
 * Reset (init or clear) a verify_chain
 */
static void x509_crt_verify_chain_reset(
    mbedtls_x509_crt_verify_chain *ver_chain )
{
    ver_chain->len   = 0;
    ver_chain->flags = 0;
}

/*
 * Merge the flags for all certs in the chain, after calling callback
 */
static int x509_crt_verify_chain_get_flags(
           const mbedtls_x509_crt_verify_chain *ver_chain,
           uint32_t *flags,
           int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
           void *p_vrfy )
{
    ((void) f_vrfy);
    ((void) p_vrfy);
    *flags = ver_chain->flags;
    return( 0 );
}

static void x509_crt_verify_chain_add_ee_flags(
    mbedtls_x509_crt_verify_chain *chain,
    uint32_t ee_flags )
{
    chain->flags |= ee_flags;
}

static void x509_crt_verify_chain_add_crt(
    mbedtls_x509_crt_verify_chain *chain,
    mbedtls_x509_crt *crt )
{
    ((void) crt);
    chain->len++;
}

static uint32_t* x509_crt_verify_chain_get_cur_flags(
    mbedtls_x509_crt_verify_chain *chain )
{
    return( &chain->flags );
}

static unsigned x509_crt_verify_chain_len(
    mbedtls_x509_crt_verify_chain const *chain )
{
    return( chain->len );
}

#endif /* MBEDTLS_X509_REMOVE_VERIFY_CALLBACK */

/*
 * Build and verify a certificate chain
 *
 * Given a peer-provided list of certificates EE, C1, ..., Cn and
 * a list of trusted certs R1, ... Rp, try to build and verify a chain
 *      EE, Ci1, ... Ciq [, Rj]
 * such that every cert in the chain is a child of the next one,
 * jumping to a trusted root as early as possible.
 *
 * Verify that chain and return it with flags for all issues found.
 *
 * Special cases:
 * - EE == Rj -> return a one-element list containing it
 * - EE, Ci1, ..., Ciq cannot be continued with a trusted root
 *   -> return that chain with NOT_TRUSTED set on Ciq
 *
 * Tests for (aspects of) this function should include at least:
 * - trusted EE
 * - EE -> trusted root
 * - EE -> intermediate CA -> trusted root
 * - if relevant: EE untrusted
 * - if relevant: EE -> intermediate, untrusted
 * with the aspect under test checked at each relevant level (EE, int, root).
 * For some aspects longer chains are required, but usually length 2 is
 * enough (but length 1 is not in general).
 *
 * Arguments:
 *  - [in] crt: the cert list EE, C1, ..., Cn
 *  - [in] trust_ca: the trusted list R1, ..., Rp
 *  - [in] ca_crl, profile: as in verify_with_profile()
 *  - [out] ver_chain: the built and verified chain
 *      Only valid when return value is 0, may contain garbage otherwise!
 *      Restart note: need not be the same when calling again to resume.
 *  - [in-out] rs_ctx: context for restarting operations
 *
 * Return value:
 *  - non-zero if the chain could not be fully built and examined
 *  - 0 is the chain was successfully built and examined,
 *      even if it was found to be invalid
 */
static int x509_crt_verify_chain(
                mbedtls_x509_crt *crt,
                mbedtls_x509_crt *trust_ca,
                mbedtls_x509_crl *ca_crl,
                const mbedtls_x509_crt_profile *profile,
                mbedtls_x509_crt_verify_chain *ver_chain,
                mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    /* Don't initialize any of those variables here, so that the compiler can
     * catch potential issues with jumping ahead when restarting */
    int ret;
    uint32_t *flags;
    mbedtls_x509_crt *child_crt;
    mbedtls_x509_crt *parent_crt;
    int parent_is_trusted;
    int child_is_trusted;
    int signature_is_good;
    unsigned self_cnt;

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* resume if we had an operation in progress */
    if( rs_ctx != NULL && rs_ctx->in_progress == x509_crt_rs_find_parent )
    {
        /* restore saved state */
        *ver_chain = rs_ctx->ver_chain; /* struct copy */
        self_cnt = rs_ctx->self_cnt;
        child_crt = rs_ctx->cur_crt;

        child_is_trusted = 0;
        goto find_parent;
    }
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    child_crt = crt;
    self_cnt = 0;
    parent_is_trusted = 0;
    child_is_trusted = 0;

    while( 1 ) {
#if defined(MBEDTLS_X509_CRL_PARSE_C)
        mbedtls_x509_buf_raw child_serial;
#endif /* MBEDTLS_X509_CRL_PARSE_C */
        int self_issued;

        /* Add certificate to the verification chain */
        x509_crt_verify_chain_add_crt( ver_chain, child_crt );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
find_parent:
#endif

        flags = x509_crt_verify_chain_get_cur_flags( ver_chain );

        {
            mbedtls_x509_crt_sig_info child_sig;
            {
                mbedtls_x509_crt_frame const *child;

                ret = mbedtls_x509_crt_frame_acquire( child_crt, &child );
                if( ret != 0 )
                    return( MBEDTLS_ERR_X509_FATAL_ERROR );

#if !defined(MBEDTLS_X509_CRT_REMOVE_TIME)
                /* Check time-validity (all certificates) */
                if( mbedtls_x509_time_is_past( &child->valid_to ) )
                    *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
                if( mbedtls_x509_time_is_future( &child->valid_from ) )
                    *flags |= MBEDTLS_X509_BADCERT_FUTURE;
#endif /* !MBEDTLS_X509_CRT_REMOVE_TIME */

                /* Stop here for trusted roots (but not for trusted EE certs) */
                if( child_is_trusted )
                {
                    mbedtls_x509_crt_frame_release( child_crt );
                    return( 0 );
                }

                self_issued = 0;
                if( mbedtls_x509_name_cmp_raw( &child->issuer_raw,
                                               &child->subject_raw,
                                               NULL, NULL ) == 0 )
                {
                    self_issued = 1;
                }

                /* Check signature algorithm: MD & PK algs */
                if( x509_profile_check_md_alg( profile, child->sig_md ) != 0 )
                    *flags |= MBEDTLS_X509_BADCERT_BAD_MD;

                if( x509_profile_check_pk_alg( profile, child->sig_pk ) != 0 )
                    *flags |= MBEDTLS_X509_BADCERT_BAD_PK;

                /* Special case: EE certs that are locally trusted */
                if( x509_crt_verify_chain_len( ver_chain ) == 1 && self_issued &&
                    x509_crt_check_ee_locally_trusted( child, trust_ca ) == 0 )
                {
                    mbedtls_x509_crt_frame_release( child_crt );
                    return( 0 );
                }

#if defined(MBEDTLS_X509_CRL_PARSE_C)
                child_serial = child->serial;
#endif /* MBEDTLS_X509_CRL_PARSE_C */

                ret = x509_crt_get_sig_info( child, &child_sig );
                mbedtls_x509_crt_frame_release( child_crt );

                if( ret != 0 )
                    return( MBEDTLS_ERR_X509_FATAL_ERROR );
            }

            /* Look for a parent in trusted CAs or up the chain */
            ret = x509_crt_find_parent( &child_sig, child_crt->next,
                                        trust_ca, &parent_crt,
                                        &parent_is_trusted, &signature_is_good,
                                        x509_crt_verify_chain_len( ver_chain ) - 1,
                                        self_cnt, rs_ctx );

            x509_crt_free_sig_info( &child_sig );
        }

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        if( rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS )
        {
            /* save state */
            rs_ctx->in_progress = x509_crt_rs_find_parent;
            rs_ctx->self_cnt = self_cnt;
            rs_ctx->ver_chain = *ver_chain; /* struct copy */
            rs_ctx->cur_crt = child_crt;
            return( ret );
        }
#else
        (void) ret;
#endif

        /* No parent? We're done here */
        if( parent_crt == NULL )
        {
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            return( 0 );
        }

        /* Count intermediate self-issued (not necessarily self-signed) certs.
         * These can occur with some strategies for key rollover, see [SIRO],
         * and should be excluded from max_pathlen checks. */
        if( x509_crt_verify_chain_len( ver_chain ) != 1 && self_issued )
            self_cnt++;

        /* path_cnt is 0 for the first intermediate CA,
         * and if parent is trusted it's not an intermediate CA */
        if( ! parent_is_trusted &&
            x509_crt_verify_chain_len( ver_chain ) >
            MBEDTLS_X509_MAX_INTERMEDIATE_CA )
        {
            /* return immediately to avoid overflow the chain array */
            return( MBEDTLS_ERR_X509_FATAL_ERROR );
        }

        /* signature was checked while searching parent */
        if( ! signature_is_good )
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;

        {
            mbedtls_pk_context *parent_pk;
            ret = mbedtls_x509_crt_pk_acquire( parent_crt, &parent_pk );
            if( ret != 0 )
                return( MBEDTLS_ERR_X509_FATAL_ERROR );

            /* check size of signing key */
            if( x509_profile_check_key( profile, parent_pk ) != 0 )
                *flags |= MBEDTLS_X509_BADCERT_BAD_KEY;

            mbedtls_x509_crt_pk_release( parent_crt );
        }

#if defined(MBEDTLS_X509_CRL_PARSE_C)
        /* Check trusted CA's CRL for the given crt */
        *flags |= x509_crt_verifycrl( child_serial.p,
                                      child_serial.len,
                                      parent_crt, ca_crl, profile );
#else
        (void) ca_crl;
#endif

        /* prepare for next iteration */
        child_crt = parent_crt;
        parent_crt = NULL;
        child_is_trusted = parent_is_trusted;
        signature_is_good = 0;
    }
}

#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
/*
 * Check for CN match
 */
static int x509_crt_check_cn( unsigned char const *buf,
                              size_t buflen,
                              const char *cn,
                              size_t cn_len )
{
    /* Try exact match */
    if( mbedtls_x509_memcasecmp( cn, buf, buflen, cn_len ) == 0 )
        return( 0 );

    /* try wildcard match */
    if( x509_check_wildcard( cn, cn_len, buf, buflen ) == 0 )
    {
        return( 0 );
    }

    return( -1 );
}

/* Returns 1 on a match and 0 on a mismatch.
 * This is because this function is used as a callback for
 * mbedtls_x509_name_cmp_raw(), which continues the name
 * traversal as long as the callback returns 0. */
static int x509_crt_check_name( void *ctx,
                                mbedtls_x509_buf *oid,
                                mbedtls_x509_buf *val,
                                int next_merged )
{
    char const *cn = (char const*) ctx;
    size_t cn_len = strlen( cn );
    ((void) next_merged);

    if( MBEDTLS_OID_CMP( MBEDTLS_OID_AT_CN, oid ) == 0 &&
        x509_crt_check_cn( val->p, val->len, cn, cn_len ) == 0 )
    {
        return( 1 );
    }

    return( 0 );
}

/* Returns 1 on a match and 0 on a mismatch.
 * This is because this function is used as a callback for
 * mbedtls_asn1_traverse_sequence_of(), which continues the
 * traversal as long as the callback returns 0. */
static int x509_crt_subject_alt_check_name( void *ctx,
                                            int tag,
                                            unsigned char *data,
                                            size_t data_len )
{
    char const *cn = (char const*) ctx;
    size_t cn_len = strlen( cn );
    ((void) tag);

    if( x509_crt_check_cn( data, data_len, cn, cn_len ) == 0 )
        return( 1 );

    return( 0 );
}

/*
 * Verify the requested CN - only call this if cn is not NULL!
 */
static int x509_crt_verify_name( const mbedtls_x509_crt *crt,
                                 const char *cn,
                                 uint32_t *flags )
{
    int ret;
    mbedtls_x509_crt_frame const *frame;

    ret = mbedtls_x509_crt_frame_acquire( crt, &frame );
    if( ret != 0 )
        return( MBEDTLS_ERR_X509_FATAL_ERROR );

    if( frame->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME )
    {
        unsigned char *p =
            frame->subject_alt_raw.p;
        const unsigned char *end =
            frame->subject_alt_raw.p + frame->subject_alt_raw.len;

        ret = mbedtls_asn1_traverse_sequence_of( &p, end,
                                      MBEDTLS_ASN1_TAG_CLASS_MASK,
                                      MBEDTLS_ASN1_CONTEXT_SPECIFIC,
                                      MBEDTLS_ASN1_TAG_VALUE_MASK,
                                      2 /* SubjectAlt DNS */,
                                      x509_crt_subject_alt_check_name,
                                      (void *) cn );
    }
    else
    {
        ret = mbedtls_x509_name_cmp_raw( &frame->subject_raw,
                                         &frame->subject_raw,
                                         x509_crt_check_name, (void *) cn );
    }

    mbedtls_x509_crt_frame_release( crt );

    /* x509_crt_check_name() and x509_crt_subject_alt_check_name()
     * return 1 when finding a name component matching `cn`. */
    if( ret == 1 )
        return( 0 );

    if( ret != 0 )
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;

    *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
    return( ret );
}
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

/*
 * Verify the certificate validity (default profile, not restartable)
 */
int mbedtls_x509_crt_verify( mbedtls_x509_crt *crt,
                     mbedtls_x509_crt *trust_ca,
                     mbedtls_x509_crl *ca_crl,
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
                     const char *cn,
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */
                     uint32_t *flags
#if !defined(MBEDTLS_X509_REMOVE_VERIFY_CALLBACK)
                     , int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *)
                     , void *p_vrfy
#endif /* MBEDTLS_X509_REMOVE_VERIFY_CALLBACK */
    )
{
    return( mbedtls_x509_crt_verify_restartable( crt, trust_ca, ca_crl,
                &mbedtls_x509_crt_profile_default,
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
                cn,
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */
                flags,
#if !defined(MBEDTLS_X509_REMOVE_VERIFY_CALLBACK)
                f_vrfy, p_vrfy,
#endif /* !MBEDTLS_X509_REMOVE_VERIFY_CALLBACK */
                NULL ) );
}

/*
 * Verify the certificate validity (user-chosen profile, not restartable)
 */
int mbedtls_x509_crt_verify_with_profile( mbedtls_x509_crt *crt,
                     mbedtls_x509_crt *trust_ca,
                     mbedtls_x509_crl *ca_crl,
                     const mbedtls_x509_crt_profile *profile,
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
                     const char *cn,
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */
                     uint32_t *flags
#if !defined(MBEDTLS_X509_REMOVE_VERIFY_CALLBACK)
                     , int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *)
                     , void *p_vrfy
#endif /* MBEDTLS_X509_REMOVE_VERIFY_CALLBACK */
    )
{
    return( mbedtls_x509_crt_verify_restartable( crt, trust_ca, ca_crl,
                profile,
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
                cn,
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */
                flags,
#if !defined(MBEDTLS_X509_REMOVE_VERIFY_CALLBACK)
                f_vrfy, p_vrfy,
#endif /* !MBEDTLS_X509_REMOVE_VERIFY_CALLBACK */
                NULL ) );
}

/*
 * Verify the certificate validity, with profile, restartable version
 *
 * This function:
 *  - checks the requested CN (if any)
 *  - checks the type and size of the EE cert's key,
 *    as that isn't done as part of chain building/verification currently
 *  - builds and verifies the chain
 *  - then calls the callback and merges the flags
 */
int mbedtls_x509_crt_verify_restartable( mbedtls_x509_crt *crt,
                     mbedtls_x509_crt *trust_ca,
                     mbedtls_x509_crl *ca_crl,
                     const mbedtls_x509_crt_profile *profile,
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
                     const char *cn,
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */
                     uint32_t *flags,
#if !defined(MBEDTLS_X509_REMOVE_VERIFY_CALLBACK)
                     int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                     void *p_vrfy,
#endif /* !MBEDTLS_X509_REMOVE_VERIFY_CALLBACK */
                     mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_x509_crt_verify_chain ver_chain;
    uint32_t ee_flags;

    *flags = 0;
    ee_flags = 0;
    x509_crt_verify_chain_reset( &ver_chain );

    if( profile == NULL )
    {
        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        goto exit;
    }

#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
    /* check name if requested */
    if( cn != NULL )
    {
        ret = x509_crt_verify_name( crt, cn, &ee_flags );
        if( ret != 0 )
            return( ret );
    }
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

    {
        mbedtls_pk_context *pk;
        mbedtls_pk_type_t pk_type;

        ret = mbedtls_x509_crt_pk_acquire( crt, &pk );
        if( ret != 0 )
            return( MBEDTLS_ERR_X509_FATAL_ERROR );

        /* Check the type and size of the key */
        pk_type = mbedtls_pk_get_type( pk );

        if( x509_profile_check_pk_alg( profile, pk_type ) != 0 )
            ee_flags |= MBEDTLS_X509_BADCERT_BAD_PK;

        if( x509_profile_check_key( profile, pk ) != 0 )
            ee_flags |= MBEDTLS_X509_BADCERT_BAD_KEY;

        mbedtls_x509_crt_pk_release( crt );
    }

    /* Check the chain */
    ret = x509_crt_verify_chain( crt, trust_ca, ca_crl, profile,
                                 &ver_chain, rs_ctx );

    if( ret != 0 )
        goto exit;

    /* Merge end-entity flags */
    x509_crt_verify_chain_add_ee_flags( &ver_chain, ee_flags );

    /* Build final flags, calling callback on the way if any */
#if !defined(MBEDTLS_X509_REMOVE_VERIFY_CALLBACK)
    ret = x509_crt_verify_chain_get_flags( &ver_chain, flags, f_vrfy, p_vrfy );
#else
    ret = x509_crt_verify_chain_get_flags( &ver_chain, flags, NULL, NULL );
#endif /* MBEDTLS_X509_REMOVE_VERIFY_CALLBACK */

exit:
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && ret != MBEDTLS_ERR_ECP_IN_PROGRESS )
        mbedtls_x509_crt_restart_free( rs_ctx );
#endif

    /* prevent misuse of the vrfy callback - VERIFY_FAILED would be ignored by
     * the SSL module for authmode optional, but non-zero return from the
     * callback means a fatal error so it shouldn't be ignored */
    if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED )
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;

    if( ret != 0 )
    {
        *flags = (uint32_t) -1;
        return( ret );
    }

    if( *flags != 0 )
        return( MBEDTLS_ERR_X509_CERT_VERIFY_FAILED );

    return( 0 );
}

/*
 * Initialize a certificate chain
 */
void mbedtls_x509_crt_init( mbedtls_x509_crt *crt )
{
    memset( crt, 0, sizeof(mbedtls_x509_crt) );
}

/*
 * Unallocate all certificate data
 */

void mbedtls_x509_crt_free( mbedtls_x509_crt *crt )
{
    mbedtls_x509_crt *cert_cur = crt;
    mbedtls_x509_crt *cert_prv;

    if( crt == NULL )
        return;

    do
    {
        x509_crt_cache_free( cert_cur->cache );
        mbedtls_free( cert_cur->cache );

#if !defined(MBEDTLS_X509_ON_DEMAND_PARSING)
        mbedtls_pk_free( &cert_cur->pk );

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
        mbedtls_free( cert_cur->sig_opts );
#endif

        mbedtls_x509_name_free( cert_cur->issuer.next );
        mbedtls_x509_name_free( cert_cur->subject.next );
        mbedtls_x509_sequence_free( cert_cur->ext_key_usage.next );
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
        mbedtls_x509_sequence_free( cert_cur->subject_alt_names.next );
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */

#endif /* !MBEDTLS_X509_ON_DEMAND_PARSING */

        if( cert_cur->raw.p != NULL && cert_cur->own_buffer )
        {
            mbedtls_platform_zeroize( cert_cur->raw.p, cert_cur->raw.len );
            mbedtls_free( cert_cur->raw.p );
        }

        cert_cur = cert_cur->next;
    }
    while( cert_cur != NULL );

    cert_cur = crt;
    do
    {
        cert_prv = cert_cur;
        cert_cur = cert_cur->next;

        mbedtls_platform_zeroize( cert_prv, sizeof( mbedtls_x509_crt ) );
        if( cert_prv != crt )
            mbedtls_free( cert_prv );
    }
    while( cert_cur != NULL );
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
/*
 * Initialize a restart context
 */
void mbedtls_x509_crt_restart_init( mbedtls_x509_crt_restart_ctx *ctx )
{
    mbedtls_pk_restart_init( &ctx->pk );

    ctx->parent = NULL;
#if defined(MBEDTLS_HAVE_TIME_DATE)
    ctx->fallback_parent = NULL;
    ctx->fallback_signature_is_good = 0;
#endif /* MBEDTLS_HAVE_TIME_DATE */

    ctx->parent_is_trusted = -1;

    ctx->in_progress = x509_crt_rs_none;
    ctx->self_cnt = 0;
    x509_crt_verify_chain_reset( &ctx->ver_chain );
}

/*
 * Free the components of a restart context
 */
void mbedtls_x509_crt_restart_free( mbedtls_x509_crt_restart_ctx *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_pk_restart_free( &ctx->pk );
    mbedtls_x509_crt_restart_init( ctx );
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

int mbedtls_x509_crt_frame_acquire( mbedtls_x509_crt const *crt,
                                          mbedtls_x509_crt_frame const **dst )
{
    int ret = 0;
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &crt->cache->frame_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif /* MBEDTLS_THREADING_C */

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
    if( crt->cache->frame_readers == 0 )
#endif
        ret = mbedtls_x509_crt_cache_provide_frame( crt );

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
    if( crt->cache->frame_readers == MBEDTLS_X509_CACHE_FRAME_READERS_MAX )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );

    crt->cache->frame_readers++;
#endif

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &crt->cache->frame_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif /* MBEDTLS_THREADING_C */

    *dst = crt->cache->frame;
    return( ret );
}

int mbedtls_x509_crt_frame_release( mbedtls_x509_crt const *crt )
{
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &crt->cache->frame_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif /* MBEDTLS_THREADING_C */

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
    if( crt->cache->frame_readers == 0 )
        return( MBEDTLS_ERR_X509_FATAL_ERROR );

    crt->cache->frame_readers--;
#endif

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock( &crt->cache->frame_mutex );
#endif /* MBEDTLS_THREADING_C */

#if defined(MBEDTLS_X509_ALWAYS_FLUSH)
    (void) mbedtls_x509_crt_flush_cache_frame( crt );
#endif /* MBEDTLS_X509_ALWAYS_FLUSH */

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) && \
    !defined(MBEDTLS_THREADING_C)
    ((void) crt);
#endif

    return( 0 );
}

int mbedtls_x509_crt_pk_acquire( mbedtls_x509_crt const *crt,
                                               mbedtls_pk_context **dst )
{
    int ret = 0;
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &crt->cache->pk_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif /* MBEDTLS_THREADING_C */

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
    if( crt->cache->pk_readers == 0 )
#endif
        ret = mbedtls_x509_crt_cache_provide_pk( crt );

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
    if( crt->cache->pk_readers == MBEDTLS_X509_CACHE_PK_READERS_MAX )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );

    crt->cache->pk_readers++;
#endif

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &crt->cache->pk_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif /* MBEDTLS_THREADING_C */

    *dst = crt->cache->pk;
    return( ret );
}

int mbedtls_x509_crt_pk_release( mbedtls_x509_crt const *crt )
{
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &crt->cache->pk_mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif /* MBEDTLS_THREADING_C */

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) ||      \
    defined(MBEDTLS_THREADING_C)
    if( crt->cache->pk_readers == 0 )
        return( MBEDTLS_ERR_X509_FATAL_ERROR );

    crt->cache->pk_readers--;
#endif

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock( &crt->cache->pk_mutex );
#endif /* MBEDTLS_THREADING_C */

#if defined(MBEDTLS_X509_ALWAYS_FLUSH)
    (void) mbedtls_x509_crt_flush_cache_pk( crt );
#endif /* MBEDTLS_X509_ALWAYS_FLUSH */

#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) && \
    !defined(MBEDTLS_THREADING_C)
    ((void) crt);
#endif

    return( 0 );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
/*
 *  X.509 Certificate Signing Request (CSR) parsing
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CSR_PARSE_C)

#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_FS_IO) || defined(EFIX64) || defined(EFI32)
#include <stdio.h>
#endif

/*
 *  Version  ::=  INTEGER  {  v1(0)  }
 */
static int x509_csr_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret );
    }

    return( 0 );
}

/*
 * Parse a CSR in DER format
 */
int mbedtls_x509_csr_parse_der( mbedtls_x509_csr *csr,
                        const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;
    mbedtls_x509_buf sig_params;

    mbedtls_platform_memset( &sig_params, 0, sizeof( mbedtls_x509_buf ) );

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL || buflen == 0 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    mbedtls_x509_csr_init( csr );

    /*
     * first copy the raw DER data
     */
    p = mbedtls_calloc( 1, len = buflen );

    if( p == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    mbedtls_platform_memcpy( p, buf, buflen );

    csr->raw.p = p;
    csr->raw.len = len;
    end = p + len;

    /*
     *  CertificationRequest ::= SEQUENCE {
     *       certificationRequestInfo CertificationRequestInfo,
     *       signatureAlgorithm AlgorithmIdentifier,
     *       signature          BIT STRING
     *  }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }

    if( len != (size_t) ( end - p ) )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     *  CertificationRequestInfo ::= SEQUENCE {
     */
    csr->cri.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = p + len;
    csr->cri.len = end - csr->cri.p;

    /*
     *  Version  ::=  INTEGER {  v1(0) }
     */
    if( ( ret = x509_csr_get_version( &p, end, &csr->version ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( csr->version != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_UNKNOWN_VERSION );
    }

    csr->version++;

    /*
     *  subject               Name
     */
    csr->subject_raw.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }
    p += len;
    csr->subject_raw.len = p - csr->subject_raw.p;

    if( ( ret = mbedtls_x509_get_name( csr->subject_raw.p,
                                       csr->subject_raw.len,
                                       &csr->subject ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    /*
     *  subjectPKInfo SubjectPublicKeyInfo
     */
    if( ( ret = mbedtls_pk_parse_subpubkey( &p, end, &csr->pk ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    /*
     *  attributes    [0] Attributes
     *
     *  The list of possible attributes is open-ended, though RFC 2985
     *  (PKCS#9) defines a few in section 5.4. We currently don't support any,
     *  so we just ignore them. This is a safe thing to do as the worst thing
     *  that could happen is that we issue a certificate that does not match
     *  the requester's expectations - this cannot cause a violation of our
     *  signature policies.
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    p += len;

    end = csr->raw.p + csr->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signature            BIT STRING
     */
    if( ( ret = mbedtls_x509_get_alg( &p, end, &csr->sig_oid, &sig_params ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( ( ret = mbedtls_x509_get_sig_alg( &csr->sig_oid, &sig_params,
                                  &csr->sig_md, &csr->sig_pk,
                                  &csr->sig_opts ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG );
    }

    if( ( ret = mbedtls_x509_get_sig( &p, end, &csr->sig ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( p != end )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

/*
 * Parse a CSR, allowing for PEM or raw DER encoding
 */
int mbedtls_x509_csr_parse( mbedtls_x509_csr *csr, const unsigned char *buf, size_t buflen )
{
#if defined(MBEDTLS_PEM_PARSE_C)
    int ret;
    size_t use_len;
    mbedtls_pem_context pem;
#endif

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL || buflen == 0 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

#if defined(MBEDTLS_PEM_PARSE_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( buf[buflen - 1] == '\0' )
    {
        mbedtls_pem_init( &pem );
        ret = mbedtls_pem_read_buffer( &pem,
                                       "-----BEGIN CERTIFICATE REQUEST-----",
                                       "-----END CERTIFICATE REQUEST-----",
                                       buf, NULL, 0, &use_len );
        if( ret == MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        {
            ret = mbedtls_pem_read_buffer( &pem,
                                           "-----BEGIN NEW CERTIFICATE REQUEST-----",
                                           "-----END NEW CERTIFICATE REQUEST-----",
                                           buf, NULL, 0, &use_len );
        }

        if( ret == 0 )
        {
            /*
             * Was PEM encoded, parse the result
             */
            ret = mbedtls_x509_csr_parse_der( csr, pem.buf, pem.buflen );
        }

        mbedtls_pem_free( &pem );
        if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
            return( ret );
    }
#endif /* MBEDTLS_PEM_PARSE_C */
    return( mbedtls_x509_csr_parse_der( csr, buf, buflen ) );
}

#if defined(MBEDTLS_FS_IO)
/*
 * Load a CSR into the structure
 */
int mbedtls_x509_csr_parse_file( mbedtls_x509_csr *csr, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_csr_parse( csr, buf, n );

    mbedtls_platform_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
#endif /* MBEDTLS_FS_IO */

#if !defined(MBEDTLS_X509_REMOVE_INFO)
#define BEFORE_COLON_CSR    14
#define BC_CSR              "14"
/*
 * Return an informational string about the CSR.
 */
int mbedtls_x509_csr_info( char *buf, size_t size, const char *prefix,
                   const mbedtls_x509_csr *csr )
{
    int ret;
    size_t n;
    char *p;
    char key_size_str[BEFORE_COLON_CSR];

    p = buf;
    n = size;

    ret = mbedtls_snprintf( p, n, "%sCSR version   : %d",
                               prefix, csr->version );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssubject name  : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_dn_gets( p, n, &csr->subject );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssigned using  : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_sig_alg_gets( p, n, csr->sig_pk,
                                     csr->sig_md, csr->sig_opts );
    MBEDTLS_X509_SAFE_SNPRINTF;

    if( ( ret = mbedtls_x509_key_size_helper( key_size_str, BEFORE_COLON_CSR,
                                      mbedtls_pk_get_name( &csr->pk ) ) ) != 0 )
    {
        return( ret );
    }

    ret = mbedtls_snprintf( p, n, "\n%s%-" BC_CSR "s: %d bits\n", prefix, key_size_str,
                          (int) mbedtls_pk_get_bitlen( &csr->pk ) );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( (int) ( size - n ) );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */

/*
 * Initialize a CSR
 */
void mbedtls_x509_csr_init( mbedtls_x509_csr *csr )
{
    mbedtls_platform_memset( csr, 0, sizeof(mbedtls_x509_csr) );
}

/*
 * Unallocate all CSR data
 */
void mbedtls_x509_csr_free( mbedtls_x509_csr *csr )
{
    mbedtls_x509_name *name_cur;
    mbedtls_x509_name *name_prv;

    if( csr == NULL )
        return;

    mbedtls_pk_free( &csr->pk );

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_free( csr->sig_opts );
#endif

    name_cur = csr->subject.next;
    while( name_cur != NULL )
    {
        name_prv = name_cur;
        name_cur = name_cur->next;
        mbedtls_platform_zeroize( name_prv, sizeof( mbedtls_x509_name ) );
        mbedtls_free( name_prv );
    }

    if( csr->raw.p != NULL )
    {
        mbedtls_platform_zeroize( csr->raw.p, csr->raw.len );
        mbedtls_free( csr->raw.p );
    }

    mbedtls_platform_zeroize( csr, sizeof( mbedtls_x509_csr ) );
}

#endif /* MBEDTLS_X509_CSR_PARSE_C */
/*
 *  X.509 base functions for creating certificates / CSRs
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CREATE_C)

#include "mbedtls/x509.h"
#include "mbedtls/x509_internal.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"

#include <string.h>

/* Structure linking OIDs for X.509 DN AttributeTypes to their
 * string representations and default string encodings used by Mbed TLS. */
typedef struct {
   const char *name; /* String representation of AttributeType, e.g.
                      * "CN" or "emailAddress". */
   size_t name_len;  /* Length of 'name', without trailing 0 byte. */
   const char *oid;  /* String representation of OID of AttributeType,
                      * as per RFC 5280, Appendix A.1. */
   int default_tag;  /* The default character encoding used for the
                      * given attribute type, e.g.
                      * MBEDTLS_ASN1_UTF8_STRING for UTF-8. */
} x509_attr_descriptor_t;

#define ADD_STRLEN( s )     s, sizeof( s ) - 1

/* X.509 DN attributes from RFC 5280, Appendix A.1. */
static const x509_attr_descriptor_t x509_attrs[] =
{
    { ADD_STRLEN( "CN" ),
      MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "commonName" ),
      MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "C" ),
      MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "countryName" ),
      MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "O" ),
      MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "organizationName" ),
      MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "L" ),
      MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "locality" ),
      MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "R" ),
      MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN( "OU" ),
      MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "organizationalUnitName" ),
      MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "ST" ),
      MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "stateOrProvinceName" ),
      MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "emailAddress" ),
      MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN( "serialNumber" ),
      MBEDTLS_OID_AT_SERIAL_NUMBER, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "postalAddress" ),
      MBEDTLS_OID_AT_POSTAL_ADDRESS, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "postalCode" ),
      MBEDTLS_OID_AT_POSTAL_CODE, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "dnQualifier" ),
      MBEDTLS_OID_AT_DN_QUALIFIER, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "title" ),
      MBEDTLS_OID_AT_TITLE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "surName" ),
      MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "SN" ),
      MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "givenName" ),
      MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "GN" ),
      MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "initials" ),
      MBEDTLS_OID_AT_INITIALS, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "pseudonym" ),
      MBEDTLS_OID_AT_PSEUDONYM, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "generationQualifier" ),
      MBEDTLS_OID_AT_GENERATION_QUALIFIER, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "domainComponent" ),
      MBEDTLS_OID_DOMAIN_COMPONENT, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN( "DC" ),
      MBEDTLS_OID_DOMAIN_COMPONENT,   MBEDTLS_ASN1_IA5_STRING },
    { NULL, 0, NULL, MBEDTLS_ASN1_NULL }
};

static const x509_attr_descriptor_t *x509_attr_descr_from_name( const char *name, size_t name_len )
{
    const x509_attr_descriptor_t *cur;

    for( cur = x509_attrs; cur->name != NULL; cur++ )
        if( cur->name_len == name_len &&
            strncmp( cur->name, name, name_len ) == 0 )
            break;

    if ( cur->name == NULL )
        return( NULL );

    return( cur );
}

static int mbedtls_x509_string_to_names( mbedtls_asn1_named_data **head, const char *name )
{
    int ret = 0;
    const char *s = name, *c = s;
    const char *end = s + strlen( s );
    const char *oid = NULL;
    const x509_attr_descriptor_t* attr_descr = NULL;
    int in_tag = 1;
    char data[MBEDTLS_X509_MAX_DN_NAME_SIZE];
    char *d = data;

    /* Clear existing chain if present */
    mbedtls_asn1_free_named_data_list( head );

    while( c <= end )
    {
        if( in_tag && *c == '=' )
        {
            if( ( attr_descr = x509_attr_descr_from_name( s, c - s ) ) == NULL )
            {
                ret = MBEDTLS_ERR_X509_UNKNOWN_OID;
                goto exit;
            }

            oid = attr_descr->oid;
            s = c + 1;
            in_tag = 0;
            d = data;
        }

        if( !in_tag && *c == '\\' && c != end )
        {
            c++;

            /* Check for valid escaped characters */
            if( c == end || *c != ',' )
            {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        }
        else if( !in_tag && ( *c == ',' || c == end ) )
        {
            mbedtls_asn1_named_data* cur =
                mbedtls_asn1_store_named_data( head, oid, strlen( oid ),
                                               (unsigned char *) data,
                                               d - data );

            if(cur == NULL )
            {
                return( MBEDTLS_ERR_X509_ALLOC_FAILED );
            }

            // set tagType
            cur->val.tag = attr_descr->default_tag;

            while( c < end && *(c + 1) == ' ' )
                c++;

            s = c + 1;
            in_tag = 1;
        }

        if( !in_tag && s != c + 1 )
        {
            *(d++) = *c;

            if( d - data == MBEDTLS_X509_MAX_DN_NAME_SIZE )
            {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        }

        c++;
    }

exit:

    return( ret );
}

/* The first byte of the value in the mbedtls_asn1_named_data structure is reserved
 * to store the critical boolean for us
 */
static int mbedtls_x509_set_extension( mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                        int critical, const unsigned char *val, size_t val_len )
{
    mbedtls_asn1_named_data *cur;

    if( ( cur = mbedtls_asn1_store_named_data( head, oid, oid_len,
                                       NULL, val_len + 1 ) ) == NULL )
    {
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );
    }

    cur->val.p[0] = critical;
    mbedtls_platform_memcpy( cur->val.p + 1, val, val_len );

    return( 0 );
}

/*
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
static int x509_write_name( unsigned char **p, unsigned char *start, mbedtls_asn1_named_data* cur_name)
{
    int ret;
    size_t len = 0;
    const char *oid             = (const char*)cur_name->oid.p;
    size_t oid_len              = cur_name->oid.len;
    const unsigned char *name   = cur_name->val.p;
    size_t name_len             = cur_name->val.len;

    // Write correct string tag and value
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tagged_string( p, start,
                                                       cur_name->val.tag,
                                                       (const char *) name,
                                                       name_len ) );
    // Write OID
    //
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( p, start, oid,
                                                       oid_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                                                    MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                                                 MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SET ) );

    return( (int) len );
}

int mbedtls_x509_write_names( unsigned char **p, unsigned char *start,
                              mbedtls_asn1_named_data *first )
{
    int ret;
    size_t len = 0;
    mbedtls_asn1_named_data *cur = first;

    while( cur != NULL )
    {
        MBEDTLS_ASN1_CHK_ADD( len, x509_write_name( p, start, cur ) );
        cur = cur->next;
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

static int mbedtls_x509_write_sig( unsigned char **p, unsigned char *start,
                    const char *oid, size_t oid_len,
                    unsigned char *sig, size_t size )
{
    int ret;
    size_t len = 0;

    if( *p < start || (size_t)( *p - start ) < size )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    len = size;
    (*p) -= len;
    mbedtls_platform_memcpy( *p, sig, len );

    if( *p - start < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_BIT_STRING ) );

    // Write OID
    //
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, oid,
                                                        oid_len, 0 ) );

    return( (int) len );
}

static int x509_write_extension( unsigned char **p, unsigned char *start,
                                 mbedtls_asn1_named_data *ext )
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start, ext->val.p + 1,
                                              ext->val.len - 1 ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, ext->val.len - 1 ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );

    if( ext->val.p[0] != 0 )
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_bool( p, start, 1 ) );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start, ext->oid.p,
                                              ext->oid.len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, ext->oid.len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OID ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

/*
 * Extension  ::=  SEQUENCE  {
 *     extnID      OBJECT IDENTIFIER,
 *     critical    BOOLEAN DEFAULT FALSE,
 *     extnValue   OCTET STRING
 *                 -- contains the DER encoding of an ASN.1 value
 *                 -- corresponding to the extension type identified
 *                 -- by extnID
 *     }
 */
static int mbedtls_x509_write_extensions( unsigned char **p, unsigned char *start,
                           mbedtls_asn1_named_data *first )
{
    int ret;
    size_t len = 0;
    mbedtls_asn1_named_data *cur_ext = first;

    while( cur_ext != NULL )
    {
        MBEDTLS_ASN1_CHK_ADD( len, x509_write_extension( p, start, cur_ext ) );
        cur_ext = cur_ext->next;
    }

    return( (int) len );
}

#endif /* MBEDTLS_X509_CREATE_C */
/*
 *  X.509 certificate writing
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 * References:
 * - certificates: RFC 5280, updated by RFC 6818
 * - CSRs: PKCS#10 v1.7 aka RFC 2986
 * - attributes: PKCS#9 v2.0 aka RFC 2985
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CRT_WRITE_C)

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/sha1.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"
#endif /* MBEDTLS_PEM_WRITE_C */

/*
 * For the currently used signature algorithms the buffer to store any signature
 * must be at least of size MAX(MBEDTLS_ECDSA_MAX_LEN, MBEDTLS_MPI_MAX_SIZE)
 */
#if MBEDTLS_ECDSA_MAX_LEN > MBEDTLS_MPI_MAX_SIZE
#define SIGNATURE_MAX_SIZE MBEDTLS_ECDSA_MAX_LEN
#else
#define SIGNATURE_MAX_SIZE MBEDTLS_MPI_MAX_SIZE
#endif

void mbedtls_x509write_crt_init( mbedtls_x509write_cert *ctx )
{
    mbedtls_platform_memset( ctx, 0, sizeof( mbedtls_x509write_cert ) );

    mbedtls_mpi_init( &ctx->serial );
    ctx->version = MBEDTLS_X509_CRT_VERSION_3;
}

void mbedtls_x509write_crt_free( mbedtls_x509write_cert *ctx )
{
    mbedtls_mpi_free( &ctx->serial );

    mbedtls_asn1_free_named_data_list( &ctx->subject );
    mbedtls_asn1_free_named_data_list( &ctx->issuer );
    mbedtls_asn1_free_named_data_list( &ctx->extensions );

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_x509write_cert ) );
}

void mbedtls_x509write_crt_set_version( mbedtls_x509write_cert *ctx, int version )
{
    ctx->version = version;
}

void mbedtls_x509write_crt_set_md_alg( mbedtls_x509write_cert *ctx, mbedtls_md_type_t md_alg )
{
    ctx->md_alg = md_alg;
}

void mbedtls_x509write_crt_set_subject_key( mbedtls_x509write_cert *ctx, mbedtls_pk_context *key )
{
    ctx->subject_key = key;
}

void mbedtls_x509write_crt_set_issuer_key( mbedtls_x509write_cert *ctx, mbedtls_pk_context *key )
{
    ctx->issuer_key = key;
}

int mbedtls_x509write_crt_set_subject_name( mbedtls_x509write_cert *ctx,
                                    const char *subject_name )
{
    return mbedtls_x509_string_to_names( &ctx->subject, subject_name );
}

int mbedtls_x509write_crt_set_issuer_name( mbedtls_x509write_cert *ctx,
                                   const char *issuer_name )
{
    return mbedtls_x509_string_to_names( &ctx->issuer, issuer_name );
}

int mbedtls_x509write_crt_set_serial( mbedtls_x509write_cert *ctx, const mbedtls_mpi *serial )
{
    int ret;

    if( ( ret = mbedtls_mpi_copy( &ctx->serial, serial ) ) != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_x509write_crt_set_validity( mbedtls_x509write_cert *ctx, const char *not_before,
                                const char *not_after )
{
    if( strlen( not_before ) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
        strlen( not_after )  != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 )
    {
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
    }
    strncpy( ctx->not_before, not_before, MBEDTLS_X509_RFC5280_UTC_TIME_LEN );
    strncpy( ctx->not_after , not_after , MBEDTLS_X509_RFC5280_UTC_TIME_LEN );
    ctx->not_before[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->not_after[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return( 0 );
}

int mbedtls_x509write_crt_set_extension( mbedtls_x509write_cert *ctx,
                                 const char *oid, size_t oid_len,
                                 int critical,
                                 const unsigned char *val, size_t val_len )
{
    return mbedtls_x509_set_extension( &ctx->extensions, oid, oid_len,
                               critical, val, val_len );
}

int mbedtls_x509write_crt_set_basic_constraints( mbedtls_x509write_cert *ctx,
                                         int is_ca, int max_pathlen )
{
    int ret;
    unsigned char buf[9];
    unsigned char *c = buf + sizeof(buf);
    size_t len = 0;

    mbedtls_platform_memset( buf, 0, sizeof(buf) );

    if( is_ca && max_pathlen > 127 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    if( is_ca )
    {
        if( max_pathlen >= 0 )
        {
            MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, max_pathlen ) );
        }
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_bool( &c, buf, 1 ) );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE ) );

    return mbedtls_x509write_crt_set_extension( ctx, MBEDTLS_OID_BASIC_CONSTRAINTS,
                                        MBEDTLS_OID_SIZE( MBEDTLS_OID_BASIC_CONSTRAINTS ),
                                        0, buf + sizeof(buf) - len, len );
}

#if defined(MBEDTLS_SHA1_C)
int mbedtls_x509write_crt_set_subject_key_identifier( mbedtls_x509write_cert *ctx )
{
    int ret;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE * 2 + 20]; /* tag, length + 2xMPI */
    unsigned char *c = buf + sizeof(buf);
    size_t len = 0;

    mbedtls_platform_memset( buf, 0, sizeof(buf) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_pk_write_pubkey( &c, buf, ctx->subject_key ) );

    ret = mbedtls_sha1_ret( buf + sizeof( buf ) - len, len,
                            buf + sizeof( buf ) - 20 );
    if( ret != 0 )
        return( ret );
    c = buf + sizeof( buf ) - 20;
    len = 20;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_OCTET_STRING ) );

    return mbedtls_x509write_crt_set_extension( ctx, MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER,
                                        MBEDTLS_OID_SIZE( MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER ),
                                        0, buf + sizeof(buf) - len, len );
}

int mbedtls_x509write_crt_set_authority_key_identifier( mbedtls_x509write_cert *ctx )
{
    int ret;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE * 2 + 20]; /* tag, length + 2xMPI */
    unsigned char *c = buf + sizeof( buf );
    size_t len = 0;

    mbedtls_platform_memset( buf, 0, sizeof(buf) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_pk_write_pubkey( &c, buf, ctx->issuer_key ) );

    ret = mbedtls_sha1_ret( buf + sizeof( buf ) - len, len,
                            buf + sizeof( buf ) - 20 );
    if( ret != 0 )
        return( ret );
    c = buf + sizeof( buf ) - 20;
    len = 20;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0 ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE ) );

    return mbedtls_x509write_crt_set_extension( ctx, MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER,
                                   MBEDTLS_OID_SIZE( MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER ),
                                   0, buf + sizeof( buf ) - len, len );
}
#endif /* MBEDTLS_SHA1_C */

static size_t crt_get_unused_bits_for_named_bitstring( unsigned char bitstring,
                                                       size_t bit_offset )
{
    size_t unused_bits;

     /* Count the unused bits removing trailing 0s */
    for( unused_bits = bit_offset; unused_bits < 8; unused_bits++ )
        if( ( ( bitstring >> unused_bits ) & 0x1 ) != 0 )
            break;

     return( unused_bits );
}

int mbedtls_x509write_crt_set_key_usage( mbedtls_x509write_cert *ctx,
                                         unsigned int key_usage )
{
    unsigned char buf[4], ku;
    unsigned char *c;
    int ret;
    size_t unused_bits;
    const unsigned int allowed_bits = MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
        MBEDTLS_X509_KU_NON_REPUDIATION   |
        MBEDTLS_X509_KU_KEY_ENCIPHERMENT  |
        MBEDTLS_X509_KU_DATA_ENCIPHERMENT |
        MBEDTLS_X509_KU_KEY_AGREEMENT     |
        MBEDTLS_X509_KU_KEY_CERT_SIGN     |
        MBEDTLS_X509_KU_CRL_SIGN;

    /* Check that nothing other than the allowed flags is set */
    if( ( key_usage & ~allowed_bits ) != 0 )
        return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );

    c = buf + 4;
    ku = (unsigned char)key_usage;
    unused_bits = crt_get_unused_bits_for_named_bitstring( ku, 1 );
    ret = mbedtls_asn1_write_bitstring( &c, buf, &ku, 8 - unused_bits );

    if( ret < 0 )
        return( ret );
    else if( ret < 3 || ret > 4 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    ret = mbedtls_x509write_crt_set_extension( ctx, MBEDTLS_OID_KEY_USAGE,
                                       MBEDTLS_OID_SIZE( MBEDTLS_OID_KEY_USAGE ),
                                       1, c, (size_t)ret );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_x509write_crt_set_ns_cert_type( mbedtls_x509write_cert *ctx,
                                    unsigned char ns_cert_type )
{
    unsigned char buf[4];
    unsigned char *c;
    size_t unused_bits;
    int ret;

    c = buf + 4;

    unused_bits = crt_get_unused_bits_for_named_bitstring( ns_cert_type, 0 );
    ret = mbedtls_asn1_write_bitstring( &c,
                                        buf,
                                        &ns_cert_type,
                                        8 - unused_bits );
    if( ret < 3 || ret > 4 )
        return( ret );

    ret = mbedtls_x509write_crt_set_extension( ctx, MBEDTLS_OID_NS_CERT_TYPE,
                                       MBEDTLS_OID_SIZE( MBEDTLS_OID_NS_CERT_TYPE ),
                                       0, c, (size_t)ret );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

static int x509_write_time( unsigned char **p, unsigned char *start,
                            const char *t, size_t size )
{
    int ret;
    size_t len = 0;

    /*
     * write MBEDTLS_ASN1_UTC_TIME if year < 2050 (2 bytes shorter)
     */
    if( t[0] == '2' && t[1] == '0' && t[2] < '5' )
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start,
                                             (const unsigned char *) t + 2,
                                             size - 2 ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_UTC_TIME ) );
    }
    else
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start,
                                                  (const unsigned char *) t,
                                                  size ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_GENERALIZED_TIME ) );
    }

    return( (int) len );
}

int mbedtls_x509write_crt_der( mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char hash[64];
    unsigned char sig[SIGNATURE_MAX_SIZE];
    unsigned char tmp_buf[2048];
    size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    mbedtls_pk_type_t pk_alg;

    /*
     * Prepare data to be signed in tmp_buf
     */
    c = tmp_buf + sizeof( tmp_buf );

    /* Signature algorithm needed in TBS, and later for actual signature */

    /* There's no direct way of extracting a signature algorithm
     * (represented as an element of mbedtls_pk_type_t) from a PK instance. */
    if( mbedtls_pk_can_do( ctx->issuer_key, MBEDTLS_PK_RSA ) )
        pk_alg = MBEDTLS_PK_RSA;
    else if( mbedtls_pk_can_do( ctx->issuer_key, MBEDTLS_PK_ECDSA ) )
        pk_alg = MBEDTLS_PK_ECDSA;
    else
        return( MBEDTLS_ERR_X509_INVALID_ALG );

    if( ( ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, ctx->md_alg,
                                          &sig_oid, &sig_oid_len ) ) != 0 )
    {
        return( ret );
    }

    /*
     *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */

    /* Only for v3 */
    if( ctx->version == MBEDTLS_X509_CRT_VERSION_3 )
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_extensions( &c, tmp_buf, ctx->extensions ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SEQUENCE ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                           MBEDTLS_ASN1_CONSTRUCTED | 3 ) );
    }

    /*
     *  SubjectPublicKeyInfo
     */
    MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_pk_write_pubkey_der( ctx->subject_key,
                                                tmp_buf, c - tmp_buf ) );
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_names( &c, tmp_buf, ctx->subject ) );

    /*
     *  Validity ::= SEQUENCE {
     *       notBefore      Time,
     *       notAfter       Time }
     */
    sub_len = 0;

    MBEDTLS_ASN1_CHK_ADD( sub_len, x509_write_time( &c, tmp_buf, ctx->not_after,
                                            MBEDTLS_X509_RFC5280_UTC_TIME_LEN ) );

    MBEDTLS_ASN1_CHK_ADD( sub_len, x509_write_time( &c, tmp_buf, ctx->not_before,
                                            MBEDTLS_X509_RFC5280_UTC_TIME_LEN ) );

    len += sub_len;
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, sub_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );

    /*
     *  Issuer  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_names( &c, tmp_buf, ctx->issuer ) );

    /*
     *  Signature   ::=  AlgorithmIdentifier
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, tmp_buf,
                       sig_oid, strlen( sig_oid ), 0 ) );

    /*
     *  Serial   ::=  INTEGER
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, tmp_buf, &ctx->serial ) );

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */

    /* Can be omitted for v1 */
    if( ctx->version != MBEDTLS_X509_CRT_VERSION_1 )
    {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_int( &c, tmp_buf, ctx->version ) );
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, sub_len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                           MBEDTLS_ASN1_CONSTRUCTED | 0 ) );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                       MBEDTLS_ASN1_SEQUENCE ) );

    /*
     * Make signature
     */
    if( ( ret = mbedtls_md( mbedtls_md_info_from_type( ctx->md_alg ), c,
                            len, hash ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_pk_sign( ctx->issuer_key, ctx->md_alg, hash, 0, sig, &sig_len,
                         f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    /*
     * Write data to output buffer
     */
    c2 = buf + size;
    MBEDTLS_ASN1_CHK_ADD( sig_and_oid_len, mbedtls_x509_write_sig( &c2, buf,
                                        sig_oid, sig_oid_len, sig, sig_len ) );

    if( len > (size_t)( c2 - buf ) )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    c2 -= len;
    mbedtls_platform_memcpy( c2, c, len );

    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c2, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c2, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

#if defined(MBEDTLS_PEM_WRITE_C)
int mbedtls_x509write_crt_pem( mbedtls_x509write_cert *crt, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    unsigned char output_buf[4096];
    size_t olen = 0;

    if( ( ret = mbedtls_x509write_crt_der( crt, output_buf, sizeof(output_buf),
                                   f_rng, p_rng ) ) < 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_CRT, PEM_END_CRT,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_X509_CRT_WRITE_C */
/*
 *  X.509 Certificate Signing Request writing
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 * References:
 * - CSRs: PKCS#10 v1.7 aka RFC 2986
 * - attributes: PKCS#9 v2.0 aka RFC 2985
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CSR_WRITE_C)

#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/platform_util.h"

#include <string.h>
#include <stdlib.h>

#if defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"
#endif

/*
 * For the currently used signature algorithms the buffer to store any signature
 * must be at least of size MAX(MBEDTLS_ECDSA_MAX_LEN, MBEDTLS_MPI_MAX_SIZE)
 */
#if MBEDTLS_ECDSA_MAX_LEN > MBEDTLS_MPI_MAX_SIZE
#define SIGNATURE_MAX_SIZE MBEDTLS_ECDSA_MAX_LEN
#else
#define SIGNATURE_MAX_SIZE MBEDTLS_MPI_MAX_SIZE
#endif

void mbedtls_x509write_csr_init( mbedtls_x509write_csr *ctx )
{
    mbedtls_platform_memset( ctx, 0, sizeof( mbedtls_x509write_csr ) );
}

void mbedtls_x509write_csr_free( mbedtls_x509write_csr *ctx )
{
    mbedtls_asn1_free_named_data_list( &ctx->subject );
    mbedtls_asn1_free_named_data_list( &ctx->extensions );

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_x509write_csr ) );
}

void mbedtls_x509write_csr_set_md_alg( mbedtls_x509write_csr *ctx, mbedtls_md_type_t md_alg )
{
    ctx->md_alg = md_alg;
}

void mbedtls_x509write_csr_set_key( mbedtls_x509write_csr *ctx, mbedtls_pk_context *key )
{
    ctx->key = key;
}

int mbedtls_x509write_csr_set_subject_name( mbedtls_x509write_csr *ctx,
                                    const char *subject_name )
{
    return mbedtls_x509_string_to_names( &ctx->subject, subject_name );
}

int mbedtls_x509write_csr_set_extension( mbedtls_x509write_csr *ctx,
                                 const char *oid, size_t oid_len,
                                 const unsigned char *val, size_t val_len )
{
    return mbedtls_x509_set_extension( &ctx->extensions, oid, oid_len,
                               0, val, val_len );
}

static size_t csr_get_unused_bits_for_named_bitstring( unsigned char bitstring,
                                                       size_t bit_offset )
{
    size_t unused_bits;

     /* Count the unused bits removing trailing 0s */
    for( unused_bits = bit_offset; unused_bits < 8; unused_bits++ )
        if( ( ( bitstring >> unused_bits ) & 0x1 ) != 0 )
            break;

     return( unused_bits );
}

int mbedtls_x509write_csr_set_key_usage( mbedtls_x509write_csr *ctx, unsigned char key_usage )
{
    unsigned char buf[4];
    unsigned char *c;
    size_t unused_bits;
    int ret;

    c = buf + 4;

    unused_bits = csr_get_unused_bits_for_named_bitstring( key_usage, 0 );
    ret = mbedtls_asn1_write_bitstring( &c, buf, &key_usage, 8 - unused_bits );

    if( ret < 0 )
        return( ret );
    else if( ret < 3 || ret > 4 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    ret = mbedtls_x509write_csr_set_extension( ctx, MBEDTLS_OID_KEY_USAGE,
                                       MBEDTLS_OID_SIZE( MBEDTLS_OID_KEY_USAGE ),
                                       c, (size_t)ret );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_x509write_csr_set_ns_cert_type( mbedtls_x509write_csr *ctx,
                                    unsigned char ns_cert_type )
{
    unsigned char buf[4];
    unsigned char *c;
    size_t unused_bits;
    int ret;

    c = buf + 4;

    unused_bits = csr_get_unused_bits_for_named_bitstring( ns_cert_type, 0 );
    ret = mbedtls_asn1_write_bitstring( &c,
                                        buf,
                                        &ns_cert_type,
                                        8 - unused_bits );

    if( ret < 0 )
        return( ret );
    else if( ret < 3 || ret > 4 )
        return( ret );

    ret = mbedtls_x509write_csr_set_extension( ctx, MBEDTLS_OID_NS_CERT_TYPE,
                                       MBEDTLS_OID_SIZE( MBEDTLS_OID_NS_CERT_TYPE ),
                                       c, (size_t)ret );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_x509write_csr_der( mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char hash[64];
    unsigned char sig[SIGNATURE_MAX_SIZE];
    unsigned char tmp_buf[2048];
    size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    mbedtls_pk_type_t pk_alg;

    /*
     * Prepare data to be signed in tmp_buf
     */
    c = tmp_buf + sizeof( tmp_buf );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_extensions( &c, tmp_buf, ctx->extensions ) );

    if( len )
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                        MBEDTLS_ASN1_SEQUENCE ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                        MBEDTLS_ASN1_SET ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( &c, tmp_buf, MBEDTLS_OID_PKCS9_CSR_EXT_REQ,
                                          MBEDTLS_OID_SIZE( MBEDTLS_OID_PKCS9_CSR_EXT_REQ ) ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                        MBEDTLS_ASN1_SEQUENCE ) );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC ) );

    MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_pk_write_pubkey_der( ctx->key,
                                                tmp_buf, c - tmp_buf ) );
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_names( &c, tmp_buf, ctx->subject ) );

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, tmp_buf, 0 ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );

    /*
     * Prepare signature
     */
    mbedtls_md( mbedtls_md_info_from_type( ctx->md_alg ), c, len, hash );

    if( ( ret = mbedtls_pk_sign( ctx->key, ctx->md_alg, hash, 0, sig, &sig_len,
                                 f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    if( mbedtls_pk_can_do( ctx->key, MBEDTLS_PK_RSA ) )
        pk_alg = MBEDTLS_PK_RSA;
    else if( mbedtls_pk_can_do( ctx->key, MBEDTLS_PK_ECDSA ) )
        pk_alg = MBEDTLS_PK_ECDSA;
    else
        return( MBEDTLS_ERR_X509_INVALID_ALG );

    if( ( ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, ctx->md_alg,
                                                &sig_oid, &sig_oid_len ) ) != 0 )
    {
        return( ret );
    }

    /*
     * Write data to output buffer
     */
    c2 = buf + size;
    MBEDTLS_ASN1_CHK_ADD( sig_and_oid_len, mbedtls_x509_write_sig( &c2, buf,
                                        sig_oid, sig_oid_len, sig, sig_len ) );

    if( len > (size_t)( c2 - buf ) )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    c2 -= len;
    mbedtls_platform_memcpy( c2, c, len );

    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c2, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c2, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

#define PEM_BEGIN_CSR           "-----BEGIN CERTIFICATE REQUEST-----\n"
#define PEM_END_CSR             "-----END CERTIFICATE REQUEST-----\n"

#if defined(MBEDTLS_PEM_WRITE_C)
int mbedtls_x509write_csr_pem( mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    unsigned char output_buf[4096];
    size_t olen = 0;

    if( ( ret = mbedtls_x509write_csr_der( ctx, output_buf, sizeof(output_buf),
                                   f_rng, p_rng ) ) < 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_CSR, PEM_END_CSR,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_X509_CSR_WRITE_C */
#endif


#include <stdio.h>
#include <string.h>

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free      free
#define mbedtls_calloc    calloc
#define mbedtls_printf    printf
#define mbedtls_snprintf  snprintf
#endif

#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif
#if defined(MBEDTLS_HAVE_TIME_DATE)
#include "mbedtls/platform_util.h"
#include <time.h>
#endif

#define CHECK(code) if( ( ret = ( code ) ) != 0 ){ return( ret ); }
#define CHECK_RANGE(min, max, val)                      \
    do                                                  \
    {                                                   \
        if( ( val ) < ( min ) || ( val ) > ( max ) )    \
        {                                               \
            return( ret );                              \
        }                                               \
    } while( 0 )

/*
 *  CertificateSerialNumber  ::=  INTEGER
 */
static int mbedtls_x509_get_serial( unsigned char **p, const unsigned char *end,
                     mbedtls_x509_buf *serial )
{
    int ret;

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_SERIAL +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    if( **p != ( MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_PRIMITIVE | 2 ) &&
        **p !=   MBEDTLS_ASN1_INTEGER )
        return( MBEDTLS_ERR_X509_INVALID_SERIAL +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    serial->tag = *(*p)++;

    if( ( ret = mbedtls_asn1_get_len( p, end, &serial->len ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_SERIAL + ret );

    serial->p = *p;
    *p += serial->len;

    return( 0 );
}

#if defined(MBEDTLS_X509_CRL_PARSE_C) || defined(MBEDTLS_X509_CSR_PARSE_C) || \
    ( !defined(MBEDTLS_X509_ON_DEMAND_PARSING) && defined(MBEDTLS_X509_CRT_PARSE_C) )
/*
 * Parse an algorithm identifier with (optional) parameters
 */
static int mbedtls_x509_get_alg( unsigned char **p, const unsigned char *end,
                  mbedtls_x509_buf *alg, mbedtls_x509_buf *params )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_alg( p, end, alg, params ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    return( 0 );
}
#endif /* defined(MBEDTLS_X509_CRL_PARSE_C) || defined(MBEDTLS_X509_CSR_PARSE_C) ||
         ( !defined(MBEDTLS_X509_ON_DEMAND_PARSING) && defined(MBEDTLS_X509_CRT_PARSE_C) ) */

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
/* Get an algorithm identifier without parameters (eg for signatures)
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static int mbedtls_x509_get_alg_null( unsigned char **p, const unsigned char *end,
                       mbedtls_x509_buf *alg )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_alg_null( p, end, alg ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    return( 0 );
}

/*
 * HashAlgorithm ::= AlgorithmIdentifier
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *
 * For HashAlgorithm, parameters MUST be NULL or absent.
 */
static int x509_get_hash_alg( const mbedtls_x509_buf *alg, mbedtls_md_type_t *md_alg )
{
    int ret;
    unsigned char *p;
    const unsigned char *end;
    mbedtls_x509_buf md_oid;
    size_t len;

    /* Make sure we got a SEQUENCE and setup bounds */
    if( alg->tag != ( MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) )
        return( MBEDTLS_ERR_X509_INVALID_ALG +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    p = (unsigned char *) alg->p;
    end = p + alg->len;

    if( p >= end )
        return( MBEDTLS_ERR_X509_INVALID_ALG +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    /* Parse md_oid */
    md_oid.tag = *p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &md_oid.len, MBEDTLS_ASN1_OID ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    md_oid.p = p;
    p += md_oid.len;

    /* Get md_alg from md_oid */
    if( ( ret = mbedtls_oid_get_md_alg( &md_oid, md_alg ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    /* Make sure params is absent of NULL */
    if( p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_NULL ) ) != 0 || len != 0 )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    if( p != end )
        return( MBEDTLS_ERR_X509_INVALID_ALG +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 *    RSASSA-PSS-params  ::=  SEQUENCE  {
 *       hashAlgorithm     [0] HashAlgorithm DEFAULT sha1Identifier,
 *       maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
 *       saltLength        [2] INTEGER DEFAULT 20,
 *       trailerField      [3] INTEGER DEFAULT 1  }
 *    -- Note that the tags in this Sequence are explicit.
 *
 * RFC 4055 (which defines use of RSASSA-PSS in PKIX) states that the value
 * of trailerField MUST be 1, and PKCS#1 v2.2 doesn't even define any other
 * option. Enfore this at parsing time.
 */
static int mbedtls_x509_get_rsassa_pss_params( const mbedtls_x509_buf *params,
                                mbedtls_md_type_t *md_alg, mbedtls_md_type_t *mgf_md,
                                int *salt_len )
{
    int ret;
    unsigned char *p;
    const unsigned char *end, *end2;
    size_t len;
    mbedtls_x509_buf alg_id, alg_params;

    /* First set everything to defaults */
    *md_alg = MBEDTLS_MD_SHA1;
    *mgf_md = MBEDTLS_MD_SHA1;
    *salt_len = 20;

    /* Make sure params is a SEQUENCE and setup bounds */
    if( params->tag != ( MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) )
        return( MBEDTLS_ERR_X509_INVALID_ALG +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    p = (unsigned char *) params->p;
    end = p + params->len;

    if( p == end )
        return( 0 );

    /*
     * HashAlgorithm
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) == 0 )
    {
        end2 = p + len;

        /* HashAlgorithm ::= AlgorithmIdentifier (without parameters) */
        if( ( ret = mbedtls_x509_get_alg_null( &p, end2, &alg_id ) ) != 0 )
            return( ret );

        if( ( ret = mbedtls_oid_get_md_alg( &alg_id, md_alg ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

        if( p != end2 )
            return( MBEDTLS_ERR_X509_INVALID_ALG +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    else if( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    if( p == end )
        return( 0 );

    /*
     * MaskGenAlgorithm
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) ) == 0 )
    {
        end2 = p + len;

        /* MaskGenAlgorithm ::= AlgorithmIdentifier (params = HashAlgorithm) */
        if( ( ret = mbedtls_x509_get_alg( &p, end2, &alg_id, &alg_params ) ) != 0 )
            return( ret );

        /* Only MFG1 is recognised for now */
        if( MBEDTLS_OID_CMP( MBEDTLS_OID_MGF1, &alg_id ) != 0 )
            return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE +
                    MBEDTLS_ERR_OID_NOT_FOUND );

        /* Parse HashAlgorithm */
        if( ( ret = x509_get_hash_alg( &alg_params, mgf_md ) ) != 0 )
            return( ret );

        if( p != end2 )
            return( MBEDTLS_ERR_X509_INVALID_ALG +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    else if( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    if( p == end )
        return( 0 );

    /*
     * salt_len
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 2 ) ) == 0 )
    {
        end2 = p + len;

        if( ( ret = mbedtls_asn1_get_int( &p, end2, salt_len ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

        if( p != end2 )
            return( MBEDTLS_ERR_X509_INVALID_ALG +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    else if( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    if( p == end )
        return( 0 );

    /*
     * trailer_field (if present, must be 1)
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 3 ) ) == 0 )
    {
        int trailer_field;

        end2 = p + len;

        if( ( ret = mbedtls_asn1_get_int( &p, end2, &trailer_field ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

        if( p != end2 )
            return( MBEDTLS_ERR_X509_INVALID_ALG +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

        if( trailer_field != 1 )
            return( MBEDTLS_ERR_X509_INVALID_ALG );
    }
    else if( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    if( p != end )
        return( MBEDTLS_ERR_X509_INVALID_ALG +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

/*
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 *
 *  NOTE: This function returns an ASN.1 low-level error code.
 */
static int x509_get_attr_type_value( unsigned char **p,
                                     const unsigned char *end,
                                     mbedtls_x509_buf *oid,
                                     mbedtls_x509_buf *val )
{
    int ret;
    size_t len;

    ret = mbedtls_asn1_get_tag( p, end, &len,
                                MBEDTLS_ASN1_CONSTRUCTED |
                                MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        goto exit;

    end = *p + len;

    ret = mbedtls_asn1_get_tag( p, end, &oid->len, MBEDTLS_ASN1_OID );
    if( ret != 0 )
        goto exit;

    oid->tag = MBEDTLS_ASN1_OID;
    oid->p = *p;
    *p += oid->len;

    if( *p == end )
    {
        ret = MBEDTLS_ERR_ASN1_OUT_OF_DATA;
        goto exit;
    }

    if( !MBEDTLS_ASN1_IS_STRING_TAG( **p ) )
    {
        ret = MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
        goto exit;
    }

    val->tag = *(*p)++;

    ret = mbedtls_asn1_get_len( p, end, &val->len );
    if( ret != 0 )
        goto exit;

    val->p = *p;
    *p += val->len;

    if( *p != end )
        ret = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

exit:
    return( ret );
}

/*
 *  Name ::= CHOICE { -- only one possibility for now --
 *       rdnSequence  RDNSequence }
 *
 *  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 *
 * The data structure is optimized for the common case where each RDN has only
 * one element, which is represented as a list of AttributeTypeAndValue.
 * For the general case we still use a flat list, but we mark elements of the
 * same set so that they are "merged" together in the functions that consume
 * this list, eg mbedtls_x509_dn_gets().
 *
 * NOTE: This function returns an ASN.1 low-level error code.
 */
static int x509_set_sequence_iterate( unsigned char **p,
                                      unsigned char const **end_set,
                                      unsigned char const *end,
                                      mbedtls_x509_buf *oid,
                                      mbedtls_x509_buf *val )
{
    int ret;
    size_t set_len;

    if( *p == *end_set )
    {
        /* Parse next TLV of ASN.1 SET structure. */
        ret = mbedtls_asn1_get_tag( p, end, &set_len,
                                    MBEDTLS_ASN1_CONSTRUCTED |
                                    MBEDTLS_ASN1_SET );
        if( ret != 0 )
            goto exit;

        *end_set = *p + set_len;
    }

    /* x509_get_attr_type_value() returns ASN.1 low-level error codes. */
    ret = x509_get_attr_type_value( p, *end_set, oid, val );

exit:
    return( ret );
}

/*
 * Like memcmp, but case-insensitive and always returns -1 if different
 */
static int mbedtls_x509_memcasecmp( const void *s1, const void *s2,
                             size_t len1, size_t len2 )
{
    size_t i;
    unsigned char diff;
    const unsigned char *n1 = s1, *n2 = s2;

    if( len1 != len2 )
        return( -1 );

    for( i = 0; i < len1; i++ )
    {
        diff = n1[i] ^ n2[i];

        if( diff == 0 )
            continue;

        if( diff == 32 &&
            ( ( n1[i] >= 'a' && n1[i] <= 'z' ) ||
              ( n1[i] >= 'A' && n1[i] <= 'Z' ) ) )
        {
            continue;
        }

        return( -1 );
    }

    return( 0 );
}

/*
 * Compare two X.509 strings, case-insensitive, and allowing for some encoding
 * variations (but not all).
 *
 * Return 0 if equal, -1 otherwise.
 */
static int x509_string_cmp( const mbedtls_x509_buf *a,
                            const mbedtls_x509_buf *b )
{
    if( a->tag == b->tag &&
        a->len == b->len &&
        mbedtls_platform_memcmp( a->p, b->p, b->len ) == 0 )
    {
        return( 0 );
    }

    if( ( a->tag == MBEDTLS_ASN1_UTF8_STRING || a->tag == MBEDTLS_ASN1_PRINTABLE_STRING ) &&
        ( b->tag == MBEDTLS_ASN1_UTF8_STRING || b->tag == MBEDTLS_ASN1_PRINTABLE_STRING ) &&
        mbedtls_x509_memcasecmp( a->p, b->p,
                                 a->len, b->len ) == 0 )
    {
        return( 0 );
    }

    return( -1 );
}

/*
 * Compare two X.509 Names (aka rdnSequence) given as raw ASN.1 data.
 *
 * See RFC 5280 section 7.1, though we don't implement the whole algorithm:
 * We sometimes return unequal when the full algorithm would return equal,
 * but never the other way. (In particular, we don't do Unicode normalisation
 * or space folding.)
 *
 * Further, this function allows to pass a callback to be triggered for every
 * pair of well-formed and equal entries in the two input name lists.
 *
 * Returns:
 * - 0 if both sequences are well-formed, present the same X.509 name,
 *   and the callback (if provided) hasn't returned a non-zero value
 *   on any of the name components.
 * - 1 if a difference was detected in the name components.
 * - A non-zero error code if the abort callback returns a non-zero value.
 *   In this case, the returned error code is the error code from the callback.
 * - A negative error code if a parsing error occurred in either
 *   of the two buffers.
 *
 * This function can be used to verify that a buffer contains a well-formed
 * ASN.1 encoded X.509 name by calling it with equal parameters.
 */
static int mbedtls_x509_name_cmp_raw( mbedtls_x509_buf_raw const *a,
                               mbedtls_x509_buf_raw const *b,
                               int (*abort_check)( void *ctx,
                                                   mbedtls_x509_buf *oid,
                                                   mbedtls_x509_buf *val,
                                                   int next_merged ),
                               void *abort_check_ctx )
{
    int ret;
    size_t idx;
    unsigned char *p[2], *end[2], *set[2];

    p[0] = a->p;
    p[1] = b->p;
    end[0] = p[0] + a->len;
    end[1] = p[1] + b->len;

    for( idx = 0; idx < 2; idx++ )
    {
        size_t len;
        ret = mbedtls_asn1_get_tag( &p[idx], end[idx], &len,
                                    MBEDTLS_ASN1_CONSTRUCTED |
                                    MBEDTLS_ASN1_SEQUENCE );

        if( end[idx] != p[idx] + len )
        {
            return( MBEDTLS_ERR_X509_INVALID_NAME +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        }

        set[idx] = p[idx];
    }

    while( 1 )
    {
        int next_merged;
        mbedtls_x509_buf oid[2], val[2];

        ret = x509_set_sequence_iterate( &p[0], (const unsigned char **) &set[0],
                                         end[0], &oid[0], &val[0] );
        if( ret != 0 )
            goto exit;

        ret = x509_set_sequence_iterate( &p[1], (const unsigned char **) &set[1],
                                         end[1], &oid[1], &val[1] );
        if( ret != 0 )
            goto exit;

        if( oid[0].len != oid[1].len ||
            mbedtls_platform_memcmp( oid[0].p, oid[1].p, oid[1].len ) != 0 )
        {
            return( 1 );
        }

        if( x509_string_cmp( &val[0], &val[1] ) != 0 )
            return( 1 );

        next_merged = ( set[0] != p[0] );
        if( next_merged != ( set[1] != p[1] ) )
            return( 1 );

        if( abort_check != NULL )
        {
            ret = abort_check( abort_check_ctx, &oid[0], &val[0],
                               next_merged );
            if( ret != 0 )
                return( ret );
        }

        if( p[0] == end[0] && p[1] == end[1] )
            break;
    }

exit:
    if( ret < 0 )
        ret += MBEDTLS_ERR_X509_INVALID_NAME;

    return( ret );
}

static int x509_get_name_cb( void *ctx,
                             mbedtls_x509_buf *oid,
                             mbedtls_x509_buf *val,
                             int next_merged )
{
    mbedtls_x509_name **cur_ptr = (mbedtls_x509_name**) ctx;
    mbedtls_x509_name *cur = *cur_ptr;

    if( cur->oid.p != NULL )
    {
        cur->next = mbedtls_calloc( 1, sizeof( mbedtls_x509_name ) );
        if( cur->next == NULL )
            return( MBEDTLS_ERR_ASN1_ALLOC_FAILED );

        cur = cur->next;
    }

    cur->oid = *oid;
    cur->val = *val;
    cur->next_merged = next_merged;

    *cur_ptr = cur;
    return( 0 );
}

static int mbedtls_x509_get_name( unsigned char *p,
                           size_t len,
                           mbedtls_x509_name *cur )
{
    mbedtls_x509_buf_raw name_buf = { p, len };
    mbedtls_platform_memset( cur, 0, sizeof( mbedtls_x509_name ) );
    return( mbedtls_x509_name_cmp_raw( &name_buf, &name_buf,
                                       x509_get_name_cb,
                                       &cur ) );
}

#if ( !defined(MBEDTLS_X509_CRT_REMOVE_TIME) && defined(MBEDTLS_X509_CRT_PARSE_C) ) || \
    defined(MBEDTLS_X509_CRL_PARSE_C)
static int x509_parse_int( unsigned char **p, size_t n, int *res )
{
    *res = 0;

    for( ; n > 0; --n )
    {
        if( ( **p < '0') || ( **p > '9' ) )
            return ( MBEDTLS_ERR_X509_INVALID_DATE );

        *res *= 10;
        *res += ( *(*p)++ - '0' );
    }

    return( 0 );
}

static int x509_date_is_valid(const mbedtls_x509_time *t )
{
    int ret = MBEDTLS_ERR_X509_INVALID_DATE;
    int month_len;

    CHECK_RANGE( 0, 9999, t->year );
    CHECK_RANGE( 0, 23,   t->hour );
    CHECK_RANGE( 0, 59,   t->min  );
    CHECK_RANGE( 0, 59,   t->sec  );

    switch( t->mon )
    {
        case 1: case 3: case 5: case 7: case 8: case 10: case 12:
            month_len = 31;
            break;
        case 4: case 6: case 9: case 11:
            month_len = 30;
            break;
        case 2:
            if( ( !( t->year % 4 ) && t->year % 100 ) ||
                !( t->year % 400 ) )
                month_len = 29;
            else
                month_len = 28;
            break;
        default:
            return( ret );
    }
    CHECK_RANGE( 1, month_len, t->day );

    return( 0 );
}

/*
 * Parse an ASN1_UTC_TIME (yearlen=2) or ASN1_GENERALIZED_TIME (yearlen=4)
 * field.
 */
static int x509_parse_time( unsigned char **p, size_t len, size_t yearlen,
                            mbedtls_x509_time *tm )
{
    int ret;

    /*
     * Minimum length is 10 or 12 depending on yearlen
     */
    if ( len < yearlen + 8 )
        return ( MBEDTLS_ERR_X509_INVALID_DATE );
    len -= yearlen + 8;

    /*
     * Parse year, month, day, hour, minute
     */
    CHECK( x509_parse_int( p, yearlen, &tm->year ) );
    if ( 2 == yearlen )
    {
        if ( tm->year < 50 )
            tm->year += 100;

        tm->year += 1900;
    }

    CHECK( x509_parse_int( p, 2, &tm->mon ) );
    CHECK( x509_parse_int( p, 2, &tm->day ) );
    CHECK( x509_parse_int( p, 2, &tm->hour ) );
    CHECK( x509_parse_int( p, 2, &tm->min ) );

    /*
     * Parse seconds if present
     */
    if ( len >= 2 )
    {
        CHECK( x509_parse_int( p, 2, &tm->sec ) );
        len -= 2;
    }
    else
        return ( MBEDTLS_ERR_X509_INVALID_DATE );

    /*
     * Parse trailing 'Z' if present
     */
    if ( 1 == len && 'Z' == **p )
    {
        (*p)++;
        len--;
    }

    /*
     * We should have parsed all characters at this point
     */
    if ( 0 != len )
        return ( MBEDTLS_ERR_X509_INVALID_DATE );

    CHECK( x509_date_is_valid( tm ) );

    return ( 0 );
}

/*
 *  Time ::= CHOICE {
 *       utcTime        UTCTime,
 *       generalTime    GeneralizedTime }
 */
static int mbedtls_x509_get_time( unsigned char **p, const unsigned char *end,
                           mbedtls_x509_time *tm )
{
    int ret;
    size_t len, year_len;
    unsigned char tag;

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_DATE +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    tag = **p;

    if( tag == MBEDTLS_ASN1_UTC_TIME )
        year_len = 2;
    else if( tag == MBEDTLS_ASN1_GENERALIZED_TIME )
        year_len = 4;
    else
        return( MBEDTLS_ERR_X509_INVALID_DATE +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    (*p)++;
    ret = mbedtls_asn1_get_len( p, end, &len );

    if( ret != 0 )
        return( MBEDTLS_ERR_X509_INVALID_DATE + ret );

    return x509_parse_time( p, len, year_len, tm );
}
#endif /* ( !defined(MBEDTLS_X509_CRT_REMOVE_TIME) && defined(MBEDTLS_X509_CRT_PARSE_C) ) ||
          defined(MBEDTLS_X509_CRL_PARSE_C) */

static int mbedtls_x509_get_sig( unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig )
{
    int ret;
    size_t len;
    int tag_type;

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_SIGNATURE +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    tag_type = **p;

    if( ( ret = mbedtls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_SIGNATURE + ret );

    sig->tag = tag_type;
    sig->len = len;
    sig->p = *p;

    *p += len;

    return( 0 );
}

static int mbedtls_x509_get_sig_alg_raw( unsigned char **p, unsigned char const *end,
                                  mbedtls_md_type_t *md_alg,
                                  mbedtls_pk_type_t *pk_alg,
                                  void **sig_opts )
{
    int ret;
    mbedtls_asn1_buf alg, params;
    ret = mbedtls_asn1_get_alg( p, end, &alg, &params );
    if( ret != 0 )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    return( mbedtls_x509_get_sig_alg( &alg, &params, md_alg,
                                      pk_alg, sig_opts ) );
}

/*
 * Get signature algorithm from alg OID and optional parameters
 */
static int mbedtls_x509_get_sig_alg( const mbedtls_x509_buf *sig_oid, const mbedtls_x509_buf *sig_params,
                      mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                      void **sig_opts )
{
    int ret;

    if( ( ret = mbedtls_oid_get_sig_alg( sig_oid, md_alg, pk_alg ) ) != 0 )
        return( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + ret );

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    if( *pk_alg == MBEDTLS_PK_RSASSA_PSS )
    {
        mbedtls_pk_rsassa_pss_options *pss_opts;

        pss_opts = mbedtls_calloc( 1, sizeof( mbedtls_pk_rsassa_pss_options ) );
        if( pss_opts == NULL )
            return( MBEDTLS_ERR_X509_ALLOC_FAILED );

        ret = mbedtls_x509_get_rsassa_pss_params( sig_params,
                                          md_alg,
                                          &pss_opts->mgf1_hash_id,
                                          &pss_opts->expected_salt_len );
        if( ret != 0 )
        {
            mbedtls_free( pss_opts );
            return( ret );
        }

        if( sig_opts != NULL )
            *sig_opts = (void *) pss_opts;
        else
            mbedtls_free( pss_opts );
    }
    else
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
    {
        /* Make sure parameters are absent or NULL */
        if( ( sig_params->tag != MBEDTLS_ASN1_NULL && sig_params->tag != 0 ) ||
              sig_params->len != 0 )
            return( MBEDTLS_ERR_X509_INVALID_ALG );

        if( sig_opts != NULL )
            *sig_opts = NULL;
    }

    return( 0 );
}

#if defined(MBEDTLS_X509_CRL_PARSE_C)
/*
 * X.509 Extensions (No parsing of extensions, pointer should
 * be either manually updated or extensions should be parsed!)
 */
static int mbedtls_x509_get_ext( unsigned char **p, const unsigned char *end,
                          mbedtls_x509_buf *ext, int tag )
{
    int ret;
    size_t len;

    /* Extension structure use EXPLICIT tagging. That is, the actual
     * `Extensions` structure is wrapped by a tag-length pair using
     * the respective context-specific tag. */
    ret = mbedtls_asn1_get_tag( p, end, &ext->len,
              MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag );
    if( ret != 0 )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

    ext->tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag;
    ext->p   = *p;
    end      = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

    if( end != *p + len )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}
#endif /* defined(MBEDTLS_X509_CRL_PARSE_C) */
/*
 * Store the name in printable form into buf; no more
 * than size characters will be written
 */
int mbedtls_x509_dn_gets( char *buf, size_t size, const mbedtls_x509_name *dn )
{
    int ret;
    size_t i, n;
    unsigned char c, merge = 0;
    const mbedtls_x509_name *name;
    const char *short_name = NULL;
    char s[MBEDTLS_X509_MAX_DN_NAME_SIZE], *p;

    memset( s, 0, sizeof( s ) );

    name = dn;
    p = buf;
    n = size;

    while( name != NULL )
    {
        if( !name->oid.p )
        {
            name = name->next;
            continue;
        }

        if( name != dn )
        {
            ret = mbedtls_snprintf( p, n, merge ? " + " : ", " );
            MBEDTLS_X509_SAFE_SNPRINTF;
        }

        ret = mbedtls_oid_get_attr_short_name( &name->oid, &short_name );

        if( ret == 0 )
            ret = mbedtls_snprintf( p, n, "%s=", short_name );
        else
            ret = mbedtls_snprintf( p, n, "\?\?=" );
        MBEDTLS_X509_SAFE_SNPRINTF;

        for( i = 0; i < name->val.len; i++ )
        {
            if( i >= sizeof( s ) - 1 )
                break;

            c = name->val.p[i];
            if( c < 32 || c == 127 || ( c > 128 && c < 160 ) )
                 s[i] = '?';
            else s[i] = c;
        }
        s[i] = '\0';
        ret = mbedtls_snprintf( p, n, "%s", s );
        MBEDTLS_X509_SAFE_SNPRINTF;

        merge = name->next_merged;
        name = name->next;
    }

    return( (int) ( size - n ) );
}

/*
 * Store the serial in printable form into buf; no more
 * than size characters will be written
 */
int mbedtls_x509_serial_gets( char *buf, size_t size, const mbedtls_x509_buf *serial )
{
    int ret;
    size_t i, n, nr;
    char *p;

    p = buf;
    n = size;

    nr = ( serial->len <= 32 )
        ? serial->len  : 28;

    for( i = 0; i < nr; i++ )
    {
        if( i == 0 && nr > 1 && serial->p[i] == 0x0 )
            continue;

        ret = mbedtls_snprintf( p, n, "%02X%s",
                serial->p[i], ( i < nr - 1 ) ? ":" : "" );
        MBEDTLS_X509_SAFE_SNPRINTF;
    }

    if( nr != serial->len )
    {
        ret = mbedtls_snprintf( p, n, "...." );
        MBEDTLS_X509_SAFE_SNPRINTF;
    }

    return( (int) ( size - n ) );
}

#if !defined(MBEDTLS_X509_REMOVE_INFO)
/*
 * Helper for writing signature algorithms
 */
static int mbedtls_x509_sig_alg_gets( char *buf, size_t size, mbedtls_pk_type_t pk_alg,
                               mbedtls_md_type_t md_alg, const void *sig_opts )
{
    int ret;
    char *p = buf;
    size_t n = size;
    const char *desc = NULL;
    mbedtls_x509_buf sig_oid;
    mbedtls_md_type_t tmp_md_alg = md_alg;

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    /* The hash for RSASSA is determined by the algorithm parameters;
     * in the OID list, the hash is set to MBEDTLS_MD_NONE. */
    if( pk_alg == MBEDTLS_PK_RSASSA_PSS )
        tmp_md_alg = MBEDTLS_MD_NONE;
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    sig_oid.tag = MBEDTLS_ASN1_OID;
    ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, tmp_md_alg,
                                          (const char**) &sig_oid.p,
                                          &sig_oid.len );
    if( ret == 0 &&
        mbedtls_oid_get_sig_alg_desc( &sig_oid, &desc ) == 0 )
    {
        ret = mbedtls_snprintf( p, n, "%s", desc );
    }
    else
        ret = mbedtls_snprintf( p, n, "???" );
    MBEDTLS_X509_SAFE_SNPRINTF;

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    if( pk_alg == MBEDTLS_PK_RSASSA_PSS )
    {
        const mbedtls_pk_rsassa_pss_options *pss_opts;
        mbedtls_md_handle_t md_info, mgf_md_info;

        pss_opts = (const mbedtls_pk_rsassa_pss_options *) sig_opts;

        md_info = mbedtls_md_info_from_type( md_alg );
        mgf_md_info = mbedtls_md_info_from_type( pss_opts->mgf1_hash_id );

        ret = mbedtls_snprintf( p, n, " (%s, MGF1-%s, 0x%02X)",
                              md_info ? mbedtls_md_get_name( md_info ) : "???",
                              mgf_md_info ? mbedtls_md_get_name( mgf_md_info ) : "???",
                              pss_opts->expected_salt_len );
        MBEDTLS_X509_SAFE_SNPRINTF;
    }
#else
    ((void) pk_alg);
    ((void) md_alg);
    ((void) sig_opts);
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    return( (int)( size - n ) );
}

/*
 * Helper for writing "RSA key size", "EC key size", etc
 */
static int mbedtls_x509_key_size_helper( char *buf, size_t buf_size, const char *name )
{
    char *p = buf;
    size_t n = buf_size;
    int ret;

    ret = mbedtls_snprintf( p, n, "%s key size", name );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( 0 );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */

#if defined(MBEDTLS_HAVE_TIME_DATE)
/*
 * Set the time structure to the current time.
 * Return 0 on success, non-zero on failure.
 */
static int x509_get_current_time( mbedtls_x509_time *now )
{
    struct tm *lt, tm_buf;
    mbedtls_time_t tt;
    int ret = 0;

    tt = mbedtls_time( NULL );
    lt = mbedtls_platform_gmtime_r( &tt, &tm_buf );

    if( lt == NULL )
        ret = -1;
    else
    {
        now->year = lt->tm_year + 1900;
        now->mon  = lt->tm_mon  + 1;
        now->day  = lt->tm_mday;
        now->hour = lt->tm_hour;
        now->min  = lt->tm_min;
        now->sec  = lt->tm_sec;
    }

    return( ret );
}

/*
 * Return 0 if before <= after, 1 otherwise
 */
static int x509_check_time( const mbedtls_x509_time *before, const mbedtls_x509_time *after )
{
    if( before->year  > after->year )
        return( 1 );

    if( before->year == after->year &&
        before->mon   > after->mon )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day   > after->day )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour  > after->hour )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min   > after->min  )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min  == after->min  &&
        before->sec   > after->sec  )
        return( 1 );

    return( 0 );
}

int mbedtls_x509_time_is_past( const mbedtls_x509_time *to )
{
    mbedtls_x509_time now;

    if( x509_get_current_time( &now ) != 0 )
        return( 1 );

    return( x509_check_time( &now, to ) );
}

int mbedtls_x509_time_is_future( const mbedtls_x509_time *from )
{
    mbedtls_x509_time now;

    if( x509_get_current_time( &now ) != 0 )
        return( 1 );

    return( x509_check_time( from, &now ) );
}
#endif  /* MBEDTLS_HAVE_TIME_DATE */

void mbedtls_x509_name_free( mbedtls_x509_name *name )
{
    while( name != NULL )
    {
        mbedtls_x509_name *next = name->next;
        mbedtls_platform_zeroize( name, sizeof( *name ) );
        mbedtls_free( name );
        name = next;
    }
}

#if defined(MBEDTLS_SELF_TEST)

#include "mbedtls/x509_crt.h"
#include "mbedtls/certs.h"

/*
 * Checkup routine
 */
int mbedtls_x509_self_test( int verbose )
{
    int ret = 0;
#if defined(MBEDTLS_CERTS_C) && defined(MBEDTLS_SHA256_C)
    uint32_t flags;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;

    if( verbose != 0 )
        mbedtls_printf( "  X.509 certificate load: " );

    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &clicert );

    ret = mbedtls_x509_crt_parse( &clicert, (const unsigned char *) mbedtls_test_cli_crt,
                           mbedtls_test_cli_crt_len );
    if( ret != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        goto cleanup;
    }

    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_ca_crt,
                          mbedtls_test_ca_crt_len );
    if( ret != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  X.509 signature verify: ");

    ret = mbedtls_x509_crt_verify( &clicert, &cacert, NULL,
#if !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
                                   NULL,
#endif /* !MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION */
                                   &flags
#if !defined(MBEDTLS_X509_REMOVE_VERIFY_CALLBACK)
                                   , NULL, NULL
#endif
                                   );

    if( ret != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n\n");

cleanup:
    mbedtls_x509_crt_free( &cacert  );
    mbedtls_x509_crt_free( &clicert );
#else
    ((void) verbose);
#endif /* MBEDTLS_CERTS_C && MBEDTLS_SHA1_C */
    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_X509_USE_C */
