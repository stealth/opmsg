/*
 * This file is part of the opmsg crypto message framework.
 *
 * (C) 2015 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
 *
 * opmsg is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * opmsg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with opmsg.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef opmsg_missing_h
#define opmsg_missing_h



extern "C" {
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
}


#if OPENSSL_VERSION_NUMBER > 0x10100000L && !(defined HAVE_LIBRESSL)

/* Idiots... Not just they are renaming EVP_MD_CTX_destroy() to EVP_MD_CTX_free() in OpenSSL >= 1.1,
 * they define EVP_MD_CTX_destroy(ctx) macro along (with braces) so we cant define the symbol
 * ourself. Forces me to introduce an entirely new name to stay compatible with older
 * versions and libressl.
 */
#define EVP_MD_CTX_delete EVP_MD_CTX_free
#else
#define EVP_MD_CTX_delete EVP_MD_CTX_destroy
#endif


namespace opmsg {

#ifdef HAVE_BORINGSSL
BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *, point_conversion_form_t, BIGNUM *, BN_CTX *);

EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *, EC_POINT *, BN_CTX *);

int EVP_PKEY_base_id(const EVP_PKEY *pkey);
#endif

#if OPENSSL_VERSION_NUMBER <= 0x10100000L || defined HAVE_LIBRESSL || defined HAVE_BORINGSSL
void DH_get0_key(const DH *dh, BIGNUM **pub_key, BIGNUM **priv_key);

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
#endif

}

#endif

