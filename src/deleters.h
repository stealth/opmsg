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

#ifndef opmsg_deleters_h
#define opmsg_deleters_h

extern "C" {
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
}

#include <cstdio>

namespace opmsg {

extern "C" typedef void (*EVP_PKEY_del)(EVP_PKEY *);

extern "C" typedef void (*EVP_PKEY_CTX_del)(EVP_PKEY_CTX *);

extern "C" typedef void (*EVP_MD_CTX_del)(EVP_MD_CTX *);

extern "C" typedef void (*EVP_CIPHER_CTX_del)(EVP_CIPHER_CTX *);

extern "C" typedef void (*DH_del)(DH *);

extern "C" typedef void (*RSA_del)(RSA *);

extern "C" typedef int (*BIO_del)(BIO *);

extern "C" typedef void (*BIGNUM_del)(BIGNUM *);

extern "C" typedef void (*BN_CTX_del)(BN_CTX *);

extern "C" typedef void (*BN_GENCB_del)(BN_GENCB *);

extern "C" typedef void (*EC_GROUP_del)(EC_GROUP *);

extern "C" typedef void (*EC_KEY_del)(EC_KEY *);

extern "C" typedef void (*EC_POINT_del)(EC_POINT *);

extern "C" typedef int (*FILE_del)(FILE *);

extern "C" typedef void (*free_del)(void *);

extern "C" int ffclose(FILE *f);

}

#endif
