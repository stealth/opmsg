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

#include <memory>

extern "C" {
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
}


#include <iostream>
namespace opmsg {

using namespace std;

#ifdef HAVE_BORINGSSL
BIGNUM *EC_POINT_point2bn(const EC_GROUP *grp, const EC_POINT *pnt, point_conversion_form_t form, BIGNUM *ret, BN_CTX *ctx)
{
	size_t blen = 0;

	if ((blen = EC_POINT_point2oct(grp, pnt, form, nullptr, 0, ctx)) == 0)
		return nullptr;

	unique_ptr<unsigned char[]> buf(new (nothrow) unsigned char[blen]);
	if (!buf.get())
		return nullptr;

	if (!EC_POINT_point2oct(grp, pnt, form, buf.get(), blen, ctx))
		return nullptr;
	ret = BN_bin2bn(buf.get(), blen, ret);

	return ret;
}


EC_POINT *EC_POINT_bn2point(const EC_GROUP *grp, const BIGNUM *bn, EC_POINT *pnt, BN_CTX *ctx)
{
	size_t blen = 0;
	EC_POINT *ret = nullptr;

	if ((blen = BN_num_bytes(bn)) == 0)
		return nullptr;
	unique_ptr<unsigned char[]> buf(new (nothrow) unsigned char[blen]);
	if (!buf.get())
		return nullptr;

	if (!BN_bn2bin(bn, buf.get()))
		return nullptr;

	if (!pnt) {
		if (!(ret = EC_POINT_new(grp)))
			return nullptr;
	} else
		ret = pnt;

	if (EC_POINT_oct2point(grp, ret, buf.get(), blen, ctx) != 1) {
		if (!pnt)
			EC_POINT_clear_free(ret);
		return nullptr;
	}

	return ret;
}


int EVP_PKEY_base_id(const EVP_PKEY *pkey)
{
	return EVP_PKEY_type(pkey->type);
}
#endif


#if OPENSSL_VERSION_NUMBER <= 0x10100000L || defined HAVE_LIBRESSL || defined HAVE_BORINGSSL
void DH_get0_key(const DH *dh, BIGNUM **pub_key, BIGNUM **priv_key)
{
	if (pub_key)
		*pub_key = dh->pub_key;
	if (priv_key)
		*priv_key = dh->priv_key;
}
#endif


#if OPENSSL_VERSION_NUMBER <= 0x10100000L || defined HAVE_LIBRESSL || defined HAVE_BORINGSSL
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
	dh->pub_key = pub_key;
	dh->priv_key = priv_key;
	return 1;
}
#endif



}

