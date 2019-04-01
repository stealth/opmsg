/*
 * This file is part of the opmsg crypto message framework.
 *
 * (C) 2015-2019 by Sebastian Krahmer,
 *                  sebastian [dot] krahmer [at] gmail [dot] com
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

#include <string>
#include <cstdio>
#include <cstring>
#include <memory>
#include <new>
#include "deleters.h"
#include "config.h"

extern "C" {
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
}


namespace opmsg {

using namespace std;


// Additionally to having the functions inside opmsg ns and
// having them static, we prefix them with bk_, so that in no event
// (even with potential compiler function-visibility bugs), our
// *rand functions can never overlay libcrypto's functions.

static int bk_RAND_bytes(unsigned char *buf, int buflen)
{
	if (config::brainkey1.size() < 16)
		return 0;

	const char *init_salt = "opmsg-brainkey-v1";
	char saltbuf[128] = {0};
	unsigned char out[32] = {0};
	unsigned int need = 0;

	static unsigned int salt_cnt = 0;

	const string &salt = config::salt1;
	const string &pass = config::brainkey1;

	memset(buf, 0, buflen);

	for (int have = 0; have < buflen;) {

		snprintf(saltbuf, sizeof(saltbuf) - 1, "%s.%s.%08x", salt.c_str(), init_salt, salt_cnt++);

		if (PKCS5_PBKDF2_HMAC(pass.c_str(), pass.size(),
		    reinterpret_cast<unsigned char *>(saltbuf),
		    strlen(saltbuf), 10000000,
	            EVP_sha256(), sizeof(out), out) != 1)
			return 0;

		need = buflen - have;
		if (need > sizeof(out))
			need = sizeof(out);
		memcpy(buf + have, out, need);
		have += need;
	}

	return buflen;
}


static int bk_bnrand(BIGNUM *rnd, int bits)
{
	int bit = 0, bytes = 0, mask = 0;

	if (bits <= 0)
		return 0;

	bytes = (bits + 7) / 8;
	bit = (bits - 1) % 8;
	mask = 0xff << (bit + 1);

	unique_ptr<unsigned char[]> buf(new (nothrow) unsigned char[bytes]);
	if (!buf.get())
		return 0;

	if (bk_RAND_bytes(buf.get(), bytes) != bytes)
		return 0;

	buf[0] &= ~mask;
	if (!BN_bin2bn(buf.get(), bytes, rnd))
		return 0;

	return 1;
}


// this function is logically based on what openssl and libressl
// are doing
static int bk_bnrand_range(BIGNUM *r, const BIGNUM *range)
{

	if (BN_is_negative(range) || BN_is_zero(range))
		return 0;

	int count = 1000;
	int n = BN_num_bits(range);

	if (n == 1) {
		BN_zero(r);
	} else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3)) {
		do {
			if (bk_bnrand(r, n + 1) != 1)
				return 0;

			if (BN_cmp(r, range) >= 0) {
				if (BN_sub(r, r, range) != 1)
					return 0;
				if (BN_cmp(r, range) >= 0) {
					if (BN_sub(r, r, range) != 1)
						return 0;
				}
			}

			if (!--count)
				return 0;
		} while (BN_cmp(r, range) >= 0);
	} else {
		do {
			if (bk_bnrand(r, n) != 1)
				return 0;

			if (!--count)
				return 0;
		} while (BN_cmp(r, range) >= 0);
	}

	return 1;
}


int EC_KEY_generate_key(EC_KEY *eckey)
{
	if (config::brainkey1.size() < 16)
		return ::EC_KEY_generate_key(eckey);

	const EC_GROUP *ec_grp = EC_KEY_get0_group(eckey);	// not unique
	unique_ptr<BIGNUM, BIGNUM_del> order(BN_new(), BN_free);
	unique_ptr<BN_CTX, BN_CTX_del> ctx(BN_CTX_new(), BN_CTX_free);
	unique_ptr<BIGNUM, BIGNUM_del> priv_key(BN_new(), BN_free);
	unique_ptr<EC_POINT, EC_POINT_del> pub_key(EC_POINT_new(ec_grp), EC_POINT_free);

	if (!ctx.get() || !order.get() || !priv_key.get() || !pub_key.get() || !ec_grp)
		return 0;

	if (EC_GROUP_get_order(ec_grp, order.get(), nullptr) != 1)
		return 0;

	do {
		if (bk_bnrand_range(priv_key.get(), order.get()) != 1)
			return 0;
	} while (BN_is_zero(priv_key.get()));

	if (EC_POINT_mul(ec_grp, pub_key.get(), priv_key.get(), nullptr, nullptr, ctx.get()) != 1)
		return 0;

	if (EC_KEY_set_private_key(eckey, priv_key.get()) != 1)
		return 0;
	if (EC_KEY_set_public_key(eckey, pub_key.get()) != 1)
		return 0;

	// important to set the encoding forms so that the PEM is equal
	// among libressl and openssl, which use different forms by default
	// to have the same persona hash on both sides
	EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);

#ifndef OPENSSL_EC_NAMED_CURVE
#define OPENSSL_EC_NAMED_CURVE 0x1
#endif
	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

	return 1;
}


}

/*
int main()
{
	EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp521r1);
	if (opmsg::EC_KEY_generate_key(eckey) != 1)
		printf("Error generating key\n");
	else
		PEM_write_ECPrivateKey(stdout, eckey, nullptr, 0, 0, nullptr, nullptr);
}

*/

