/*
 * This file is part of the opmsg crypto message framework.
 *
 * (C) 2015-2021 by Sebastian Krahmer,
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
#include "config.h"

extern "C" {
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
}


namespace opmsg {

using namespace std;


// Additionally to having the functions inside opmsg ns and
// having them static, we prefix them with bk_, so that in no event
// (even with potential compiler function-visibility bugs), our
// *rand functions can never overlay libcrypto's functions.

static int bk_RAND_bytes(unsigned char *buf, int buflen)
{
	if (config::brainkey12.size() < 16)
		return 0;

	const char *init_salt = "opmsg-brainkey-v1";
	char saltbuf[128] = {0};
	unsigned char out[32] = {0};
	unsigned int need = 0;

	static unsigned int salt_cnt = 0;

	const string &salt = config::salt1;
	const string &pass = config::brainkey12;

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


EVP_PKEY *ECKEY_gen(const string &curve, int nid)
{
	if (config::brainkey12.size() < 16)
		return EVP_EC_gen(curve.c_str());

	unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> ec_grp{
		EC_GROUP_new_by_curve_name(nid),
		EC_GROUP_free
	};
	unique_ptr<BIGNUM, decltype(&BN_free)> order{
		BN_new(),
		BN_free
	};
	unique_ptr<BIGNUM, decltype(&BN_free)> priv_key{
		BN_new(),
		BN_free
	};
	unique_ptr<BN_CTX, decltype(&BN_CTX_free)> bctx{
		BN_CTX_new(),
		BN_CTX_free
	};
	unique_ptr<EC_POINT, decltype(&EC_POINT_free)> pub_key{
		EC_POINT_new(ec_grp.get()),
		EC_POINT_free
	};

	if (!bctx.get() || !order.get() || !priv_key.get() || !pub_key.get() || !ec_grp.get())
		return nullptr;

	if (EC_GROUP_get_order(ec_grp.get(), order.get(), bctx.get()) != 1)
		return nullptr;

	do {
		if (bk_bnrand_range(priv_key.get(), order.get()) != 1)
			return nullptr;
	} while (BN_is_zero(priv_key.get()));

	if (EC_POINT_mul(ec_grp.get(), pub_key.get(), priv_key.get(), nullptr, nullptr, bctx.get()) != 1)
		return nullptr;

	unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx{
		EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr),
		EVP_PKEY_CTX_free
	};
	if (!pctx.get() || EVP_PKEY_fromdata_init(pctx.get()) != 1)
		return nullptr;

	int priv_len = BN_num_bytes(priv_key.get());
	if (priv_len <= 0)
		return nullptr;
	unique_ptr<unsigned char[]> priv_bin(new (nothrow) unsigned char[priv_len]);

	// attention: must use native format as expected by OSSL_PARAM_construct_BN() later
	if (!priv_bin.get() || BN_bn2nativepad(priv_key.get(), priv_bin.get(), priv_len) != priv_len)
		return nullptr;

	unsigned char *pub_bin = nullptr;
	int pub_len = EC_POINT_point2buf(ec_grp.get(), pub_key.get(), POINT_CONVERSION_COMPRESSED, &pub_bin, bctx.get());
	if (pub_len <= 0 || !pub_bin)
		return nullptr;

	unique_ptr<char, decltype(&free)> gname(strdup(curve.c_str()), free);
	char nc[]{"named_curve"}, cmp[]{"compressed"};
	int one = 1;

	OSSL_PARAM p[] = {
		OSSL_PARAM_construct_utf8_string("group", gname.get(), 0),
		OSSL_PARAM_construct_utf8_string("encoding", nc, 0),
		OSSL_PARAM_construct_utf8_string("point-format", cmp, 0),
		OSSL_PARAM_construct_int("include-public", &one),
		OSSL_PARAM_construct_BN("priv", priv_bin.get(), priv_len),
		OSSL_PARAM_construct_octet_string("pub", pub_bin, pub_len),
		OSSL_PARAM_END
	};

	EVP_PKEY *evp = nullptr;
	EVP_PKEY_fromdata(pctx.get(), &evp, EVP_PKEY_KEYPAIR, p);
	OPENSSL_free(pub_bin);

	return evp;
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

