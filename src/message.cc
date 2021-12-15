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
#include <vector>
#include <memory>
#include <algorithm>
#include <iterator>
#include <iostream>

#include "misc.h"
#include "base64.h"
#include "keystore.h"
#include "missing.h"
#include "message.h"
#include "marker.h"


extern "C" {
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
}

#include "missing.h"

namespace opmsg {

using namespace std;


static string::size_type lwidth = 80, max_sane_string = 0x1000, min_entropy_bytes = 16;


static int kdf_v1234(unsigned int vers, const unsigned char *secret, int slen,
                     const string &s1, const string &s2, const string &pqsalt1,
                     unsigned char key[OPMSG_MAX_KEY_LENGTH])	// 64 byte
{
	unsigned int hlen = 0;
	unsigned char digest[EVP_MAX_MD_SIZE] = {0xff};	// 64 which matches sha512

	errno = 0;

	if (slen <= 0 || vers < 1 || vers > 4)
		return -1;

	unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_delete)> md_ctx{
		EVP_MD_CTX_create(),
		EVP_MD_CTX_delete
	};
	if (!md_ctx.get())
		return -1;
	if (EVP_DigestInit_ex(md_ctx.get(), EVP_sha512(), nullptr) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), secret, slen) != 1)
		return -1;

	string vs = "";
	switch (vers) {
	case 1:
		vs = marker::version1;
		break;
	case 2:
		vs = marker::version2;
		break;
	case 3:
		vs = marker::version3;
		break;
	case 4:
		vs = marker::version4;
		break;
	default:
		return -1;
	}

	if (EVP_DigestUpdate(md_ctx.get(), vs.c_str(), vs.size()) != 1)
		return -1;

	if (vers >= 2) {
		if (EVP_DigestUpdate(md_ctx.get(), s1.c_str(), s1.size()) != 1)
			return -1;
		if (EVP_DigestUpdate(md_ctx.get(), s2.c_str(), s2.size()) != 1)
			return -1;
	}

	// Add PQC salt if given
	if (vers >= 4 && pqsalt1.size() > 0) {
		for (uint32_t i = 0; i < 64; ++i) {
			if (EVP_DigestUpdate(md_ctx.get(), pqsalt1.c_str(), pqsalt1.size()) != 1)
				return -1;
			char stri[16] = {0};
			snprintf(stri, sizeof(stri), "%015x", i);
			if (EVP_DigestUpdate(md_ctx.get(), stri, sizeof(stri)) != 1)
				return -1;
		}
	}

	if (EVP_DigestFinal_ex(md_ctx.get(), digest, &hlen) != 1)
		return -1;
	if (hlen != 64)
		return -1;

	if (hlen > OPMSG_MAX_KEY_LENGTH)
		hlen = OPMSG_MAX_KEY_LENGTH;
	memcpy(key, digest, hlen);
	return 0;
}


static int kdf_v1(unsigned char *secret, int slen, unsigned char key[OPMSG_MAX_KEY_LENGTH])
{
	return kdf_v1234(1, secret, slen, "", "", "", key);
}


// Different opmsg versions use different AEAD
static vector<unsigned char> derive_aead(int version, const string &src_id_hex, const string &base_data)
{
	vector<unsigned char> aead(0);

	// version 1-3 just use the src-id
	if (version < 4) {
		aead.insert(aead.end(), src_id_hex.begin(), src_id_hex.end());
	} else {

		// later versions use entire constructed header, including session pub-keys
		// in order to "sign" the entire opmsg a 2nd time (the data part is also integrity protected
		// by AEAD algos) to combat Shors algo in a post-quantum world. We use our KDF function
		// for it by passing apropriate parameters. The "secret" is the base_data.

		aead.resize(OPMSG_MAX_KEY_LENGTH);
		if (kdf_v1234(version, reinterpret_cast<const unsigned char*>(base_data.c_str()), base_data.size(), "AEAD", "SHA512", "", &aead[0]) < 0)
			aead.clear();
	}

	// returns 0-sized vector if kdf fails
	return aead;
}


int message::sign(const string &msg, persona *src_persona, string &result)
{
	size_t siglen = 0;

	result = "";

	if (!src_persona->can_sign())
		return build_error("sign:: Persona has no pkey.", -1);

	if (!is_valid_halgo(d_shash, 1))
		return build_error("sign:: Not a valid hash algo for signing.", -1);

	// do not take ownership
	EVP_PKEY *evp = src_persona->get_pkey()->d_priv;

	if (EVP_PKEY_get_base_id(evp) == EVP_PKEY_RSA) {
		// XXX: blinding?
	}

	unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_delete)> md_ctx{
		EVP_MD_CTX_create(),
		EVP_MD_CTX_delete
	};
	if (!md_ctx.get())
		return build_error("sign::EVP_MD_CTX_create:", -1);
	if (EVP_DigestSignInit(md_ctx.get(), nullptr, algo2md(d_shash), nullptr, evp) != 1)
		return build_error("sign::EVP_DigestSignInit:", -1);
	if (EVP_DigestSignUpdate(md_ctx.get(), msg.c_str(), msg.size()) != 1)
		return build_error("sign::EVP_DigestSignUpdate:", -1);
	if (EVP_DigestSignFinal(md_ctx.get(), nullptr, &siglen) != 1)
		return build_error("sign::EVP_DigestSignFinal: Message signing failed", -1);

	unique_ptr<unsigned char[]> sig(new (nothrow) unsigned char[siglen]);
	if (!sig.get() || EVP_DigestSignFinal(md_ctx.get(), sig.get(), &siglen) != 1)
		return build_error("sign:: EVP_DigestSignFinal: Message signing failed", -1);

	string s = "";
	b64_encode(reinterpret_cast<char *>(sig.get()), siglen, s);
	if (s.empty())
		return build_error("sign:: Failed to create signature", -1);

	result = marker::sig_begin;
	while (s.size() > 0) {
		result += s.substr(0, lwidth);
		s.erase(0, lwidth);
		result += "\n";
	}
	result += marker::sig_end;
	return 1;
}


int message::encrypt(string &raw, persona *src_persona, persona *dst_persona)
{
	unsigned char iv[OPMSG_MAX_IV_LENGTH] = {0}, iv_kdf[OPMSG_MAX_KEY_LENGTH] = {0};
	char aad_tag[16] = {0};
	// an ECDH or DH key
	vector<PKEYbox *> ec_dh;
	vector<string> b64pubkeys;
	string outmsg = "", b64sig = "", iv_b64 = "", b64_aad_tag = "";
	string::size_type aad_tag_insert_pos = string::npos;
	bool no_dh_key = (d_kex_id_hex == marker::rsa_kex_id);
	size_t n = 0;
	unsigned int i = 0;

	for (i = 0; i < sizeof(iv); ++i)
		iv[i] = i;

	if (!src_persona || !dst_persona)
		return build_error("encrypt: No src/dst personas specified!", -1);

	if (!is_valid_halgo(d_phash, 1) || !is_valid_halgo(d_khash, 1) || !is_valid_halgo(d_shash, 1) || !is_valid_calgo(d_calgo, 1))
		return build_error("encrypt: Invalid algo name(s).", -1);

	if (!is_hex_hash(d_src_id_hex) || !is_hex_hash(d_dst_id_hex))
		return build_error("encrypt: Invalid persona id(s).", -1);

	if (d_src_id_hex != src_persona->get_id() || d_dst_id_hex != dst_persona->get_id())
		return build_error("encrypt: Persona/ID specification mismatch.", -1);

	if (!is_hex_hash(d_kex_id_hex))
		return build_error("encrypt: Invalid DH key id " + d_kex_id_hex, -1);

	if (!src_persona->can_sign())
		return build_error("encrypt: missing signature key for src persona " + d_src_id_hex, -1);

	if (src_persona->is_pq1()) {
		if (d_version < 4)
			return build_error("encrypt: PQC personas need configured version >= 4.", -1);
		if (d_src_id_hex != d_dst_id_hex)
			return build_error("encrypt: PQC personas must be deniable.", -1);
	}

	if (!dst_persona->can_encrypt())
		return build_error("encrypt:: missing key for dst persona " + d_dst_id_hex, -1);

	if (!no_dh_key) {
		ec_dh = dst_persona->find_dh_key(d_kex_id_hex);
		if (ec_dh.empty() || !ec_dh[0]->can_encrypt())
			return build_error("encrypt: Invalid (EC)DH key id " + d_kex_id_hex, -1);
	}

	if (RAND_bytes(iv, sizeof(iv)) != 1)
		return build_error("encrypt::RAND_bytes:", -1);

	// this is only to not directly use random bytes in the IV. No real 'KDF' and hence v1.
	if (kdf_v1(iv, sizeof(iv), iv_kdf) < 0)
		return build_error("encrypt: Error deriving IV: ", -1);
	memcpy(iv, iv_kdf, sizeof(iv));
	b64_encode(reinterpret_cast<char *>(iv), sizeof(iv), iv_b64);

	outmsg = marker::algos + d_phash + ":" + d_khash + ":" + d_shash + ":" + d_calgo + ":" + iv_b64 + "\n";

	char cfg_s[32] = {0};
	snprintf(cfg_s, sizeof(cfg_s), "%s%u:%u:\n", marker::cfg_num.c_str(), d_version, d_ec_domains);
	outmsg += cfg_s;

	// in case of GCM modes, the AAD tag value goes right here
	aad_tag_insert_pos = outmsg.size();

	outmsg += marker::src_id + d_src_id_hex + "\n";
	outmsg += marker::dst_id + d_dst_id_hex + "\n";
	outmsg += marker::kex_id + d_kex_id_hex + "\n";

	// null encryption: plaintext signing case
	if (d_calgo == "null") {
		outmsg += marker::opmsg_databegin;
		outmsg += raw;
		if (sign(outmsg, src_persona, b64sig) != 1)
			return build_error("encrypt::" + d_err, -1);

		outmsg.insert(0, b64sig);
		if (d_version == 1)
			outmsg.insert(0, marker::version1);
		else if (d_version == 2)
			outmsg.insert(0, marker::version2);
		else if (d_version == 3)
			outmsg.insert(0, marker::version3);
		else
			outmsg.insert(0, marker::version4);

		outmsg.insert(0, marker::opmsg_begin);
		outmsg += marker::opmsg_end;
		raw = outmsg;
		return 1;
	}

	bool has_aad = (d_calgo.find("gcm") != string::npos || d_calgo == "chacha20-poly1305");

	// append public (EC)DH keys
	for (auto it = d_ecdh_keys.begin(); it != d_ecdh_keys.end(); ++it) {
		outmsg += *it;
		outmsg += "\n";
	}


	// Kex (DH if avail, RSA as fallback for DH. EC personas have no RSA fallback)
	int slen = OPMSG_RSA_ENCRYPTED_KEYLEN;
	unique_ptr<unsigned char[]> secret(new (nothrow) unsigned char[slen]);
	if (!secret.get())
		return build_error("encrypt: OOM", -1);

	// DH or ECDH Kex
	if (!ec_dh.empty()) {

		vector<unsigned char> secret_v;
		secret_v.reserve(0x1000);	// to avoid re-allocation
		slen = 0;

		if (ec_dh.size() > 1 && EVP_PKEY_base_id(ec_dh[0]->d_pub) != EVP_PKEY_EC)
			return build_error("encrypt: Found non-ECDH key in cross-domain ECDH Kex.", -1);

		for (unsigned int i = 0; i < ec_dh.size(); ++i) {
			if (!ec_dh[i]->can_encrypt())
				return build_error("encrypt: Impossible key in ECDH Kex loop.", -1);

			unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx1{
				EVP_PKEY_CTX_new(ec_dh[i]->d_pub, nullptr),
				EVP_PKEY_CTX_free
			};
			if (!ctx1.get() || EVP_PKEY_keygen_init(ctx1.get()) != 1)
				return build_error("encrypt::EVP_PKEY_keygen_init:", -1);
			EVP_PKEY *ppkey = nullptr;
			if (EVP_PKEY_keygen(ctx1.get(), &ppkey) != 1)
				return build_error("encrypt::EVP_PKEY_keygen:", -1);

			unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> gen_key(ppkey, EVP_PKEY_free);
			unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx2{
				EVP_PKEY_CTX_new(gen_key.get(), nullptr),
				EVP_PKEY_CTX_free
			};
			if (EVP_PKEY_derive_init(ctx2.get()) != 1)
				return build_error("encrypt::EVP_PKEY_derive_init: ", -1);
			if (EVP_PKEY_derive_set_peer(ctx2.get(), ec_dh[i]->d_pub) != 1)
				return build_error("encrypt::EVP_PKEY_derive_set_peer: ", -1);

			// find len
			size_t len = 0;
			if (EVP_PKEY_derive(ctx2.get(), nullptr, &len) != 1)
				return build_error("encrypt::EVP_PKEY_derive: ", -1);
			if ((unsigned int)slen > max_sane_string || len > max_sane_string || len < min_entropy_bytes)
				return build_error("encrypt: Insane large or too small derived keylen.", -1);
			vector<unsigned char> secret_i(len, 0);

			if (EVP_PKEY_derive(ctx2.get(), &secret_i[0], &len) != 1)
				return build_error("encrypt::EVP_PKEY_derive for key " + d_kex_id_hex, -1);
			secret_v.insert(secret_v.end(), secret_i.begin(), secret_i.end());
			slen += (int)len;

			unique_ptr<BIGNUM, decltype(&BN_free)> bn(nullptr, BN_free);

			if (EVP_PKEY_base_id(gen_key.get()) == EVP_PKEY_EC) {

				unsigned char obuf[8192] = {0};
				//char cmp[]{"compressed"};
				OSSL_PARAM p[] = {
					OSSL_PARAM_construct_octet_string("pub", obuf, sizeof(obuf)),
					//OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, cmp, 0),
					OSSL_PARAM_END
				};
				if (EVP_PKEY_get_params(gen_key.get(), p) != 1 || p[0].return_size == 0)
					return build_error("encrypt::EVP_PKEY_get_params:", -1);

				BIGNUM *tbn = nullptr;
				if (!(tbn = BN_bin2bn(obuf, p[0].return_size, nullptr)))
					return build_error("encrypt::BN_bin2bn:", -1);
				bn.reset(tbn);

			// DH
			} else {
				BIGNUM *tbn = nullptr;
				if (!EVP_PKEY_get_bn_param(gen_key.get(), "pub", &tbn))
					return build_error("encrypt::EVP_PKEY_get_bn_param:", -1);
				bn.reset(tbn);
			}

			if (!bn.get())
				return build_error("encrypt::Empty Kex key?!:", -1);
			int binlen = BN_num_bytes(bn.get());

			unique_ptr<unsigned char[]> bin(new (nothrow) unsigned char[binlen]);
			if (!bin.get() || BN_bn2bin(bn.get(), bin.get()) != binlen)
				return build_error("encrypt::BN_bn2bin: Cannot convert ECDH key ", -1);

			string s = "";
			b64_encode(reinterpret_cast<char *>(bin.get()), binlen, s);
			b64pubkeys.push_back(s);
		}

		if ((unsigned int)slen != secret_v.size() || (unsigned int)slen > max_sane_string)
			return build_error("encrypt: Huh? Mismatch in calculated secret sizes.", -1);

		secret.reset(new (nothrow) unsigned char[slen]);
		if (!secret.get())
			return build_error("encrypt: OOM", -1);
		memcpy(secret.get(), &secret_v[0], slen);

	} else {
		if (RAND_bytes(secret.get(), slen) != 1)
			return build_error("encrypt::RAND_bytes: ", -1);

		EVP_PKEY *evp = dst_persona->get_pkey()->d_pub;
		unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> p_ctx{
			EVP_PKEY_CTX_new(evp, nullptr),
			EVP_PKEY_CTX_free
		};
		if (!p_ctx.get())
			return build_error("encrypt:: Unable to create PKEY encryption context ", -1);
		if (EVP_PKEY_encrypt_init(p_ctx.get()) != 1)
			return build_error("encrypt::EVP_PKEY_encrypt_init:", -1);

		if (EVP_PKEY_get_base_id(evp) == EVP_PKEY_RSA) {
			if (EVP_PKEY_CTX_set_rsa_padding(p_ctx.get(), RSA_PKCS1_PADDING) != 1)
				return build_error("encrypt::EVP_PKEY_CTX_set_rsa_padding", -1);
		}
		size_t outlen = 0;
		if (EVP_PKEY_encrypt(p_ctx.get(), nullptr, &outlen, secret.get(), slen) != 1)
			return build_error("encrypt::EVP_PKEY_encrypt: ", -1);
		unique_ptr<unsigned char[]> outbuf(new (nothrow) unsigned char[outlen]);
		if (!outbuf.get())
			return build_error("encrypt: OOM", -1);
		if (EVP_PKEY_encrypt(p_ctx.get(), outbuf.get(), &outlen, secret.get(), slen) != 1)
			return build_error("encrypt::EVP_PKEY_encrypt: ", -1);

		string s = "";
		b64_encode(reinterpret_cast<char *>(outbuf.get()), outlen, s);
		b64pubkeys.push_back(s);
	}

	if (slen < (int)min_entropy_bytes)
		return build_error("encrypt: Huh? Generated secret len of insufficient entropy size.", -1);

	for (string &s : b64pubkeys) {
		outmsg += marker::kex_begin;

		while (s.size() > 0) {
			outmsg += s.substr(0, lwidth);
			outmsg += "\n";
			s.erase(0, lwidth);
		}

		outmsg += marker::kex_end;
		outmsg += "\n";
	}

	outmsg += marker::opmsg_databegin;

	string pqsalt1{""};
	if (src_persona->is_pq1())
		pqsalt1 = src_persona->get_pqsalt1();

	unsigned char key[OPMSG_MAX_KEY_LENGTH] = {0};
	if (kdf_v1234(d_version, secret.get(), slen, d_src_id_hex, d_dst_id_hex, pqsalt1, key) < 0)
		return build_error("encrypt::kdf_v1234: Error deriving key: ", -1);
	unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> c_ctx{
		EVP_CIPHER_CTX_new(),
		EVP_CIPHER_CTX_free
	};
	if (!c_ctx.get())
		return build_error("encrypt::EVP_CIPHER_CTX_new: ", -1);
	if (EVP_EncryptInit_ex(c_ctx.get(), algo2cipher(d_calgo), nullptr, key, iv) != 1)
		return build_error("encrypt::EVP_EncryptInit_ex: ", -1);

	// AEAD ciphers need special treatment
	if (has_aad) {
		int aadlen = 0;
		auto aead = derive_aead(d_version, d_src_id_hex, outmsg);
		if (!aead.size())
			return build_error("encrypt: Can't derive AEAD:", -1);

		if (EVP_EncryptUpdate(c_ctx.get(), nullptr, &aadlen, &aead[0], aead.size()) != 1)
			return build_error("encrypt::EVP_EncryptUpdate (AEAD):", -1);
	}
	EVP_CIPHER_CTX_set_padding(c_ctx.get(), 1);

	string b64_enc = "";
	const size_t blen = 8000000*3;
	unique_ptr<unsigned char[]> outbuf(new (nothrow) unsigned char[blen + EVP_MAX_BLOCK_LENGTH]);
	if (!outbuf.get())
		return build_error("encrypt:: OOM", -1);
	int outlen = 0;
	string::size_type idx = 0, rawsize = raw.size(), b64idx = 0, b64size = 0;
	while (idx < rawsize) {
		outlen = 0;
		if (rawsize - idx < blen)
			n = rawsize - idx;
		else
			n = blen;
		if (EVP_EncryptUpdate(c_ctx.get(), outbuf.get(), &outlen, (unsigned char *)(raw.c_str() + idx), n) != 1)
			return build_error("encrypt::EVP_EncryptUpdate:", -1);
		idx += n;
		// if last chunk, also add padding from block cipher
		if (idx == rawsize) {
			int padlen = 0;
			if (EVP_EncryptFinal_ex(c_ctx.get(), outbuf.get() + outlen, &padlen) != 1)
				return build_error("encrypt::EVP_EncryptFinal_ex:", -1);
			outlen += padlen;
			if (has_aad) {
				if (EVP_CIPHER_CTX_ctrl(c_ctx.get(), EVP_CTRL_AEAD_GET_TAG, sizeof(aad_tag), aad_tag) != 1)
					return build_error("encrypt::EVP_CIPHER_CTX_ctrl:", -1);
				b64_encode(aad_tag, sizeof(aad_tag), b64_aad_tag);
				b64_aad_tag.insert(0, marker::aad_tag);
				b64_aad_tag += "\n";
			}
		}
		b64_encode(reinterpret_cast<const char *>(outbuf.get()), outlen, b64_enc);
		b64size = b64_enc.size();
		b64idx = 0;
		while (b64idx < b64size) {
			outmsg += b64_enc.substr(b64idx, lwidth);
			outmsg += "\n";
			b64idx += lwidth;
		}
		b64_enc.clear();
	}

	c_ctx.reset();
	raw.clear();

	if (b64_aad_tag.size() > 0)
		outmsg.insert(aad_tag_insert_pos, b64_aad_tag);

	if (sign(outmsg, src_persona, b64sig) != 1)
		return build_error("encrypt::" + d_err, -1);

	outmsg.insert(0, b64sig);
	if (d_version == 1)
		outmsg.insert(0, marker::version1);
	else if (d_version == 2)
		outmsg.insert(0, marker::version2);
	else if (d_version == 3)
		outmsg.insert(0, marker::version3);
	else
		outmsg.insert(0, marker::version4);

	outmsg.insert(0, marker::opmsg_begin);
	outmsg += marker::opmsg_end;

	raw = outmsg;

	return 1;
}


// helper function to parse some of the key=value parts of the opmsg blob,
// to keep the decrypt() function straight forward. Only called after signature
// verified correctly.
// By splitting of the hdr and parsing it separately, this also speeds up
// entire decrypt(), since optional tags are only searched within header
// and not in the entire blob.
int message::parse_hdr(string &hdr, vector<string> &kexdhs, vector<char> &aad_tag)
{
	string s = "";
	string::size_type pos = string::npos, nl = string::npos;

	kexdhs.clear();
	kexdhs.reserve(3);
	aad_tag.clear();

	// For optional extensions later. Also check the pinned version number to match
	// whats been found at the entry (before signature)
	if ((pos = hdr.find(marker::cfg_num)) != string::npos) {
		unsigned int v = 0, e = 1;

		// 'e' value might be there or not, so dont compare result like != 2
		if (sscanf(hdr.c_str() + pos + marker::cfg_num.size(), "%u:%u:", &v, &e) < 1)
			return build_error("parse_hdr: Invalid cfg-num tag.", -1);
		if (v != d_version)
			return build_error("parse_hdr: Version mismatch. Someone modified the message.", -1);
		d_ec_domains = e;
	}

	// get AAD tag if any (only required by GCM mode ciphers and poly1305)
	if ((pos = hdr.find(marker::aad_tag)) != string::npos) {
		pos += marker::aad_tag.size();
		if ((nl = hdr.find("\n", pos)) == string::npos)
			return build_error("parse_hdr: Error finding end of AAD tag.", -1);
		string b64_aad_tag = hdr.substr(pos, nl - pos);
		b64_decode(b64_aad_tag, s);
		if (s.size() < 16 || s.size() > 32)
			return build_error("parse_hdr: Invalid AAD tag size.", -1);
		aad_tag.insert(aad_tag.end(), s.begin(), s.end());
	}

	if ((pos = hdr.find(marker::kex_id)) == string::npos)
		return build_error("parse_hdr: Not in OPMSG format (1).", -1);
	pos += marker::kex_id.size();
	nl = hdr.find("\n", pos);
	if (nl == string::npos || nl - pos > max_sane_string)
		return build_error("parse_hdr: Not in OPMSG format (2).", -1);
	s = hdr.substr(pos, nl - pos);
	if (!is_hex_hash(s))
		return build_error("parse_hdr: Not in OPMSG format (3).", -1);
	d_kex_id_hex = s;


	// dst persona
	if ((pos = hdr.find(marker::dst_id)) == string::npos)
		return build_error("parse_hdr: Not in OPMSG format (4).", -1);
	pos += marker::dst_id.size();
	nl = hdr.find("\n", pos);
	if (nl == string::npos || nl - pos > max_sane_string)
		return build_error("parse_hdr: Not in OPMSG format (5).", -1);
	s = hdr.substr(pos, nl - pos);
	if (!is_hex_hash(s))
		return build_error("parse_hdr: Not in OPMSG format (6).", -1);
	d_dst_id_hex = s;

	// new (ec)dh keys included for later (EC)DH kex?
	string newdh = "";
	for (;;) {
		if ((pos = hdr.find(marker::ec_dh_begin)) == string::npos)
			break;
		if ((nl = hdr.find(marker::ec_dh_end, pos)) == string::npos)
			return build_error("parse_hdr: Not in OPMSG format (7)", -1);
		if (nl - pos > max_sane_string)
			return build_error("parse_hdr: Not in OPMSG format (8).", -1);
		newdh = hdr.substr(pos, nl + marker::ec_dh_end.size() - pos);
		hdr.erase(pos, nl + marker::ec_dh_end.size() - pos);
		d_ecdh_keys.push_back(newdh);
		if (d_ecdh_keys.size() >= d_max_new_dh_keys)
			break;
	}

	if (d_ec_domains < 1 || d_ec_domains > 3 || (d_ecdh_keys.size() % d_ec_domains) != 0)
		return build_error("parse_hdr: Invalid number of EC domains.", -1);

	for (;;) {
		// the (EC)DH public part, optional. For "null" calgos, there is no kex.
		if ((pos = hdr.find(marker::kex_begin)) == string::npos)
			break;

		if ((nl = hdr.find(marker::kex_end, pos)) == string::npos)
			return build_error("parse_hdr: Not in OPMSG format (9).", -1);
		if (nl - pos > max_sane_string)
			return build_error("parse_hdr: Not in OPMSG format (10).", -1);
		string b64_kexdh = hdr.substr(pos + marker::kex_begin.size(), nl - pos - marker::kex_begin.size());
		hdr.erase(pos, nl - pos + marker::kex_end.size());
		b64_kexdh.erase(remove(b64_kexdh.begin(), b64_kexdh.end(), '\n'), b64_kexdh.end());
		b64_decode(b64_kexdh, s);
		if (s.empty())
			return build_error("parse_hdr: Invalid Kex Base64.", -1);
		kexdhs.push_back(s);
	}

	return 1;
}


// must not be called twice on the same object and not intermixed with encrypt()
// on the same object
int message::decrypt(string &raw)
{
	string::size_type pos = string::npos, pos_sigend = string::npos, nl = string::npos;
	vector<PKEYbox *> ec_dh;
	unsigned char iv[OPMSG_MAX_IV_LENGTH] = {0};
	vector<char> aad_tag;
	vector<string> kexdhs;
	string kexdh = "";
	unsigned int i = 0;
	string s = "", iv_kdf = "", b64_aad_tag = "";
	size_t n = 0;

	for (i = 0; i < sizeof(iv); ++i)
		iv[i] = i;

	// nuke leading header, dont accept leading junk
	if ((pos = raw.find(marker::opmsg_begin)) != 0)
		return build_error("decrypt: Not in OPMSGv1 format (1).", -1);
	raw.erase(0, pos + marker::opmsg_begin.size());

	d_version = 1;
	// next must come "version=N" , nuke it
	if ((pos = raw.find(marker::version1)) != 0) {
		d_version = 2;
		if ((pos = raw.find(marker::version2)) != 0) {
			d_version = 3;
			if ((pos = raw.find(marker::version3)) != 0) {
				d_version = 4;
				if ((pos = raw.find(marker::version4)) != 0)
					return build_error("decrypt: Not in OPMSG format (2). Need to update opmsg?", -1);
			}
		}
	}

	raw.erase(0, pos + marker::version1.size());

	// nuke OPMSg trailer, its also not part of signing. Do not accept junk after
	// footer.
	if ((pos = raw.find(marker::opmsg_end)) == string::npos || pos + marker::opmsg_end.size() != raw.size())
		return build_error("decrypt: Not in OPMSG format (3).", -1);
	raw.erase(pos, marker::opmsg_end.size());

	// next must come signature b64 sigblob
	if ((pos = raw.find(marker::sig_begin)) != 0 || (pos_sigend = raw.find(marker::sig_end)) == string::npos)
		return build_error("decrypt: Not in OPMSG format (4).", -1);

	// weird or unreasonable large signature?
	if (pos_sigend >= max_sane_string)
		return build_error("decrypt: Not in OPMSG format (5).", -1);

	string b64sig = raw.substr(marker::sig_begin.size(), pos_sigend - marker::sig_begin.size());
	raw.erase(0, pos_sigend + marker::sig_end.size());

	// nuke newlines
	b64sig.erase(remove(b64sig.begin(), b64sig.end(), '\n'), b64sig.end());

	//
	// now we have the raw message that was presumably signed and the signature blob splitted from it
	//

	if ((pos = raw.find(marker::algos)) != 0)
		return build_error("decrypt: Not in OPMSG format (6).", -1);

	char b[5][64];
	for (i = 0; i < 5; ++i)
		memset(b[i], 0, sizeof(b[0]));
	if (sscanf(raw.c_str() + marker::algos.size(), "%32[^:]:%32[^:]:%32[^:]:%32[^:]:%32[^\n]", b[0], b[1], b[2], b[3], b[4]) != 5)
		return build_error("decrypt: Not in OPMSG format (7).", -1);

	d_phash = b[0]; d_khash = b[1]; d_shash = b[2]; d_calgo = b[3];
	if (!is_valid_halgo(d_phash, 0) || !is_valid_halgo(d_khash, 0) || !is_valid_halgo(d_shash, 0) || !is_valid_calgo(d_calgo, 0))
		return build_error("decrypt: Not in OPMSG format (8). Invalid algo name. Need to update opmsg?", -1);

	bool has_aad = (d_calgo.find("gcm") != string::npos || d_calgo == "chacha20-poly1305");

	// IV are 24byte encoded as b64 == 32byte
	b64_decode(reinterpret_cast<char *>(b[4]), 32, iv_kdf);
	if (iv_kdf.size() < sizeof(iv))
		return build_error("decrypt: Error decoding IV value.", -1);
	memcpy(iv, iv_kdf.c_str(), sizeof(iv));

	// src persona
	if ((pos = raw.find(marker::src_id)) == string::npos)
		return build_error("decrypt: Not in OPMSG format (9).", -1);
	pos += marker::src_id.size();
	nl = raw.find("\n", pos);
	if (nl == string::npos || nl - pos > max_sane_string)
		return build_error("decrypt:: Not in OPMSG format (10).", -1);
	s = raw.substr(pos, nl - pos);
	if (!is_hex_hash(s))
		return build_error("decrypt: Not in OPMSG format (11).", -1);
	d_src_id_hex = s;

	// for src persona, we only need native (RSA or EC) key for signature validation
	unique_ptr<persona> src_persona(new (nothrow) persona(d_cfgbase, d_src_id_hex));
	if (!src_persona.get() || src_persona->load(marker::rsa_kex_id) < 0 || !src_persona->can_verify())
		return build_error("decrypt: Unknown or invalid src persona " + d_src_id_hex, 0);

	// check sig
	unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_delete)> md_ctx{
		EVP_MD_CTX_create(),
		EVP_MD_CTX_delete
	};
	if (!md_ctx.get())
		return build_error("decrypt::EVP_MD_CTX_create:", -1);
	EVP_PKEY *src_evp = src_persona->get_pkey()->d_pub;
	if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, algo2md(d_shash), nullptr, src_evp) != 1)
		return build_error("decrypt::EVP_DigestVerifyInit:", -1);
	if (EVP_DigestVerifyUpdate(md_ctx.get(), raw.c_str(), raw.size()) != 1)
		return build_error("decrypt::EVP_DigestVerifyUpdate:", -1);
	string sig = "";
	b64_decode(b64sig, sig);
	errno = 0;	// Dont consider errno on wrong message signature error message
	if (EVP_DigestVerifyFinal(md_ctx.get(), (unsigned char *)(sig.c_str()), sig.size()) != 1)
		return build_error("decrypt::EVP_DigestVerifyFinal: Message verification FAILED.", -1);

	md_ctx.reset();

	//
	// at this point, the message is valid authenticated by src_id's signature.
	// AEAD MAC (if any) still to proove, so do not import any attached keys yet.
	//

	string::size_type databegin = string::npos;
	if ((databegin = raw.find(marker::opmsg_databegin)) == string::npos)
		return build_error("decrypt: Not in OPMSG format (12).", -1);

	string hdr = raw.substr(0, databegin + marker::opmsg_databegin.size());

	// parse_hdr() will modify 'hdr', so make a copy for AAD computation later
	string aead_hdr = hdr;

	// parse the remaining parts of the header
	// Fills: kex_id_hex, dst_id_hex, kexdhs, aad_tag, d_ecdh_keys, d_ec_domains
	if (parse_hdr(hdr, kexdhs, aad_tag) != 1)
		return build_error("decrypt: " + d_err, -1);

	// header parsed correctly, split it off data body
	raw.erase(0, databegin + marker::opmsg_databegin.size());

	unique_ptr<persona> dst_persona(new (nothrow) persona(d_cfgbase, d_dst_id_hex));
	if (!dst_persona.get() || dst_persona->load(d_kex_id_hex) < 0 || (!dst_persona->can_decrypt() && d_calgo != "null"))
		return build_error("decrypt: Unknown or invalid dst persona " + d_dst_id_hex, 0);

	if (dst_persona->is_pq1() && (!is_valid_pq_calgo(d_calgo) || d_version < 4))
		return build_error("decrypt: Persona requires PQC, but non-PQC calgo specified in message.", 0);

	d_src_name = src_persona->get_name();

	// Not recommended, but if "null" encrypted, import keys and thats all!
	if (d_calgo == "null") {

		for (auto it = d_ecdh_keys.begin(); it != d_ecdh_keys.end();) {
			// d_ec_domains validity checked in parse_hdr()
			vector<string> v(it, it + d_ec_domains);
			if ((src_persona->add_dh_pubkey(d_khash, v)).empty())
				it = d_ecdh_keys.erase(it, it + d_ec_domains);
			else
				it += d_ec_domains;
		}

		return 1;
	}

	// everything else have to have a kex
	if (kexdhs.empty())
		return build_error("decrypt: Missing Kex tag for non-null encryption!", -1);

	bool has_dh_key = (d_kex_id_hex != marker::rsa_kex_id);

	if (has_dh_key) {
		ec_dh = dst_persona->find_dh_key(d_kex_id_hex);
		if (ec_dh.empty())
			return build_error("decrypt::find_dh_key: No such key " + d_kex_id_hex, 0);
		for (auto it : ec_dh) {
			if (!it->can_decrypt())
				return build_error("decrypt::find_dh_key: No private key " + d_kex_id_hex, 0);
		}

		// We could make this an exact == match, but maybe peer is only using one of the many keys
		// from the cross-domain Kex (due to downgrading opmsg version or alike), so we also accept
		// less kexdh's than we have actually in the queue. This is not a security risk. Its only that
		// the peer (verified by signature) decided to use fewer EC domains than what we offered.
		// Maybe in future, this could be enforced to be an exact match.
		if (ec_dh.size() < kexdhs.size())
			return build_error("decrypt: Mismatch in number of ECDH domains.", -1);

		if (d_peer_isolation && !ec_dh[0]->matches_peer_id(d_src_id_hex))
			return build_error("decrypt: persona " + d_src_id_hex + " references kex id's which were sent to persona " + ec_dh[0]->get_peer_id() +
			                   ".\nAttack or isolation leak detected?\nIf not, rm ~/.opmsg/" + d_dst_id_hex + "/" + d_kex_id_hex + "/peer and try again\n"
			                   "or set peer_isolation=0 in config file.\n", -1);
	}

	unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> p_ctx(nullptr, EVP_PKEY_CTX_free);

	// Kex: (EC)DH if avail, RSA as fallback
	int slen = 0;
	unique_ptr<unsigned char[]> secret(nullptr);
	if (!has_dh_key) {
		kexdh = kexdhs[0];
		if (!dst_persona->can_decrypt())
			return build_error("decrypt: No private PKEY for persona " + dst_persona->get_id(), 0);
		// kexdh contains pub encrypted secret, not DH BIGNUM
		p_ctx.reset(EVP_PKEY_CTX_new(dst_persona->get_pkey()->d_priv, nullptr));
		if (!p_ctx.get() || EVP_PKEY_decrypt_init(p_ctx.get()) != 1)
			return build_error("decrypt::EVP_PKEY_decrypt_init:", -1);

		if (EVP_PKEY_get_base_id(dst_persona->get_pkey()->d_priv) == EVP_PKEY_RSA) {
			// XXX: enable blinding?
			if (EVP_PKEY_CTX_set_rsa_padding(p_ctx.get(), RSA_PKCS1_PADDING) != 1)
				return build_error("decrypt::EVP_PKEY_CTX_set_rsa_padding", -1);
		}
		size_t outlen = 0;
		if (EVP_PKEY_decrypt(p_ctx.get(), nullptr, &outlen, reinterpret_cast<const unsigned char *>(kexdh.c_str()), kexdh.size()) != 1 || outlen > max_sane_string)
			return build_error("decrypt::EVP_PKEY_decrypt: ", -1);
		if (outlen < OPMSG_RSA_ENCRYPTED_KEYLEN)
			return build_error("decrypt: Invalid secret-size for RSA encrypted message.", -1);
		secret.reset(new (nothrow) unsigned char[outlen]);
		if (EVP_PKEY_decrypt(p_ctx.get(), secret.get(), &outlen, reinterpret_cast<const unsigned char *>(kexdh.c_str()), kexdh.size()) != 1)
			return build_error("decrypt::EVP_PKEY_decrypt: ", -1);
		// The input secret buffer that was sent, have had a fixed size of this:
		slen = OPMSG_RSA_ENCRYPTED_KEYLEN;
	} else {
		vector<unsigned char> secret_v;
		secret_v.reserve(0x1000);

		// could also be ec_dh.size(), but see above comment for accepting fewer Kex'es
		for (unsigned int i = 0; i < kexdhs.size(); ++i) {
			kexdh = kexdhs[i];

			// do the (EC)DH kex
			unique_ptr<BIGNUM, decltype(&BN_free)> bn{
				BN_bin2bn(reinterpret_cast<const unsigned char *>(kexdh.c_str()), kexdh.size(), nullptr),
				BN_free
			};
			if (!bn.get())
				return build_error("decrypt::BN_bin2bn: ", -1);

			unique_ptr<unsigned char[]> bin(nullptr), native_bin(nullptr);

			OSSL_PARAM params[12];

			// These must be declared outside the following if{} block, as the PARAM constructions must stay in valid scope that is
			// beyond this enclosing block, as the addresses would be referenced out of scope otherwise.
			int one = 1;
			unsigned int dh_bits = 0, dh_g = 0;
			unsigned char dh_p[8192] = {0}, ec_a[8192] = {0}, ec_b[8192] = {0}, ec_p[8192] = {0}, ec_g[8192] = {0}, ec_order[8192] = {0};
			char cmp[]{"compressed"}, nc[]{"named_curve"};
			char ec_grp[64] = {0};

			// bn is a BN pubkey in DH case...
			if (EVP_PKEY_base_id(ec_dh[i]->d_priv) == EVP_PKEY_DH) {

				if (i > 0)
					return build_error("decrypt: Huh? No more than 1 DH key in Kex allowed.", -1);

				// obtain the DH parameters from our privkey and construct a peerkey of them,
				// containing the pubkey from the Kex and our known DH params
				params[0] = OSSL_PARAM_construct_BN("p", dh_p, sizeof(dh_p));
				params[1] = OSSL_PARAM_construct_uint("g", &dh_g);
				params[2] = OSSL_PARAM_construct_uint("bits", &dh_bits);
				params[3] = OSSL_PARAM_END;

				if (EVP_PKEY_get_params(ec_dh[i]->d_priv, params) != 1)
					return build_error("decrypt::EVP_PKEY_get_params:", -1);

				auto nlen = BN_num_bytes(bn.get());
				native_bin.reset(new (nothrow) unsigned char[nlen]);
				if (!native_bin.get())
					return build_error("decrypt::OOM", -1);
				if (BN_bn2nativepad(bn.get(), native_bin.get(), nlen) == -1)
					return build_error("decrypt::BN_bn2nativepad:", -1);

				// attention: the OSSL_PARAM_construct_BN() params are in native bin format, unlike what BN_bn2bin() produces,
				// so we have to use BN_bn2nativepad() when passing this parameter here. Ugly OpenSSL :(
				params[3] = OSSL_PARAM_construct_BN("pub", native_bin.get(), nlen);
				params[4] = OSSL_PARAM_END;

				p_ctx.reset(EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr));

			// ...and a compressed EC_POINT pubkey in ECDH case
			} else {

				params[0] = OSSL_PARAM_construct_utf8_string("group", ec_grp, sizeof(ec_grp));
				params[1] = OSSL_PARAM_construct_BN("p", ec_p, sizeof(ec_p));
				params[2] = OSSL_PARAM_construct_BN("a", ec_a, sizeof(ec_a));
				params[3] = OSSL_PARAM_construct_BN("b", ec_b, sizeof(ec_b));
				params[4] = OSSL_PARAM_construct_octet_string("generator", ec_g, sizeof(ec_g));
				params[5] = OSSL_PARAM_construct_BN("order", ec_order, sizeof(ec_order));
				params[6] = OSSL_PARAM_END;

				if (EVP_PKEY_get_params(ec_dh[i]->d_priv, params) != 1)
					return build_error("decrypt::EVP_PKEY_get_params:", -1);

				auto nlen = BN_num_bytes(bn.get());
				bin.reset(new (nothrow) unsigned char[nlen]);
				if (!bin.get())
					return build_error("decrypt::OOM", -1);
				if (BN_bn2bin(bn.get(), bin.get()) <= 0)
					return build_error("decrypt::BN_bn2bin:", -1);

				int pidx = 0;

				// valid EC group name obtained?
				if (ec_grp[0] != 0) {
					params[1] = OSSL_PARAM_construct_utf8_string("encoding", nc, 0);
					pidx = 2;
				} else
					pidx = 6;

				params[pidx++] = OSSL_PARAM_construct_utf8_string("point-format", cmp, 0);
				params[pidx++] = OSSL_PARAM_construct_int("include-public", &one);

				// Then again, for ECDH the _octet_string() params are NOT in native but in BN_bn2bin() format. %)
				params[pidx++] = OSSL_PARAM_construct_octet_string("pub", bin.get(), nlen);
				params[pidx++] = OSSL_PARAM_END;

				p_ctx.reset(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
			}

			EVP_PKEY *tpk = nullptr;
			unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> peer_key{
				nullptr,
				EVP_PKEY_free
			};
			if (!p_ctx.get() || EVP_PKEY_fromdata_init(p_ctx.get()) != 1)
				return build_error("decrypt::EVP_PKEY_fromdata_init:", -1);
			if (EVP_PKEY_fromdata(p_ctx.get(), &tpk, EVP_PKEY_PUBLIC_KEY, params) != 1 || !tpk)
				return build_error("decrypt::EVP_PKEY_fromdata:", -1);
			peer_key.reset(tpk);

			unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx{
				EVP_PKEY_CTX_new(ec_dh[i]->d_priv, nullptr),
				EVP_PKEY_CTX_free
			};
			if (!ctx.get() || EVP_PKEY_derive_init(ctx.get()) != 1)
				return build_error("decrypt::EVP_PKEY_derive_init: ", -1);
			if (EVP_PKEY_derive_set_peer(ctx.get(), peer_key.get()) != 1)
				return build_error("decrypt::EVP_PKEY_derive_set_peer: ", -1);

			// find len
			size_t len = 0;
			if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1)
				return build_error("decrypt::EVP_PKEY_derive: ", -1);
			if ((unsigned int)slen > max_sane_string || len > max_sane_string || len < min_entropy_bytes)
				return build_error("decrypt: Insane large or too small derived keylen.", -1);
			vector<unsigned char> secret_i(len, 0);
			if (EVP_PKEY_derive(ctx.get(), &secret_i[0], &len) != 1)
				return build_error("decrypt::EVP_PKEY_derive for key " + d_kex_id_hex, -1);
			slen += (int)len;
			secret_v.insert(secret_v.end(), secret_i.begin(), secret_i.end());
		}

		if ((unsigned int)slen != secret_v.size() || (unsigned int)slen > max_sane_string)
			return build_error("decrypt: Huh? Mismatch in calculated secret sizes.", -1);

		secret.reset(new (nothrow) unsigned char[slen]);
		if (!secret.get())
			return build_error("decrypt: OOM", -1);
		memcpy(secret.get(), &secret_v[0], slen);
	}

	p_ctx.reset(nullptr);

	string pqsalt1{""};
	if (dst_persona->is_pq1())
		pqsalt1 = dst_persona->get_pqsalt1();

	unsigned char key[OPMSG_MAX_KEY_LENGTH] = {0};
	if (kdf_v1234(d_version, secret.get(), slen, d_src_id_hex, d_dst_id_hex, pqsalt1, key) < 0)
		return build_error("decrypt: Error deriving key: ", -1);

	unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> c_ctx{
		EVP_CIPHER_CTX_new(),
		EVP_CIPHER_CTX_free
	};
	if (!c_ctx.get())
		return build_error("decrypt::EVP_CIPHER_CTX_new:", -1);
	if (EVP_DecryptInit_ex(c_ctx.get(), algo2cipher(d_calgo), nullptr, key, iv) != 1)
		return build_error("decrypt::EVP_DecryptInit_ex: ", -1);

	if (has_aad) {
		int aadlen = 0;
		if (EVP_CIPHER_CTX_ctrl(c_ctx.get(), EVP_CTRL_AEAD_SET_TAG, aad_tag.size(), &aad_tag[0]) != 1)
			return build_error("decrypt::EVP_CIPHER_CTX_ctrl: ", -1);

		if (d_version > 3) {
			string::size_type idx;
			if ((idx = aead_hdr.find(marker::aad_tag)) == string::npos)
				return build_error("decrypt: Can't find AAD tag (1).", -1);
			auto nl_idx = aead_hdr.find("\n", idx);
			if (nl_idx == string::npos)
				return build_error("decrypt: Can't find AAD tag (2).", -1);
			aead_hdr.erase(idx, nl_idx - idx + 1);
		}

		auto aead = derive_aead(d_version, d_src_id_hex, aead_hdr);
		if (!aead.size())
			return build_error("decrypt: Can't derive AEAD.", -1);
		if (EVP_DecryptUpdate(c_ctx.get(), nullptr, &aadlen, &aead[0], aead.size()) != 1)
			return build_error("decrypt::EVP_DecryptUpdate (AEAD):", -1);
	}
	EVP_CIPHER_CTX_set_padding(c_ctx.get(), 1);

	raw.erase(remove(raw.begin(), raw.end(), '\n'), raw.end());

	string plaintext = "";
	string b64_enc = "", enc = "";
	// multiple of 3, 4  on b64 boundary, if read in chunks of this size
	const size_t blen = 0x100000*3*4;
	unique_ptr<unsigned char[]> outbuf(new (nothrow) unsigned char[blen + EVP_MAX_BLOCK_LENGTH]);
	if (!outbuf.get())
		return build_error("decrypt: OOM", -1);
	int outlen = 0;
	string::size_type rawsize = raw.size(), idx = 0;
	while (idx < rawsize) {
		outlen = 0;
		if (rawsize - idx < blen)
			n = rawsize - idx;
		else
			n = blen;
		enc = "";
		b64_decode(raw.c_str() + idx, n, enc);
		if (enc.empty() || enc.size() > n)
			return build_error("decrypt::b64_decode: Invalid Base64 input.", -1);
		idx += n;
		if (EVP_DecryptUpdate(c_ctx.get(), outbuf.get(), &outlen, (unsigned char *)enc.c_str(), enc.size()) != 1)
			return build_error("decrypt::EVP_DecryptUpdate:", -1);
		if (idx == rawsize) {
			int padlen = 0;
			if (EVP_DecryptFinal_ex(c_ctx.get(), outbuf.get() + outlen, &padlen) != 1)
				return build_error("decrypt::EVP_DecryptFinal_ex: AAD check failed?", -1);
			outlen += padlen;
		}
		plaintext += string(reinterpret_cast<char *>(outbuf.get()), outlen);
	}

	raw = plaintext;
	plaintext.clear();

	// Now that integrity is also AEAD-proof (if it exists), import the new (EC)DH keys
	// that shipped with the message
	for (auto it = d_ecdh_keys.begin(); it != d_ecdh_keys.end();) {
		// d_ec_domains validity checked in parse_hdr()
		vector<string> v(it, it + d_ec_domains);
		if ((src_persona->add_dh_pubkey(d_khash, v)).empty())
			it = d_ecdh_keys.erase(it, it + d_ec_domains);
		else
			it += d_ec_domains;
	}

	return 1;
}


}


