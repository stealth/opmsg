/*
 * This file is part of the opmsg crypto message framework.
 *
 * (C) 2015-2016 by Sebastian Krahmer,
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
#include "message.h"
#include "deleters.h"
#include "marker.h"


extern "C" {
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
}

#include "missing.h"

namespace opmsg {

using namespace std;


static string::size_type lwidth = 80, max_sane_string = 0x1000, min_entropy_bytes = 16;


//                                                                                                                                          64
static int kdf_v123(unsigned int vers, unsigned char *secret, int slen, const string &s1, const string &s2, unsigned char key[OPMSG_MAX_KEY_LENGTH])
{
	unsigned int hlen = 0;
	unsigned char digest[EVP_MAX_MD_SIZE];	// 64 which matches sha512

	if (slen <= 0 || vers < 1 || vers > 3)
		return -1;
	memset(key, 0xff, OPMSG_MAX_KEY_LENGTH);

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
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

	if (EVP_DigestFinal_ex(md_ctx.get(), digest, &hlen) != 1)
		return -1;

	if (hlen > OPMSG_MAX_KEY_LENGTH)
		hlen = OPMSG_MAX_KEY_LENGTH;
	memcpy(key, digest, hlen);
	return 0;
}


static int kdf_v1(unsigned char *secret, int slen, unsigned char key[OPMSG_MAX_KEY_LENGTH])
{
	return kdf_v123(1, secret, slen, "", "", key);
}


int message::sign(const string &msg, persona *src_persona, string &result)
{
	size_t siglen = 0;
	RSA *rsa = nullptr;

	result = "";

	if (!src_persona->can_sign())
		return build_error("sign:: Persona has no pkey.", -1);

	// do not take ownership
	EVP_PKEY *evp = src_persona->get_pkey()->d_priv;

	if ((rsa = EVP_PKEY_get1_RSA(evp))) {
		RSA_blinding_on(rsa, nullptr);
		RSA_free(rsa);
		rsa = nullptr;
	}

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return build_error("sign::EVP_MD_CTX_create:", -1);
	if (EVP_DigestSignInit(md_ctx.get(), nullptr, algo2md(shash), nullptr, evp) != 1)
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
	unsigned char iv[OPMSG_MAX_IV_LENGTH], iv_kdf[OPMSG_MAX_KEY_LENGTH];
	char aad_tag[16];
	RSA *rsa = nullptr;
	// an ECDH or DH key
	vector<PKEYbox *> ec_dh;
	vector<string> b64pubkeys;
	string outmsg = "", b64sig = "", iv_b64 = "", b64_aad_tag = "";
	string::size_type aad_tag_insert_pos = string::npos;
	bool no_dh_key = (kex_id_hex == marker::rsa_kex_id);
	int ecode = 0;
	size_t n = 0;
	unsigned int i = 0;

	for (i = 0; i < sizeof(iv); ++i)
		iv[i] = i;

	memset(aad_tag, 0, sizeof(aad_tag));

	if (!src_persona || !dst_persona)
		return build_error("encrypt: No src/dst personas specified!", -1);

	if (!is_valid_halgo(phash) || !is_valid_halgo(khash) || !is_valid_halgo(shash) || !is_valid_calgo(calgo))
		return build_error("encrypt: Invalid algo name(s).", -1);

	if (!is_hex_hash(src_id_hex) || !is_hex_hash(dst_id_hex))
		return build_error("encrypt: Invalid persona id(s).", -1);

	if (src_id_hex != src_persona->get_id() || dst_id_hex != dst_persona->get_id())
		return build_error("encrypt: Persona/ID specification mismatch.", -1);

	if (!is_hex_hash(kex_id_hex))
		return build_error("encrypt: Invalid DH key id " + kex_id_hex, -1);

	if (!src_persona->can_sign())
		return build_error("encrypt: missing signature key for src persona " + src_id_hex, -1);
	if (!dst_persona->can_encrypt())
		return build_error("encrypt:: missing key for dst persona " + dst_id_hex, -1);

	if (!no_dh_key) {
		ec_dh = dst_persona->find_dh_key(kex_id_hex);
		if (ec_dh.empty() || !ec_dh[0]->can_encrypt())
			return build_error("encrypt: Invalid (EC)DH key id " + kex_id_hex, -1);
	}

	if (RAND_bytes(iv, sizeof(iv)) != 1)
		return build_error("encrypt::RAND_bytes:", -1);

	// this is only to not directly use random bytes in the IV. No real 'KDF' and hence v1.
	if (kdf_v1(iv, sizeof(iv), iv_kdf) < 0)
		return build_error("encrypt: Error deriving IV: ", -1);
	memcpy(iv, iv_kdf, sizeof(iv));
	b64_encode(reinterpret_cast<char *>(iv), sizeof(iv), iv_b64);

	outmsg = marker::algos + phash + ":" + khash + ":" + shash + ":" + calgo + ":" + iv_b64 + "\n";

	char cfg_s[32] = {0};
	snprintf(cfg_s, sizeof(cfg_s), "%s%u:%u:\n", marker::cfg_num.c_str(), version, ec_domains);
	outmsg += cfg_s;

	// in case of GCM modes, the AAD tag value goes right here
	aad_tag_insert_pos = outmsg.size();

	outmsg += marker::src_id + src_id_hex + "\n";
	outmsg += marker::dst_id + dst_id_hex + "\n";
	outmsg += marker::kex_id + kex_id_hex + "\n";

	// null encryption: plaintext signing case
	if (calgo == "null") {
		outmsg += marker::opmsg_databegin;
		outmsg += raw;
		if (sign(outmsg, src_persona, b64sig) != 1)
			return build_error("encrypt::" + err, -1);

		outmsg.insert(0, b64sig);
		if (version == 1)
			outmsg.insert(0, marker::version1);
		else if (version == 2)
			outmsg.insert(0, marker::version2);
		else
			outmsg.insert(0, marker::version3);
		outmsg.insert(0, marker::opmsg_begin);
		outmsg += marker::opmsg_end;
		raw = outmsg;
		return 1;
	}

	bool has_aad = (calgo.find("gcm") != string::npos || calgo == "chacha20-poly1305");

	// append public (EC)DH keys
	for (auto it = ecdh_keys.begin(); it != ecdh_keys.end(); ++it) {
		outmsg += *it;
		outmsg += "\n";
	}


	// Kex (DH if avail, RSA as fallback for DH. EC personas have no RSA fallback)
	int slen = OPMSG_RSA_ENCRYPTED_KEYLEN;
	unique_ptr<unsigned char[]> secret(new (nothrow) unsigned char[slen]);
	if (!secret.get())
		return build_error("encrypt: OOM", -1);

	if (!ec_dh.empty() && (EVP_PKEY_base_id(ec_dh[0]->d_pub) == EVP_PKEY_DH)) {
		const BIGNUM *his_pub_key = nullptr, *my_pub_key = nullptr;
		unique_ptr<DH, DH_del> dh(EVP_PKEY_get1_DH(ec_dh[0]->d_pub), DH_free);
		if (!dh.get())
			return build_error("encrypt: OOM", -1);
		unique_ptr<DH, DH_del> mydh(DHparams_dup(dh.get()), DH_free);
		if (!mydh.get() || DH_generate_key(mydh.get()) != 1 || DH_check(mydh.get(), &ecode) != 1)
			return build_error("encrypt::DH_generate_key: Cannot generate DH key ", -1);
		// re-calculate size for secret in the DH case; it differs
		slen = DH_size(mydh.get());
		secret.reset(new (nothrow) unsigned char[slen]);
		opmsg::DH_get0_key(dh.get(), &his_pub_key, nullptr);
		if (!secret.get() || DH_compute_key(secret.get(), his_pub_key, mydh.get()) != slen)
			return build_error("encrypt::DH_compute_key: Cannot compute DH key ", -1);

		opmsg::DH_get0_key(mydh.get(), &my_pub_key, nullptr);
		int binlen = BN_num_bytes(my_pub_key);
		unique_ptr<unsigned char[]> bin(new (nothrow) unsigned char[binlen]);
		if (!bin.get() || BN_bn2bin(my_pub_key, bin.get()) != binlen)
			return build_error("encrypt::BN_bn2bin: Cannot convert DH key ", -1);

		string s = "";
		b64_encode(reinterpret_cast<char *>(bin.get()), binlen, s);
		b64pubkeys.push_back(s);

	} else if (!ec_dh.empty() && (EVP_PKEY_base_id(ec_dh[0]->d_pub) == EVP_PKEY_EC)) {

		vector<unsigned char> secret_v;
		secret_v.reserve(0x1000);	// to avoid re-allocation
		slen = 0;

		for (unsigned int i = 0; i < ec_dh.size(); ++i) {
			if (!ec_dh[i]->can_encrypt() || EVP_PKEY_base_id(ec_dh[i]->d_pub) != EVP_PKEY_EC)
				return build_error("encrypt: Found non-ECDH key in ECDH loop.", -1);

			unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_del> ctx1(EVP_PKEY_CTX_new(ec_dh[i]->d_pub, nullptr), EVP_PKEY_CTX_free);
			if (!ctx1.get() || EVP_PKEY_keygen_init(ctx1.get()) != 1)
				return build_error("encrypt::EVP_PKEY_keygen_init:", -1);
			EVP_PKEY *ppkey = nullptr;
			if (EVP_PKEY_keygen(ctx1.get(), &ppkey) != 1)
				return build_error("encrypt::EVP_PKEY_keygen:", -1);
			unique_ptr<EVP_PKEY, EVP_PKEY_del> my_ec(ppkey, EVP_PKEY_free);
			unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_del> ctx2(EVP_PKEY_CTX_new(my_ec.get(), nullptr), EVP_PKEY_CTX_free);
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
				return build_error("encrypt::EVP_PKEY_derive for key " + kex_id_hex, -1);
			secret_v.insert(secret_v.end(), secret_i.begin(), secret_i.end());
			slen += (int)len;
			unique_ptr<EC_KEY, EC_KEY_del> ec(EVP_PKEY_get1_EC_KEY(my_ec.get()), EC_KEY_free);
			unique_ptr<BIGNUM, BIGNUM_del> bn(EC_POINT_point2bn(EC_KEY_get0_group(ec.get()),
		        	                                            EC_KEY_get0_public_key(ec.get()),
		                	                                    POINT_CONVERSION_COMPRESSED, nullptr, nullptr), BN_free);
			if (!bn.get())
				return build_error("encrypt::EC_POINT_point2bn:", -1);
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
		unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_del> p_ctx(EVP_PKEY_CTX_new(evp, nullptr), EVP_PKEY_CTX_free);
		if (!p_ctx.get())
			return build_error("encrypt:: Unable to create PKEY encryption context ", -1);
		if (EVP_PKEY_encrypt_init(p_ctx.get()) != 1)
			return build_error("encrypt::EVP_PKEY_encrypt_init:", -1);

		if ((rsa = EVP_PKEY_get1_RSA(evp))) {
			if (EVP_PKEY_CTX_set_rsa_padding(p_ctx.get(), RSA_PKCS1_PADDING) != 1)
				return build_error("encrypt::EVP_PKEY_CTX_set_rsa_padding", -1);
			RSA_free(rsa);
			rsa = nullptr;
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

	unsigned char key[OPMSG_MAX_KEY_LENGTH];
	if (kdf_v123(version, secret.get(), slen, src_id_hex, dst_id_hex, key) < 0)
		return build_error("encrypt: Error deriving key: ", -1);
	unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_del> c_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!c_ctx.get())
		return build_error("encrypt::EVP_CIPHER_CTX_new: ", -1);
	if (EVP_EncryptInit_ex(c_ctx.get(), algo2cipher(calgo), nullptr, key, iv) != 1)
		return build_error("encrypt::EVP_EncryptInit_ex: ", -1);

	// GCM ciphers need special treatment, the persona src id is used as AAD
	if (has_aad) {
		int aadlen = 0;
		if (EVP_EncryptUpdate(c_ctx.get(), nullptr, &aadlen, (unsigned char *)(src_id_hex.c_str()), src_id_hex.size()) != 1)
			return build_error("encrypt::EVP_EncryptUpdate (AAD):", -1);
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
				if (EVP_CIPHER_CTX_ctrl(c_ctx.get(), EVP_CTRL_GCM_GET_TAG, sizeof(aad_tag), aad_tag) != 1)
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
		return build_error("encrypt::" + err, -1);

	outmsg.insert(0, b64sig);
	if (version == 1)
		outmsg.insert(0, marker::version1);
	else if (version == 2)
		outmsg.insert(0, marker::version2);
	else
		outmsg.insert(0, marker::version3);
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
		if (v != version)
			return build_error("parse_hdr: Version mismatch. Someone modified the message.", -1);
		ec_domains = e;
	}

	// get AAD tag if any (only required by GCM mode ciphers and poly1305)
	if ((pos = hdr.find(marker::aad_tag)) != string::npos) {
		pos += marker::aad_tag.size();
		if ((nl = hdr.find("\n", pos)) == string::npos)
			return build_error("parse_hdr: Error finding end of AAD tag.", -1);
		string b64_aad_tag = hdr.substr(pos, nl - pos);
		b64_decode(b64_aad_tag, s);
		if (s.size() > 32)
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
	kex_id_hex = s;


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
	dst_id_hex = s;

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
		ecdh_keys.push_back(newdh);
		if (ecdh_keys.size() >= max_new_dh_keys)
			break;
	}

	if (ec_domains < 1 || ec_domains > 3 || (ecdh_keys.size() % ec_domains) != 0)
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
	RSA *rsa = nullptr;
	unsigned char iv[OPMSG_MAX_IV_LENGTH];
	vector<char> aad_tag;
	vector<string> kexdhs;
	string kexdh = "";
	unsigned int i = 0;
	int ecode = 0;
	string s = "", iv_kdf = "", b64_aad_tag = "";
	size_t n = 0;

	for (i = 0; i < sizeof(iv); ++i)
		iv[i] = i;

	// nuke leading header, dont accept leading junk
	if ((pos = raw.find(marker::opmsg_begin)) != 0)
		return build_error("decrypt: Not in OPMSGv1 format (1).", -1);
	raw.erase(0, pos + marker::opmsg_begin.size());

	version = 1;
	// next must come "version=N" , nuke it
	if ((pos = raw.find(marker::version1)) != 0) {
		version = 2;
		if ((pos = raw.find(marker::version2)) != 0) {
			version = 3;
			if ((pos = raw.find(marker::version3)) != 0)
				return build_error("decrypt: Not in OPMSG format (2). Need to update opmsg?", -1);
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

	phash = b[0]; khash = b[1]; shash = b[2]; calgo = b[3];
	if (!is_valid_halgo(phash) || !is_valid_halgo(khash) || !is_valid_halgo(shash) || !is_valid_calgo(calgo))
		return build_error("decrypt: Not in OPMSG format (8). Invalid algo name. Need to update opmsg?", -1);

	bool has_aad = (calgo.find("gcm") != string::npos || calgo == "chacha20-poly1305");

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
	src_id_hex = s;

	// for src persona, we only need native (RSA or EC) key for signature validation
	unique_ptr<persona> src_persona(new (nothrow) persona(cfgbase, src_id_hex));
	if (!src_persona.get() || src_persona->load(marker::rsa_kex_id) < 0 || !src_persona->can_verify())
		return build_error("decrypt: Unknown or invalid src persona " + src_id_hex, 0);

	// check sig
	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return build_error("decrypt::EVP_MD_CTX_create:", -1);
	EVP_PKEY *evp = src_persona->get_pkey()->d_pub;
	if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, algo2md(shash), nullptr, evp) != 1)
		return build_error("decrypt::EVP_DigestVerifyInit:", -1);
	if (EVP_DigestVerifyUpdate(md_ctx.get(), raw.c_str(), raw.size()) != 1)
		return build_error("decrypt::EVP_DigestVerifyUpdate:", -1);
	string sig = "";
	b64_decode(b64sig, sig);
	errno = 0;	// Dont consider errno on wrong message signature error message
	if (EVP_DigestVerifyFinal(md_ctx.get(), (unsigned char *)(sig.c_str()), sig.size()) != 1)
		return build_error("decrypt::EVP_DigestVerifyFinal: Message verification FAILED.", -1);

	md_ctx.reset();
	evp = nullptr;

	//
	// at this point, the message is valid authenticated by src_id
	//

	string::size_type databegin = string::npos;
	if ((databegin = raw.find(marker::opmsg_databegin)) == string::npos)
		return build_error("decrypt: Not in OPMSG format (12).", -1);

	string hdr = raw.substr(0, databegin);

	// parse the remaining parts of the header
	// Fills: kex_id_hex, dst_id_hex, kexdhs, aad_tag
	if (parse_hdr(hdr, kexdhs, aad_tag) != 1)
		return build_error("decrypt: " + err, -1);

	unique_ptr<persona> dst_persona(new (nothrow) persona(cfgbase, dst_id_hex));
	if (!dst_persona.get() || dst_persona->load(kex_id_hex) < 0 || (!dst_persona->can_decrypt() && calgo != "null"))
		return build_error("decrypt: Unknown or invalid dst persona " + dst_id_hex, 0);

	// header parsed correctly, split it off data body
	raw.erase(0, databegin + marker::opmsg_databegin.size());

	// import the new (EC)DH keys that shipped with the message
	for (auto it = ecdh_keys.begin(); it != ecdh_keys.end();) {
		// ec_domains validity checked in parse_hdr()
		vector<string> v(it, it + ec_domains);
		if ((src_persona->add_dh_pubkey(khash, v)).empty())
			it = ecdh_keys.erase(it, it + ec_domains);
		else
			it += ec_domains;
	}

	src_name = src_persona->get_name();
	src_persona.reset();

	// if null encryption, thats all!
	if (calgo == "null")
		return 1;

	// everything else have to have a kex
	if (kexdhs.empty())
		return build_error("decrypt: Missing Kex tag for non-null encryption!", -1);

	bool has_dh_key = (kex_id_hex != marker::rsa_kex_id);

	if (has_dh_key) {
		ec_dh = dst_persona->find_dh_key(kex_id_hex);
		if (ec_dh.empty())
			return build_error("decrypt::find_dh_key: No such key " + kex_id_hex, 0);
		for (auto it : ec_dh) {
			if (!it->can_decrypt())
				return build_error("decrypt::find_dh_key: No private key " + kex_id_hex, 0);
		}

		// We could make this an exact == match, but maybe peer is only using one of the many keys
		// from the cross-domain Kex (due to downgrading opmsg version or alike), so we also accept
		// less kexdh's than we have actually in the queue. This is not a security risk. Its only that
		// the peer (verified by signature) decided to use fewer EC domains than what we offered.
		// Maybe in future, this could be enforced to be an exact match.
		if (ec_dh.size() < kexdhs.size())
			return build_error("decrypt: Mismatch in number of ECDH domains.", -1);

		if (peer_isolation && !ec_dh[0]->matches_peer_id(src_id_hex))
			return build_error("decrypt: persona " + src_id_hex + " references kex id's which were sent to persona " + ec_dh[0]->get_peer_id() +
			                   ".\nAttack or isolation leak detected?\nIf not, rm ~/.opmsg/" + dst_id_hex + "/" + kex_id_hex + "/peer and try again\n"
			                   "or set peer_isolation=0 in config file.\n", -1);
	}

	// Kex: (EC)DH if avail, RSA as fallback
	int slen = 0;
	unique_ptr<unsigned char[]> secret(nullptr);
	if (!has_dh_key) {
		kexdh = kexdhs[0];
		if (!dst_persona->can_decrypt())
			return build_error("decrypt: No private PKEY for persona " + dst_persona->get_id(), 0);
		// kexdh contains pub encrypted secret, not DH BIGNUM
		evp = dst_persona->get_pkey()->d_priv;

		unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_del> p_ctx(EVP_PKEY_CTX_new(evp, nullptr), EVP_PKEY_CTX_free);
		if (!p_ctx.get())
			return build_error("decrypt:: Unable to set PKEY decryption context ", -1);
		if (EVP_PKEY_decrypt_init(p_ctx.get()) != 1)
			return build_error("decrypt::EVP_PKEY_decrypt_init", -1);

		if ((rsa = EVP_PKEY_get1_RSA(evp))) {
			RSA_blinding_on(rsa, nullptr);
			RSA_free(rsa);
			rsa = nullptr;
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
			unique_ptr<BIGNUM, BIGNUM_del> bn(BN_bin2bn(reinterpret_cast<const unsigned char *>(kexdh.c_str()), kexdh.size(), nullptr), BN_free);
			if (!bn.get())
				return build_error("decrypt::BN_bin2bn: ", -1);
			unique_ptr<EVP_PKEY, EVP_PKEY_del> peer_key(EVP_PKEY_new(), EVP_PKEY_free);
			if (!peer_key.get())
				return build_error("decrypt: OOM", -1);

			// bn is a BN pubkey in DH case...
			if (EVP_PKEY_base_id(ec_dh[i]->d_priv) == EVP_PKEY_DH) {
				if (i > 0)
					return build_error("decrypt: Huh? No more than 1 DH key in Kex allowed.", -1);
				DH *tmpdh = EVP_PKEY_get1_DH(ec_dh[i]->d_priv);	// older OpenSSL lacking get0
				if (!tmpdh)
					return build_error("decrypt: EVP_PKEY_get1_DH return NULL.", -1);
				unique_ptr<DH, DH_del> dh(DHparams_dup(tmpdh), DH_free);
				DH_free(tmpdh);
				if (!dh.get())
					return build_error("decrypt: OOM", -1);
				if (DH_check_pub_key(dh.get(), bn.get(), &ecode) != 1)
					return build_error("decrypt: DH_check_pub_key failed.", -1);
				opmsg::DH_set0_key(dh.get(), bn.release(), nullptr);
				if (EVP_PKEY_assign_DH(peer_key.get(), dh.release()) != 1)
					return build_error("decrypt::EVP_PKEY_assign_DH:", -1);
			// ...and a compressed EC_POINT pubkey in ECDH case
			} else {
				unique_ptr<EC_KEY, EC_KEY_del> my_ec(EVP_PKEY_get1_EC_KEY(ec_dh[i]->d_priv), EC_KEY_free);
				if (!my_ec.get())
					return build_error("decrypt::EVP_PKEY_get1_EC_KEY:", -1);
				const EC_GROUP *ecg0 = EC_KEY_get0_group(my_ec.get());
				if (ecg0 == nullptr)
					return build_error("decrypt::EC_KEY_get0_group:", -1);
				unique_ptr<EC_POINT, EC_POINT_del> ecp(EC_POINT_bn2point(ecg0, bn.get(), nullptr, nullptr), EC_POINT_free);
				if (!ecp.get())
					return build_error("decrypt::EC_POINT_bn2point:", -1);
				int nid = EC_GROUP_get_curve_name(ecg0);
				if (nid == 0)
					return build_error("decrypt::EC_GROUP_get_curve_name: No NID associated with curve.", -1);
				unique_ptr<EC_KEY, EC_KEY_del> peer_ec(EC_KEY_new_by_curve_name(nid), EC_KEY_free);
				if (!peer_ec.get())
					return build_error("decrypt::EC_KEY_new_by_curve_name:", -1);
				if (EC_KEY_set_public_key(peer_ec.get(), ecp.get()) != 1)
					return build_error("decrypt::EC_KEY_set_public_key:", -1);
				if (EC_KEY_check_key(peer_ec.get()) != 1)
					return build_error("decrypt::EC_KEY_check_key:", -1);
				if (EVP_PKEY_assign_EC_KEY(peer_key.get(), peer_ec.release()) != 1)
					return build_error("decrypt::EVP_PKEY_assign_EC_KEY:", -1);
			}

			unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_del> ctx(EVP_PKEY_CTX_new(ec_dh[i]->d_priv, nullptr), EVP_PKEY_CTX_free);
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
				return build_error("decrypt::EVP_PKEY_derive for key " + kex_id_hex, -1);
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

	unsigned char key[OPMSG_MAX_KEY_LENGTH];
	if (kdf_v123(version, secret.get(), slen, src_id_hex, dst_id_hex, key) < 0)
		return build_error("decrypt: Error deriving key: ", -1);

	unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_del> c_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!c_ctx.get())
		return build_error("decrypt::EVP_CIPHER_CTX_new:", -1);
	if (EVP_DecryptInit_ex(c_ctx.get(), algo2cipher(calgo), nullptr, key, iv) != 1)
		return build_error("decrypt::EVP_DecryptInit_ex: ", -1);

	if (has_aad) {
		int aadlen = 0;
		if (EVP_CIPHER_CTX_ctrl(c_ctx.get(), EVP_CTRL_GCM_SET_TAG, aad_tag.size(), &aad_tag[0]) != 1)
			return build_error("decrypt::EVP_CIPHER_CTX_ctrl: ", -1);
		if (EVP_DecryptUpdate(c_ctx.get(), nullptr, &aadlen, (unsigned char *)(src_id_hex.c_str()), src_id_hex.size()) != 1)
			return build_error("decrypt::EVP_DecryptUpdate (AAD):", -1);
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

	return 1;
}


}


