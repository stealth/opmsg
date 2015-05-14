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

#include <string>
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
}

namespace opmsg {

using namespace std;


static string::size_type lwidth = 80, max_sane_string = 0x1000;


//                                                                         64
static int kdf_v1(unsigned char *secret, int slen, unsigned char key[OPMSG_MAX_KEY_LENGTH])
{
	unsigned int hlen = 0;
	unsigned char digest[EVP_MAX_MD_SIZE];	// 64 which matches sha512

	if (slen <= 0)
		return -1;
	memset(key, 0xff, OPMSG_MAX_KEY_LENGTH);

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
	if (!md_ctx.get())
		return -1;
	if (EVP_DigestInit_ex(md_ctx.get(), EVP_sha512(), nullptr) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), secret, slen) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), marker::version.c_str(), marker::version.size()) != 1)
		return -1;
	if (EVP_DigestFinal_ex(md_ctx.get(), digest, &hlen) != 1)
		return -1;

	if (hlen > OPMSG_MAX_KEY_LENGTH)
		hlen = OPMSG_MAX_KEY_LENGTH;
	memcpy(key, digest, hlen);
	return 0;
}


int message::sign(const string &msg, persona *src_persona, string &result)
{
	size_t siglen = 0;
	EVP_MD_CTX md_ctx;

	result = "";

	EVP_MD_CTX_init(&md_ctx);
	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
	if (!evp.get())
		return build_error("signature::EVP_PKEY_new: OOM", -1);
	if (EVP_PKEY_set1_RSA(evp.get(), src_persona->get_rsa()->priv) != 1)
		return build_error("signature::EVP_PKEY_set1_RSA", -1);
	if (EVP_DigestSignInit(&md_ctx, nullptr, algo2md(shash), nullptr, evp.get()) != 1)
		return build_error("signature::EVP_DigestSignInit", -1);
	if (EVP_DigestSignUpdate(&md_ctx, msg.c_str(), msg.size()) != 1)
		return build_error("signature::EVP_DigestSignUpdate:", -1);
	if (EVP_DigestSignFinal(&md_ctx, nullptr, &siglen) != 1)
		return build_error("signature:: EVP_DigestSignFinal: Message signing failed", -1);

	unique_ptr<unsigned char[]> sig(new (nothrow) unsigned char[siglen]);
	if (!sig.get() || EVP_DigestSignFinal(&md_ctx, sig.get(), &siglen) != 1)
		return build_error("signature:: EVP_DigestSignFinal: Message signing failed", -1);
	EVP_MD_CTX_cleanup(&md_ctx);

	string s = "";
	b64_encode(reinterpret_cast<char *>(sig.get()), siglen, s);
	if (s.empty())
		return build_error("signature:: Failed to create signature", -1);

	result = marker::sig_begin;
	while (s.size() > 0) {
		result += s.substr(0, lwidth);
		s.erase(0, lwidth);
		result += "\n";
	}
	result += marker::sig_end;
	return 0;
}


int message::encrypt(string &raw, persona *src_persona, persona *dst_persona)
{
	unsigned char iv[OPMSG_MAX_IV_LENGTH], iv_kdf[OPMSG_MAX_KEY_LENGTH];
	char aad_tag[16];
	EVP_CIPHER_CTX c_ctx;
	DHbox *dh = nullptr;
	string outmsg = "", b64pubkey = "", b64sig = "", iv_b64 = "", b64_aad_tag = "";
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

	if (!dst_persona || !src_persona)
		return build_error("encrypt: Missing personas", -1);

	if (!src_persona->can_sign())
		return build_error("encrypt: missing RSA signature key for src persona " + src_id_hex, -1);

	if (!no_dh_key) {
		if (!(dh = dst_persona->find_dh_key(kex_id_hex)))
			return build_error("encrypt: Invalid DH key id " + kex_id_hex, -1);
	}

	if (RAND_bytes(iv, sizeof(iv)) != 1)
		return build_error("encrypt::RAND_bytes:", -1);

	if (kdf_v1(iv, sizeof(iv), iv_kdf) < 0)
		return build_error("encrypt: Error deriving IV: ", -1);
	memcpy(iv, iv_kdf, sizeof(iv));
	b64_encode(reinterpret_cast<char *>(iv), sizeof(iv), iv_b64);

	outmsg = marker::algos + phash + ":" + khash + ":" + shash + ":" + calgo + ":" + iv_b64 + "\n";

	// in case of GCM modes, the AAD tag value goes right after algo marker
	aad_tag_insert_pos = outmsg.size();

	outmsg += marker::src_id + src_id_hex + "\n";
	outmsg += marker::dst_id + dst_id_hex + "\n";
	outmsg += marker::kex_id + kex_id_hex + "\n";

	// null encryption: plaintext signing case
	if (calgo == "null") {
		outmsg += marker::opmsg_databegin;
		outmsg += raw;
		if (sign(outmsg, src_persona, b64sig) < 0)
			return build_error("encrypt::" + err, -1);

		outmsg.insert(0, b64sig);
		outmsg.insert(0, marker::version);
		outmsg.insert(0, marker::opmsg_begin);
		outmsg += marker::opmsg_end;
		raw = outmsg;
		return 0;
	}

	bool has_aad = (calgo.find("gcm") != string::npos);

	// append public DH keys
	for (auto it = dh_keys.begin(); it != dh_keys.end(); ++it) {
		outmsg += *it;
		outmsg += "\n";
	}


	// Kex (DH if avail, RSA as fallback)
	int slen = OPMSG_RSA_ENCRYPTED_KEYLEN;
	unique_ptr<unsigned char[]> secret(new (nothrow) unsigned char[slen]);
	if (!secret.get())
		return build_error("encrypt: OOM", -1);
	outmsg += marker::kex_begin;
	if (dh) {
		unique_ptr<DH, DH_del> mydh(DHparams_dup(dh->pub), DH_free);
		if (!mydh.get() || DH_generate_key(mydh.get()) != 1 || DH_check(mydh.get(), &ecode) != 1)
			return build_error("encrypt::DH_generate_key: Cannot generate DH key ", -1);
		// re-calculate size for secret in the DH case; it differes
		slen = DH_size(mydh.get());
		secret.reset(new (nothrow) unsigned char[slen]);
		if (!secret.get() || DH_compute_key(secret.get(), dh->pub->pub_key, mydh.get()) != slen)
			return build_error("encrypt::DH_compute_key: Cannot compute DH key ", -1);

		int binlen = BN_num_bytes(mydh->pub_key);
		unique_ptr<unsigned char[]> bin(new (nothrow) unsigned char[binlen]);
		if (!bin.get() || BN_bn2bin(mydh->pub_key, bin.get()) != binlen)
			return build_error("encrypt::BN_bn2bin: Cannot convert DH key ", -1);
		b64_encode(reinterpret_cast<char *>(bin.get()), binlen, b64pubkey);
	} else {
		if (RAND_bytes(secret.get(), slen) != 1)
			return build_error("encrypt::RAND_bytes: ", -1);

		unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
		if (!evp.get() || EVP_PKEY_set1_RSA(evp.get(), dst_persona->get_rsa()->pub) != 1)
			return build_error("encrypt:: Unable to set RSA encryption key ", -1);
		unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_del> p_ctx(EVP_PKEY_CTX_new(evp.get(), nullptr), EVP_PKEY_CTX_free);
		if (!p_ctx.get())
			return build_error("encrypt:: Unable to create RSA encryption context ", -1);
		if (EVP_PKEY_encrypt_init(p_ctx.get()) != 1)
			return build_error("encrypt::EVP_PKEY_encrypt_init:", -1);
		if (EVP_PKEY_CTX_set_rsa_padding(p_ctx.get(), RSA_PKCS1_PADDING) != 1)
			return build_error("encrypt::EVP_PKEY_CTX_set_rsa_padding", -1);
		size_t outlen = 0;
		if (EVP_PKEY_encrypt(p_ctx.get(), nullptr, &outlen, secret.get(), slen) != 1)
			return build_error("encrypt::EVP_PKEY_encrypt: ", -1);
		unique_ptr<unsigned char[]> outbuf(new (nothrow) unsigned char[outlen]);
		if (!outbuf.get())
			return build_error("encrypt: OOM", -1);
		if (EVP_PKEY_encrypt(p_ctx.get(), outbuf.get(), &outlen, secret.get(), slen) != 1)
			return build_error("encrypt::EVP_PKEY_encrypt: ", -1);

		b64_encode(reinterpret_cast<char *>(outbuf.get()), outlen, b64pubkey);
	}

	while (b64pubkey.size() > 0) {
		outmsg += b64pubkey.substr(0, lwidth);
		outmsg += "\n";
		b64pubkey.erase(0, lwidth);
	}

	outmsg += marker::kex_end;
	outmsg += marker::opmsg_databegin;

	unsigned char key[OPMSG_MAX_KEY_LENGTH];
	if (kdf_v1(secret.get(), slen, key) < 0)
		return build_error("encrypt: Error deriving key: ", -1);
	EVP_CIPHER_CTX_init(&c_ctx);
	if (EVP_EncryptInit_ex(&c_ctx, algo2cipher(calgo), nullptr, key, iv) != 1)
		return build_error("encrypt::EVP_EncryptInit_ex: ", -1);

	// GCM ciphers need special treatment, the persona src id is used as AAD
	if (has_aad) {
		int aadlen = 0;
		if (EVP_EncryptUpdate(&c_ctx, nullptr, &aadlen, (unsigned char *)(src_id_hex.c_str()), src_id_hex.size()) != 1)
			return build_error("encrypt::EVP_EncryptUpdate (AAD):", -1);
	}
	EVP_CIPHER_CTX_set_padding(&c_ctx, 1);

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
		if (EVP_EncryptUpdate(&c_ctx, outbuf.get(), &outlen, (unsigned char *)(raw.c_str() + idx), n) != 1)
			return build_error("encrypt::EVP_EncryptUpdate:", -1);
		idx += n;
		// if last chunk, also add padding from block cipher
		if (idx == rawsize) {
			int padlen = 0;
			if (EVP_EncryptFinal_ex(&c_ctx, outbuf.get() + outlen, &padlen) != 1)
				return build_error("encrypt::EVP_EncryptFinal_ex:", -1);
			outlen += padlen;
			if (has_aad) {
				if (EVP_CIPHER_CTX_ctrl(&c_ctx, EVP_CTRL_GCM_GET_TAG, sizeof(aad_tag), aad_tag) != 1)
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

	EVP_CIPHER_CTX_cleanup(&c_ctx);
	raw.clear();

	if (b64_aad_tag.size() > 0)
		outmsg.insert(aad_tag_insert_pos, b64_aad_tag);

	if (sign(outmsg, src_persona, b64sig) < 0)
		return build_error("encrypt::" + err, -1);

	outmsg.insert(0, b64sig);
	outmsg.insert(0, marker::version);
	outmsg.insert(0, marker::opmsg_begin);
	outmsg += marker::opmsg_end;

	raw = outmsg;

	return 0;
}


int message::decrypt(string &raw)
{
	string::size_type pos = string::npos, pos_sigend = string::npos, nl = string::npos;
	DHbox *dh = nullptr;
	EVP_MD_CTX md_ctx;
	EVP_CIPHER_CTX c_ctx;
	unsigned char iv[OPMSG_MAX_IV_LENGTH];
	char aad_tag[16];
	unsigned int i = 0;
	string s = "", iv_kdf = "", b64_aad_tag = "";
	size_t n = 0;

	for (i = 0; i < sizeof(iv); ++i)
		iv[i] = i;

	memset(aad_tag, 0, sizeof(aad_tag));

	// nuke leading header, dont accept leading junk
	if ((pos = raw.find(marker::opmsg_begin)) != 0)
		return build_error("decrypt: Not in OPMSGv1 format (1).", -1);
	raw.erase(0, pos + marker::opmsg_begin.size());

	// next must come "version=1", nuke it
	if ((pos = raw.find(marker::version)) != 0)
		return build_error("decrypt: Not in OPMSGv1 format (2). Need to update opmsg?", -1);
	raw.erase(0, pos + marker::version.size());

	// nuke OPMSg trailer, its also not part of signing. Do not accept junk after
	// footer.
	if ((pos = raw.find(marker::opmsg_end)) == string::npos || pos + marker::opmsg_end.size() != raw.size())
		return build_error("decrypt: Not in OPMSGv1 format (3).", -1);
	raw.erase(pos, marker::opmsg_end.size());

	// next must come signature b64 sigblob
	if ((pos = raw.find(marker::sig_begin)) != 0 || (pos_sigend = raw.find(marker::sig_end)) == string::npos)
		return build_error("decrypt: Not in OPMSGv1 format (4).", -1);

	// weird or unreasonable large signature?
	if (pos_sigend >= max_sane_string)
		return build_error("decrypt: Not in OPMSGv1 format (5).", -1);

	string b64sig = raw.substr(marker::sig_begin.size(), pos_sigend - marker::sig_begin.size());
	raw.erase(0, pos_sigend + marker::sig_end.size());

	// nuke newlines
	b64sig.erase(remove(b64sig.begin(), b64sig.end(), '\n'), b64sig.end());

	//
	// now we have the raw message that was presumably signed and the signature blob splitted from it
	//

	if ((pos = raw.find(marker::algos)) != 0)
		return build_error("decrypt: Not in OPMSGv1 format (6).", -1);

	char b[5][64];
	for (i = 0; i < 5; ++i)
		memset(b[i], 0, sizeof(b[0]));
	if (sscanf(raw.c_str() + marker::algos.size(), "%32[^:]:%32[^:]:%32[^:]:%32[^:]:%32[^\n]", b[0], b[1], b[2], b[3], b[4]) != 5)
		return build_error("decrypt: Not in OPMSGv1 format (7).", -1);

	phash = b[0]; khash = b[1]; shash = b[2]; calgo = b[3];
	if (!is_valid_halgo(phash) || !is_valid_halgo(khash) || !is_valid_halgo(shash) || !is_valid_calgo(calgo))
		return build_error("decrypt: Not in OPMSGv1 format (8). Invalid algo name. Need to update opmsg?", -1);

	// IV are 24byte encoded as b64 == 32byte
	b64_decode(reinterpret_cast<char *>(b[4]), 32, iv_kdf);
	if (iv_kdf.size() < sizeof(iv))
		return build_error("decrypt: Error decoding IV value.", -1);
	memcpy(iv, iv_kdf.c_str(), sizeof(iv));

	// get AAD tag if any (only required by GCM mode ciphers)
	if ((pos = raw.find(marker::aad_tag)) != string::npos) {
		pos += marker::aad_tag.size();
		if ((nl = raw.find("\n", pos)) == string::npos) {
			return build_error("decrypt: Error finding end of AAD tag.", -1);
		}
		b64_aad_tag = raw.substr(pos, nl - pos);
		b64_decode(b64_aad_tag, s);
		if (s.size() != sizeof(aad_tag))
			return build_error("decrypt: Invalid AAD tag size.", -1);
		memcpy(aad_tag, s.c_str(), sizeof(aad_tag));
	}

	// src persona
	if ((pos = raw.find(marker::src_id)) == string::npos)
		return build_error("decrypt: Not in OPMSGv1 format (9).", -1);
	pos += marker::src_id.size();
	nl = raw.find("\n", pos);
	if (nl == string::npos || nl - pos > max_sane_string)
		return build_error("decrypt:: Not in OPMSGv1 format (10).", -1);
	s = raw.substr(pos, nl - pos);
	if (!is_hex_hash(s))
		return build_error("decrypt: Not in OPMSGv1 format (11).", -1);
	src_id_hex = s;

	// for src persona, we only need RSA keys for signature validation
	unique_ptr<persona> src_persona(new (nothrow) persona(cfgbase, src_id_hex));
	if (!src_persona.get() || src_persona->load(marker::rsa_kex_id) < 0)
		return build_error("decrypt: Unknown src persona " + src_id_hex, -1);

	// check sig
	EVP_MD_CTX_init(&md_ctx);
	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
	if (!evp.get())
		return build_error("decrypt::EVP_PKEY_new: OOM", -1);
	if (EVP_PKEY_set1_RSA(evp.get(), src_persona->get_rsa()->pub) != 1)
		return build_error("decrypt::EVP_PKEY_set1_RSA:", -1);
	if (EVP_DigestVerifyInit(&md_ctx, nullptr, algo2md(shash), nullptr, evp.get()) != 1)
		return build_error("decrypt::EVP_DigestVerifyInit:", -1);
	if (EVP_DigestVerifyUpdate(&md_ctx, raw.c_str(), raw.size()) != 1)
		return build_error("decrypt::EVP_DigestVerifyUpdate:", -1);
	string sig = "";
	b64_decode(b64sig, sig);
	if (EVP_DigestVerifyFinal(&md_ctx, (unsigned char *)(sig.c_str()), sig.size()) != 1)
		return build_error("decrypt::EVP_DigestVerifyFinal: Message verification FAILED:", -1);

	EVP_MD_CTX_cleanup(&md_ctx);

	//
	// at this point, the message is valid authenticated by src_id
	//

	src_name = src_persona->get_name();

	// new dh keys included for later DH kex?
	string newdh = "";
	for (;;) {
		if ((pos = raw.find(marker::dh_begin)) == string::npos)
			break;
		if ((nl = raw.find(marker::dh_end, pos)) == string::npos)
			break;
		if (nl - pos > max_sane_string)
			return build_error("decrypt: Not in OPMSGv1 format (12).", -1);
		newdh = raw.substr(pos, nl + marker::dh_end.size() - pos);
		raw.erase(pos, nl + marker::dh_end.size() - pos);
		dh_keys.push_back(newdh);
		if (!src_persona->add_dh_pubkey(khash, newdh))
			dh_keys.pop_back();
		if (dh_keys.size() >= max_new_dh_keys)
			break;
	}

	src_persona.reset();

	// if null encryption, thats all!
	if (calgo == "null") {
		if ((pos = raw.find(marker::opmsg_databegin)) == string::npos)
			return build_error("decrypt: Not in OPMSGv1 format (13).", -1);
		raw.erase(0, pos + marker::opmsg_databegin.size());
		return 0;
	}

	bool has_aad = (calgo.find("gcm") != string::npos);

	// kex id
	if ((pos = raw.find(marker::kex_id)) == string::npos)
		return build_error("decrypt: Not in OPMSGv1 format (14).", -1);
	pos += marker::kex_id.size();
	nl = raw.find("\n", pos);
	if (nl == string::npos || nl - pos > max_sane_string)
		return build_error("decrypt: Not in OPMSGv1 format (15).", -1);
	s = raw.substr(pos, nl - pos);
	bool has_dh_key = (s != marker::rsa_kex_id);
	if (!is_hex_hash(s))
		return build_error("decrypt: Not in OPMSGv1 format (16).", -1);
	kex_id_hex = s;

	// the DH public part
	if ((pos = raw.find(marker::kex_begin)) == string::npos || (nl = raw.find(marker::kex_end, pos)) == string::npos)
		return build_error("decrypt: Not in OPMSGv1 format (17).", -1);
	if (nl - pos > max_sane_string)
		return build_error("decrypt: Not in OPMSGv1 format (18).", -1);
	string b64_kexdh = raw.substr(pos + marker::kex_begin.size(), nl - pos - marker::kex_begin.size());
	raw.erase(pos, nl - pos + marker::kex_end.size());
	b64_kexdh.erase(remove(b64_kexdh.begin(), b64_kexdh.end(), '\n'), b64_kexdh.end());
	string kexdh = "";
	b64_decode(b64_kexdh, kexdh);
	if (kexdh.empty())
		return build_error("decrypt: Not in OPMSGv1 format (19).", -1);

	// dst persona
	if ((pos = raw.find(marker::dst_id)) == string::npos)
		return build_error("decrypt: Not in OPMSGv1 format (20).", -1);
	pos += marker::dst_id.size();
	nl = raw.find("\n", pos);
	if (nl == string::npos || nl - pos > max_sane_string)
		return build_error("decrypt: Not in OPMSGv1 format (21).", -1);
	s = raw.substr(pos, nl - pos);
	if (!is_hex_hash(s))
		return build_error("decrypt: Not in OPMSGv1 format (22).", -1);
	dst_id_hex = s;

	unique_ptr<persona> dst_persona(new (nothrow) persona(cfgbase, dst_id_hex));
	if (!dst_persona.get() || dst_persona->load(kex_id_hex) < 0)
		return build_error("decrypt:: Unknown dst persona " + dst_id_hex, -1);
	if (has_dh_key) {
		if (!(dh = dst_persona->find_dh_key(kex_id_hex)))
			return build_error("decrypt::find_dh_key: No such key " + kex_id_hex, -1);
		if (!dh->can_decrypt())
			return build_error("decrypt::find_dh_key: No private key " + kex_id_hex, -1);
	}

	// Kex (DH if avail, RSA as fallback)
	int slen = 0;
	unique_ptr<unsigned char[]> secret(nullptr);
	if (!has_dh_key) {
		if (!dst_persona->get_rsa()->can_decrypt())
			return build_error("decrypt: No private RSA key for persona " + dst_persona->get_id(), -1);
		// kexdh contains pub encrypted secret, not DH BIGNUM
		unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
		if (!evp.get() || EVP_PKEY_set1_RSA(evp.get(), dst_persona->get_rsa()->priv) != 1)
			return build_error("decrypt:: Unable to set RSA decryption key ", -1);
		unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_del> p_ctx(EVP_PKEY_CTX_new(evp.get(), nullptr), EVP_PKEY_CTX_free);
		if (!p_ctx.get())
			return build_error("decrypt:: Unable to set RSA decryption context ", -1);
		if (EVP_PKEY_decrypt_init(p_ctx.get()) != 1)
			return build_error("decrypt::EVP_PKEY_decrypt_init", -1);
		if (EVP_PKEY_CTX_set_rsa_padding(p_ctx.get(), RSA_PKCS1_PADDING) != 1)
			return build_error("decrypt::EVP_PKEY_CTX_set_rsa_padding", -1);
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
		// do the DH kex
		unique_ptr<BIGNUM, BIGNUM_del> bn(BN_bin2bn(reinterpret_cast<const unsigned char *>(kexdh.c_str()), kexdh.size(), nullptr), BN_free);
		if (!bn.get())
			return build_error("decrypt::BN_bin2bn: ", -1);
		slen = DH_size(dh->priv);
		secret.reset(new (nothrow) unsigned char[slen]);
		// secret is binary representation of a BN
		if (!secret.get() || DH_compute_key(secret.get(), bn.get(), dh->priv) != slen)
			return build_error("decrypt::DH_compute_key for key " + kex_id_hex, -1);
	}

	unsigned char key[OPMSG_MAX_KEY_LENGTH];
	if (kdf_v1(secret.get(), slen, key) < 0)
		return build_error("decrypt: Error deriving key: ", -1);

	if ((pos = raw.find(marker::opmsg_databegin)) == string::npos)
		return build_error("decrypt: Not in OPMSGv1 format (23).", -1);
	// nuke anything until we get just encrypted (b64) payload
	raw.erase(0, pos + marker::opmsg_databegin.size());

	EVP_CIPHER_CTX_init(&c_ctx);
	if (EVP_DecryptInit_ex(&c_ctx, algo2cipher(calgo), nullptr, key, iv) != 1)
		return build_error("decrypt::EVP_DecryptInit_ex: ", -1);

	if (has_aad) {
		int aadlen = 0;
		if (EVP_CIPHER_CTX_ctrl(&c_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(aad_tag), aad_tag) != 1)
			return build_error("decrypt::EVP_CIPHER_CTX_ctrl: ", -1);
		if (EVP_DecryptUpdate(&c_ctx, nullptr, &aadlen, (unsigned char *)(src_id_hex.c_str()), src_id_hex.size()) != 1)
			return build_error("decrypt::EVP_DecryptUpdate (AAD):", -1);
	}

	EVP_CIPHER_CTX_set_padding(&c_ctx, 1);

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
		if (!enc.size() || enc.size() > n)
			break;
		idx += n;
		if (EVP_DecryptUpdate(&c_ctx, outbuf.get(), &outlen, (unsigned char *)enc.c_str(), enc.size()) != 1)
			return build_error("decrypt::EVP_DecryptUpdate:", -1);
		if (idx == rawsize) {
			int padlen = 0;
			if (EVP_DecryptFinal_ex(&c_ctx, outbuf.get() + outlen, &padlen) != 1)
				return build_error("decrypt::EVP_DecryptFinal_ex:", -1);
			outlen += padlen;
		}
		plaintext += string(reinterpret_cast<char *>(outbuf.get()), outlen);
	}

	EVP_CIPHER_CTX_cleanup(&c_ctx);
	raw = plaintext;
	plaintext.clear();

	if (has_dh_key && used_keys)
		dst_persona->used_key(kex_id_hex, 1);
	return 0;
}


}


