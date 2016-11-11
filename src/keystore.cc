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
#include <cstring>
#include <vector>
#include <memory>
#include <utility>
#include <algorithm>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

extern "C" {
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
}

#include "missing.h"
#include "marker.h"
#include "deleters.h"
#include "keystore.h"
#include "config.h"
#include "misc.h"

namespace opmsg {

using namespace std;


static int mkdir_helper(const string &base, string &result)
{
	char unique[256];
	timeval tv;

	result = "";

	gettimeofday(&tv, NULL);
	snprintf(unique, sizeof(unique), "/%zx.%zx.%d", (size_t)tv.tv_sec, (size_t)tv.tv_usec, getpid());

	string file = base + string(unique);

	if (mkdir(file.c_str(), 0700) < 0)
		return -1;

	result = file;
	return 0;
}


static int bn2hexhash(const EVP_MD *mdtype, const BIGNUM *bn, string &result)
{
	result = "";

	if (!bn)
		return -1;

	unsigned char h[EVP_MAX_MD_SIZE];
	unsigned int hlen = 0;
	memset(h, 0, sizeof(h));

	int nlen = BN_num_bytes(bn);
	if (nlen <= 0)
		return -1;
	unique_ptr<unsigned char[]> bin(new (nothrow) unsigned char[nlen]);
	if (!bin.get())
		return -1;
	BN_bn2bin(bn, bin.get());

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return -1;
	if (EVP_DigestInit_ex(md_ctx.get(), mdtype, nullptr) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), bin.get(), nlen) != 1)
		return -1;
	if (EVP_DigestFinal_ex(md_ctx.get(), h, &hlen) != 1)
		return -1;

	blob2hex(string(reinterpret_cast<char *>(h), hlen), result);
	return 0;
}


// normalize and hash a PEM pubkey
int normalize_and_hexhash(const EVP_MD *mdtype, string &s, string &result)
{
	result = "";

	unsigned char h[EVP_MAX_MD_SIZE];
	unsigned int hlen = 0;
	memset(h, 0, sizeof(h));

	string::size_type start = string::npos, end = string::npos;

	// sanitize checking, and put keyblob in a uniform format
	if ((start = s.find(marker::pub_begin)) == string::npos)
		return -1;
	if (start > 0)
		s.erase(0, start);
	// dont allow more than one key in keyblob
	if (s.find(marker::pub_begin, marker::pub_begin.size()) != string::npos)
		return -1;
	if ((end = s.find(marker::pub_end)) == string::npos)
		return -1;
	s.erase(end + marker::pub_end.size());

	// one single newline after we truncated anything after end-marker which does not contain \n
	s += "\n";

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return -1;
	if (EVP_DigestInit_ex(md_ctx.get(), mdtype, nullptr) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), s.c_str(), s.size()) != 1)
		return -1;
	if (EVP_DigestFinal_ex(md_ctx.get(), h, &hlen) != 1)
		return -1;

	// now this creates a hash that can be re-checked via e.g. sha256sum rsa.pub.pem inside keystore

	blob2hex(string(reinterpret_cast<char *>(h), hlen), result);
	return 0;
}


static int key_cb(int a1, int a2, BN_GENCB *a3)
{
	if (a1 == 1)
		fprintf(stderr, "o");
	else if (a1 == 2)
		fprintf(stderr, "O");
	else if (a1 == 3)
		fprintf(stderr, "+");
	else
		fprintf(stderr, ".");
	return 1;
}


int keystore::load(const string &hex)
{
	if (hex.size() > 0) {
		if (!is_hex_hash(hex) || hex.size() < 16)
			return build_error("keystore::load: Invalid hex id.", -1);
	}

	// assume --long form which may be used directly to access subdirs and which
	// tells us to just load a single persona of this id
	if (hex.size() > 16) {
		// was already loaded? ->load() may be called multiple times
		if (personas.count(hex) > 0)
			return 0;

		unique_ptr<persona> p(new (nothrow) persona(cfgbase, hex));
		if (!p.get())
			return build_error("keystore::load:: OOM", -1);
		if (p->load() < 0)
			return build_error("keystore::load::" + string(p->why()), -1);
		personas[hex] = p.release();
		return 0;
	}

	persona *p = nullptr;
	string dhex = "";

	DIR *d = opendir(cfgbase.c_str());
	if (!d)
		return build_error("load::opendir:", -1);

	dirent de, *result = nullptr;
	for (;;) {
		memset(&de, 0, sizeof(de));
		if (readdir_r(d, &de, &result) < 0)
			break;
		if (!result)
			break;
		dhex = result->d_name;
		if (!is_hex_hash(dhex))
			continue;

		// short id form as a filter given?
		if (hex.size() == 16 && dhex.find(hex) != 0)
			continue;

		if (personas.count(dhex) > 0)
			continue;

		p = new (nothrow) persona(cfgbase, dhex);
		if (!p)
			break;

		// might have stale DH keys or so, so dont abort on -1
		if (p->load() < 0) {
			delete p;
			continue;
		}
		personas[dhex] = p;

		// short id was given, no more loads after success
		if (hex.size() == 16)
			break;
	}
	closedir(d);

	errno = 0;
	return 0;
}


/* global version, as its needed by persona and keystore class */
int gen_ec(string &pub, string &priv, int nid, string &err)
{
	char *ptr = nullptr;

	pub = "";
	priv = "";

	if (RAND_load_file("/dev/urandom", 256) != 256)
		RAND_load_file("/dev/random", 8);

	unique_ptr<EC_KEY, EC_KEY_del> eckey(EC_KEY_new_by_curve_name(nid), EC_KEY_free);
	if (!eckey.get()) {
		err += build_error("gen_ec::EC_KEY_new_by_curve_name:");
		return -1;
	}

	if (EC_KEY_generate_key(eckey.get()) != 1) {
		err += build_error("gen_ec::EC_KEY_generate_key:");
		return -1;
	}
	if (EC_KEY_check_key(eckey.get()) != 1) {
		err += build_error("gen_ec::EC_KEY_check_key:");
		return -1;
	}

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
	unique_ptr<BIO, BIO_del> bio(BIO_new(BIO_s_mem()), BIO_free);
	if (!evp.get() || !bio.get()) {
		err += build_error("gen_ec: OOM");
		return -1;
	}
	if (EVP_PKEY_set1_EC_KEY(evp.get(), eckey.get()) != 1) {
		err += build_error("gen_ec::EVP_PKEY_set1_EC_KEY: Error generating EC key");
		return -1;
	}

/*	unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_del> ctx(EVP_PKEY_CTX_new(evp.get(), nullptr), EVP_PKEY_CTX_free);
	if (!ctx.get())
		return build_error("gen_ec: OOM", -1);
	if (EVP_PKEY_CTX_ctrl_str(ctx.get(), "ec_param_enc", "explicit") <= 0)
		return build_error("gen_ec::EVP_PKEY_CTX_ctrl_str:", -1);
*/
	if (PEM_write_bio_PUBKEY(bio.get(), evp.get()) != 1) {
		err += build_error("gen_ec::PEM_write_bio_PUBKEY: Error generating EC key");
		return -1;
	}

	long l = BIO_get_mem_data(bio.get(), &ptr);
	pub = string(ptr, l);

	bio.reset(BIO_new(BIO_s_mem()));
	if (!bio.get()) {
		err += build_error("gen_ec::BIO_new: OOM");
		return -1;
	}

	if (PEM_write_bio_PrivateKey(bio.get(), evp.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
		err += build_error("gen_ec::PEM_write_bio_PrivateKey: Error generating EC key");
		return -1;
	}

	l = BIO_get_mem_data(bio.get(), &ptr);
	priv = string(ptr, l);

	return 0;
}


int keystore::gen_ec(string &pub, string &priv, int nid)
{
	err = "keystore::";
	return opmsg::gen_ec(pub, priv, nid, err);
}


int keystore::gen_rsa(string &pub, string &priv)
{
	BIGNUM *b = nullptr;
	BN_GENCB *cb_ptr = nullptr;
	char *ptr = nullptr;

	pub = "";
	priv = "";

	if (RAND_load_file("/dev/urandom", 256) != 256)
		RAND_load_file("/dev/random", 8);

	unique_ptr<BIGNUM, BIGNUM_del> e(nullptr, BN_free);
	if (BN_dec2bn(&b, config::rsa_e.c_str()) == 0)
		return build_error("gen_rsa::BN_dec2b: Error generating RSA key", -1);
	e.reset(b);

// In OpenSSL 1.1.0, static decl of BN_GENCB disappeared and before BN_GENCB_new was not there!
#if HAVE_BN_GENCB_NEW
	unique_ptr<BN_GENCB, BN_GENCB_del> cb(BN_GENCB_new(), BN_GENCB_free);
	if (!(cb_ptr = cb.get()))
		return build_error("gen_rsa: OOM", -1);
#else
	BN_GENCB cb_s;
	cb_ptr = &cb_s;
#endif
	BN_GENCB_set(cb_ptr, key_cb, nullptr);

	unique_ptr<RSA, RSA_del> rsa(RSA_new(), RSA_free);
	if (!rsa.get())
		return build_error("gen_rsa::RSA_ne: OOM", -1);
	if (RSA_generate_key_ex(rsa.get(), config::rsa_len, e.get(), cb_ptr) != 1)
		return build_error("gen_rsa::RSA_generate_key_ex: Error generating RSA key", -1);

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
	unique_ptr<BIO, BIO_del> bio(BIO_new(BIO_s_mem()), BIO_free);
	if (!evp.get() || !bio.get())
		return build_error("gen_rsa: OOM", -1);

	if (EVP_PKEY_set1_RSA(evp.get(), rsa.get()) != 1)
		return build_error("gen_rsa::EVP_PKEY_set1_RSA: Error generating RSA key", -1);

	if (PEM_write_bio_PUBKEY(bio.get(), evp.get()) != 1)
		return build_error("gen_rsa::PEM_write_bio_PUBKEY: Error generating RSA key", -1);

	long l = BIO_get_mem_data(bio.get(), &ptr);
	pub = string(ptr, l);

	bio.reset(BIO_new(BIO_s_mem()));
	if (!bio.get())
		return build_error("gen_rsa::BIO_new: OOM", -1);

	if (PEM_write_bio_PrivateKey(bio.get(), evp.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1)
		return build_error("gen_rsa::PEM_write_bio_PrivateKey: Error generating RSA key", -1);

	l = BIO_get_mem_data(bio.get(), &ptr);
	priv = string(ptr, l);

	return 0;
}


persona *keystore::find_persona(const std::string &hex)
{
	errno = 0;
	if (!is_hex_hash(hex))
		return build_error("find_persona: Invalid id.", nullptr);

	// try to find 64bit shortcuts
	if (hex.size() == 16) {
		for (auto i : personas) {
			if (i.first.find(hex) == 0)
				return i.second;
		}
	}

	auto i = personas.find(hex);
	if (i == personas.end())
		return build_error("find_persona: No such persona.", nullptr);
	return i->second;
}


// new persona
persona *keystore::add_persona(const string &name, const string &c_pub_pem, const string &priv_pem, const string &dhparams_pem)
{
	int fd = -1;

	string type1 = marker::unknown, type2 = marker::unknown;

	// create hash (hex view) of public part and use as a reference
	string hex = "";
	string pub_pem = c_pub_pem;
	if (normalize_and_hexhash(md, pub_pem, hex) < 0)
		return build_error("add_persona: Invalid pubkey blob. Missing BEGIN/END markers?", nullptr);

	string tmpdir;
	if (mkdir_helper(cfgbase, tmpdir) < 0)
		return build_error("add_persona::mkdir:", nullptr);

	if (name.size() > 0) {
		string nfile = tmpdir + "/name";
		if ((fd = open(nfile.c_str(), O_CREAT|O_RDWR|O_EXCL, 0600)) < 0)
			return build_error("add_persona::open:", nullptr);
		if (write(fd, name.c_str(), name.size()) < 0)
			return build_error("add_persona::write:", nullptr);
		if (write(fd, "\n", 1) != 1)
			return build_error("add_persona::write:", nullptr);;
		close(fd);
	}

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp_pub(nullptr, EVP_PKEY_free);
	if (pub_pem.size() > 0) {
		unique_ptr<char, free_del> sdup(strdup(pub_pem.c_str()), free);
		unique_ptr<BIO, BIO_del> bio(BIO_new_mem_buf(sdup.get(), pub_pem.size()), BIO_free);
		if (!bio.get())
			return build_error("add_persona: OOM", nullptr);

		evp_pub.reset(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
		if (!evp_pub.get())
			return build_error("add_persona::PEM_read_bio_PUBKEY: Error reading PEM key", nullptr);

		if (EVP_PKEY_base_id(evp_pub.get()) == EVP_PKEY_EC)
			type1 = marker::ec;
		else if (EVP_PKEY_base_id(evp_pub.get()) == EVP_PKEY_RSA)
			type1 = marker::rsa;
		else
			return build_error("add_persona: Unknown persona type.", nullptr);

		string rfile = tmpdir + "/" + type1 + ".pub.pem";
		if ((fd = open(rfile.c_str(), O_CREAT|O_RDWR|O_EXCL, 0600)) < 0)
			return build_error("add_persona::open:", nullptr);
		if (write(fd, pub_pem.c_str(), pub_pem.size()) < 0)
			return build_error("add_persona::write:", nullptr);
		close(fd);
	}

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp_priv(nullptr, EVP_PKEY_free);
	if (priv_pem.size() > 0) {
		unique_ptr<char, free_del> sdup(strdup(priv_pem.c_str()), free);
		unique_ptr<BIO, BIO_del> bio(BIO_new_mem_buf(sdup.get(), priv_pem.size()), BIO_free);
		if (!bio.get())
			return build_error("add_persona: OOM", nullptr);

		evp_priv.reset(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
		if (!evp_priv.get())
			return build_error("add_persona::PEM_read_bio_PrivateKey: Error reading PEM key", nullptr);

		if (EVP_PKEY_base_id(evp_priv.get()) == EVP_PKEY_EC)
			type2 = marker::ec;
		else if (EVP_PKEY_base_id(evp_priv.get()) == EVP_PKEY_RSA)
			type2 = marker::rsa;
		else
			return build_error("add_persona: Unknown persona type.", nullptr);

		if (type1 != marker::unknown && type1 != type2)
			return build_error("add_persona: Different persona keytypes " + type1 + " vs. " + type2, nullptr);

		string rfile = tmpdir + "/" + type2 + ".priv.pem";
		if ((fd = open(rfile.c_str(), O_CREAT|O_RDWR|O_EXCL, 0600)) < 0)
			return build_error("add_persona::open:", nullptr);
		if (write(fd, priv_pem.c_str(), priv_pem.size()) < 0)
			return build_error("add_persona::write:", nullptr);
		close(fd);
	}

	string hexdir = cfgbase + "/" + hex;
	if (rename(tmpdir.c_str(), hexdir.c_str()) < 0) {
		int saved_errno = errno;
		unlink(string(tmpdir + "/" + type1 + ".priv.pem").c_str());
		unlink(string(tmpdir + "/" + type1 + ".pub.pem").c_str());
		unlink(string(tmpdir + "/name").c_str());
		rmdir(tmpdir.c_str());
		errno = saved_errno;
		return build_error("add_persona::rename: Error creating persona " + hex, nullptr);
	}

	unique_ptr<persona> p(new (nothrow) persona(cfgbase, hex, name));
	if (!p.get())
		return build_error("add_persona::OOM", nullptr);

	p->set_pkey(evp_pub.release(), evp_priv.release());
	p->pkey->pub_pem = pub_pem;
	p->pkey->priv_pem = priv_pem;
	p->set_type(type1);

	if (dhparams_pem.size() > 0 && type1 == marker::rsa) {
		if (dhparams_pem == "new") {
			if (p->new_dh_params() == nullptr)
				return build_error(p->why(), nullptr);
		} else if (p->new_dh_params(dhparams_pem) == nullptr)
			return build_error(p->why(), nullptr);
	}

	// do not free evp_ structs and persona
	personas[hex] = p.get();
	return p.release();
}


map<string, persona *>::iterator keystore::first_pers()
{
	return personas.begin();
}


map<string, persona *>::iterator keystore::end_pers()
{
	return personas.end();
}


map<string, persona *>::iterator keystore::next_pers(const map<string, persona *>::iterator &it)
{
	auto it2 = it;
	return ++it2;
}


vector<PKEYbox *> persona::find_dh_key(const string &hex)
{
	vector<PKEYbox *> v;

	// In case EC persona peer is out of ephemeral ECDH keys
	if (hex == marker::ec_kex_id && ptype == marker::ec) {
		v.push_back(pkey);
		return v;
	}

	auto i = keys.find(hex);
	if (i == keys.end())
		return build_error("find_dh_key: No such key.", v);
	return i->second;
}


map<string, vector<PKEYbox *>>::iterator persona::first_key()
{
	return keys.begin();
}


map<string, vector<PKEYbox *>>::iterator persona::end_key()
{
	return keys.end();
}


map<string, vector<PKEYbox *>>::iterator persona::next_key(const map<string, vector<PKEYbox *>>::iterator &it)
{
	auto it2 = it;
	return ++it2;
}


// only load certain DH key. Try to be as relaxed as possible about missing keys,
// and try to get one part of pub/priv if possible.
//
// Note that 'dh' key can also be a EC_KEY for ECDH. Both, DH and EC keys are inside
// the files named dh.{pub, priv}. This makes sense, as both keytypes are later used
// for a DH Kex or ECDH Kex.
//
int persona::load_dh(const string &hex)
{
	size_t r = 0;
	char buf[8192], *fr = nullptr;

	if (!is_hex_hash(hex))
		return build_error("load_dh: Not a valid (EC)DH hex id.", -1);

	if (keys.count(hex) > 0)
		return build_error("load_dh: This key was already loaded.", -1);

	string dhfile = "";
	unique_ptr<FILE, FILE_del> f(nullptr, ffclose);

	// up to 3 session keys per kex-id (kex-id is hexhash of first key)
	for (int i = 0; i < 3; ++i) {
		dhfile = "";

		// load public part of (EC)DH key
		dhfile = cfgbase + "/" + id + "/" + hex;
		if (i > 0) {
			char s[32] = {0};
			snprintf(s, sizeof(s), "/dh.pub.%d.pem", i);
			dhfile += s;
		} else
			dhfile += "/dh.pub.pem";

		unique_ptr<PKEYbox> pbox(new (nothrow) PKEYbox(nullptr, nullptr));
		if (!pbox.get())
			return build_error("load_dh: OOM", -1);
		pbox->hex = hex;

		f.reset(fopen(dhfile.c_str(), "r"));

		// Do not optimize by leaving the for loop if we dont find a pubkey.
		// We may nevertheless hold a priv key in case we send test messages to ourselfs.

		do {
			if (!f.get())
				break;
			if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
				break;
			rewind(f.get());
			unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(PEM_read_PUBKEY(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
			if (!evp.get())
				break;
			pbox->pub = evp.release();
			pbox->pub_pem = string(buf, r);
		} while (0);

		// now load private part, if available
		dhfile = cfgbase + "/" + id + "/" + hex;
		if (i > 0) {
			char s[32] = {0};
			snprintf(s, sizeof(s), "/dh.priv.%d.pem", i);
			dhfile += s;
		} else
			dhfile += "/dh.priv.pem";

		f.reset(fopen(dhfile.c_str(), "r"));
		do {
			if (!f.get())
				break;
			if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
				return build_error("load_dh::fread: invalid (EC)DH privkey " + hex, -1);
			rewind(f.get());
			unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(PEM_read_PrivateKey(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
			if (!evp.get())
				return build_error("load_dh::PEM_read_PrivateKey: Error reading (EC)DH privkey " + hex, -1);
			pbox->priv = evp.release();
			pbox->priv_pem = string(buf, r);
		} while (0);

		if (pbox->pub || pbox->priv)
			keys[hex].push_back(pbox.release());
		else {
			// this can happen, as we leave empty dir's for already imported (EC)DH keys, that
			// are tried to be re-imported from old mails in opmsg versions before using "imported" file
			if (i == 0) {
				errno = 0;
				return 0;
			}

			// Can leave for loop if didnt find pub.1 and priv.1 key
			break;
		}
	}

	// check if there was a designated peer. No problem if there isn't.
	string peerfile = cfgbase + "/" + id + "/" + hex + "/peer";
	f.reset(fopen(peerfile.c_str(), "r"));
	if (f.get()) {
		char s[512];
		memset(s, 0, sizeof(s));
		fr = fgets(s, sizeof(s) - 1, f.get());
		size_t slen = strlen(s);
		if (fr && slen > 0) {
			if (s[slen - 1] == '\n')
				s[slen - 1] = 0;
		}
		string peer = string(s);
		if (is_hex_hash(peer))
			keys[hex][0]->set_peer_id(peer);
	}

	errno = 0;
	return 0;
}


// determine type of a persona
int persona::check_type()
{
	if (!is_hex_hash(id))
		return build_error("check_type: Not a valid persona id", -1);

	string dir = cfgbase + "/" + id;
	string rsa = dir + "/rsa.pub.pem";
	struct stat st;
	if (stat(rsa.c_str(), &st) == 0) {
		ptype = marker::rsa;
	} else {
		string ec = dir + "/ec.pub.pem";
		if (stat(ec.c_str(), &st) == 0)
			ptype = marker::ec;
		else
			return build_error("check_type: Neither RSA nor EC keys found for persona.", -1);
	}

	errno = 0;
	return 0;
}


int persona::load(const std::string &dh_hex)
{
	size_t r = 0;
	char buf[8192], *fr = nullptr;
	string dir = cfgbase + "/" + id;
	string file = dir + "/name";
	string hex = "";
	DH *dhp = nullptr;

	if (!is_hex_hash(id))
		return build_error("load: Not a valid persona id", -1);
	if (dh_hex.size() > 0 && !is_hex_hash(dh_hex))
		return build_error("load: Not a valid session-key hex id", -1);

	// check our own persona type if not already known
	if (ptype == marker::unknown) {
		if (this->check_type() < 0)
			return -1;
	}

	// load name, if any
	unique_ptr<FILE, FILE_del> f(fopen(file.c_str(), "r"), ffclose);
	if (f.get()) {
		char s[512];
		memset(s, 0, sizeof(s));
		rlockf(f.get());
		fr = fgets(s, sizeof(s) - 1, f.get());
		unlockf(f.get());
		size_t slen = strlen(s);
		if (fr && slen > 0) {
			if (s[slen - 1] == '\n')
				s[slen - 1] = 0;
		}
		name = string(s);
	}

	// load default linked src, if any
	file = dir + "/srclink";
	f.reset(fopen(file.c_str(), "r"));
	if (f.get()) {
		char s[512];
		memset(s, 0, sizeof(s));
		rlockf(f.get());
		fr = fgets(s, sizeof(s) - 1, f.get());
		unlockf(f.get());
		size_t slen = strlen(s);
		if (fr && slen > 0) {
			if (s[slen - 1] == '\n')
				s[slen - 1] = 0;
		}
		link_src = string(s);
	}

	// load list of hashes of keys that have been imported once
	file = dir + "/imported";
	f.reset(fopen(file.c_str(), "r"));
	if (f.get()) {
		char s[512];
		size_t slen = 0;
		memset(s, 0, sizeof(s));
		string line = "";
		rlockf(f.get());
		while (fgets(s, sizeof(s) - 1, f.get()) != nullptr) {
			slen = strlen(s);
			if (slen < 1 || s[0] == '#')
				continue;
			line = s;
			line.erase(remove(line.begin(), line.end(), '\n'), line.end());
			string::size_type idx = 0;
			if ((idx = line.find(":")) != string::npos) {
				string h = line.substr(0, idx);
				if (is_hex_hash(h))
					imported[h] = 1;	// timestamp not needed yet
			}
		}
		unlockf(f.get());
	}

	// load EC/RSA keys
	string pub_pem = "", priv_pem = "";

	file = dir + "/" + ptype + ".pub.pem";
	f.reset(fopen(file.c_str(), "r"));
	if (!f.get())
		return build_error("load: Error reading public key file for " + id, -1);

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp_pub(PEM_read_PUBKEY(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (!evp_pub.get())
		return build_error("load::PEM_read_PUBKEY: Error reading public key file for " + id, -1);
	rewind(f.get());
	if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
		return build_error("load::fread:", -1);
	pub_pem = string(buf, r);

	file = dir + "/" + ptype + ".priv.pem";
	f.reset(fopen(file.c_str(), "r"));
	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp_priv(nullptr, EVP_PKEY_free);
	if (f.get()) {
		evp_priv.reset(PEM_read_PrivateKey(f.get(), nullptr, nullptr, nullptr));
		if (!evp_priv.get())
			return build_error("load::PEM_read_PrivateKey: Error reading private key file for " + id, -1);
		rewind(f.get());
		if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
			return build_error("load::fread:", -1);
		priv_pem = string(buf, r);
	}

	set_pkey(evp_pub.release(), evp_priv.release());
	pkey->pub_pem = pub_pem;
	pkey->priv_pem = priv_pem;

	if (ptype == marker::rsa) {
		// load DH params if avail
		file = dir + "/dhparams.pem";
		f.reset(fopen(file.c_str(), "r"));
		if (f.get()) {
			if (!PEM_read_DHparams(f.get(), &dhp, nullptr, nullptr))
				return build_error("load::PEM_read_DHparams: Error reading DH params for " + id, -1);
			dh_params = new (nothrow) DHbox(dhp, nullptr);
			// do not free dh
		}
	}

	// if a certain dh_hex was given, only load this one. A dh_hex of special kind, only
	// make us load RSA keys
	if (dh_hex.size() > 0) {
		if (dh_hex == marker::rsa_kex_id || dh_hex == marker::ec_kex_id)
			return 0;
		return this->load_dh(dh_hex);
	}

	// otherwise, add all DH keys that are available
	DIR *d = opendir(dir.c_str());
	if (!d)
		return build_error("load_keys::opendir:", -1);

	dirent de, *result = nullptr;
	for (;;) {
		memset(&de, 0, sizeof(de));
		if (readdir_r(d, &de, &result) < 0)
			break;
		if (!result)
			break;
		hex = result->d_name;
		if (!is_hex_hash(hex))
			continue;
		this->load_dh(hex);
	}
	closedir(d);

	errno = 0;
	return 0;
}


extern "C" typedef void (*vector_pkeybox_del)(vector<PKEYbox *> *);
extern "C" void vector_pkeybox_free(vector<PKEYbox *> *v)
{
	for (auto it = v->begin(); it != v->end(); ++it)
		delete *it;
	delete v;
}


PKEYbox *persona::set_pkey(EVP_PKEY *pub, EVP_PKEY *priv)
{
	if (pkey)
		delete pkey;
	pkey = new (nothrow) PKEYbox(pub, priv);
	return pkey;
}


// create new DH struct from a given PEM DH params string
DHbox *persona::new_dh_params(const string &pem)
{
	DH *dh = nullptr;
	int fd = -1;
	string file = cfgbase + "/" + id + "/dhparams.pem";

	if ((fd = open(file.c_str(), O_CREAT|O_RDWR|O_TRUNC, 0600)) < 0)
		return build_error("new_dh_params::open: Error opening DH params for " + id, nullptr);
	unique_ptr<FILE, FILE_del> f(fdopen(fd, "r+"), ffclose);
	if (!f.get()) {
		close(fd);
		return build_error("new_dh_params::fdopen:", nullptr);
	}
	wlockf(f.get());
	if (fwrite(pem.c_str(), pem.size(), 1, f.get()) != 1)
		return build_error("new_dh_params::fwrite:", nullptr);;
	rewind(f.get());

	if (!PEM_read_DHparams(f.get(), &dh, nullptr, nullptr))
		return build_error("new_dh_params::PEM_read_DHparams: Error reading DH params for " + id, nullptr);

	f.reset();	// calls unlock

	if (dh_params)
		delete dh_params;

	dh_params = new (nothrow) DHbox(dh, nullptr);
	if (!dh_params)
		return build_error("new_dh_params::OOM", nullptr);

	dh_params->pub_pem = pem;

	return dh_params;
}


DHbox *persona::new_dh_params()
{
	size_t r = 0;
	int fd = -1, ecode = 0;
	BN_GENCB *cb_ptr = nullptr;

	unique_ptr<DH, DH_del> dh(DH_new(), DH_free);
	if (!dh.get())
		return build_error("new_dh_params::DH_new: OOM", nullptr);

	if (RAND_load_file("/dev/urandom", 256) != 256)
		RAND_load_file("/dev/random", 8);

// In OpenSSL 1.1.0, static decl of BN_GENCB disappeared and before BN_GENCB_new was not there!
#if HAVE_BN_GENCB_NEW
	unique_ptr<BN_GENCB, BN_GENCB_del> cb(BN_GENCB_new(), BN_GENCB_free);
	if (!(cb_ptr = cb.get()))
		return build_error("new_dh_params: OOM", nullptr);
#else
	BN_GENCB cb_s;
	cb_ptr = &cb_s;
#endif

	BN_GENCB_set(cb_ptr, key_cb, nullptr);
	if (DH_generate_parameters_ex(dh.get(), config::dh_plen, 5, cb_ptr) != 1 || DH_check(dh.get(), &ecode) != 1)
		return build_error("new_dh_paramms::DH_generate_parameters_ex: Error generating DH params for " + id, nullptr);

	string file = cfgbase + "/" + id + "/dhparams.pem";
	if ((fd = open(file.c_str(), O_CREAT|O_RDWR|O_TRUNC, 0600)) < 0)
		return build_error("new_dh_params::open: Error opening DH params for " + id, nullptr);
	unique_ptr<FILE, FILE_del> f(fdopen(fd, "r+"), ffclose);
	if (!f.get()) {
		close(fd);
		return build_error("new_dh_params::fdopen:", nullptr);
	}
	wlockf(f.get());
	if (PEM_write_DHparams(f.get(), dh.get()) != 1)
		return build_error("new_dh_params::PEM_write_DHparams: Error writing DH params for " + id, nullptr);
	rewind(f.get());

	char buf[8192];
	if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
		return build_error("new_dh_params::fread: Error generating DH params for " + id, nullptr);

	f.reset();	// calls unlock

	if (dh_params)
		delete dh_params;

	dh_params = new (nothrow) DHbox(dh.release(), nullptr);
	if (!dh_params)
		return build_error("new_dh_params::OOM", nullptr);

	dh_params->pub_pem = string(buf, r);

	// do not call DH_free(dh)

	return dh_params;
}


// get a new ephemeral (session, kex-id) key. Bind to a destination peer if given
vector<PKEYbox *> persona::gen_kex_key(const string &hash, const string &peer)
{
	return gen_kex_key(algo2md(hash), peer);
}


vector<PKEYbox *> persona::gen_kex_key(const EVP_MD *md, const string &peer)
{
	string pub_pem = "", priv_pem = "";
	struct stat st;
	int fd = -1;

	vector<pair<string, string>> kex_keys;

	// v0 empty vector for error return
	vector<PKEYbox *> v0;
	string hex = "", h = "";

	if (ptype == marker::ec || config::ecdh_rsa) {
		err = "persona::gen_kex_key::";
		// for each defined curve
		for (unsigned int i = 0; i < config::curve_nids.size(); ++i) {
			if (opmsg::gen_ec(pub_pem, priv_pem, config::curve_nids[i], err) < 0)
				return v0;
			err = "";
			if (normalize_and_hexhash(md, pub_pem, h) < 0)
				return build_error("gen_kex_key::normalize_and_hexhash: Cant hash key.", v0);
			// first curve makes the hex-id
			if (i == 0)
				hex = h;
			kex_keys.push_back(make_pair(pub_pem, priv_pem));
		}

	} else {
		if (this->gen_dh_key(md, pub_pem, priv_pem, hex) < 0)
			return v0;
		kex_keys.push_back(make_pair(pub_pem, priv_pem));
	}

	// unlikely...
	if (keys.count(hex) > 0)
		return keys[hex];

	string hexdir = cfgbase + "/" + id + "/" + hex;
	if (stat(hexdir.c_str(), &st) == 0)
		return build_error("gen_kex_key: Error storing ECDH keys " + hex, v0);

	string tmpdir = "";
	if (mkdir_helper(cfgbase + "/" + id, tmpdir) < 0)
		return build_error("gen_kex_key::mkdir:", v0);

	unique_ptr<vector<PKEYbox *>, vector_pkeybox_del> pboxes(new (nothrow) vector<PKEYbox *>, vector_pkeybox_free);

	for (unsigned int i = 0; i < kex_keys.size(); ++i) {
		pub_pem = kex_keys[i].first;
		priv_pem = kex_keys[i].second;

		unique_ptr<char, free_del> sdup(strdup(pub_pem.c_str()), free);
		unique_ptr<BIO, BIO_del> bio(BIO_new_mem_buf(sdup.get(), pub_pem.size()), BIO_free);
		if (!bio.get())
			return build_error("gen_kex_key: OOM", v0);
		unique_ptr<EVP_PKEY, EVP_PKEY_del> evp_pub(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
		if (!evp_pub.get())
			return build_error("gen_kex_key::PEM_read_bio_PUBKEY: Error reading PEM key", v0);

		sdup.reset(strdup(priv_pem.c_str()));
		bio.reset(BIO_new_mem_buf(sdup.get(), priv_pem.size()));
		if (!bio.get())
			return build_error("gen_kex_key: OOM", v0);

		unique_ptr<EVP_PKEY, EVP_PKEY_del> evp_priv(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
		if (!evp_priv.get())
			return build_error("gen_kex_key::PEM_read_bio_PrivateKey: Error reading PEM key", v0);

		string dhfile1 = tmpdir + "/dh.pub.pem";
		if (i > 0) {
			char s[32] = {0};
			snprintf(s, sizeof(s), "/dh.pub.%d.pem", i);
			dhfile1 = tmpdir + s;
		}

		if ((fd = open(dhfile1.c_str(), O_RDWR|O_CREAT|O_EXCL, 0600)) < 0)
			return build_error("gen_kex_key::open:", v0);
		unique_ptr<FILE, FILE_del> f(fdopen(fd, "r+"), ffclose);
		if (!f.get())
			return build_error("gen_kex_key::fdopen:", v0);
		if (fwrite(pub_pem.c_str(), pub_pem.size(), 1, f.get()) != 1)
			return build_error("gen_kex_key::fwrite:", v0);
		f.reset();

		string dhfile2 = tmpdir + "/dh.priv.pem";
		if (i > 0) {
			char s[32] = {0};
			snprintf(s, sizeof(s), "/dh.priv.%d.pem", i);
			dhfile2 = tmpdir + s;
		}
		if ((fd = open(dhfile2.c_str(), O_RDWR|O_CREAT|O_EXCL, 0600)) < 0)
			return build_error("gen_kex_key::open:", v0);
		f.reset(fdopen(fd, "r+"));
		if (!f.get())
			return build_error("gen_kex_key::fdopen:", v0);
		if (fwrite(priv_pem.c_str(), priv_pem.size(), 1, f.get()) != 1)
			return build_error("gen_kex_key::fwrite:", v0);
		f.reset();

		PKEYbox *pbox = new (nothrow) PKEYbox(evp_pub.release(), evp_priv.release());
		if (!pbox)
			return build_error("gen_kex_key: OOM", v0);

		pbox->pub_pem = pub_pem;
		pbox->priv_pem = priv_pem;
		pbox->hex = hex;
		pbox->set_peer_id(peer);

		pboxes->push_back(pbox);
	}

	string peerfile = tmpdir + "/peer";
	// record any given designated peer
	// really an "if". But errors here are non-fatal and may be "break" ed
	while (peer.size() > 0 && is_hex_hash(peer)) {
		if ((fd = open(peerfile.c_str(), O_RDWR|O_CREAT|O_TRUNC, 0600)) < 0)
			break;
		string s = peer + "\n";
		if (write(fd, s.c_str(), s.size()) < 0)
			unlink(peerfile.c_str());
		close(fd);
		break;
	}


	if (rename(tmpdir.c_str(), hexdir.c_str()) < 0) {
		for (const string &s : vector<string>{"/dh.pub.pem", "/dh.priv.pem", "/dh.pub.1.pem", "/dh.priv.1.pem", "/dh.pub.2.pem", "/dh.priv.2.pem"}) {
			string s2 = tmpdir + s;
			unlink(s2.c_str());
		}
		unlink(peerfile.c_str());
		rmdir(tmpdir.c_str());
		return build_error("gen_kex_key: Error storing ECDH keys " + hex, v0);
	}

	keys[hex] = *(pboxes.release());
	return keys[hex];
}


// get a new ephemeral (session, kex-id) DH key.
int persona::gen_dh_key(const EVP_MD *md, string &pub, string &priv, string &hex)
{
	char *ptr = nullptr;
	int ecode = 0;

	if (RAND_load_file("/dev/urandom", 256) != 256)
		RAND_load_file("/dev/random", 8);

	if (!dh_params)
		return build_error("gen_dh_key: Invalid persona. No DH params for " + id, -1);

	unique_ptr<DH, DH_del> dh(DHparams_dup(dh_params->pub), DH_free);
	if (!dh.get() || DH_generate_key(dh.get()) != 1 || DH_check(dh.get(), &ecode) != 1)
		return build_error("gen_dh_key::DH_generate_key: Error generating DH key for " + id, -1);

	hex = "";
	pub = "";
	priv = "";

	BIGNUM *pub_key = nullptr;
	DH_get0_key(dh.get(), &pub_key, nullptr);
	if (bn2hexhash(md, pub_key, hex) < 0)
		return build_error("gen_dh_key::bn2hexhash: Error hashing DH key.", -1);

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
	unique_ptr<BIO, BIO_del> bio(BIO_new(BIO_s_mem()), BIO_free);
	if (!evp.get() || !bio.get())
		return build_error("gen_dh_key:: OOM", -1);

	if (EVP_PKEY_set1_DH(evp.get(), dh.get()) != 1)
		return build_error("gen_dh_key::EVP_PKEY_set1_EC_KEY: Error generating DH key", -1);

	if (PEM_write_bio_PUBKEY(bio.get(), evp.get()) != 1)
		return build_error("gen_dh_key::PEM_write_bio_PUBKEY: Error generating DH key", -1);

	long l = BIO_get_mem_data(bio.get(), &ptr);
	pub = string(ptr, l);

	bio.reset(BIO_new(BIO_s_mem()));
	if (!bio.get())
		return build_error("gen_dh_key::BIO_new: OOM", -1);

	if (PEM_write_bio_PrivateKey(bio.get(), evp.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1)
		return build_error("gen_dh_key::PEM_write_bio_PrivateKey: Error generating DH key", -1);

	l = BIO_get_mem_data(bio.get(), &ptr);
	priv = string(ptr, l);

	return 0;
}


void persona::used_key(const string &hexid, bool u)
{
	if (!is_hex_hash(hexid))
		return;
	if (hexid == marker::rsa_kex_id || hexid == marker::ec_kex_id)
		return;

	string file = cfgbase + "/" + id + "/" + hexid + "/used";
	if (!u)
		unlink(file.c_str());
	else
		close(open(file.c_str(), O_CREAT|O_EXCL, 0600));
}


vector<PKEYbox *> persona::add_dh_pubkey(const string &hash, vector<string> &pem)
{
	return add_dh_pubkey(algo2md(hash), pem);
}


// import a new (EC)DH pub key from a message to be later used for sending
// encrypted messages to this persona
vector<PKEYbox *> persona::add_dh_pubkey(const EVP_MD *md, vector<string> &pubs)
{
	struct stat st = {0};
	int fd = -1, keytype = -1, keytype0 = -1;
	string hex = "", dhfile = "", hexdir = "", tmpdir = "";
	vector<PKEYbox *> v0;	// empty vector for error return

	if (pubs.size() > 3)
		return build_error("add_dh_pubkey: Too many keys in import vector.", v0);

	unique_ptr<vector<PKEYbox *>, vector_pkeybox_del> pboxes(new (nothrow) vector<PKEYbox *>, vector_pkeybox_free);
	unique_ptr<FILE, FILE_del> f(nullptr, ffclose);

	for (unsigned int i = 0; i < pubs.size(); ++i) {
		string &pub_pem = pubs[i];

		unique_ptr<char, free_del> sdup(strdup(pub_pem.c_str()), free);
		unique_ptr<BIO, BIO_del> bio(BIO_new_mem_buf(sdup.get(), pub_pem.size()), BIO_free);
		if (!bio.get())
			return build_error("add_dh_pubkey: OOM", v0);
		unique_ptr<EVP_PKEY, EVP_PKEY_del> evp_pub(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
		if (!evp_pub.get())
			return build_error("add_dh_pubkey::PEM_read_bio_PUBKEY: Error reading PEM key", v0);

		// pin keytype
		if (i == 0)
			keytype0 = EVP_PKEY_base_id(evp_pub.get());

		keytype = EVP_PKEY_base_id(evp_pub.get());

		if (keytype != keytype0)
			return build_error("add_dh_pubkey: Mismatch in multiple keys' types. (ECDH and DH mixed).", v0);

		// DH keys are hashed differently than EC(DH) keys, as DH pubkey consists of a single
		// BN, ECDH consists of a pair of BNs (EC point)
		if (keytype == EVP_PKEY_DH) {
			if (i > 0)
				return build_error("add_dh_key:: Trying to add multiple DH keys as one.", v0);
			unique_ptr<DH, DH_del> dh(EVP_PKEY_get1_DH(evp_pub.get()), DH_free);
			BIGNUM *pub_key = nullptr;
			DH_get0_key(dh.get(), &pub_key, nullptr);
			if (!dh.get() || bn2hexhash(md, pub_key, hex) < 0)
				return build_error("add_dh_key::bn2hexhash: Error hashing DH pubkey.", v0);
		} else if (keytype == EVP_PKEY_EC) {
			string h = "";
			if (normalize_and_hexhash(md, pub_pem, h) < 0)
				return build_error("add_dh_key:: Error hashing ECDH pubkey.", v0);
			// the first key makes the hex id
			if (i == 0)
				hex = h;
		} else
			return build_error("add_dh_pubkey: Unknown key type.", v0);

		hexdir = cfgbase + "/" + id + "/" + hex;

		if (i == 0) {
			// some remote persona tries to import a key twice?
			// stat() to check if an empty key directory exists. That'd mean that
			// key was already imported and used once. Do not reimport. (Later rename()
			// would not fail on empty target dirs.)
			// Needed since older opmsg versions leave empty hexdir instead of recording
			// it in "imported" file
			if (imported.count(hex) > 0 || keys.count(hex) > 0 || stat(hexdir.c_str(), &st) == 0)
				return build_error("add_dh_pubkey: Key already exist(ed).", v0);

			if (mkdir_helper(cfgbase + "/" + id, tmpdir) < 0)
				return build_error("add_dh_key::mkdir:", v0);

			dhfile = tmpdir + "/dh.pub.pem";
		} else {
			char s[32] = {0};
			snprintf(s, sizeof(s), "/dh.pub.%d.pem", i);
			dhfile = tmpdir + s;
		}

		if ((fd = open(dhfile.c_str(), O_RDWR|O_CREAT|O_EXCL, 0600)) < 0)
			return build_error("add_dh_key::open:", v0);
		f.reset(fdopen(fd, "r+"));
		if (!f.get())
			return build_error("add_dh_key::fdopen:", v0);
		if (fwrite(pub_pem.c_str(), pub_pem.size(), 1, f.get()) != 1)
			return build_error("add_dh_key::fwrite:", v0);
		f.reset();

		PKEYbox *pbox = new (nothrow) PKEYbox(evp_pub.release(), nullptr);
		if (!pbox)
			return build_error("add_dh_pubkey:: OOM", v0);
		pbox->pub_pem = pub_pem;
		pbox->hex = hex;
		pboxes->push_back(pbox);
	}

	if (rename(tmpdir.c_str(), hexdir.c_str()) < 0) {
		for (const string &s : vector<string>{"/dh.pub.pem", "/dh.priv.pem", "/dh.pub.1.pem", "/dh.priv.1.pem", "/dh.pub.2.pem", "/dh.priv.2.pem"}) {
			string s2 = tmpdir + s;
			unlink(s2.c_str());
		}
		rmdir(tmpdir.c_str());
		return build_error("add_dh_key: Error storing (EC)DH pubkey " + hex, v0);
	}

	// record this key id as imported
	imported[hex] = 1;
	string imfile = cfgbase + "/" + id + "/imported";
	f.reset(fopen(imfile.c_str(), "a"));
	if (f.get()) {
		wlockf(f.get());
		fprintf(f.get(), "%s:1\n", hex.c_str());
	}
	f.reset();	// calls unlock

	keys[hex] = *(pboxes.release());

	return keys[hex];
}



int persona::del_dh_id(const string &hex)
{
	if (!is_hex_hash(hex))
		return build_error("del_dh_id: Invalid key id.", -1);
	if (hex == marker::rsa_kex_id || hex == marker::ec_kex_id)
		return 0;

	string dir = cfgbase + "/" + id + "/" + hex;
	if (keys.count(hex) > 0) {
		for (auto it = keys[hex].begin(); it != keys[hex].end(); ++it)
			delete *it;
		keys.erase(hex);
	}
	return rmdir(dir.c_str());
}


int persona::del_dh_priv(const string &hex)
{
	if (!is_hex_hash(hex))
		return build_error("del_dh_priv: Invalid key id.", -1);

	if (hex == marker::rsa_kex_id || hex == marker::ec_kex_id)
		return 0;

	string base = cfgbase + "/" + id + "/" + hex;
	string used = cfgbase + "/" + id + "/" + hex + "/used";
	string peer = cfgbase + "/" + id + "/" + hex + "/peer";

	int j = 0;
	struct stat st = {0};
	for (const string &s : vector<string>{"/dh.priv.pem", "/dh.priv.1.pem", "/dh.priv.2.pem"}) {
		string file = base + s;
		int fd = open(file.c_str(), O_RDWR);

		// ENOENT errors for (possibly not existing) subkeys are OK
		if (fd < 0) {
			if (j == 0 || errno != ENOENT)
				return build_error("del_dh_priv: Unable to open keyfile for shredding.", -1);
			else
				continue;
		}

		if (fstat(fd, &st) < 0)
			return build_error("del_dh_priv: Unable to fstat keyfile during shredding.", -1);

		char buf[512];
		memset(buf, 0, sizeof(buf));
		for (off_t i = 0; i < st.st_size; i += sizeof(buf)) {
			if (write(fd, buf, sizeof(buf)) > 0)
				sync();
		}
		close(fd);
		unlink(file.c_str());
		++j;
	}

	unlink(used.c_str());
	unlink(peer.c_str());

	if (keys.count(hex) > 0) {
		for (auto it = keys[hex].begin(); it != keys[hex].end(); ++it) {
			(*it)->priv_pem = "";
			EVP_PKEY_free((*it)->priv); (*it)->priv = nullptr;
		}
	}

	errno = 0;
	return 0;
}


// do not delete private keys
int persona::del_dh_pub(const string &hex)
{
	if (!is_hex_hash(hex))
		return build_error("del_dh_pub: Invalid key id.", -1);
	if (hex == marker::rsa_kex_id || hex == marker::ec_kex_id)
		return 0;

	string file = cfgbase + "/" + id + "/" + hex;
	for (const string &s : vector<string>{"/dh.pub.pem", "/dh.pub.1.pem", "/dh.pub.2.pem"})
		unlink((file + s).c_str());

	if (keys.count(hex) > 0) {
		for (auto it = keys[hex].begin(); it != keys[hex].end(); ++it) {
			(*it)->pub_pem = "";
			EVP_PKEY_free((*it)->pub); (*it)->pub = nullptr;
		}
	}
	return 0;
}


int persona::link(const string &hex)
{
	if (!is_hex_hash(hex))
		return build_error("link: Invalid src id.", -1);

	string file = cfgbase + "/" + id + "/srclink";

	int saved_errno = 0;
	int fd = open(file.c_str(), O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (fd >= 0) {
		wlockf(fd);
		if (write(fd, hex.c_str(), hex.size()) < 0)
			saved_errno = errno;
		if (write(fd, "\n", 1) < 0)
			saved_errno = errno;
		unlockf(fd);
		close(fd);
	} else
		return build_error("link: ", -1);

	if (saved_errno != 0) {
		errno = saved_errno;
		return build_error("link::write:", -1);
	}

	return 0;
}


} // namespace

