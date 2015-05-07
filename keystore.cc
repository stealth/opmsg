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
#include <cstring>
#include <memory>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

extern "C" {
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
}

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


static int bn2hex(const EVP_MD *mdtype, const BIGNUM *bn, string &result)
{
	result = "";

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

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
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


static int key_cb(int a1, int a2, BN_GENCB *a3)
{
	if (a1 == 2)
		fprintf(stderr, "o");
	else if (a1 == 3)
		fprintf(stderr, "O");
	else
		fprintf(stderr, ".");
	return 1;
}


int keystore::load(const string &hex)
{
	if (!is_hex_hash(hex))
		return build_error("keystore::load: Invalid hex id.", -1);
	unique_ptr<persona> p(new (nothrow) persona(cfgbase, hex));
	if (!p.get())
		return build_error("keystore::load:: OOM", -1);
	p->load();
	personas[hex] = p.release();
	return 0;
}


int keystore::load()
{
	persona *p = nullptr;
	string hex = "";

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
		hex = result->d_name;
		if (!is_hex_hash(hex))
			continue;
		p = new (nothrow) persona(cfgbase, hex);
		if (!p)
			break;

		// might have stale DH keys or so, so dont abort on -1
		if (p->load() < 0) {
			delete p;
			continue;
		}
		personas[hex] = p;
	}
	closedir(d);
	return 0;
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

// In OpenSSL 1.1.0, static decl of BN_GENCB disappeared and before BN_GENCB_new was bot there!
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
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
persona *keystore::add_persona(const string &name, const string &rsa_pub_pem, const string &rsa_priv_pem, const string &dhparams_pem)
{
	int fd = -1;

	string tmpdir;
	if (mkdir_helper(cfgbase, tmpdir) < 0)
		return build_error("add_persona::mkdir:", nullptr);

	if (name.size() > 0) {
		string nfile = tmpdir + "/name";
		if ((fd = open(nfile.c_str(), O_CREAT|O_RDWR|O_EXCL, 0600)) < 0)
			return build_error("add_persona::open:", nullptr);
		write(fd, name.c_str(), name.size());
		write(fd, "\n", 1);
		close(fd);
	}

	unique_ptr<RSA, RSA_del> rpub(nullptr, RSA_free), rpriv(nullptr, RSA_free);

	if (rsa_pub_pem.size() > 0) {
		string rfile = tmpdir + "/rsa.pub.pem";
		if ((fd = open(rfile.c_str(), O_CREAT|O_RDWR|O_EXCL, 0600)) < 0)
			return build_error("add_persona::open:", nullptr);
		write(fd, rsa_pub_pem.c_str(), rsa_pub_pem.size());
		close(fd);

		unique_ptr<FILE, FILE_del> f(fopen(rfile.c_str(), "r"), ffclose);
		if (!f.get())
			 return build_error("add_persona::fopen:", nullptr);
		unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(PEM_read_PUBKEY(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
		if (!evp.get())
			return build_error("add_persona::PEM_read_PUBKEY: Error reading RSA key", nullptr);
		rpub.reset(EVP_PKEY_get1_RSA(evp.get()));
		if (!rpub.get())
			return build_error("add_persona::EVP_PKEY_get1_RSA: Error reading RSA key", nullptr);
	}

	if (rsa_priv_pem.size() > 0) {
		string rfile = tmpdir + "/rsa.priv.pem";
		if ((fd = open(rfile.c_str(), O_CREAT|O_RDWR|O_EXCL, 0600)) < 0)
			return build_error("add_persona::open:", nullptr);
		write(fd, rsa_priv_pem.c_str(), rsa_priv_pem.size());
		close(fd);

		unique_ptr<FILE, FILE_del> f(fopen(rfile.c_str(), "r"), ffclose);
		if (!f.get())
			return build_error("add_persona::fopen:", nullptr);
		unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(PEM_read_PrivateKey(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
		if (!evp.get())
			return build_error("add_persona::PEM_read_PrivateKey: Error reading RSA key", nullptr);
		rpriv.reset(EVP_PKEY_get1_RSA(evp.get()));
		if (!rpriv.get())
			return build_error("add_persona::EVP_PKEY_get1_RSA: Error reading RSA key", nullptr);
	}


	// create hash (hex view) of public RSA modulus and use as a reference
	string hex = "";
	if (bn2hex(md, rpub->n, hex) < 0)
		return build_error("add_persona: Error hashing RSA pubkey", nullptr);
	string hexdir = cfgbase + "/" + hex;
	if (rename(tmpdir.c_str(), hexdir.c_str()) < 0) {
		int saved_errno = errno;
		unlink(string(tmpdir + "/rsa.priv.pem").c_str());
		unlink(string(tmpdir + "/rsa.pub.pem").c_str());
		unlink(string(tmpdir + "/name").c_str());
		rmdir(tmpdir.c_str());
		errno = saved_errno;
		return build_error("add_persona::rename: Error creating persona " + hex, nullptr);
	}

	unique_ptr<persona> p(new (nothrow) persona(cfgbase, hex, name));
	if (!p.get())
		return build_error("add_persona::OOM", nullptr);

	p->set_rsa(rpub.release(), rpriv.release());
	p->rsa->pub_pem = rsa_pub_pem;
	p->rsa->priv_pem = rsa_priv_pem;

	if (dhparams_pem.size() > 0) {
		if (dhparams_pem == "new") {
			if (p->new_dh_params() == nullptr)
				return build_error(p->why(), nullptr);
		} else if (p->new_dh_params(dhparams_pem) == nullptr)
			return build_error(p->why(), nullptr);
	}

	// do not free RSA structs and persona
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


DHbox *persona::find_dh_key(const string &hex)
{
	auto i = keys.find(hex);
	if (i == keys.end())
		return build_error("find_dh_key: No such key.", nullptr);
	return i->second;
}


map<string, DHbox *>::iterator persona::first_key()
{
	return keys.begin();
}


map<string, DHbox *>::iterator persona::end_key()
{
	return keys.end();
}


map<string, DHbox *>::iterator persona::next_key(const map<string, DHbox *>::iterator &it)
{
	auto it2 = it;
	return ++it2;
}


// only load certain DH key. Try to be as relaxed as possible about missing keys,
// and try to get one part of pub/priv if possible
int persona::load_dh(const string &hex)
{
	size_t r = 0;
	char buf[8192];

	if (!is_hex_hash(hex))
		return build_error("load_dh: Not a valid DH hex id", -1);

	// load public part of DH key
	string dhfile = cfgbase + "/" + id + "/" + hex + "/dh.pub.pem";

	unique_ptr<DHbox> dhbox(new (nothrow) DHbox(nullptr, nullptr));
	if (!dhbox.get())
		return build_error("load_dh: OOM", -1);
	dhbox->hex = hex;

	unique_ptr<FILE, FILE_del> f(fopen(dhfile.c_str(), "r"), ffclose);
	do {
		if (!f.get())
			break;
		if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
			break;
		rewind(f.get());
		unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(PEM_read_PUBKEY(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
		if (!evp.get())
			break;
		unique_ptr<DH, DH_del> dh1(EVP_PKEY_get1_DH(evp.get()), DH_free);
		if (!dh1.get())
			break;
		dhbox->pub = dh1.release();
		dhbox->pub_pem = string(buf, r);
	} while (0);

	keys[hex] = dhbox.release();

	// now load private part, if available
	dhfile = cfgbase + "/" + id + "/" + hex + "/dh.priv.pem";
	f.reset(fopen(dhfile.c_str(), "r"));
	do {
		if (!f.get())
			break;
		if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
			return build_error("load_dh::fread: invalid DH privkey " + hex, -1);
		rewind(f.get());
		unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(PEM_read_PrivateKey(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
		if (!evp.get())
			return build_error("load_dh::PEM_read_PrivateKey: Error reading DH privkey " + hex, -1);
		unique_ptr<DH, DH_del> dh2(EVP_PKEY_get1_DH(evp.get()), DH_free);
		if (!dh2.get())
			return build_error("load_dh::EVP_PKEY_get1_DH: Invalid DH privkey " + hex, -1);
		keys[hex]->priv = dh2.release();
		keys[hex]->priv_pem = string(buf, r);
	} while (0);

	return 0;
}


int persona::load(const std::string &dh_hex)
{
	size_t r = 0;
	char buf[8192];
	string dir = cfgbase + "/" + id;
	string file = dir + "/name";
	string hex = "";
	DH *dhp = nullptr;

	if (!is_hex_hash(id))
		return build_error("load: Not a valid persona id", -1);
	if (dh_hex.size() > 0 && !is_hex_hash(dh_hex))
		return build_error("load: Not a valid DH hex id", -1);

	// load name, if any
	unique_ptr<FILE, FILE_del> f(fopen(file.c_str(), "r"), ffclose);
	if (f.get()) {
		char s[512];
		memset(s, 0, sizeof(s));
		fgets(s, sizeof(s) - 1, f.get());
		size_t slen = strlen(s);
		if (slen > 0) {
			if (s[slen - 1] == '\n')
				s[slen - 1] = 0;
		}
		name = string(s);
	}

	// load RSA keys
	RSA *rpub = nullptr, *rpriv = nullptr;
	string pub_pem = "", priv_pem = "";

	file = dir + "/rsa.pub.pem";
	f.reset(fopen(file.c_str(), "r"));
	if (!f.get())
		return build_error("load: Error reading public RSA file for " + id, -1);

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(PEM_read_PUBKEY(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (!evp.get())
		return build_error("load::PEM_read_PUBKEY: Error reading public RSA file for " + id, -1);
	rewind(f.get());
	if (!(rpub = EVP_PKEY_get1_RSA(evp.get())))
		return build_error("load::EVP_PKEY_get1_RSA:", -1);
	if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
		return build_error("load::fread:", -1);
	pub_pem = string(buf, r);

	file = dir + "/rsa.priv.pem";
	f.reset(fopen(file.c_str(), "r"));
	if (f.get()) {
		evp.reset(PEM_read_PrivateKey(f.get(), nullptr, nullptr, nullptr));
		if (!evp.get())
			return build_error("load::PEM_read_PrivateKey: Error reading private RSA file for " + id, -1);
		rewind(f.get());
		if (!(rpriv = EVP_PKEY_get1_RSA(evp.get())))
			return build_error("load::EVP_PKEY_get1_RSA:", -1);
		if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
			return build_error("load::fread:", -1);
		priv_pem = string(buf, r);
	}

	set_rsa(rpub, rpriv);
	rsa->pub_pem = pub_pem;
	rsa->priv_pem = priv_pem;

	// load DH params if avail
	file = dir + "/dhparams.pem";
	f.reset(fopen(file.c_str(), "r"));
	if (f.get()) {
		if (!PEM_read_DHparams(f.get(), &dhp, nullptr, nullptr))
			return build_error("load::PEM_read_DHparams: Error reading DH params for " + id, -1);
		dh_params = new (nothrow) DHbox(dhp, nullptr);
		// do not free dh
	}

	// if a certain DH hex was given, only load this one. A dh_hex of special kind, only
	// make us load RSA keys
	if (dh_hex.size() > 0) {
		if (dh_hex == marker::rsa_kex_id)
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

	return 0;
}


RSAbox *persona::set_rsa(RSA *pub, RSA *priv)
{
	if (rsa)
		delete rsa;
	rsa = new (nothrow) RSAbox(pub, priv);
	return rsa;
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
	if (fwrite(pem.c_str(), pem.size(), 1, f.get()) != 1)
		return build_error("new_dh_params::fwrite:", nullptr);;
	rewind(f.get());

	if (!PEM_read_DHparams(f.get(), &dh, nullptr, nullptr))
		return build_error("new_dh_params::PEM_read_DHparams: Error reading DH params for " + id, nullptr);

	if (dh_params)
		delete dh_params;

	dh_params = new (nothrow) DHbox(dh, nullptr);
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

// In OpenSSL 1.1.0, static decl of BN_GENCB disappeared and before BN_GENCB_new was bot there!
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	unique_ptr<BN_GENCB, BN_GENCB_del> cb(BN_GENCB_new(), BN_GENCB_free);
	if (!(cb_ptr = cb.get()))
		return build_error("gen_rsa: OOM", nullptr);
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
	if (PEM_write_DHparams(f.get(), dh.get()) != 1)
		return build_error("new_dh_params::PEM_write_DHparams: Error writing DH params for " + id, nullptr);
	rewind(f.get());

	char buf[8192];
	if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
		return build_error("new_dh_params::fread: Error generating DH params for " + id, nullptr);

	if (dh_params)
		delete dh_params;

	dh_params = new (nothrow) DHbox(dh.release(), nullptr);
	dh_params->pub_pem = string(buf, r);

	// do not call DH_free(dh)

	return dh_params;
}


DHbox *persona::gen_dh_key(const string &hash)
{
	return gen_dh_key(algo2md(hash));
}


// create an entirely new DH key (based on DH params) for this persona. Key will
// later be used to decrypt incoming msg, using existing private half of saved DH
DHbox *persona::gen_dh_key(const EVP_MD *md)
{
	char buf[8192];
	int fd = -1, ecode = 0;
	size_t r = 0;

	if (!dh_params)
		return build_error("gen_dh_key: Invalid persona. No DH params for " + id, nullptr);

	if (RAND_load_file("/dev/urandom", 256) != 256)
		RAND_load_file("/dev/random", 8);

	unique_ptr<DH, DH_del> dh1(DHparams_dup(dh_params->pub), DH_free);
	if (!dh1.get() || DH_generate_key(dh1.get()) != 1 || DH_check(dh1.get(), &ecode) != 1)
		return build_error("gen_dh_key::DH_generate_key: Error generating DH key for " + id, nullptr);

	string hex = "";
	if (bn2hex(md, dh1->pub_key, hex) < 0)
		return build_error("gen_dh_key::bn2hex: Error hashing DH key.", nullptr);

	// that case would be really weird...
	if (keys.count(hex) > 0)
		return keys[hex];

	string dhdir = cfgbase + "/" + id + "/" + hex;

	if (mkdir(dhdir.c_str(), 0700) < 0) {
		if (errno != EEXIST)
			return build_error("gen_dh_key::mkdir: Error creating DH dir for " + hex, nullptr);
	}

	string dhpub = dhdir + "/dh.pub.pem";
	if ((fd = open(dhpub.c_str(), O_RDWR|O_CREAT|O_TRUNC, 0600)) < 0)
		return build_error("gen_dh_key::open: Error creating DH pubfile " + hex, nullptr);
	unique_ptr<FILE, FILE_del> f(fdopen(fd, "r+"), ffclose);
	if (!f.get()) {
		close(fd);
		return build_error("gen_dh_key::fdopen:", nullptr);
	}
	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp1(EVP_PKEY_new(), EVP_PKEY_free);
	if (!evp1.get())
		return build_error("gen_dh_key::EVP_PKEY_new: OOM", nullptr);
	if (EVP_PKEY_set1_DH(evp1.get(), dh1.get()) != 1)
		return build_error("gen_dh_key::EVP_PKEY_set1_DH: invalid DH pubkey " + hex, nullptr);
	if (PEM_write_PUBKEY(f.get(), evp1.get()) != 1) {
		unlink(dhpub.c_str());
		rmdir(dhdir.c_str());
		return build_error("gen_dh_key::PEM_write_PUBKEY: Error writing DH pubfile " + hex, nullptr);
	}
	rewind(f.get());
	if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
		return build_error("gen_dh_key::fread: invalid DH pubkey " + hex, nullptr);
	string pub_pem = string(buf, r);
	rewind(f.get());
	// re-read PEM pubkey, to have distict public key in dh2 for DHbox()
	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp2(PEM_read_PUBKEY(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (!evp2.get())
		return build_error("gen_dh_key::PEM_read_PUBKEY: invalid DH pubkey " + hex, nullptr);
	unique_ptr<DH, DH_del> dh2(EVP_PKEY_get1_DH(evp2.get()), DH_free);
	if (!dh2.get())
		return build_error("gen_dh_key::EVP_PKEY_get1_DH: invalid DH pubkey " + hex, nullptr);
	f.reset(); // closes f and fd

	string dhpriv = dhdir + "/dh.priv.pem";
	if ((fd = open(dhpriv.c_str(), O_RDWR|O_CREAT|O_TRUNC, 0600)) < 0)
		return build_error("gen_dh_key::open: Error creating DH privfile " + hex, nullptr);
	f.reset(fdopen(fd, "r+"));
	if (!f.get()) {
		close(fd);
		return build_error("gen_dh_key::fdopen: OOM", nullptr);
	}
	if (PEM_write_PrivateKey(f.get(), evp1.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
		unlink(dhpriv.c_str());
		return build_error("gen_dh_key::PEM_write_PrivateKey: Error writing DH privfile " + hex, nullptr);
	}
	rewind(f.get());
	if ((r = fread(buf, 1, sizeof(buf), f.get())) <= 0)
		return build_error("gen_dh_key::fread: invalid DH privkey " + hex, nullptr);
	string priv_pem = string(buf, r);

	DHbox *dhb = new DHbox(dh2.release(), dh1.release());
	dhb->pub_pem = pub_pem;
	dhb->priv_pem = priv_pem;
	dhb->hex = hex;
	keys[hex] = dhb;

	return dhb;
}


void persona::used_key(const string &hexid, bool u)
{
	if (!is_hex_hash(hexid))
		return;

	string file = cfgbase + "/" + id + "/" + hexid + "/used";
	if (!u)
		unlink(file.c_str());
	else
		close(open(file.c_str(), O_CREAT|O_EXCL, 0600));
}


DHbox *persona::add_dh_pubkey(const string &hash, const string &pem)
{
	return add_dh_pubkey(algo2md(hash), pem);
}


// Create a new DH pubkey (using existing persona DH params) to persona dir.
// pub_b64 is taken from the message; key will later be used to send messages
DHbox *persona::add_dh_pubkey(const EVP_MD *md, const string &pub_pem)
{
	int fd = -1;

	if (!dh_params)
		return build_error("add_dh_key: Invalid persona (no DH params).", nullptr);

	string tmpdir = "";
	if (mkdir_helper(cfgbase + "/" + id, tmpdir) < 0)
		return build_error("add_dh_key::mkdir:", nullptr);

	string dhfile = tmpdir + "/dh.pub.pem";
	if ((fd = open(dhfile.c_str(), O_RDWR|O_CREAT|O_EXCL, 0600)) < 0)
		return build_error("add_dh_key::open:", nullptr);
	unique_ptr<FILE, FILE_del> f(fdopen(fd, "r+"), ffclose);
	if (!f.get())
		return build_error("add_dh_key::fdopen:", nullptr);
	if (fwrite(pub_pem.c_str(), pub_pem.size(), 1, f.get()) != 1)
		return build_error("add_dh_key::fwrite:", nullptr);
	rewind(f.get());
	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(PEM_read_PUBKEY(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (!evp.get())
		return build_error("add_dh_key::PEM_read_PUBKEY: Invalid PEM pubkey", nullptr);

	unique_ptr<DH, DH_del> dh(EVP_PKEY_get1_DH(evp.get()), DH_free);
	if (!dh.get())
		return build_error("add_dh_key::EVP_PKEY_get1_DY: Invalid PEM pubkey", nullptr);

	string hex = "";
	if (bn2hex(md, dh->pub_key, hex) < 0)
		return build_error("add_dh_key::bn2hex: Error hashing DH pubkey.", nullptr);

	// some remote persona tries to import a key twice?
	if (keys.count(hex) > 0) {
		unlink(dhfile.c_str());
		rmdir(tmpdir.c_str());
		return keys[hex];
	}

	string hexdir = cfgbase + "/" + id + "/" + hex;

	// if something went wrong, try to clean up; but we cant repair all mess if someone changed
	// underlying DB
	if (rename(tmpdir.c_str(), hexdir.c_str()) < 0) {
		unlink(string(hexdir + "/dh.pub.pem").c_str());
		if (rename(string(tmpdir + "/dh.pub.pem").c_str(), string(hexdir + "/dh.pub.pem").c_str()) < 0) {
			unlink(string(tmpdir + "/dh.pub.pem").c_str());
			rmdir(tmpdir.c_str());
			return build_error("add_dh_key: Error storing DH pubkey " + hex, nullptr);
		}
		rmdir(tmpdir.c_str());
	}

	DHbox *dhb = new DHbox(dh.release(), nullptr);
	dhb->pub_pem = pub_pem;
	dhb->hex = hex;
	keys[hex] = dhb;
	return dhb;
}



int persona::del_dh_id(const string &hex)
{
	if (!is_hex_hash(hex))
		return build_error("del_dh_id: Invalid key id.", -1);

	string dir = cfgbase + "/" + id + "/" + hex;
	keys.erase(hex);
	return rmdir(dir.c_str());
}


int persona::del_dh_priv(const string &hex)
{
	if (!is_hex_hash(hex))
		return build_error("del_dh_priv: Invalid key id.", -1);

	string file = cfgbase + "/" + id + "/" + hex + "/dh.priv.pem";
	unlink(file.c_str());
	auto i = keys.find(hex);
	if (i != keys.end()) {
		i->second->priv_pem = "";
		DH_free(i->second->priv); i->second->priv = nullptr;
	}
	return 0;
}


// do not delete private keys
int persona::del_dh_pub(const string &hex)
{
	if (!is_hex_hash(hex))
		return build_error("del_dh_pub: Invalid key id.", -1);

	string file = cfgbase + "/" + id + "/" + hex + "/dh.pub.pem";
	unlink(file.c_str());
	auto i = keys.find(hex);
	if (i != keys.end()) {
		i->second->pub_pem = "";
		DH_free(i->second->pub); i->second->pub = nullptr;
	}
	return 0;
}


} // namespace

