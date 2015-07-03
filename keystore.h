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

#ifndef __keystore_h__
#define __keystore_h__


#include <map>
#include <string>
#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>

#include "misc.h"
#include "marker.h"


extern "C" {
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
}

#ifndef HAVE_BN_GENCB_NEW
#define HAVE_BN_GENCB_NEW OPENSSL_VERSION_NUMBER >= 0x10100000L
#endif

namespace opmsg {


class RSAbox {

public:

	RSA *pub, *priv;

	std::string pub_pem, priv_pem, hex;


	RSAbox(RSA *p, RSA *s)
		: pub(p), priv(s), pub_pem(""), priv_pem(""), hex("")
	{
	}

	virtual ~RSAbox()
	{
		if (pub)
			RSA_free(pub);
		if (priv)
			RSA_free(priv);
	}

	bool can_sign()
	{
		return priv != nullptr;
	}

	bool can_decrypt()
	{
		return priv != nullptr;
	}

	bool can_encrypt()
	{
		return pub != nullptr;
	}
};


class PKEYbox {

public:

	EVP_PKEY *pub, *priv;

	std::string pub_pem, priv_pem, hex;


	PKEYbox(EVP_PKEY *p, EVP_PKEY *s)
		: pub(p), priv(s), pub_pem(""), priv_pem(""), hex("")
	{
	}

	virtual ~PKEYbox()
	{
		if (pub)
			EVP_PKEY_free(pub);
		if (priv)
			EVP_PKEY_free(priv);
	}

	bool can_sign()
	{
		return priv != nullptr;
	}

	bool can_decrypt()
	{
		return priv != nullptr;
	}

	bool can_encrypt()
	{
		return pub != nullptr;
	}
};


class DHbox {

public:

	DH *pub, *priv;

	std::string pub_pem, priv_pem, hex;

	DHbox(DH *dh1, DH *dh2) : pub(dh1), priv(dh2), pub_pem(""), priv_pem(""), hex("")
	{
	}

	virtual ~DHbox()
	{
		if (pub)
			DH_free(pub);
		if (priv)
			DH_free(priv);
	}

	bool can_decrypt()
	{
		return priv != nullptr;
	}

	bool can_encrypt()
	{
		return pub != nullptr;
	}
};


class persona {

	std::string id, name, link_src, ptype;
	std::map<std::string, DHbox *> keys;

	PKEYbox *pkey;
	DHbox *dh_params;

	std::string cfgbase, err;

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		err = "persona::";
		err += msg;
		if (ERR_get_error()) {
			err += ":";
			err += ERR_error_string(ERR_get_error(), nullptr);
		} else if (errno) {
			err += ":";
			err += strerror(errno);
		}
		return r;
	}

	int load_dh(const std::string &hex);

public:

	persona(const std::string &dir, const std::string &hash, const std::string &n = "")
		: id(hash), name(n), link_src(""), pkey(nullptr), dh_params(nullptr), cfgbase(dir), err("")
	{
		if (!is_hex_hash(id))
			id = "dead";

		ptype = marker::unknown;
	}

	virtual ~persona()
	{
		for (auto i = keys.begin(); i != keys.end(); ++i) {
			if (i->second)
				delete i->second;
		}
		delete pkey;
		delete dh_params;
	}

	void set_type(const std::string &t)
	{
		if (t == marker::rsa || t == marker::ec)
			ptype = t;
	}

	std::string get_type()
	{
		return ptype;
	}

	int check_type();

	bool can_verify()
	{
		return can_encrypt();
	}

	bool can_encrypt()
	{
		return pkey != nullptr && pkey->pub != nullptr;
	}

	bool can_sign()
	{
		return pkey != nullptr && pkey->priv != nullptr;
	}

	bool can_decrypt()
	{
		return can_sign();
	}

	bool can_gen_dh()
	{
		return dh_params != nullptr && dh_params->pub != nullptr;
	}

	PKEYbox *set_pkey(EVP_PKEY *, EVP_PKEY *);

	PKEYbox *get_pkey()
	{
		return pkey;
	}

	std::string get_id()
	{
		return id;
	}

	std::string get_name()
	{
		return name;
	}

	std::string linked_src()
	{
		return link_src;
	}

	DHbox *new_dh_params();

	DHbox *new_dh_params(const std::string &pem);

	DHbox *add_dh_pubkey(const std::string &hash, const std::string &pem);

	DHbox *add_dh_pubkey(const EVP_MD *md, const std::string &pem);

	DHbox *gen_dh_key(const std::string &hash);

	DHbox *gen_dh_key(const EVP_MD *md);

	DHbox *find_dh_key(const std::string &hex);

	int del_dh_id(const std::string &hex);

	int del_dh_pub(const std::string &hex);

	int del_dh_priv(const std::string &hex);

	void used_key(const std::string &hex, bool);

	int load(const std::string &hex = "");

	int link(const std::string &hex);

	std::map<std::string, DHbox *>::iterator first_key();

	std::map<std::string, DHbox *>::iterator end_key();

	std::map<std::string, DHbox *>::iterator next_key(const std::map<std::string, DHbox *>::iterator &);

	int size()
	{
		return keys.size();
	}

	const char *why()
	{
		return err.c_str();
	}

	friend class keystore;
};


class keystore {

	std::string cfgbase;
	std::map<std::string, persona *> personas;

	const EVP_MD *md;

	std::string err;

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		int e = 0;
		err = "keystore::";
		err += msg;
		if ((e = ERR_get_error())) {
			ERR_load_crypto_strings();
			err += ":";
			err += ERR_error_string(e, nullptr);
		} else if (errno) {
			err += ":";
			err += strerror(errno);
		}
		return r;
	}

public:

	keystore(const std::string& hash, const std::string &base = ".opmsg")
		: cfgbase(base), md(nullptr)
	{
		md = algo2md(hash);
	}


	~keystore()
	{
		for (auto i : personas)
			delete i.second;
	}

	const EVP_MD *md_type()
	{
		return md;
	}

	int load(const std::string &);

	int load();

	int gen_rsa(std::string &pub, std::string &priv);

	int gen_ec(std::string &pub, std::string &priv);

	persona *add_persona(const std::string &name, const std::string &rsa_pub_pem, const std::string &rsa_priv_pem, const std::string &dhparams_pem);

	persona *find_persona(const std::string &hex);

	int size()
	{
		return personas.size();
	}

	std::map<std::string, persona *>::iterator first_pers();

	std::map<std::string, persona *>::iterator end_pers();

	std::map<std::string, persona *>::iterator next_pers(const std::map<std::string, persona *>::iterator &);


	const char *why()
	{
		return err.c_str();
	}
};

} // namespace

#endif






