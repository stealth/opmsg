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

#ifndef opmsg_keystore_h
#define opmsg_keystore_h


#include <map>
#include <vector>
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


class PKEYbox {

public:

	EVP_PKEY *pub, *priv;

	std::string pub_pem, priv_pem, hex;

	/* The peer id is assigned if new ephemeral keys are generated to be attached to
	 * a message that is destinated to a certain persona. Only this persona (peer id)
	 * should eventually come back with a kex-id referencing _this_ key. This only affects
	 * Kex keys, not persona keys. It is OK to have an empty peer id.
	 */
	std::string peer_id;


	PKEYbox(EVP_PKEY *p, EVP_PKEY *s)
		: pub(p), priv(s), pub_pem(""), priv_pem(""), hex(""), peer_id("")
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

	bool matches_peer_id(const std::string &s)
	{
		// If no designated peer was recorded, any peer is OK
		if (peer_id.size() == 0)
			return 1;
		return peer_id == s;
	}

	std::string get_peer_id()
	{
		return peer_id;
	}


	void set_peer_id(const std::string &s)
	{
		peer_id = s;
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

	// The (EC)DH 'session' keys this persona holds
	std::map<std::string, std::vector<PKEYbox *>> keys;

	// List of hashes of all imported keys so far
	std::map<std::string, unsigned int> imported;

	PKEYbox *pkey;
	DHbox *dh_params;

	std::string cfgbase, err;

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		int e = 0;
		err = "persona::";
		err += msg;
		if ((e = ERR_get_error())) {
			ERR_load_crypto_strings();
			err += ":";
			err += ERR_error_string(e, nullptr);
			ERR_clear_error();
		} else if (errno) {
			err += ":";
			err += strerror(errno);
		}
		errno = 0;
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
			for (auto j = i->second.begin(); j != i->second.end(); ++j)
				delete *j;
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

	bool can_kex_gen()
	{
		if (ptype == marker::rsa)
			return dh_params != nullptr && dh_params->pub != nullptr;
		return true;
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

	std::vector<PKEYbox *> add_dh_pubkey(const std::string &hash, std::vector<std::string> &pems);

	std::vector<PKEYbox *> add_dh_pubkey(const EVP_MD *md, std::vector<std::string> &pems);

	std::vector<PKEYbox *> gen_kex_key(const std::string &hash, const std::string & = "");

	int gen_dh_key(const EVP_MD *md, std::string&, std::string&, std::string&);

	std::vector<PKEYbox *> gen_kex_key(const EVP_MD *md, const std::string & = "");

	std::vector<PKEYbox *> find_dh_key(const std::string &hex);

	int del_dh_id(const std::string &hex);

	int del_dh_pub(const std::string &hex);

	int del_dh_priv(const std::string &hex);

	bool has_imported(const std::string &hex)
	{
		return imported.count(hex) > 0;
	}

	void used_key(const std::string &hex, bool);

	int load(const std::string &hex = "");

	int link(const std::string &hex);

	std::map<std::string, std::vector<PKEYbox *>>::iterator first_key();

	std::map<std::string, std::vector<PKEYbox *>>::iterator end_key();

	std::map<std::string, std::vector<PKEYbox *>>::iterator next_key(const std::map<std::string, std::vector<PKEYbox *>>::iterator &);

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
			ERR_clear_error();
		} else if (errno) {
			err += ":";
			err += strerror(errno);
		}
		errno = 0;
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

	int load(const std::string &id = "");

	int gen_rsa(std::string &pub, std::string &priv);

	int gen_ec(std::string &pub, std::string &priv, int);

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

int normalize_and_hexhash(const EVP_MD *, std::string &s, std::string &);

} // namespace

#endif






