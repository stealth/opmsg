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

#ifndef opmsg_message_h
#define opmsg_message_h

#include <string>
#include <vector>
#include <cerrno>
#include <cstring>
#include "keystore.h"
#include "numbers.h"

extern "C" {
#include <openssl/err.h>
}


namespace opmsg {


enum {
	OPMSG_RSA_ENCRYPTED_KEYLEN	= 64,

	//EVP_MAX_KEY_LENGTH:64
	OPMSG_MAX_KEY_LENGTH		= 64,

	//EVP_MAX_IV_LENGTH:16
	OPMSG_MAX_IV_LENGTH		= 24

};


class message {

	unsigned int d_version, d_max_new_dh_keys{MAX_NEW_DH_KEYS};

	std::string d_src_id_hex{""}, d_dst_id_hex{""}, d_kex_id_hex{""}, d_src_name{""};
	std::string d_phash, d_khash, d_shash, d_calgo;
	std::string d_cfgbase{""}, d_err{""};

	bool d_peer_isolation{0};

	std::vector<std::string> d_ecdh_keys;	// either DH or ECDH keys
	unsigned int d_ec_domains{1};		// number of curves for cross-domain ECDH

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		int e = 0;
		d_err = "message::";
		d_err += msg;
		if ((e = ERR_get_error())) {
			ERR_load_crypto_strings();
			d_err += ":";
			d_err += ERR_error_string(e, nullptr);
			ERR_clear_error();
		} else if (errno) {
			d_err += ":";
			d_err += strerror(errno);
		}
		return r;
	}

protected:

	int parse_hdr(std::string &, std::vector<std::string> &, std::vector<char> &);


public:

	message(unsigned int vers, const std::string &c, const std::string &a1, const std::string &a2, const std::string &a3, const std::string &a4)
		: d_version(vers), d_phash(a1), d_khash(a2), d_shash(a3), d_calgo(a4), d_cfgbase(c)
	{
	}

	virtual ~message()
	{
	}

	std::string src_id()
	{
		return d_src_id_hex;
	}

	std::string dst_id()
	{
		return d_dst_id_hex;
	}

	std::string kex_id()
	{
		return d_kex_id_hex;
	}

	void src_id(const std::string &s)
	{
		d_src_id_hex = s;
	}

	void dst_id(const std::string &s)
	{
		d_dst_id_hex = s;
	}

	void kex_id(const std::string &s)
	{
		d_kex_id_hex = s;
	}

	std::string get_srcname()
	{
		return d_src_name;
	}

	std::string get_shash()
	{
		return d_shash;
	}

	std::string get_calgo()
	{
		return d_calgo;
	}

	void enable_peer_isolation()
	{
		d_peer_isolation = 1;
	}

	int get_ec_domains()
	{
		return d_ec_domains;
	}

	void set_ec_domains(int d)
	{
		d_ec_domains = d;
	}

	int decrypt(std::string &msg);

	int encrypt(std::string &msg, persona *src_persona, persona *dst_persona);

	int sign(const std::string &msg, persona *src_persona, std::string &result);

	void add_ecdh_key(const std::string &s)
	{
		d_ecdh_keys.emplace_back(s);
	}

	decltype(d_ecdh_keys)::size_type num_ecdh_keys()
	{
		return d_ecdh_keys.size();
	}

	const char *why()
	{
		return d_err.c_str();
	}
};


}


#endif

