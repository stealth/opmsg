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

#ifndef __message_h__
#define __message_h__

#include <string>
#include <vector>
#include <cerrno>
#include <cstring>
#include "keystore.h"

extern "C" {
#include <openssl/err.h>
}


namespace opmsg {

namespace marker {

extern std::string rsa_kex_id;

}


enum {
	OPMSG_RSA_ENCRYPTED_KEYLEN	= 64,

	//EVP_MAX_KEY_LENGTH:64
	OPMSG_MAX_KEY_LENGTH		= 64,

	//EVP_MAX_IV_LENGTH:16
	OPMSG_MAX_IV_LENGTH		= 24

};


class message {

	unsigned int version, max_new_dh_keys;

	std::string sig, src_id_hex, dst_id_hex, kex_id_hex, pubkey_pem, src_name;
	std::string phash, khash, shash, calgo;
	std::string cfgbase, err;

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		int e = 0;
		err = "message::";
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

	std::vector<std::string> ecdh_keys;	// either DH or ECDH keys

	message(const std::string &c, const std::string &a1, const std::string &a2, const std::string &a3, const std::string &a4)
		: version(1), max_new_dh_keys(10), sig(""), src_id_hex(""), dst_id_hex(""), kex_id_hex(""),
	          pubkey_pem(""), src_name(""), phash(a1), khash(a2), shash(a3), calgo(a4), cfgbase(c), err("")
	{
	}

	virtual ~message()
	{
	}

	std::string src_id()
	{
		return src_id_hex;
	}

	std::string dst_id()
	{
		return dst_id_hex;
	}

	std::string kex_id()
	{
		return kex_id_hex;
	}

	void src_id(const std::string &s)
	{
		src_id_hex = s;
	}

	void dst_id(const std::string &s)
	{
		dst_id_hex = s;
	}

	void kex_id(const std::string &s)
	{
		kex_id_hex = s;
	}

	std::string get_srcname()
	{
		return src_name;
	}

	std::string get_shash()
	{
		return shash;
	}

	std::string get_calgo()
	{
		return calgo;
	}

	int decrypt(std::string &msg);

	int encrypt(std::string &msg, persona *src_persona, persona *dst_persona);

	int sign(const std::string &msg, persona *src_persona, std::string &result);

	void add_dh_key(const std::string &s)
	{
		ecdh_keys.push_back(s);
	}

	const char *why()
	{
		return err.c_str();
	}
};


}


#endif

