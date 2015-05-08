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

#include <map>
#include <string>
#include <cstdio>
#include <iostream>


extern "C" {
#include <openssl/evp.h>
}


namespace opmsg {

using namespace std;

extern const string prefix = "opmsg: ";

string &blob2hex(const string &blob, string &hex)
{
	char h[3];

	hex = "";
	for (string::size_type i = 0; i < blob.size(); ++i) {
		snprintf(h, sizeof(h), "%02x", 0xff&blob[i]);
		hex += h;
	}
	return hex;
}

// only lowercase hex
bool is_hex_hash(const string &s)
{
	if (s.size() % 2 != 0 || s.size() < 2)
		return 0;

	for (string::size_type i = 0; i < s.size(); ++i) {
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
			return 0;
	}
	return 1;
}


const EVP_CIPHER *algo2cipher(const string &s)
{
	const EVP_CIPHER *cipher = EVP_aes_256_cbc();

	if (s == "aes128cbc")
		cipher = EVP_aes_128_cbc();
	else if (s == "aes128cfb")
		cipher = EVP_aes_128_cfb();
	else if (s == "aes128ofb")
		cipher = EVP_aes_128_ofb();
	else if (s == "aes256cbc")
		cipher = EVP_aes_256_cbc();
	else if (s == "aes256cfb")
		cipher = EVP_aes_256_cfb();
	else if (s == "aes256ofb")
		cipher = EVP_aes_256_ofb();
	else if (s == "bfcbc")
		cipher = EVP_bf_cbc();
	else if (s == "bfcfb")
		cipher = EVP_bf_cfb();
	else if (s == "bfofb")
		cipher = EVP_bf_ofb();
	else if (s == "cast5cbc")
		cipher = EVP_cast5_cbc();
	else if (s == "cast5cfb")
		cipher = EVP_cast5_cfb();
	else if (s == "cast5ofb")
		cipher = EVP_cast5_ofb();

	return cipher;
}

// do not allow null algo
const EVP_MD *algo2md(const string &s)
{
	const EVP_MD *md = EVP_sha512();

	if (s == "sha256")
		md = EVP_sha256();
	else if (s == "ripemd160")
		md = EVP_ripemd160();

	return md;
}


void print_halgos()
{
	map<string, int> m{
	        {"sha256", 1}, {"sha512", 1}, {"ripemd160", 1}
	};

	for (auto i = m.begin(); i != m.end(); ++i)
		cerr<<prefix<<i->first<<endl;
}


void print_calgos()
{
	extern const string prefix;
	map<string, int> m{
	        {"bfcfb", 1}, {"bfcbc", 1}, {"bfofb", 1},
	        {"aes256ofb", 1}, {"aes256cfb", 1}, {"aes256cbc", 1},
	        {"aes128ofb", 1}, {"aes128cfb", 1}, {"aes128cbc", 1},
	        {"cast5ofb", 1}, {"cast5cfb", 1}, {"cast5cbc", 1},
	        {"null", 1}
	};

	for (auto i = m.begin(); i != m.end(); ++i)
		cerr<<prefix<<i->first<<endl;
}


bool is_valid_calgo(const string &s)
{
	map<string, int> m{
	        {"bfcfb", 1}, {"bfcbc", 1}, {"bfofb", 1},
	        {"aes256ofb", 1}, {"aes256cfb", 1}, {"aes256cbc", 1},
	        {"aes128ofb", 1}, {"aes128cfb", 1}, {"aes128cbc", 1},
	        {"cast5ofb", 1}, {"cast5cfb", 1}, {"cast5cbc", 1},
	        {"null", 1}
	};

	return m.count(s) > 0;
}


bool is_valid_halgo(const string &s)
{
	map<string, int> m{
	        {"sha256", 1}, {"sha512", 1}, {"ripemd160", 1}
	};

	return m.count(s) > 0;
}


} // namespace

