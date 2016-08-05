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

#include <iostream>
#include <algorithm>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include "numbers.h"

extern "C" {
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
}

namespace opmsg {

namespace config {

int dh_plen = DEFAULT_DH_PLEN;
int rsa_len = DEFAULT_RSA_LEN;
int new_dh_keys = DEFAULT_NEW_DH_KEYS;

int native_crypt = 0;

// when creating or importing personas, do it deniable
int deniable = 0;

unsigned int version = 2;
unsigned int peer_isolation = 0;

std::string rsa_e = "65537";

std::string calgo = "aes128gcm";
std::string phash = "sha256";
std::string shash = "sha256";
std::string khash = "sha256";

std::string infile = "/dev/stdin";
std::string outfile = "/dev/stdout";
std::string idformat = "split";
std::string my_id = "";



#if defined NID_brainpoolP512t1 && !defined HAVE_BORINGSSL
int curve_nid = NID_brainpoolP320r1;
std::string curve = "brainpoolP320r1";
#else

#warning "Your libcrypto library is outdated and has no support for Brainpool EC curves."
#warning "Falling back to NIST curve secp521r. You should consider cloning libressl or"
#warning "openssl git and build your own libcrypto setup in order to get full ECC support."

int curve_nid = NID_secp521r1;
std::string curve = "secp521r1";
#endif

bool burn = 0;

bool nodos2unix = 0;

std::string cfgbase = ".opmsg";

}

using namespace std;

int parse_config(const string &cfgbase)
{
	ifstream fin{cfgbase + "/config", ios::in};

	if (!fin)
		return -1;

	string sline = "";

	for (;;) {
		getline(fin, sline, '\n');
		if (!fin.good())
			break;

		sline.erase(remove(sline.begin(), sline.end(), ' '), sline.end());
		sline.erase(remove(sline.begin(), sline.end(), '\t'), sline.end());

		if (sline.find("outfile=") == 0)
			config::outfile = sline.substr(8);
		else if (sline.find("infile=") == 0)
			config::infile = sline.substr(7);
		else if (sline.find("idformat=long") == 0)
			config::idformat = "long";
		else if (sline.find("idformat=short") == 0)
			config::idformat = "short";
		else if (sline.find("idformat=split") == 0)
			config::idformat = "split";
		else if (sline.find("my_id=") == 0)
			config::my_id = sline.substr(6);
		else if (sline.find("calgo=") == 0)
			config::calgo = sline.substr(6);
		else if (sline.find("phash=") == 0)
			config::phash = sline.substr(6);
		else if (sline.find("shash=") == 0)
			config::shash = sline.substr(6);
		else if (sline.find("khash=") == 0)
			config::khash = sline.substr(6);
		else if (sline.find("rsa_e=") == 0)
			config::rsa_e = sline.substr(6);
		else if (sline.find("peer_isolation=") == 0)
			config::peer_isolation = strtoul(sline.substr(15).c_str(), nullptr, 0);
		else if (sline.find("rsa_len=") == 0) {
			config::rsa_len = strtoul(sline.substr(8).c_str(), nullptr, 0);
			if (config::rsa_len < MIN_RSA_LEN || config::rsa_len > MAX_RSA_LEN)
				config::rsa_len = DEFAULT_RSA_LEN;
		} else if (sline.find("dh_plen=") == 0) {
			config::dh_plen = strtoul(sline.substr(8).c_str(), nullptr, 0);
			if (config::dh_plen < MIN_DH_PLEN || config::dh_plen > MAX_DH_PLEN)
				config::dh_plen = DEFAULT_DH_PLEN;
		} else if (sline.find("new_dh_keys=") == 0) {
			config::new_dh_keys = strtoul(sline.substr(12).c_str(), nullptr, 0);
			if (config::new_dh_keys < MIN_NEW_DH_KEYS || config::new_dh_keys > MAX_NEW_DH_KEYS)
				config::new_dh_keys = DEFAULT_NEW_DH_KEYS;
		} else if (sline == "rsa_override")
			config::native_crypt = 1;
		else if (sline == "native_crypt")
			config::native_crypt = 1;
		else if (sline == "burn")
			config::burn = 1;
		else if (sline == "no-dos2unix")
			config::nodos2unix = 1;
		else if (sline == "version=1")
			config::version = 1;
		else if (sline == "version=2")
			config::version = 2;
		else if (sline == "curve=secp521r1") {
			config::curve = "secp521r1";
			config::curve_nid = NID_secp521r1;
#ifdef NID_brainpoolP512t1
		} else if (sline == "curve=brainpoolP320r1") {
			config::curve = "brainpoolP320r1";
			config::curve_nid = NID_brainpoolP320r1;
		} else if (sline == "curve=brainpoolP384r1") {
			config::curve = "brainpoolP384r1";
			config::curve_nid = NID_brainpoolP384r1;
		} else if (sline == "curve=brainpoolP512r1") {
			config::curve = "brainpoolP512r1";
			config::curve_nid = NID_brainpoolP512r1;
		} else if (sline == "curve=brainpoolP320t1") {
			config::curve = "brainpoolP320t1";
			config::curve_nid = NID_brainpoolP320t1;
		} else if (sline == "curve=brainpoolP384t1") {
			config::curve = "brainpoolP384t1";
			config::curve_nid = NID_brainpoolP384t1;
		} else if (sline == "curve=brainpoolP512t1") {
			config::curve = "brainpoolP512t1";
			config::curve_nid = NID_brainpoolP512t1;
#endif
		}
	}
	return 0;
}

}


