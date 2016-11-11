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

#include <iostream>
#include <algorithm>
#include <fstream>
#include <string>
#include <vector>
#include <map>
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

std::vector<int> curve_nids;
std::vector<std::string> curves;

bool burn = 0;

bool nodos2unix = 0;

bool ecdh_rsa = 0;

std::string cfgbase = ".opmsg";

}

using namespace std;

int parse_config(const string &cfgbase)
{
	map<string, int> seen_ec;

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
		else if (sline == "version=3")
			config::version = 3;
		else if (sline == "ecdh-rsa")
			config::ecdh_rsa = 1;
		else if (sline == "curve=secp521r1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("secp521r1");
			config::curve_nids.push_back(NID_secp521r1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=secp384r1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("secp384r1");
			config::curve_nids.push_back(NID_secp384r1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=sect283k1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("sect283k1");
			config::curve_nids.push_back(NID_sect283k1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=sect283r1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("sect283r1");
			config::curve_nids.push_back(NID_sect283r1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=sect409k1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("sect409k1");
			config::curve_nids.push_back(NID_sect409k1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=sect409r1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("sect409r1");
			config::curve_nids.push_back(NID_sect409r1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=sect571k1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("sect571k1");
			config::curve_nids.push_back(NID_sect571k1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=sect571r1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("sect571r1");
			config::curve_nids.push_back(NID_sect571r1);
			seen_ec[sline] = 1;

#ifdef NID_brainpoolP512t1
		} else if (sline == "curve=brainpoolP320r1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("brainpoolP320r1");
			config::curve_nids.push_back(NID_brainpoolP320r1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=brainpoolP384r1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("brainpoolP384r1");
			config::curve_nids.push_back(NID_brainpoolP384r1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=brainpoolP512r1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("brainpoolP512r1");
			config::curve_nids.push_back(NID_brainpoolP512r1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=brainpoolP320t1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("brainpoolP320t1");
			config::curve_nids.push_back(NID_brainpoolP320t1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=brainpoolP384t1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("brainpoolP384t1");
			config::curve_nids.push_back(NID_brainpoolP384t1);
			seen_ec[sline] = 1;
		} else if (sline == "curve=brainpoolP512t1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("brainpoolP512t1");
			config::curve_nids.push_back(NID_brainpoolP512t1);
			seen_ec[sline] = 1;
#endif
		// bitcoin curve
		} else if (sline == "curve=secp256k1") {
			if (seen_ec.count(sline) > 0)
				continue;
			config::curves.push_back("secp256k1");
			config::curve_nids.push_back(NID_secp256k1);
			seen_ec[sline] = 1;
		}
	}

	// for version < 3, only one curve
	if (config::version < 3 && config::curves.size() > 1)  {
		config::curves.resize(1);
		config::curve_nids.resize(1);
	} else if (config::version >= 3 && config::curves.size() > 3) {
		// no more than 3 curves otherwise
		config::curves.resize(3);
		config::curve_nids.resize(3);
	}

	if (config::curves.empty()) {
#if defined NID_brainpoolP512t1 && !defined HAVE_BORINGSSL
		config::curve_nids.push_back(NID_brainpoolP320r1);
		config::curves.push_back("brainpoolP320r1");
#else
		config::curve_nids.push_back(NID_secp521r1);
		config::curves.push_back("secp521r1");
#endif
	}

	return 0;
}

}


