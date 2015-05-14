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


namespace opmsg {

namespace config {

int dh_plen = 1024;

int rsa_len = 4096;

int new_dh_keys = 3;

int rsa_override = 0;

std::string rsa_e = "65537";

std::string calgo = "aes128cbc";
std::string phash = "sha256";
std::string shash = "sha256";
std::string khash = "sha256";

std::string infile = "/dev/stdin";
std::string outfile = "/dev/stdout";
std::string idformat = "split";
std::string my_id = "";

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
		else if (sline.find("rsa_len=") == 0) {
			config::rsa_len = strtoul(sline.substr(8).c_str(), nullptr, 0);
			if (config::rsa_len < 1024 || config::rsa_len > 16000)
				config::rsa_len = 4096;
		} else if (sline.find("dh_plen=") == 0) {
			config::dh_plen = strtoul(sline.substr(8).c_str(), nullptr, 0);
			if (config::dh_plen < 512 || config::dh_plen > 8192)
				config::dh_plen = 1024;
		} else if (sline.find("new_dh_keys=") == 0) {
			config::new_dh_keys = strtoul(sline.substr(12).c_str(), nullptr, 0);
			if (config::new_dh_keys < 0 || config::new_dh_keys > 100)
				config::new_dh_keys = 3;
		} else if (sline == "rsa_override")
			config::rsa_override = 1;
	}
	return 0;
}

}


