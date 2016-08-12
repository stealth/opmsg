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

#ifndef opmsg_config_h
#define opmsg_config_h

#include <string>
#include <vector>


namespace opmsg {

namespace config {

extern int dh_plen, rsa_len, new_dh_keys, native_crypt, deniable;

extern std::vector<int> curve_nids;
extern std::vector<std::string> curves;

extern std::string rsa_e;

extern std::string infile, outfile, calgo, idformat, my_id;
extern std::string phash, shash, khash, cfgbase;

extern unsigned int version;

extern unsigned int peer_isolation;

extern bool burn;

extern bool nodos2unix;

extern bool ecdh_rsa;

}

int parse_config(const std::string &);

}

#endif

