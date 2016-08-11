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

namespace opmsg {

namespace marker {

using namespace std;

string ec_dh_begin = "-----BEGIN PUBLIC KEY-----\n";
string ec_dh_end = "-----END PUBLIC KEY-----\n";

string pub_begin = "-----BEGIN PUBLIC KEY-----\n";
string pub_end = "-----END PUBLIC KEY-----";		// note missing trailing \n

string priv_begin = "-----BEGIN PRIVATE KEY-----\n";
string priv_end = "-----END PRIVATE KEY-----\n";

string sig_begin = "-----BEGIN SIGNATURE-----\n";
string sig_end = "-----END SIGNATURE-----\n";

string dh_params_begin = "-----BEGIN DH PARAMETERS-----\n";
string dh_params_end = "-----END DH PARAMETERS-----\n";

string opmsg_begin = "-----BEGIN OPMSG-----\n";
string opmsg_end = "\n-----END OPMSG-----\n";
string opmsg_databegin = "-----BEGIN OPMSG DATA-----\n";

string kex_begin = "-----BEGIN KEX-----\n";
string kex_end = "-----END KEX-----\n";

string version1 = "version=1\n";
string version2 = "version=2\n";
string version3 = "version=3\n";

string src_id = "src-id=";
string dst_id = "dst-id=";
string kex_id = "kex-id=";
string aad_tag = "gcm-aad-tag=";
string cfg_num = "cfg-num=";

// if no ephemeral DH keys are left, this signals standart RSA encrypted secret
string rsa_kex_id = "00000000";

// if no ephemeral ECDH keys are left, the EC persona key is used for ECDH kex
string ec_kex_id = "11111111";


// rythmz=persona-hash:key-hash:sign-hash:crypto:IV
string algos = "rythmz=";

string ec = "ec";
string rsa = "rsa";
string dh = "dh";
string unknown = "unknown";

}

}

