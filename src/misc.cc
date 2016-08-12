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
#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sstream>


extern "C" {
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef HAVE_BORINGSSL
#include <openssl/cipher.h>
#endif
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
	else if (s == "aes128gcm")
		cipher = EVP_aes_128_gcm();
	else if (s == "aes128ctr")
		cipher = EVP_aes_128_ctr();
	else if (s == "aes256cbc")
		cipher = EVP_aes_256_cbc();
	else if (s == "aes256gcm")
		cipher = EVP_aes_256_gcm();
	else if (s == "aes256ctr")
		cipher = EVP_aes_256_ctr();
#ifdef CHACHA20
	else if (s == "chacha20-poly1305")
		cipher = EVP_chacha20_poly1305();
#endif

// BoringSSL not implementing a lot of modes!!!
#ifndef HAVE_BORINGSSL
	else if (s == "bfcbc")
		cipher = EVP_bf_cbc();
	else if (s == "bfcfb")
		cipher = EVP_bf_cfb();
	else if (s == "cast5cbc")
		cipher = EVP_cast5_cbc();
	else if (s == "cast5cfb")
		cipher = EVP_cast5_cfb();
	else if (s == "aes128cfb")
		cipher = EVP_aes_128_cfb();
	else if (s == "aes256cfb")
		cipher = EVP_aes_256_cfb();
#endif

	return cipher;
}

// do not allow null algo
const EVP_MD *algo2md(const string &s)
{
	const EVP_MD *md = EVP_sha512();

	if (s == "sha256")
		md = EVP_sha256();
	else if (s == "sha384")
		md = EVP_sha384();
#ifndef HAVE_BORINGSSL
	else if (s == "ripemd160")
		md = EVP_ripemd160();
#endif
	return md;
}


void print_halgos(ostringstream &os)
{
	map<string, int> m{
	        {"sha256", 1}, {"sha512", 1}, {"ripemd160", 1}
	};

	for (auto i = m.begin(); i != m.end(); ++i)
		os<<prefix<<i->first<<endl;
}


void print_calgos(ostringstream &os)
{
	extern const string prefix;
	map<string, int> m{
	        {"bfcfb", 0}, {"bfcbc", 0},
	        {"aes256cfb", 0}, {"aes256cbc", 0}, {"aes256gcm", 0}, {"aes256ctr", 0},
	        {"aes128cfb", 0}, {"aes128cbc", 0}, {"aes128gcm", 1}, {"aes128ctr", 0},
	        {"cast5cfb", 0}, {"cast5cbc", 0},
#ifdef CHACHA20
		{"chacha20-poly1305", 0},
#endif
	        {"null", 0}
	};

	map<string, int> ec{
	        {"secp384r1", 0}, {"secp521r1", 0},
	        {"secp256k1", 0},	// BTC curve
	        {"sect283k1", 0}, {"sect283r1", 0},
	        {"sect409k1", 0}, {"sect409r1", 0},
	        {"sect571k1", 0},{"sect571r1", 0},
#ifdef NID_brainpoolP512t1
	        {"brainpoolP320r1", 0}, {"brainpoolP384r1", 0}, {"brainpoolP512r1", 0},
	        {"brainpoolP320t1", 0}, {"brainpoolP384t1", 0}, {"brainpoolP512t1", 0}
#endif
	};

	for (auto&& it : m) {
		os<<prefix<<it.first;
		if (it.second)
			os<<" (default)";
		os<<endl;
	}

	os<<endl<<prefix<<"Supported EC curves:\n\n";
	for (auto&& it : ec)
		os<<prefix<<it.first<<endl;
}


bool is_valid_calgo(const string &s)
{
	map<string, int> m{
	        {"bfcfb", 1}, {"bfcbc", 1},
	        {"aes256cfb", 1}, {"aes256cbc", 1}, {"aes256gcm", 1}, {"aes256ctr", 1},
	        {"aes128cfb", 1}, {"aes128cbc", 1}, {"aes128gcm", 1}, {"aes128ctr", 1},
	        {"cast5cfb", 1}, {"cast5cbc", 1},
#ifdef CHACHA20
		{"chacha20-poly1305", 1},
#endif
	        {"null", 1}
	};

	return m.count(s) > 0;
}


bool is_valid_halgo(const string &s)
{
	map<string, int> m{
	        {"sha256", 1}, {"sha384", 1}, {"sha512", 1}, {"ripemd160", 1}
	};

	return m.count(s) > 0;
}


void rlockf(int fd)
{
	struct flock fl;
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fcntl(fd, F_SETLKW, &fl);
}


// fcntl() files locks are not really to be used with FILE
// (buffered) operations, but we indeed dont lock records but
// whole files and close them after read/write operation anyway.
void rlockf(FILE *f)
{
	rlockf(fileno(f));
}


void unlockf(int fd)
{
	struct flock fl;
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fcntl(fd, F_SETLKW, &fl);
}

void unlockf(FILE *f)
{
	unlockf(fileno(f));
}


void wlockf(int fd)
{
	struct flock fl;
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fcntl(fd, F_SETLKW, &fl);
}


void wlockf(FILE *f)
{
	wlockf(fileno(f));
}


string build_error(const string &msg)
{
	int e = 0;
	string err = msg;
	if ((e = ERR_get_error())) {
		ERR_load_crypto_strings();
		err += ":";
		err += ERR_error_string(e, nullptr);
		ERR_clear_error();
	} else if (errno) {
		err += ":";
		err += strerror(errno);
	}
	return err;
}


#if 0

// for debugging/inspection
void hex_dump(const char *buf, size_t blen)
{
	fprintf(stderr, "\n(%d)\n", blen);
	for (size_t i = 0; i < blen; ++i)
		fprintf(stderr, "%02x ", buf[i] & 0xff);
	fprintf(stderr, "\n");
}

#endif

} // namespace

