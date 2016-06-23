/*
 * This file is part of the opmsg crypto message framework.
 *
 * (C) 2015-2016 by Sebastian Krahmer,
 *               sebastian [dot] krahmer [at] gmail [dot] com
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


// bitcoin-cli listaccounts
// bitcoin-cli getaddressesbyaccount

// bitcoin-cli dumpprivkey <address>
// to obtain base58check encoded privatekey
//
// bitcoin-cli validateaddress <address>
// to obtain hex encoded pubkey

#include <iostream>
#include <string>
#include <cstring>
#include <memory>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <getopt.h>
#include "base58.h"
#include "deleters.h"
#include "keystore.h"
#include "missing.h"


extern "C" {
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
}


using namespace std;
using namespace opmsg;


namespace ns_opcoin {


class opcoin {

	string err, cfg;

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		int e = 0;
		err = "opcoin::";
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

	opcoin(const string &cfgbase) : err(""), cfg(cfgbase) {};

	~opcoin()
	{
	}

	const char *why()
	{
		return err.c_str();
	}


	int import_pub(const string &, const string &);

	int import_priv(const string &, const string &);

};


static int key2bcaddress(const string &, string &);



int opcoin::import_pub(const string &name, const string &pubhex)
{
	if (!is_hex_hash(pubhex))
		return build_error("import_pub:", -1);

	unique_ptr<EC_KEY, EC_KEY_del> eck(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
	if (!eck.get())
		return build_error("import_pub::EC_KEY_new_by_curve_name:", -1);

	BIGNUM *b = nullptr;
	if (BN_hex2bn(&b, pubhex.c_str()) == 0)
		return build_error("import_pub::BN_hex2bn:", -1);
	unique_ptr<BIGNUM, BIGNUM_del> bn(b, BN_free);
	if (!bn.get())
		return build_error("import_pub::BN_hex2bn:", -1);

	// Before continuing, calculate the bitcoin address, now that we have the BIGNUM
	string bca = "";
	unique_ptr<unsigned char[]> bin(new (nothrow) unsigned char[BN_num_bytes(bn.get())]);
	if (!bin.get())
		return build_error("import_pub: OOM", -1);
	int binlen = BN_bn2bin(bn.get(), bin.get());
	if (binlen <= 0)
		return build_error("import_pub::BN_bn2bin:", -1);
	if (key2bcaddress(string(reinterpret_cast<const char*>(bin.get()), binlen), bca) < 0)
		return build_error("import_pub::key2bcaddress:", -1);

	if (bca != name)
		return build_error("import_pub: Given BTC address does not match calculated one: " + bca + " ", -1);

	// continue constructing PEM format of pubkey
	unique_ptr<EC_POINT, EC_POINT_del> ecp(EC_POINT_bn2point(EC_KEY_get0_group(eck.get()), bn.get(), nullptr, nullptr), EC_POINT_free);

	if (EC_KEY_set_public_key(eck.get(), ecp.get()) != 1)
		return build_error("import_pub::EC_KEY_set_private_key:", -1);

	if (EC_KEY_check_key(eck.get()) != 1)
		return build_error("import_pub::EC_KEY_check_key:", -1);

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
	unique_ptr<BIO, BIO_del> bio(BIO_new(BIO_s_mem()), BIO_free);
	if (!evp.get() || !bio.get())
		return build_error("OOM", -1);

	if (EVP_PKEY_set1_EC_KEY(evp.get(), eck.get()) != 1)
		return build_error("import_pub::EVP_PKEY_set1_EC_KEY:", -1);

	if (PEM_write_bio_PUBKEY(bio.get(), evp.get()) != 1)
		return build_error("import_pub::PEM_write_bio_PUBKEY:", -1);

	char *ptr = nullptr;
	long l = BIO_get_mem_data(bio.get(), &ptr);
	string pub_pem = string(ptr, l);
	bio.reset(BIO_new(BIO_s_mem()));
	if (!bio.get())
		return build_error("import_pub::BIO_new: OOM", -1);

	keystore ks("sha256", cfg);
	if (!ks.add_persona(bca, pub_pem, "", ""))
		return build_error("import_pub::" + string(ks.why()), -1);

	string hex = "";
	normalize_and_hexhash(EVP_sha256(), pub_pem, hex);

	cout<<pub_pem<<endl;

	return 0;
}


// Bitcoins base58check format
static int base58check(const string &data, const string &check, string &ret)
{

	unsigned int hlen = data.size();
	unsigned char digest[32], digest2[32], *dptr = digest;
	const void *ptr = data.c_str();

	ret = "";

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return -1;
	for (int i = 0; i < 2; ++i) {
		if (EVP_DigestInit_ex(md_ctx.get(), EVP_sha256(), nullptr) != 1)
			return -1;
		if (EVP_DigestUpdate(md_ctx.get(), ptr, hlen) != 1)
			return -1;
		if (EVP_DigestFinal_ex(md_ctx.get(), dptr, &hlen) != 1)
			return -1;
		ptr = digest;
		dptr = digest2;
	}

	ret = string(reinterpret_cast<const char *>(dptr), 4);

	if (ret != check)
		return 0;

	return 1;
}


static int key2bcaddress(const string &data, string &address)
{

	unsigned int hlen = 0;
	unsigned char digest[32], digest2[20];

	address = "";

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return -1;

	if (EVP_DigestInit_ex(md_ctx.get(), EVP_sha256(), nullptr) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), data.c_str(), data.size()) != 1)
		return -1;
	if (EVP_DigestFinal_ex(md_ctx.get(), digest, &hlen) != 1)
		return -1;

	if (EVP_DigestInit_ex(md_ctx.get(), EVP_ripemd160(), nullptr) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), digest, sizeof(digest)) != 1)
		return -1;
	if (EVP_DigestFinal_ex(md_ctx.get(), digest2, &hlen) != 1)
		return -1;

	string s = string("\x00", 1), check = "";
	s += string(reinterpret_cast<char *>(digest2), sizeof(digest2));

	if (base58check(s, "", check) < 0)
		return -1;

	s += check;
	b58_encode(s, address);

	return 0;
}



int opcoin::import_priv(const string &name, const string &b58)
{
	string err, t = "", computed_name = "";
	string oct_priv = "";

	// wants compressed public key? (WIF-compressed form)
	bool comp = 0;
	if (b58[0] == 'K' || b58[0] == 'L')
		comp = 1;

	b58_decode(b58, oct_priv);
	if (oct_priv.size() < 33)
		return build_error("import_priv: Invalid b58", -1);

	string check = oct_priv.substr(oct_priv.size() - 4);
	oct_priv = oct_priv.substr(0, oct_priv.size() - 4);

	if (base58check(oct_priv, check, t) != 1)
		return build_error("import_priv: Base58 check not valid.", -1);

	if (oct_priv.size() == 34)
		oct_priv = oct_priv.substr(1, oct_priv.size() - 2);
	else
		oct_priv = oct_priv.substr(1, oct_priv.size() - 1);

	unique_ptr<EC_KEY, EC_KEY_del> eck(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
	if (!eck.get())
		return build_error("import_priv::EC_KEY_new_by_curve_name:", -1);

	unique_ptr<BIGNUM, BIGNUM_del> priv_bn(BN_bin2bn((const unsigned char *)oct_priv.c_str(), oct_priv.size(), nullptr), BN_free);
	if (!priv_bn.get())
		return build_error("import_priv::BN_bin2bn:", -1);

	if (EC_KEY_set_private_key(eck.get(), priv_bn.get()) != 1)
		return build_error("import_priv::EC_KEY_set_private_key:", -1);

	// "0" means no-ownership
	const EC_GROUP *ecg = EC_KEY_get0_group(eck.get());
	if (!ecg)
		return build_error("import_priv::EC_KEY_get0_group:", -1);
	const EC_POINT *gen = EC_GROUP_get0_generator(ecg);
	if (!gen)
		return build_error("import_priv::EC_GROUP_get0_generator:", -1);

	unique_ptr<EC_POINT, EC_POINT_del> ecpub(EC_POINT_new(ecg), EC_POINT_free);
	if (!ecpub.get())
		return build_error("import_priv::EC_POINT_new:", -1);

	unique_ptr<BN_CTX, BN_CTX_del> bnctx(BN_CTX_new(), BN_CTX_free);
	if (!bnctx.get())
		return build_error("import_priv::BN_CTX_new: OOM", -1);

	if (EC_POINT_mul(ecg, ecpub.get(), nullptr, gen, priv_bn.get(), bnctx.get()) != 1)
		return build_error("import_priv::EC_POINT_mul:", -1);

	if (EC_POINT_is_on_curve(ecg, ecpub.get(), bnctx.get()) != 1)
		return build_error("import_priv::EC_POINT_is_on_curve:", -1);


	// Before continuing, calculate the bitcoin address, now that we have the pub BIGNUM point
	point_conversion_form_t form = comp ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
	unique_ptr<BIGNUM, BIGNUM_del> pub_bn(EC_POINT_point2bn(ecg, ecpub.get(), form, nullptr, bnctx.get()), BN_free);
	if (!pub_bn.get())
		return build_error("import_priv::EC_POINT_point2bn:", -1);
	string bca = "";
	unique_ptr<unsigned char[]> pub_bin(new (nothrow) unsigned char[BN_num_bytes(pub_bn.get())]);
	if (!pub_bin.get())
		return build_error("import_priv: OOM", -1);
	int binlen = BN_bn2bin(pub_bn.get(), pub_bin.get());
	if (binlen <= 0)
		return build_error("import_priv::BN_bn2bin:", -1);
	if (key2bcaddress(string(reinterpret_cast<const char*>(pub_bin.get()), binlen), bca) < 0)
		return build_error("import_priv::key2bcaddress:", -1);

	if (bca != name)
		return build_error("import_priv: Given BTC address does not match calculated one: " + bca + " ", -1);

	// continue getting PEM keys
	if (EC_KEY_set_public_key(eck.get(), ecpub.get()) != 1)
		return build_error("import_priv::EC_KEY_set_public_key:", -1);

	if (EC_KEY_check_key(eck.get()) != 1)
		return build_error("import_priv::EC_KEY_check_key:", -1);

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
	unique_ptr<BIO, BIO_del> bio(BIO_new(BIO_s_mem()), BIO_free);
	if (!evp.get() || !bio.get())
		return build_error("OOM", -1);

	if (EVP_PKEY_set1_EC_KEY(evp.get(), eck.get()) != 1)
		return build_error("import_priv::EVP_PKEY_set1_EC_KEY:", -1);

	if (PEM_write_bio_PUBKEY(bio.get(), evp.get()) != 1)
		return build_error("import_priv::PEM_write_bio_PUBKEY:", -1);

	char *ptr = nullptr;
	long l = BIO_get_mem_data(bio.get(), &ptr);
	string pub_pem = string(ptr, l);
	bio.reset(BIO_new(BIO_s_mem()));
	if (!bio.get())
		return build_error("import_priv::BIO_new: OOM", -1);

	if (PEM_write_bio_PrivateKey(bio.get(), evp.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1)
		return build_error("import_priv::PEM_write_bio_PrivateKey:", -1);

	ptr = nullptr;
	l = BIO_get_mem_data(bio.get(), &ptr);
	string priv_pem = string(ptr, l);

	keystore ks("sha256", cfg);
	if (!ks.add_persona(name, pub_pem, priv_pem, ""))
		return build_error("import_priv::" + string(ks.why()), -1);

	string hex = "";
	normalize_and_hexhash(EVP_sha256(), pub_pem, hex);

	cout<<pub_pem<<endl;

	return 0;
}


const string prefix = "opcoin: ";


void usage(const string &p)
{
	cout<<"\nUsage: opcoin [--public hex] [--private WIF] <--name BTC address> [--yes]\n\n";
	exit(-1);
}


} // namespace

using namespace ns_opcoin;


const string banner = "\nopcoin: version=1.71 -- (C) 2016 opmsg-team: https://github.com/stealth/opmsg\n\n";


int main(int argc, char **argv)
{

	struct option lopts[] = {
	        {"confdir", required_argument, nullptr, 'c'},
	        {"public", required_argument, nullptr, 'p'},
	        {"private", required_argument, nullptr, 'P'},
	        {"name", required_argument, nullptr, 'n'},
		{"yes", no_argument, nullptr, 'y'},
	        {nullptr, 0, nullptr, 0}};
	int c = 1, opt_idx = 0;
	using ns_opcoin::prefix;

	cerr<<banner;

	if (argc == 1)
		usage(argv[0]);

	OpenSSL_add_all_algorithms();
	RAND_load_file("/dev/urandom", 2048);
	ERR_clear_error();

	string cfg = "";
	if (getenv("HOME")) {
		cfg = getenv("HOME");
		cfg += "/.opmsg";
	}

	umask(077);

	// no output buffering
	setbuffer(stdout, nullptr, 0);
	setbuffer(stderr, nullptr, 0);
	cout.unsetf(ios::unitbuf);
	cerr.unsetf(ios::unitbuf);

	// first, try to find out any --config option
	if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--config") == 0) {
		if (!argv[2])
			usage(argv[0]);
		cfg = argv[2];
	}

	string pub_pem = "", priv_pem = "", name = "";
	bool yes = 0;

	while ((c = getopt_long(argc, argv, "p:P:n:yc:", lopts, &opt_idx)) != -1) {
		switch (c) {
		case 'c':
			// was already handled
			break;
		case 'p':
			pub_pem = optarg;
			break;
		case 'P':
			priv_pem = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		case 'y':
			yes = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (priv_pem.size() > 0) {
		if (!yes) {
			cerr<<prefix<<"In order to understand that your private bitcoin key is imported\n"
			    <<prefix<<"unencrypted into the opmsg keystore, add the '--yes' switch.\n\n";
			exit(0);
		} else if (pub_pem.size() > 0)
			usage(argv[0]);
	}

	if (name.size() == 0 || (pub_pem.size() == 0 && priv_pem.size() == 0))
		usage(argv[0]);

	opcoin oc(cfg);

	int r = 0;
	if (priv_pem.size() > 0)
		r = oc.import_priv(name, priv_pem);
	else if (pub_pem.size() > 0)
		r = oc.import_pub(name, pub_pem);

	if (r != 0) {
		cerr<<prefix<<"ERROR: "<<oc.why()<<endl;
		cerr<<prefix<<"FAILED.\n";
		exit(1);
	}

	cerr<<prefix<<"SUCESS.\n";
	return 0;
}

