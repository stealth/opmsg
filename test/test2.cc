#include <cstdio>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <memory>

#include "deleters.h"
#include "keystore.h"
#include "message.h"

using namespace std;
using namespace opmsg;


int main()
{

	OpenSSL_add_all_algorithms();
	ERR_clear_error();

	keystore ks("sha256", ".opmsg");
	string p, s;

	setbuffer(stdout, nullptr, 0);

	cout<<endl<<"Loading keystore...\n";

	string ps = "e0013cf796f2e6e8";

	if (ks.load() < 0)
		cerr<<ks.why()<<endl;

	cout<<"Successfully loaded "<<ks.size()<<" personas\n";

	persona *pers = ks.find_persona(ps);
	if (!pers) {
		cerr<<ks.why()<<endl;
		return -1;
	}

	auto i = pers->first_key();
	for (; i != pers->end_key(); i = pers->next_key(i)) {
		if (i->second->can_encrypt())
			break;
	}

	message damsg(".opmsg", "sha256", "sha256", "sha256", "bfcbc");

	damsg.kex_id(i->first);
//	damsg.kex_id(marker::rsa_kex_id);
	damsg.src_id(pers->get_id());
	damsg.dst_id(pers->get_id());

	string text = "12345678901";
	if (damsg.encrypt(text, pers, pers) < 0)
		cerr<<damsg.why()<<endl;

	cerr<<"Enc result:"<<endl<<text<<endl;

	if (damsg.decrypt(text) < 0)
		cerr<<damsg.why()<<endl;

	cerr<<"Dec result:"<<endl<<text<<endl;


	text = "abcdefg";

	message damsg2(".opmsg", "sha512", "sha512", "sha512", "null");

	damsg2.kex_id(marker::rsa_kex_id);
	damsg2.src_id(pers->get_id());
	damsg2.dst_id(pers->get_id());

	if (damsg2.encrypt(text, pers, pers) < 0)
		cerr<<damsg2.why()<<endl;

	cerr<<"Enc result:"<<endl<<text<<endl;

	if (damsg2.decrypt(text) < 0)
		cerr<<damsg2.why()<<endl;

	cerr<<"Dec result:"<<endl<<text<<endl;


	BN_free(nullptr);
	DH_free(nullptr);
	RSA_free(nullptr);
	BIO_free(nullptr);
	EVP_MD_CTX_destroy(nullptr);
	EVP_PKEY_free(nullptr);

	unique_ptr<FILE, FILE_del> f(fopen("/etc/passwd", "r"), ffclose);
	return 0;
}

