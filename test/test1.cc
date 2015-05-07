#include <cstdio>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include "keystore.h"
#include "config.h"

using namespace std;
using namespace opmsg;


int main()
{
	keystore ks("sha256", ".opmsg");
	persona *pers = nullptr;
	string p, s;

	setbuffer(stdout, nullptr, 0);


	mkdir(".opmsg", 0700);
	for (int i = 0; i < 1; ++i) {
		if (ks.gen_rsa(p, s) < 0)
			cerr<<ks.why()<<endl;

		cout<<endl<<p<<endl<<s<<endl;

		if (!(pers = ks.add_persona("test1", p, s, "")))
			cerr<<ks.why()<<endl;
		else {
			cerr<<"\nSuccessfully added persona "<<pers->get_id()<<endl;
			pers->gen_dh_key("sha256");
		}
	}

	cout<<"\nSuccessfully wrote "<<ks.size()<<" personas\n";

	keystore ks2("sha256", ".opmsg");

	cout<<endl<<"Loading keystore...\n";
	if (ks2.load() < 0)
		cerr<<ks2.why()<<endl;

	cout<<"Successfully loaded "<<ks2.size()<<" personas\n";

	pers = ks2.find_persona("fd8c9ab19845592d");
	if (!pers)
		cerr<<ks2.why()<<endl;
	else {
		if (!pers->gen_dh_key(ks2.md_type()))
			cerr<<pers->why()<<endl;
	}

	keystore ks3("sha256", ".opmsg");

	if (ks3.load() < 0)
		cerr<<ks2.why()<<endl;

	for (auto i = pers->first_key(); i != pers->end_key(); i = pers->next_key(i))
		cout<<i->first<<endl;

	return 0;
}

