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
#include <sstream>
#include <memory>
#include <string>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <algorithm>
#include <sys/stat.h>
#include <sys/types.h>

#include "misc.h"
#include "marker.h"
#include "deleters.h"
#include "config.h"
#include "message.h"
#include "keystore.h"

extern "C" {
#include <openssl/evp.h>
#include <openssl/rand.h>
}


using namespace std;
using namespace opmsg;

enum {
	ID_FORMAT_SHORT		= 0,
	ID_FORMAT_LONG		= 1,
	ID_FORMAT_SPLIT		= 2,
	NEWDHP			= 3,
	LINK			= 4,
	BURN			= 5,
	NEWECP			= 6,
	FREEHUGS		= 7,

	CMODE_INVALID		= 0,
	CMODE_ENCRYPT		= 0x100,
	CMODE_DECRYPT		= 0x200,
	CMODE_SIGN		= 0x400,
	CMODE_VERIFY		= 0x800,
	CMODE_NEWP		= 0x1000,
	CMODE_NEWDHP		= 0x2000,
	CMODE_IMPORT		= 0x4000,
	CMODE_LIST		= 0x8000,
	CMODE_PGPLIST		= 0x10000,
	CMODE_LINK		= 0x20000,
	CMODE_NEWECP		= 0x40000,
	CMODE_FREEHUGS		= 0x80000
};


const string banner = "\nopmsg: version=1.5 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg\n\n";

/* The iostream lib works not very well wrt customized buffering and flushing
 * (unlike C's setbuffer), so we use string streams and flush ourself when we need to.
 * otherwise cerr<< may break up messages in too many useless chunks, fucking up the order
 * when called remotely without pty (ropmsg case)
 */
ostringstream ostr, estr;

void eflush()
{
	cerr<<estr.str();
	estr.str("");
}


void oflush()
{
	cout<<ostr.str();
	ostr.str("");
}



void usage(const char *p)
{
	estr<<banner;
	eflush();

	ostr<<"\nUsage: opmsg [--confdir dir] [--native] [--encrypt dst-ID] [--decrypt] [--sign]"<<endl
	    <<"\t[--verify file] <--persona ID> [--import] [--list] [--listpgp]"<<endl
	    <<"\t[--short] [--long] [--split] [--new(ec)p] [--newdhp] [--calgo name]"<<endl
	    <<"\t[--phash name [--name name] [--in infile] [--out outfile]"<<endl
	    <<"\t[--link target id] [--burn]"<<endl<<endl
            <<"\t--confdir,\t-c\t(must come first) defaults to ~/.opmsg"<<endl
	    <<"\t--native,\t-R\tEC/RSA override (dont use existing (EC)DH keys)"<<endl
	    <<"\t--encrypt,\t-E\trecipients persona hex id (-i to -o, needs -P)"<<endl
	    <<"\t--decrypt,\t-D\tdecrypt --in to --out"<<endl
	    <<"\t--sign,\t\t-S\tcreate detached signature file from -i via -P"<<endl
	    <<"\t--verify,\t-V\tvrfy hash contained in detached file against -i"<<endl
	    <<"\t--persona,\t-P\tyour persona hex id as used for signing"<<endl
	    <<"\t--import,\t-I\timport new persona from --in"<<endl
	    <<"\t--list,\t\t-l\tlist all personas"<<endl
	    <<"\t--listpgp,\t-L\tlist personas in PGP format (for mutt etc.)"<<endl
	    <<"\t--short\t\t\tshort view of hex ids"<<endl
	    <<"\t--long\t\t\tlong view of hex ids"<<endl
	    <<"\t--split\t\t\tsplit view of hex ids"<<endl
	    <<"\t--newp,\t\t-N\tcreate new RSA persona (should add --name)"<<endl
	    <<"\t--newecp\t\tcreate new EC persona (should add --name)"<<endl
	    <<"\t--link\t\t\tlink (your) --persona as default src to this"<<endl
	    <<"\t\t\t\ttarget id"<<endl
	    <<"\t--newdhp\t\tcreate new DHparams for persona (rarely needed)"<<endl
	    <<"\t--calgo,\t-C\tuse this algo for encryption"<<endl
	    <<"\t--phash,\t-p\tuse this hash algo for hashing personas"<<endl
	    <<"\t--in,\t\t-i\tinput file (stdin)"<<endl
	    <<"\t--out,\t\t-o\toutput file (stdout)"<<endl
	    <<"\t--name,\t\t-n\tuse this name for newly created personas"<<endl
	    <<"\t--burn\t\t\t(!dangerous!) burn private (EC)DH key after"<<endl
	    <<"\t\t\t\tdecryption to achieve 'full' PFS"<<endl<<endl;

	oflush();
	exit(-1);
}



int read_msg(const string &path, string &msg)
{
	msg = "";
	int fd = 0;
	bool was_opened = 0;

	if (path != "/dev/stdin") {
		if ((fd = open(path.c_str(), O_RDONLY)) < 0)
			return -1;
		was_opened = 1;
	}

	const size_t blen = 0x10000;
	char *buf = new char[blen];
	ssize_t r = 0;
	do {
		r = read(fd, buf, blen);

		// check for EOT (Ctrl-C). In case stdin is a pipe (ropmsg called),
		// we wont receive Ctrl-C triggered SIGINT
		if (r == 1 && fd == 0 && buf[0] == 0x3)
			break;
		if (r > 0)
			msg += string(buf, r);
	} while (r > 0);

	delete [] buf;

	if (was_opened)
		close(fd);
	return 0;
}


int write_msg(const string &path, const string &msg)
{
	int fd = 1;
	bool was_opened = 0;

	if (path != "/dev/stdout") {
		if ((fd = open(path.c_str(), O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0)
			return -1;
		was_opened = 1;
	}

	string::size_type idx = 0;
	size_t n = 0, chunk_size= 0x1000;
	do {
		if (msg.size() - idx < chunk_size)
			n = msg.size() - idx;
		else
			n = chunk_size;
		if ((string::size_type)write(fd, msg.c_str() + idx, n) != n) {
			if (was_opened)
				close(fd);
			return -1;
		}
		idx += n;
	} while (idx < msg.size());

	if (was_opened)
		close(fd);
	return 0;
}


string idformat(const string &id)
{
	if (config::idformat == "short")
		return id.substr(0, 16);
	else if (config::idformat == "split") {
		string s = "";
		for (string::size_type i = 0; i < id.size(); i += 16) {
			s += id.substr(i, 16);
			if (i + 16 < id.size())
				s += " ";
		}
		return s;
	}

	return id;
}


int file2hexhash(const string &path, string &hexhash)
{
	hexhash = "";
	string text = "";
	if (read_msg(path, text) < 0)
		return -1;

	unsigned int hlen = 0;
	unsigned char digest[EVP_MAX_MD_SIZE];	// 64 which matches sha512
	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
	if (!md_ctx.get())
		return -1;
	if (EVP_DigestInit_ex(md_ctx.get(), algo2md(config::shash), nullptr) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), text.c_str(), text.size()) != 1)
		return -1;
	if (EVP_DigestFinal_ex(md_ctx.get(), digest, &hlen) != 1)
		return -1;

	text = "";
	blob2hex(string(reinterpret_cast<char *>(digest), hlen), hexhash);
	return 0;
}


// a detached signature
int do_sign()
{
	string hexhash = "";

	unique_ptr<persona> my_persona(nullptr);
	unique_ptr<keystore> ks(new (nothrow) keystore(config::phash, config::cfgbase));
	persona *my_p = nullptr;

	if (!ks.get()) {
		estr<<prefix<<"ERROR: OOM\n"; eflush();
		return -1;
	}

	if (config::my_id.size() == 16) {
		if (ks->load() < 0) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
		if (!(my_p = ks->find_persona(config::my_id))) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
	} else {
		my_persona.reset(new (nothrow) persona(config::cfgbase, config::my_id));
		if (!(my_p = my_persona.get())) {
			estr<<prefix<<"ERROR: OOM\n"; eflush();
			return -1;
		}
		if (my_p->load() < 0) {
			estr<<prefix<<"ERROR: "<<my_p->why()<<endl; eflush();
			return -1;
		}
		if (!my_p->can_sign()) {
			estr<<prefix<<"ERROR: Missing keys for signing!\n"; eflush();
			return -1;
		}
	}

	if (file2hexhash(config::infile, hexhash) < 0) {
		estr<<prefix<<"ERROR: generating "<<config::shash<<" for file.\n"; eflush();
		return -1;
	}

	message msg(config::cfgbase, config::phash, config::khash, config::shash, "null");
	msg.src_id(my_p->get_id());
	msg.dst_id(my_p->get_id());

	if (my_p->get_type() == marker::rsa)
		msg.kex_id(marker::rsa_kex_id);
	else
		msg.kex_id(marker::ec_kex_id);

	if (msg.encrypt(hexhash, my_p, my_p) < 0) {
		estr<<prefix<<"ERROR: Signing file: "<<msg.why()<<endl; eflush();
		return -1;
	}
	if (write_msg(config::outfile, hexhash) < 0) {
		estr<<prefix<<"ERROR: Writing outfile: "<<strerror(errno)<<endl; eflush();
		return -1;
	}
	return 0;
}


int do_encrypt(const string &dst_id)
{
	int r1 = 0, r2 = 0;

	unique_ptr<persona> dst_persona(nullptr), src_persona(nullptr);
	unique_ptr<keystore> ks(new (nothrow) keystore(config::phash, config::cfgbase));
	persona *dst_p = nullptr, *src_p = nullptr;
	string text = "", kex_id = marker::rsa_kex_id;

	if (!ks.get()) {
		estr<<prefix<<"ERROR: OOM\n"; eflush();
		return -1;
	}

	if (dst_id.size() == 16 || config::my_id.size() == 16) {
		if (ks->load() < 0) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
		// do not use unique_ptr here, we dont have ownership
		if (!(dst_p = ks->find_persona(dst_id))) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
		// any default src linked to this target? override!
		if (dst_p->linked_src().size() > 0)
			config::my_id = dst_p->linked_src();

		if (!(src_p = ks->find_persona(config::my_id))) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
	} else {
		dst_persona.reset(new (nothrow) persona(config::cfgbase, dst_id));
		if (!(dst_p = dst_persona.get())) {
			estr<<prefix<<"ERROR: OOM\n"; eflush();
			return -1;
		}
		if (dst_p->load() < 0) {
			estr<<prefix<<"ERROR: "<<dst_persona->why()<<endl; eflush();
			return -1;
		}
		// any default src linked to this target? override!
		if (dst_p->linked_src().size() > 0)
			config::my_id = dst_p->linked_src();

		src_persona.reset(new (nothrow) persona(config::cfgbase, config::my_id));
		if (!(src_p = src_persona.get())) {
			estr<<prefix<<"ERROR: OOM\n"; eflush();
			return -1;
		}
		if (src_p->load() < 0) {
			estr<<prefix<<"ERROR: "<<src_persona->why()<<endl; eflush();
			return -1;
		}
	}

	if (!dst_p->can_encrypt()) {
		estr<<prefix<<"ERROR: Missing keys for encryption.\n"; eflush();
		return -1;
	}
	if (!src_p->can_sign()) {
		estr<<prefix<<"ERROR: Missing signing key for ourselfs.\n"; eflush();
		return -1;
	}

	if (read_msg(config::infile, text) < 0) {
		estr<<prefix<<"ERROR: reading infile: "<<strerror(errno)<<"\n"; eflush();
		return -1;
	}

	message msg(config::cfgbase, config::phash, config::khash, config::shash, config::calgo);
	msg.src_id(src_p->get_id());
	msg.dst_id(dst_p->get_id());

	if (dst_p->get_type() == marker::ec)
		kex_id = marker::ec_kex_id;

	if (!config::native_crypt) {
		for (auto i = dst_p->first_key(); i != dst_p->end_key(); i = dst_p->next_key(i)) {
			if (i->second->can_encrypt()) {
				kex_id = i->first;
				break;
			}
		}
		if (kex_id == marker::rsa_kex_id ||
		    kex_id == marker::ec_kex_id) {
			estr<<prefix<<"warn: Out of (EC)DH keys for target persona. Using EC/RSA fallback.\n";
			eflush();
		}
	}

	// rsa/ec marker in case no ephemeral (EC)DH key was found
	msg.kex_id(kex_id);

	// Add new (EC)DH keys for upcoming Kex in future
	vector<PKEYbox *> newdh;
	for (int i = 0; src_p->can_gen_dh() && i < config::new_dh_keys; ++i) {
		PKEYbox *pbox = src_p->gen_dh_key(config::khash);
		if (pbox) {
			newdh.push_back(pbox);
			msg.ecdh_keys.push_back(pbox->pub_pem);
		}
	}

	r1 = msg.encrypt(text, src_p, dst_p);
	if (r1 >= 0)
		r2 = write_msg(config::outfile, text);

	// in case of errors, the message cant get sent out. So, erase generated DH
	// keys from keystore
	if (r1 < 0 || r2 < 0) {
		for (auto i = newdh.begin(); i != newdh.end(); ++i) {
			src_p->del_dh_pub((*i)->hex);
			src_p->del_dh_priv((*i)->hex);
			src_p->del_dh_id((*i)->hex);
		}

		if (r1 < 0) {
			estr<<prefix<<"ERROR: "<<msg.why()<<endl;
			eflush();
		} else {
			estr<<prefix<<"ERROR: writing outfile: "<<strerror(errno)<<"\n";
			eflush();
		}
		return -1;
	}

	// everything went fine, so erase used pub DH key from
	// peer personas store to avoid using them twice
	if (kex_id != marker::rsa_kex_id && kex_id != marker::ec_kex_id) {
		dst_p->del_dh_pub(kex_id);

		// dont delete the id itself, it would erase underlying
		// key directory. But we want to keep it so that no DH keys
		// are re-used, once old opmsg are decrypted and old "new" DH keys
		// are tried to be imported again.
		//dst_p->del_dh_id(kex_id);
	}

	return 0;
}


int do_decrypt()
{
	string ctext = "";

	if (read_msg(config::infile, ctext) < 0) {
		estr<<prefix<<"ERROR: reading infile: "<<strerror(errno)<<"\n"; eflush();
		return -1;
	}

	string::size_type pos = 0;
	if ((pos = ctext.find(marker::opmsg_begin)) == string::npos) {
		estr<<prefix<<"ERROR: Infile not in OPMSG format.\n"; eflush();
		return -1;
	}
	if (pos > 0)
		ctext.erase(0, pos);
	if ((pos = ctext.find(marker::opmsg_end)) == string::npos) {
		estr<<prefix<<"ERROR: Infile not in OPMSG format.\n"; eflush();
		return -1;
	}
	// cut off anything at the end
	ctext.erase(pos + marker::opmsg_end.size());

	message msg(config::cfgbase, config::phash, config::khash, config::shash, config::calgo);

	if (msg.decrypt(ctext) < 0) {
		estr<<prefix<<"ERROR: decrypting message: "<<msg.why()<<endl; eflush();
		return -1;
	}

	if (msg.kex_id() == marker::rsa_kex_id ||
	    msg.kex_id() == marker::ec_kex_id)
		estr<<prefix<<"warn: Your peer is out of (EC)DH keys and uses EC/RSA fallback mode.\n";

	estr<<prefix<<"GOOD signature from persona "<<idformat(msg.src_id());
	if (msg.get_srcname().size() > 0)
		estr<<" ("<<msg.get_srcname()<<")";
	estr<<endl<<prefix<<"Imported "<<msg.ecdh_keys.size()<<" new (EC)DH keys.\n\n"; eflush();

	if (write_msg(config::outfile, ctext) < 0) {
		estr<<prefix<<"ERROR: writing outfile: "<<strerror(errno)<<"\n"; eflush();
		return -1;
	}

	// only burn keys after everything else was a success, including
	// writing of plaintext message
	persona p(config::cfgbase, msg.dst_id());
	if (config::burn) {
		p.del_dh_priv(msg.kex_id());
		p.del_dh_pub(msg.kex_id());
		p.del_dh_id(msg.kex_id());
	} else {
		p.used_key(msg.kex_id(), 1);
	}
	return 0;
}


int do_verify(const string &verify_file)
{
	string ctext = "", hexhash = "";

	if (read_msg(config::infile, ctext) < 0) {
		estr<<prefix<<"ERROR: reading infile: "<<strerror(errno)<<"\n"; eflush();
		return -1;
	}

	message msg(config::cfgbase, config::phash, config::khash, config::shash, config::calgo);

	if (msg.decrypt(ctext) < 0) {
		estr<<prefix<<"ERROR: verifying message: "<<msg.why()<<endl; eflush();
		return -1;
	}

	if (file2hexhash(verify_file, hexhash) < 0) {
		estr<<prefix<<"ERROR: generating hash for file.\n"; eflush();
		return -1;
	}
	if (ctext == hexhash) {
		estr<<prefix<<"GOOD signature and hash via persona "<<idformat(msg.src_id())<<"\n"; eflush();
		return 0;
	} else {
		estr<<prefix<<"BAD "<<msg.get_shash()<<" of input file for persona "<<idformat(msg.src_id())<<"\n"; eflush();
	}
	return -1;
}


int do_newpersona(const string &name, const string &type)
{
	keystore ks(config::phash, config::cfgbase);

	string pub = "", priv = "";

	if (type == marker::rsa) {
		if (ks.gen_rsa(pub, priv) < 0) {
			estr<<prefix<<"ERROR: generating new RSA keys: "<<ks.why()<<endl; eflush();
			return -1;
		}
	} else {
		if (ks.gen_ec(pub, priv) < 0) {
			estr<<prefix<<"ERROR: generating new EC keys: "<<ks.why()<<endl; eflush();
			return -1;
		}
	}

	// "new" means, generate new DHparams in case of RSA
	persona *p = nullptr;
	if (!(p = ks.add_persona(name, pub, priv, "new"))) {
		estr<<prefix<<"ERROR: Adding new persona to keystore: "<<ks.why()<<endl; eflush();
		return -1;
	}
	estr<<"\n\n"<<prefix<<"Successfully generated persona with id\n"<<prefix<<idformat(p->get_id())<<endl;
	estr<<prefix<<"Tell your remote peer to add the following pubkey like this:\n";
	estr<<prefix<<"opmsg --import --phash "<<config::phash;
	if (name.size() > 0)
		estr<<" --name "<<name;
	estr<<"\n\n";
	eflush();
	ostr<<pub<<endl;
	oflush();
	estr<<prefix<<"Check (by phone, otr, twitter, id-selfie etc.) that above id matches\n";
	estr<<prefix<<"the import message from your peer.\n";
	estr<<prefix<<"AFTER THAT, you can go ahead, safely exchanging op-messages.\n\n";
	eflush();
	return 0;
}


int do_new_rsa_persona(const string &name)
{
	return do_newpersona(name, marker::rsa);
}


int do_new_ec_persona(const string &name)
{
	return do_newpersona(name, marker::ec);
}


int do_newdhparams()
{
	unique_ptr<persona> my_persona(nullptr);
	unique_ptr<keystore> ks(new (nothrow) keystore(config::phash, config::cfgbase));
	persona *my_p = nullptr;

	if (!ks.get()) {
		estr<<prefix<<"ERROR: OOM\n"; eflush();
		return -1;
	}

	if (config::my_id.size() == 16) {
		if (ks->load() < 0) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
		if (!(my_p = ks->find_persona(config::my_id))) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
	} else {
		my_persona.reset(new (nothrow) persona(config::cfgbase, config::my_id));
		if (!(my_p = my_persona.get())) {
			estr<<prefix<<"ERROR: OOM\n"; eflush();
			return -1;
		}
		if (my_p->load() < 0) {
			estr<<prefix<<"ERROR: "<<my_p->why()<<endl; eflush();
			return -1;
		}
		if (!my_p->can_sign()) {
			estr<<prefix<<"ERROR: Missing keys for signing.\n"; eflush();
			return -1;
		}
	}

	if (!my_p->new_dh_params()) {
		estr<<"\n\n"<<prefix<<"ERROR: Generating DHparams for "<<config::my_id<<"\n"; eflush();
		return -1;
	}
	estr<<"\n\n"<<prefix<<"Successfully generated new DHparams for "<<config::my_id<<"\n"; eflush();

	return 0;
}


int do_list(const string &name)
{
	keystore ks(config::phash, config::cfgbase);
	if (ks.load() < 0) {
		estr<<prefix<<"ERROR: Loading keystore.\n"; eflush();
		return -1;
	}
	estr<<prefix<<"Successfully loaded "<<ks.size()<<" personas.\n";
	estr<<prefix<<"id | type | has privkey | #(EC)DHkeys | name\n";
	eflush();
	for (auto i = ks.first_pers(); i != ks.end_pers(); i = ks.next_pers(i)) {
		if (name.size() == 0 || i->second->get_name().find(name) != string::npos) {
			ostr<<prefix<<idformat(i->second->get_id())<<" "<<i->second->get_type()<<"\t";
			ostr<<i->second->can_sign()<<" "<<i->second->size()<<"\t"<<i->second->get_name()<<endl;
		}
	}
	oflush();
	return 0;
}


int do_pgplist(const string &name)
{
	keystore ks(config::phash, config::cfgbase);
	if (ks.load() < 0)
		return -1;

	for (auto i = ks.first_pers(); i != ks.end_pers(); i = ks.next_pers(i)) {
		if (name.size() == 0 || i->second->get_name().find(name) != string::npos)
			ostr<<"pub:u:1337:1:"<<idformat(i->second->get_id())<<":1::"<<idformat(i->second->get_id())<<"::"<<i->second->get_name()<<"::eEsS\n";
	}
	oflush();
	return 0;
}


int do_import(const string &name)
{
	if (config::infile == "/dev/stdin")
		estr<<prefix<<"Paste the EC/RSA pubkey here. End with <Ctrl-C>\n\n";

	string pub = "";
	if (read_msg(config::infile, pub) < 0) {
		estr<<prefix<<"ERROR: Importing persona: "<<strerror(errno)<<endl; eflush();
		return -1;
	}

	keystore ks(config::phash, config::cfgbase);

	persona *p = nullptr;
	if (!(p = ks.add_persona(name, pub, "", ""))) {
		estr<<prefix<<"ERROR: Importing persona: "<<ks.why()<<endl; eflush();
		return -1;
	}
	estr<<prefix<<"Successfully imported pesona with id "<<idformat(p->get_id())<<".\n";
	estr<<prefix<<"Check with your peer (phone, otr, twitter, selfie, ...) whether above id matches\n";
	estr<<prefix<<"with the id that your peer got printed when generating that persona.\n";
	estr<<prefix<<"If they do not match, you can delete this persona by removing the subdirectory\n";
	estr<<prefix<<"of obove id inside your ~/.opmsg directory.\n";
	eflush();
	return 0;
}


int do_link(const string &dst_id)
{
	persona *src_p = nullptr, *dst_p = nullptr;
	unique_ptr<persona> src_persona(nullptr), dst_persona(nullptr);
	unique_ptr<keystore> ks(new (nothrow) keystore(config::phash, config::cfgbase));

	if (!ks.get()) {
		estr<<prefix<<"ERROR: OOM\n"; eflush();
		return -1;
	}

	string link_id = config::my_id;

	if (dst_id.size() == 16 || config::my_id.size() == 16) {
		if (ks->load() < 0) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
		// do not use unique_ptr here, we dont have ownership
		if (!(dst_p = ks->find_persona(dst_id))) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
		if (!(src_p = ks->find_persona(config::my_id))) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
		// take the long form
		link_id = src_p->get_id();
	} else {
		dst_persona.reset(new (nothrow) persona(config::cfgbase, dst_id));
		if (!(dst_p = dst_persona.get())) {
			estr<<prefix<<"ERROR: OOM\n"; eflush();
			return -1;
		}
		if (dst_p->load() < 0) {
			estr<<prefix<<"ERROR: "<<dst_persona->why()<<endl; eflush();
			return -1;
		}
		src_persona.reset(new (nothrow) persona(config::cfgbase, config::my_id));
		if (!(src_p = src_persona.get())) {
			estr<<prefix<<"ERROR: OOM\n"; eflush();
			return -1;
		}
		if (src_p->load() < 0) {
			estr<<prefix<<"ERROR: "<<src_persona->why()<<endl; eflush();
			return -1;
		}
	}

	if (!src_p->can_sign()) {
		estr<<prefix<<"ERROR: "<<config::my_id<<" cannot be set as default-src because it lacks a private key.\n"; eflush();
		return -1;
	}
	if (!dst_p->can_encrypt()) {
		estr<<prefix<<"ERROR: Invalid target persona "<<dst_id<<endl; eflush();
		return -1;
	}

	if (dst_p->link(link_id) < 0) {
		estr<<prefix<<"ERROR: "<<dst_p->why()<<endl; eflush();
		return -1;
	}
	return 0;
}


void sig_int(int x)
{
	return;
}


int main(int argc, char **argv)
{

	struct option lopts[] = {
	        {"confdir", required_argument, nullptr, 'c'},
	        {"native", no_argument, nullptr, 'R'},
	        {"encrypt", required_argument, nullptr, 'E'},
	        {"decrypt", no_argument, nullptr, 'D'},
	        {"sign", no_argument, nullptr, 'S'},
	        {"verify", required_argument, nullptr, 'V'},
	        {"persona", required_argument, nullptr, 'P'},
	        {"import", no_argument, nullptr, 'I'},
	        {"list", no_argument, nullptr, 'l'},
	        {"listpgp", no_argument, nullptr, 'L'},
	        {"short", no_argument, nullptr, ID_FORMAT_SHORT},
	        {"long", no_argument, nullptr, ID_FORMAT_LONG},
	        {"split", no_argument, nullptr, ID_FORMAT_SPLIT},
	        {"newp", no_argument, nullptr, 'N'},
		{"newecp", no_argument, nullptr, NEWECP},
		{"newdhp", no_argument, nullptr, NEWDHP},
	        {"calgo", required_argument, nullptr, 'C'},
	        {"phash", required_argument, nullptr, 'p'},
	        {"name", required_argument, nullptr, 'n'},
	        {"link", required_argument, nullptr, LINK},
	        {"burn", no_argument, nullptr, BURN},
	        {"in", required_argument, nullptr, 'i'},
	        {"out", required_argument, nullptr, 'o'},
	        {"freehugs", no_argument, nullptr, FREEHUGS},
	        {nullptr, 0, nullptr, 0}};

	int c = 1, opt_idx = 0, cmode = CMODE_INVALID, r = -1;
	string detached_file = "", dst_id = "", verify_file = "", name = "", link_src = "";

	if (getenv("HOME")) {
		config::cfgbase = getenv("HOME");
		config::cfgbase += "/.opmsg";
	}

	// no output buffering
	setbuffer(stdout, nullptr, 0);
	setbuffer(stderr, nullptr, 0);
	cout.unsetf(ios::unitbuf);
	cerr.unsetf(ios::unitbuf);

	if (argc == 1)
		usage(argv[0]);

	// first, try to find out any --config option
	if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--config") == 0) {
		if (!argv[2])
			usage(argv[0]);
		config::cfgbase = argv[2];
	}

	mkdir(config::cfgbase.c_str(), 0700);
	parse_config(config::cfgbase);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_int;
	sigaction(SIGINT, &sa, nullptr);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, nullptr);


	while ((c = getopt_long(argc, argv, "RLlIn:NP:C:p:SE:DV:i:o:c:", lopts, &opt_idx)) != -1) {
		switch (c) {
		case 'c':
			// was already handled
			break;
		case 'i':
			config::infile = optarg;
			break;
		case 'o':
			config::outfile = optarg;
			break;
		case 'C':
			config::calgo = optarg;
			break;
		case 'E':
			cmode = CMODE_ENCRYPT;
			dst_id = optarg;
			break;
		case 'D':
			cmode = CMODE_DECRYPT;
			break;
		case 'S':
			cmode = CMODE_SIGN;
			break;
		case 'P':
			config::my_id = optarg;
			break;
		case 'V':
			cmode = CMODE_VERIFY;
			verify_file = optarg;
			break;
		case 'N':
			cmode = CMODE_NEWP;
			break;
		case 'I':
			cmode = CMODE_IMPORT;
			break;
		case 'R':
			config::native_crypt = 1;
			break;
		case 'l':
			cmode = CMODE_LIST;
			break;
		case 'L':
			cmode = CMODE_PGPLIST;
			break;
		case 'n':
			name = optarg;
			break;
		case 'p':
			config::phash = optarg;
			break;
		case NEWDHP:
			cmode = CMODE_NEWDHP;
			break;
		case NEWECP:
			cmode = CMODE_NEWECP;
			break;
		case ID_FORMAT_LONG:
			config::idformat = "long";
			break;
		case ID_FORMAT_SPLIT:
			config::idformat = "split";
			break;
		case ID_FORMAT_SHORT:
			config::idformat = "short";
			break;
		case LINK:
			link_src = optarg;
			cmode = CMODE_LINK;
			break;
		case BURN:
			config::burn = 1;
			break;
		case FREEHUGS:
			cmode = CMODE_FREEHUGS;
			break;
		}
	}

	if (cmode == CMODE_INVALID)
		usage(argv[0]);

	if (cmode != CMODE_PGPLIST) {
		estr<<banner; eflush();
	}

	if (cmode == CMODE_FREEHUGS) {
		ostr<<"HUG, HUG - sell a bug.\n"; oflush();
	}

	if (!is_valid_halgo(config::phash)) {
		estr<<prefix<<"Invalid persona hashing algorithm. Valid hash algorithms are:\n\n";
		print_halgos(estr);
		estr<<"\n"<<prefix<<"FAILED.\n";
		eflush();
		return -1;
	}

	if (!is_valid_calgo(config::calgo)) {
		estr<<prefix<<"Invalid crypto algorithm. Valid crypto algorithms are:\n\n";
		print_calgos(estr);
		estr<<"\n"<<prefix<<"FAILED.\n";
		eflush();
		return -1;
	}

	OpenSSL_add_all_algorithms();

	RAND_load_file("/dev/urandom", 2048);

	// clear error queue, since FIPS loading bugs might overlay our own errors
	ERR_clear_error();

	if (config::infile == "-")
		config::infile = "/dev/stdin";
	if (config::outfile == "-")
		config::outfile = "/dev/stdout";

	// strip of spaces in case of split format id given
	config::my_id.erase(remove(config::my_id.begin(), config::my_id.end(), ' '), config::my_id.end());
	dst_id.erase(remove(dst_id.begin(), dst_id.end(), ' '), dst_id.end());

	// remove any leading 0x in the ID's, as passed by mutt etc.
	if (dst_id.find("0x") == 0)
		dst_id.erase(0, 2);
	if (config::my_id.find("0x") == 0)
		config::my_id.erase(0, 2);

	switch (cmode) {
	case CMODE_ENCRYPT:
		estr<<prefix<<"encrypting for persona "<<idformat(dst_id)<< "\n"; eflush();
		r = do_encrypt(dst_id);
		break;
	case CMODE_DECRYPT:
		estr<<prefix<<"decrypting\n"; eflush();
		r = do_decrypt();
		break;
	case CMODE_SIGN:
		estr<<prefix<<"detached file-signing by persona "<<idformat(config::my_id)<<"\n"; eflush();
		r = do_sign();
		break;
	case CMODE_VERIFY:
		estr<<prefix<<"verifying detached file\n"; eflush();
		r = do_verify(verify_file);
		break;
	case CMODE_NEWP:
		estr<<prefix<<"creating new persona (RSA "<<config::rsa_len<<", DH "<<config::dh_plen<<")\n\n"; eflush();
		r = do_new_rsa_persona(name);
		break;
	case CMODE_NEWDHP:
		estr<<prefix<<"creating new DHparams for persona "<<idformat(config::my_id)<<"\n\n"; eflush();
		r = do_newdhparams();
		break;
	case CMODE_NEWECP:
		estr<<prefix<<"creating new EC persona (curve "<<config::curve<<")\n\n"; eflush();
		r = do_new_ec_persona(name);
		break;
	case CMODE_IMPORT:
		estr<<prefix<<"importing persona\n"; eflush();
		r = do_import(name);
		break;
	case CMODE_LINK:
		estr<<prefix<<"linking personas\n"; eflush();
		r = do_link(link_src);
		break;
	case CMODE_LIST:
		estr<<prefix<<"persona list:\n"; eflush();
		r = do_list(name);
		break;
	case CMODE_PGPLIST:
		r = do_pgplist(name);
		break;
	}

	if (cmode != CMODE_PGPLIST) {
		if (r == 0)
			estr<<prefix<<"SUCCESS.\n";
		else
			estr<<prefix<<"FAILED.\n";
	}

	eflush();

	return r;
}


