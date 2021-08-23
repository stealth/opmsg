/*
 * This file is part of the opmsg crypto message framework.
 *
 * (C) 2015-2021 by Sebastian Krahmer,
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

#include <iostream>
#include <sstream>
#include <memory>
#include <vector>
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
#include "missing.h"
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
	DENIABLE		= 7,
	FREEHUGS		= 8,
	BRAINKEY1		= 9,
	SALT1			= 10,
	BRAINKEY2		= 11,
	SALT2			= 12,

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


const string banner = "\nopmsg: version=1.83 (C) 2021 Sebastian Krahmer: https://github.com/stealth/opmsg\n\n";

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
	ostr<<"\nUsage: opmsg [--confdir dir] [--native] [--encrypt dst-ID] [--decrypt] [--sign]"<<endl
	    <<"\t[--verify file] <--persona ID> [--import] [--list] [--listpgp]"<<endl
	    <<"\t[--short] [--long] [--split] [--new(ec)p] [--newdhp] [--brainkey1/2]"<<endl
	    <<"\t[--salt1/2 slt] [--calgo name] [--phash name [--name name] [--in infile]"<<endl
	    <<"\t[--out outfile] [--link target id] [--deniable] [--burn]"<<endl<<endl
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
	    <<"\t--deniable\t\twhen create/import personas, do it deniable"<<endl
	    <<"\t--link\t\t\tlink (your) --persona as default src to this"<<endl
	    <<"\t\t\t\ttarget id"<<endl
	    <<"\t--newdhp\t\tcreate new DHparams for persona (rarely needed)"<<endl
	    <<"\t--brainkey1/2\t\tuse secret to derive deniable persona keys"<<endl
	    <<"\t--salt1/2\t\toptional: use salt when when using brainkeys"<<endl
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


int write_msg(const string &path, const string &msg, int append)
{
	int fd = 1;
	bool was_opened = 0;

	if (path != "/dev/stdout") {
		int flags = O_WRONLY|O_CREAT|O_EXCL;
		if (append)
			flags = O_WRONLY|O_CREAT|O_APPEND;
		if ((fd = open(path.c_str(), flags, 0600)) < 0)
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
	unsigned char digest[EVP_MAX_MD_SIZE] = {0};	// 64 which matches sha512
	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
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

	unique_ptr<keystore> ks(new (nothrow) keystore(config::phash, config::cfgbase));
	persona *my_p = nullptr;

	if (!ks.get()) {
		estr<<prefix<<"ERROR: OOM\n"; eflush();
		return -1;
	}

	if (ks->load(config::my_id) < 0) {
		estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
		return -1;
	}

	if (!(my_p = ks->find_persona(config::my_id))) {
		estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
		return -1;
	}

	if (!my_p->can_sign()) {
		estr<<prefix<<"ERROR: Missing keys for signing!\n"; eflush();
		return -1;
	}

	if (file2hexhash(config::infile, hexhash) < 0) {
		estr<<prefix<<"ERROR: generating "<<config::shash<<" for file.\n"; eflush();
		return -1;
	}

	message msg(config::version, config::cfgbase, config::phash, config::khash, config::shash, "null");
	msg.src_id(my_p->get_id());
	msg.dst_id(my_p->get_id());

	if (my_p->get_type() == marker::rsa)
		msg.kex_id(marker::rsa_kex_id);
	else
		msg.kex_id(marker::ec_kex_id);

	if (msg.encrypt(hexhash, my_p, my_p) != 1) {
		estr<<prefix<<"ERROR: Signing file: "<<msg.why()<<endl; eflush();
		return -1;
	}
	if (write_msg(config::outfile, hexhash, 0) < 0) {
		estr<<prefix<<"ERROR: Writing outfile: "<<strerror(errno)<<endl; eflush();
		return -1;
	}
	return 0;
}


int do_encrypt(const string &dst_id, const string &s, int may_append)
{
	int r1 = 0, r2 = 0;
	bool linked_to_myself = 0;

	unique_ptr<keystore> ks(new (nothrow) keystore(config::phash, config::cfgbase));
	persona *dst_p = nullptr, *src_p = nullptr;
	string kex_id = marker::rsa_kex_id, text = s;

	if (!ks.get()) {
		estr<<prefix<<"ERROR: OOM\n"; eflush();
		return -1;
	}

	string src_id = config::my_id;

	if (ks->load(dst_id) < 0) {
		estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
		return -1;
	}

	// do not use unique_ptr here, we dont have ownership
	if (!(dst_p = ks->find_persona(dst_id))) {
		estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
		return -1;
	}

	if (dst_p->is_pq1()) {
		if (config::version < 4) {
			estr<<prefix<<"ERROR: PQC personas need at least version 4 configured.\n"; eflush();
			return -1;
		}
		if (!is_valid_pq_calgo(config::calgo)) {
			estr<<prefix<<"ERROR: '"<<config::calgo<<"' is not a valid PQC algo.\n"; eflush();
			return -1;
		}
	}

	// any default src linked to this target? override!
	if (dst_p->linked_src().size() > 0) {
		src_id = dst_p->linked_src();

		// check if that persona was linked to itself. That means OTR-like sharing
		// of the EC/RSA persona secret and Kex-id's chosen for encryption must not have
		// the secret part on our keysore since peer who is decrypting, would be missing it.
		// Only Kex-id's with missing secret part have the secret part at the peer side.
		if (src_id == dst_p->get_id())
			linked_to_myself = 1;
	}

	if (!linked_to_myself) {
		if (ks->load(src_id) < 0) {
			estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
			return -1;
		}
	}

	if (!(src_p = ks->find_persona(src_id))) {
		estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
		return -1;
	}

	if (!dst_p->can_encrypt()) {
		estr<<prefix<<"ERROR: Missing keys for encryption.\n"; eflush();
		return -1;
	}
	if (!src_p->can_sign()) {
		estr<<prefix<<"ERROR: Missing signing key for ourselfs ("<<src_id<<").\n"; eflush();
		return -1;
	}

	message msg(config::version, config::cfgbase, config::phash, config::khash, config::shash, config::calgo);
	msg.src_id(src_p->get_id());
	msg.dst_id(dst_p->get_id());

	if (dst_p->get_type() == marker::ec)
		kex_id = marker::ec_kex_id;

	if (!config::native_crypt && config::calgo != "null") {
		for (auto i = dst_p->first_key(); i != dst_p->end_key(); i = dst_p->next_key(i)) {
			if (!i->second.empty() && i->second[0]->can_encrypt()) {
				// only keys that peer sent us for import, so ignore (EC)DH keys
				// where we also store the private half
				if (linked_to_myself && i->second[0]->can_decrypt())
					continue;
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
	vector<string> newdh;
	for (int i = 0; config::calgo != "null" && src_p->can_kex_gen() && i < config::new_dh_keys; ++i) {
		vector<PKEYbox *> vpbox = src_p->gen_kex_key(config::khash, dst_p->get_id());
		if (vpbox.size() > 0) {
			newdh.push_back(vpbox[0]->d_hex);
			msg.set_ec_domains(vpbox.size());
			for (auto j = vpbox.begin(); j != vpbox.end(); ++j)
				msg.add_ecdh_key((*j)->d_pub_pem);
		}
	}

	r1 = msg.encrypt(text, src_p, dst_p);
	if (r1 == 1)
		r2 = write_msg(config::outfile, text, may_append);

	// in case of errors, the message cant get sent out. So, erase generated DH
	// keys from keystore
	if (r1 < 1 || r2 < 0) {
		int save_errno = errno;

		for (auto i = newdh.begin(); i != newdh.end(); ++i) {
			src_p->del_dh_pub(*i);
			src_p->del_dh_priv(*i);
			src_p->del_dh_id(*i);
		}

		if (r1 < 1) {
			estr<<prefix<<"ERROR: "<<msg.why()<<endl;
			eflush();
		} else {
			estr<<prefix<<"ERROR: writing outfile: "<<strerror(save_errno)<<"\n";
			eflush();
		}
		return -1;
	}

	// everything went fine, so erase used pub DH key from
	// peer personas store to avoid using them twice
	if (kex_id != marker::rsa_kex_id && kex_id != marker::ec_kex_id) {
		dst_p->del_dh_pub(kex_id);
		// hexid directory can be delted too, newly imported keys are tracked
		// via 'imported' file per persona. If we dont track it in "imported"
		// files, leave empty dir in place
		if (dst_p->has_imported(kex_id))
			dst_p->del_dh_id(kex_id);
	}

	return 0;
}


int do_decrypt()
{
	string ctext = "";
	int r = 0, found_one = 0;

	if (read_msg(config::infile, ctext) < 0) {
		estr<<prefix<<"ERROR: reading infile: "<<strerror(errno)<<"\n"; eflush();
		return -1;
	}

	if (!config::nodos2unix && ctext.substr(0, 1024).find('\r') != string::npos) {
		estr<<prefix<<"WARN: removing CR from newlines. Inserted by your mailer?\n";
		ctext.erase(remove(ctext.begin(), ctext.end(), '\r'), ctext.end());
	}

	string::size_type pos = 0;

	// Might be multiple opmsg appended in a row (Cc mail), try to find
	// one thats for us
	for (;;) {
		estr<<prefix<<"decrypting\n";

		// Only an error if no opmsg found so far
		if ((pos = ctext.find(marker::opmsg_begin)) == string::npos) {
			if (!found_one) {
				estr<<prefix<<"ERROR: Missing persona/kex keys or not in OPMSG format.\n";
				return -1;
			}
			break;
		}
		if (pos > 0)
			ctext.erase(0, pos);

		if ((pos = ctext.find(marker::opmsg_end)) == string::npos) {
			estr<<prefix<<"ERROR: Infile not in OPMSG format.\n";
			return -1;
		}

		// split off one message
		string s = ctext.substr(0, pos + marker::opmsg_end.size());
		ctext.erase(0, pos + marker::opmsg_end.size());

		message msg(1, config::cfgbase, config::phash, config::khash, config::shash, config::calgo);

		if (config::peer_isolation)
			msg.enable_peer_isolation();

		r = msg.decrypt(s);
		if (r != 1) {
			// Due to Cc, it could be a message we find no persona for
			if (r == 0) {
				estr<<prefix<<msg.why()<<endl;
				continue;
			}
			estr<<prefix<<"ERROR: decrypting message: "<<msg.why()<<endl;
			return r;
		}

		if (msg.kex_id() == marker::rsa_kex_id ||
		    msg.kex_id() == marker::ec_kex_id)
			estr<<prefix<<"warn: Your peer is out of (EC)DH keys and uses EC/RSA fallback mode.\n";

		estr<<prefix<<"GOOD signature from persona "<<idformat(msg.src_id());
		if (msg.get_srcname().size() > 0)
			estr<<" ("<<msg.get_srcname()<<")";
		estr<<endl<<prefix<<"Imported "<<msg.num_ecdh_keys()<<" new (EC)DH key(s) from "<<msg.get_ec_domains()<<" domain(s).\n\n";
		eflush();

		if (write_msg(config::outfile, s, found_one) < 0) {
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
		found_one = 1;
	}

	return 0;
}


int do_verify(const string &verify_file)
{
	string ctext = "", hexhash = "";
	string::size_type pos = 0;

	if (read_msg(config::infile, ctext) < 0) {
		estr<<prefix<<"ERROR: reading infile: "<<strerror(errno)<<"\n"; eflush();
		return -1;
	}

	if ((pos = ctext.find(marker::opmsg_begin)) == string::npos) {
		estr<<prefix<<"ERROR: Infile not in OPMSG format.\n";
		return -1;
	}
	if (pos > 0)
		ctext.erase(0, pos);

	if ((pos = ctext.find(marker::opmsg_end)) == string::npos) {
		estr<<prefix<<"ERROR: Infile not in OPMSG format.\n";
		return -1;
	}

	ctext.erase(pos + marker::opmsg_end.size());

	message msg(1, config::cfgbase, config::phash, config::khash, config::shash, config::calgo);

	if (msg.decrypt(ctext) != 1) {
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


int do_newpersona(const string &name, const string &type, bool sign)
{

	if (!is_valid_halgo(config::phash, 1)) {
		estr<<prefix<<"ERROR: not a valid persona hash algorithm.\n"; eflush();
		return -1;
	}

	keystore ks(config::phash, config::cfgbase);

	string pub = "", priv = "";

	if (type == marker::rsa) {
		if (ks.gen_rsa(pub, priv) < 0) {
			estr<<prefix<<"ERROR: generating new RSA keys: "<<ks.why()<<endl; eflush();
			return -1;
		}
	} else {
		if (ks.gen_ec(pub, priv, config::curve_nids[0]) < 0) {
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
	if (config::deniable) {
		if (p->link(p->get_id()) < 0)
			estr<<prefix<<"ERROR: Failed to link deniable persona to itself: "<<ks.why()<<endl;

		if (config::pq_type.size() > 0) {
			if (p->make_pq1(config::pq_type, config::brainkey12, config::salt2) < 0) {
				estr<<prefix<<"ERROR: Failed to make persona PQ-safe: "<<ks.why()<<endl; eflush();
				return -1;
			}
			estr<<prefix<<"You created a deniable PQC persona.\n";
		} else
			estr<<prefix<<"You created a deniable persona.\n";

		if (config::brainkey12.size() > 0) {
			estr<<prefix<<"Your persona key was derived from a brainkey. No need to exchange keys\n"
			    <<prefix<<"with your peer. Your peer just needs to execute the same command as you\n"
			    <<prefix<<"in order to create the same deniable persona on their side.\n\n";
			eflush();
			return 0;
		} else
			estr<<prefix<<"SEND BOTH KEYS ONLY ACROSS EXISTING _SECURE_ OPMSG CHANNEL.\n";
	}

	estr<<prefix<<"Tell your remote peer to add the following pubkey like this:\n";
	estr<<prefix<<"opmsg --import --phash "<<config::phash;
	if (name.size() > 0)
		estr<<" --name '"<<name<<"'";
	if (config::deniable)
		estr<<" --deniable";
	estr<<"\n\n";
	eflush();

	ostr<<pub;
	if (config::deniable)
		ostr<<priv;

	// (self-)sign output data shown to user with the freshly generated persona;
	// output can be --imported and verified via --decrypt
	if (sign) {
		string s = ostr.str();
		message msg(config::version, config::cfgbase, config::phash, config::khash, config::shash, "null");
		msg.src_id(p->get_id());
		msg.dst_id(p->get_id());

		if (p->get_type() == marker::ec)
			msg.kex_id(marker::ec_kex_id);
		else
			msg.kex_id(marker::rsa_kex_id);

		if (msg.encrypt(s, p, p) < 0) {
			estr<<prefix<<"ERROR: Signing freshly generated persona key: "<<msg.why()<<endl; eflush();
			return -1;
		}
		ostr.str("");
		ostr<<s;
	}

	ostr<<endl;
	oflush();

	estr<<prefix<<"Check (by phone, otr, twitter, id-selfie etc.) that above id matches\n";
	estr<<prefix<<"the import message from your peer.\n";
	estr<<prefix<<"AFTER THAT, you can go ahead, safely exchanging op-messages.\n\n";
	eflush();
	return 0;
}


int do_new_rsa_persona(const string &name, bool sign)
{
	return do_newpersona(name, marker::rsa, sign);
}


int do_new_ec_persona(const string &name, bool sign)
{
	return do_newpersona(name, marker::ec, sign);
}


int do_newdhparams()
{
	unique_ptr<keystore> ks(new (nothrow) keystore(config::phash, config::cfgbase));
	persona *my_p = nullptr;

	if (!ks.get()) {
		estr<<prefix<<"ERROR: OOM\n"; eflush();
		return -1;
	}

	if (ks->load(config::my_id) < 0) {
		estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
		return -1;
	}

	if (!(my_p = ks->find_persona(config::my_id))) {
		estr<<prefix<<"ERROR: "<<ks->why()<<endl; eflush();
		return -1;
	}

	if (!my_p->can_sign() || my_p->get_type() != marker::rsa) {
		estr<<prefix<<"ERROR: Wrong persona for DH param generation (not owning privkey or not RSA).\n"; eflush();
		return -1;
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
	// for convenience, treat hash sums the way they are, even
	// if passed as --name for searching
	string search = "", type = "";

	if (name.size() >= 16 && is_hex_hash(name))
		search = name;

	keystore ks(config::phash, config::cfgbase);
	if (ks.load(search) < 0) {
		estr<<prefix<<"ERROR: Loading keystore.\n"; eflush();
		return -1;
	}
	estr<<prefix<<"Successfully loaded "<<ks.size()<<" personas.\n";
	estr<<prefix<<"id | type | has privkey | #(EC)DHkeys | name\n";
	eflush();
	for (auto i = ks.first_pers(); i != ks.end_pers(); i = ks.next_pers(i)) {
		if (search.size() > 0 || name.size() == 0 || i->second->get_name().find(name) != string::npos) {
			type = i->second->get_type();
			if (i->second->is_pq1())
				type = "pq1";
			ostr<<prefix<<idformat(i->second->get_id())<<" "<<type<<"\t";
			ostr<<i->second->can_sign()<<" "<<i->second->size()<<"\t"<<i->second->get_name()<<endl;
		}
	}
	oflush();
	return 0;
}


// As per gnupg source keylist.c: list_keyblock_colon()
int do_pgplist(const string &name)
{
	string search = "";
	if (name.size() >= 16 && is_hex_hash(name))
		search = name;

	keystore ks(config::phash, config::cfgbase);
	if (ks.load(search, LFLAGS_ALL & ~LFLAGS_KEX) < 0)	// speedup: no Kex keys needed for listing
		return -1;

	for (auto i = ks.first_pers(); i != ks.end_pers(); i = ks.next_pers(i)) {
		if (search.size() > 0 || name.size() == 0 || i->second->get_name().find(name) != string::npos)
			ostr<<"pub:u:4096:1:"<<idformat(i->second->get_id())<<":1:0:::::eEsScCaA::+:::\n"
			    <<"uid:u::::1:0:"<<idformat(i->second->get_id())<<"::"<<i->second->get_name()<<":\n";
	}
	oflush();
	return 0;
}


static int split_deniable_keys(string &pub, string &priv)
{
	string::size_type priv_b = string::npos;
	string::size_type priv_e = string::npos;

	if ((priv_b = pub.find(marker::priv_begin)) == string::npos)
		return 0;
	if ((priv_e = pub.find(marker::priv_end, priv_b)) == string::npos)
		return -1;

	priv = pub.substr(priv_b, priv_e - priv_b + marker::priv_end.size());
	pub.erase(priv_b, priv_e - priv_b + marker::priv_end.size());
	return 1;
}


int do_import(const string &name)
{
	if (!is_valid_halgo(config::phash, 1)) {
		estr<<prefix<<"ERROR: Invalid persona hash algorithm.\n"; eflush();
		return -1;
	}

	if (config::infile == "/dev/stdin") {
		estr<<prefix<<"Paste the EC/RSA pubkey here. End with <Return> followed by <Ctrl-C>\n\n";
		eflush();
	}

	string pub = "", priv = "";
	if (read_msg(config::infile, pub) < 0) {
		estr<<prefix<<"ERROR: Importing persona: "<<strerror(errno)<<endl; eflush();
		return -1;
	}

	// if deniable persona, split off private key thats appended
	if (split_deniable_keys(pub, priv) < 0) {
		estr<<prefix<<"ERROR: Junk at end of public key!\n"; eflush();
		return -1;
	}
	if (!config::deniable && priv.size() > 0) {
		estr<<prefix<<"ERROR: Found appended private key, but no --deniable switch!\n"; eflush();
		return -1;
	}

	keystore ks(config::phash, config::cfgbase);

	persona *p = nullptr;
	if (!(p = ks.add_persona(name, pub, priv, ""))) {
		estr<<prefix<<"ERROR: Importing persona: "<<ks.why()<<endl;
		estr<<prefix<<"ERROR: Not a PEM pubkey, missing newline at end of pubkey, or missing Brainpool EC curves? Check 'opmsg -D -C list' with your peer.\n";
		eflush();
		return -1;
	}
	if (config::deniable) {
		if (p->link(p->get_id()) < 0) {
			estr<<prefix<<"ERROR: Failed to link deniable persona to itself: "<<ks.why()<<endl; eflush();
			return -1;
		}
	}

	estr<<prefix<<"Successfully imported pesona with id "<<idformat(p->get_id())<<".\n";
	estr<<prefix<<"Check with your peer (phone, otr, twitter, selfie, ...) whether above id matches\n";
	estr<<prefix<<"with the id that your peer got printed when generating that persona.\n";
	estr<<prefix<<"If they do not match, you can delete this persona by removing the subdirectory\n";
	estr<<prefix<<"of obove id inside your ~/.opmsg directory.\n\n";
	estr<<prefix<<"Do not forget to 'opmsg --link' this persona to have a valid sender-id.\n";

	// add_persona() also sets persona type. Check for RSA personas which need also DH params
	// in the deniable case since it also generates new DH Kex keys
	if (config::deniable && p->get_type() == marker::rsa)
		estr<<"\n"<<prefix<<"You imported a deniable RSA persona. Dont forget 'opmsg --newdhp -P <above id>'\n";

	eflush();
	return 0;
}


int do_link(const string &dst_id)
{
	persona *src_p = nullptr, *dst_p = nullptr;
	unique_ptr<keystore> ks(new (nothrow) keystore(config::phash, config::cfgbase));

	if (!ks.get()) {
		estr<<prefix<<"ERROR: OOM\n"; eflush();
		return -1;
	}

	string link_id = config::my_id;

	if (ks->load(dst_id) < 0 || ks->load(config::my_id) < 0) {
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


int check_valid_options(int cmode)
{
	// never ever use brainkeys for non-deniable personas or any other

	if (config::brainkey12.size() > 0) {
		if (config::pq_type.size() > 0 && config::version < 4) {
			estr<<prefix<<"ERROR: PQC needs a version configured >= 4!\n"; eflush();
			return -1;
		}
		if (!config::deniable || cmode != CMODE_NEWECP) {
			estr<<prefix<<"ERROR: Invalid combination of options!\n"; eflush();
			return -1;
		}
		if (config::brainkey12.size() < 16) {
			estr<<prefix<<"ERROR: brainkey size must be 16bytes minimum!\n"; eflush();
			return -1;
		}
	}

	return 0;
}


int main(int argc, char **argv)
{

	struct option lopts[] = {
	        {"confdir", required_argument, nullptr, 'c'},
		{"help", no_argument, nullptr, 'h'},
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
		{"newecp", optional_argument, nullptr, NEWECP},
		{"newdhp", no_argument, nullptr, NEWDHP},
		{"deniable", no_argument, nullptr, DENIABLE},
	        {"calgo", required_argument, nullptr, 'C'},
	        {"phash", required_argument, nullptr, 'p'},
	        {"name", required_argument, nullptr, 'n'},
	        {"link", required_argument, nullptr, LINK},
	        {"burn", no_argument, nullptr, BURN},
	        {"in", required_argument, nullptr, 'i'},
	        {"out", required_argument, nullptr, 'o'},
		{"brainkey1", optional_argument, nullptr, BRAINKEY1},
		{"salt1", required_argument, nullptr, SALT1},
		{"brainkey2", optional_argument, nullptr, BRAINKEY2},
		{"salt2", required_argument, nullptr, SALT2},
	        {"freehugs", no_argument, nullptr, FREEHUGS},
	        {nullptr, 0, nullptr, 0}};

	int c = 1, opt_idx = 0, cmode = CMODE_INVALID, r = -1;
	char bkbuf[256] = {0}, *nl = nullptr;
	string detached_file = "", verify_file = "", name = "", link_src = "", s = "";
	string::size_type ridx = string::npos;
	vector<string> dst_ids;

	umask(077);

	if (getenv("HOME")) {
		config::cfgbase = getenv("HOME");
		config::cfgbase += "/.opmsg";
	}

	// no output buffering
	setbuffer(stdout, nullptr, 0);
	setbuffer(stderr, nullptr, 0);
	cout.unsetf(ios::unitbuf);
	cerr.unsetf(ios::unitbuf);

	estr<<banner;
	eflush();

	if (argc == 1)
		usage(argv[0]);

	// first, try to find out any --config option
	if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--confdir") == 0) {
		if (!argv[2])
			usage(argv[0]);
		if (strcmp(argv[2], "") != 0)
			config::cfgbase = argv[2];
	}

	if (mkdir(config::cfgbase.c_str(), 0700) < 0 && errno != EEXIST) {
		estr<<prefix<<"mkdir: "<<strerror(errno)<<"\nFAILED.\n"; eflush();
		return -1;
	}
	if (parse_config(config::cfgbase) < 0) {
		estr<<prefix<<"WARN: No readable config file found.\n";
		eflush();
	}

	// should not really happen
	if (config::curve_nids.empty() || config::curves.empty()) {
		estr<<prefix<<"ERROR: Huh? No ECC curves defined.\n"; eflush();
		return -1;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_int;
	if (sigaction(SIGINT, &sa, nullptr) < 0) {
		estr<<prefix<<"sigaction: "<<strerror(errno)<<"\nFAILED.\n"; eflush();
		return -1;
	}
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, nullptr) < 0) {
		estr<<prefix<<"sigaction: "<<strerror(errno)<<"\nFAILED.\n"; eflush();
		return -1;
	}


	while ((c = getopt_long(argc, argv, "hRLlIn:NP:C:p:SE:DV:i:o:c:", lopts, &opt_idx)) != -1) {
		switch (c) {
		case 'c':
			// was already handled
			break;
		case 'h':
			usage(argv[0]);
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
			s = optarg;

			// mutt has some special calling 'conventions'. detect mutt by 0x prefix for the
			// recipient IDs:
			if (s.find("0x") != string::npos) {
				// in case the quotes are still there
				s.erase(remove(s.begin(), s.end(), '\''), s.end());

				// In case of multiple recipients, they are split by spaces:
				// -E 0x11223344 0x55667788 ...
				for (ridx = 0;;) {
					ridx = s.find(" ", ridx);
					// last recipient ID or single one
					if (ridx == string::npos || ridx < 3) {
						s.erase(0, 2);
						dst_ids.push_back(s);
						break;
					}
					// 2 to also get rid of leading "0x"
					dst_ids.push_back(s.substr(2, ridx - 2));
					s.erase(0, ridx + 1);
				}
			} else {
				s.erase(remove(s.begin(), s.end(), ' '), s.end());
				dst_ids.push_back(s);
			}
			break;
		case 'D':
			cmode = CMODE_DECRYPT;
			break;
		case 'S':
			cmode |= CMODE_SIGN;
			break;
		case 'P':
			config::my_id = optarg;
			break;
		case 'V':
			cmode = CMODE_VERIFY;
			verify_file = optarg;
			break;
		case 'N':
			cmode |= CMODE_NEWP;
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
			cmode |= CMODE_NEWECP;

			// the curve name may be overriden to config file,
			// in order to have config-independent one-liners for
			// brainkey personas
			if (optarg) {
				int nid = curve2nid(optarg);
				if (nid == -1) {
					estr<<prefix<<"Invalid curve name. Valid algorithms are:\n\n";
					print_calgos(estr);
					estr<<"\n"<<prefix<<"FAILED.\n";
					eflush();
					return -1;
				}
				config::curve_nids.clear();
				config::curves.clear();
				config::curve_nids.push_back(nid);
				config::curves.push_back(optarg);
			}
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
		case DENIABLE:
			config::deniable = 1;
			break;
		case BRAINKEY1:
		case BRAINKEY2:
			if (optarg)
				config::brainkey12 = optarg;
			else {
				estr<<prefix<<"Enter the brainkey, 16 chars minimum (echoed): ";
				eflush();
				if (read(0, bkbuf, sizeof(bkbuf) - 1) <= 2) {
					estr<<prefix<<"Aborted.\n\n"<<prefix<<"FAILED.\n";
					eflush();
					return -1;
				}
				if ((nl = strchr(bkbuf, '\r')))
					*nl = 0;
				if ((nl = strchr(bkbuf, '\n')))
					*nl = 0;
				config::brainkey12 = bkbuf;
			}

			if (c == BRAINKEY2)
				config::pq_type = "brainkey2";
			break;
		case SALT1:
			config::salt1 = optarg;
			break;
		case SALT2:
			config::salt2 = optarg;
			break;
		case FREEHUGS:
			cmode = CMODE_FREEHUGS;
			break;
		}
	}

	if (cmode == CMODE_INVALID)
		usage(argv[0]);

	if (cmode == CMODE_FREEHUGS) {
		ostr<<"HUG, HUG - sell a bug.\n"; oflush();
	}

	if (check_valid_options(cmode) < 0)
		return -1;

	if (!is_valid_halgo(config::phash, 1)) {
		estr<<prefix<<"Invalid persona hashing algorithm. Valid hash algorithms are:\n\n";
		print_halgos(estr);
		estr<<"\n"<<prefix<<"FAILED.\n";
		eflush();
		return -1;
	}

	if (!is_valid_calgo(config::calgo, 1)) {
		estr<<prefix<<"Invalid crypto algorithm. Valid crypto algorithms are:\n\n";
		print_calgos(estr);
		estr<<"\n"<<prefix<<"FAILED.\n";
		eflush();
		return -1;
	}

	OpenSSL_add_all_algorithms();

	if (RAND_load_file("/dev/urandom", 2048) != 2048) {
		if (RAND_load_file("/dev/random", 64) != 64) {
			estr<<prefix<<"Unable to load randomness.\n\n";
			estr<<prefix<<"FAILED.\n";
			eflush();
			return -1;
		}
	}

	// clear error queue, since FIPS loading bugs might overlay our own errors
	ERR_clear_error();

	if (config::infile == "-")
		config::infile = "/dev/stdin";
	if (config::outfile == "-")
		config::outfile = "/dev/stdout";

	// strip of spaces in case of split format id given
	config::my_id.erase(remove(config::my_id.begin(), config::my_id.end(), ' '), config::my_id.end());


	// remove any leading 0x in the ID's, as passed by mutt etc.
	if (config::my_id.find("0x") == 0)
		config::my_id.erase(0, 2);

	switch (cmode) {
	case CMODE_ENCRYPT:
		s = "";
		if (read_msg(config::infile, s) < 0) {
			estr<<prefix<<"ERROR: reading infile: "<<strerror(errno)<<"\n"; eflush();
			return -1;
		}
		c = 0;
		for (auto dst_id : dst_ids) {
			estr<<prefix<<"encrypting for persona "<<idformat(dst_id)<< "\n"; eflush();

			// last parameter to signal if encrypted blob may be
			// appended to previous output
			r = do_encrypt(dst_id, s, c % 2);
			if (r < 0)
				break;
			++c;
		}
		break;
	case CMODE_DECRYPT:
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
	case CMODE_NEWP|CMODE_SIGN:
		estr<<prefix<<"creating new persona (RSA "<<config::rsa_len<<", DH "<<config::dh_plen<<")\n\n"; eflush();
		r = do_new_rsa_persona(name, (cmode & CMODE_SIGN) == CMODE_SIGN);
		break;
	case CMODE_NEWDHP:
		estr<<prefix<<"creating new DHparams for persona "<<idformat(config::my_id)<<"\n\n"; eflush();
		r = do_newdhparams();
		break;
	case CMODE_NEWECP:
	case CMODE_NEWECP|CMODE_SIGN:
		estr<<prefix<<"creating new EC persona (curve "<<config::curves[0]<<")\n\n"; eflush();
		r = do_new_ec_persona(name, (cmode & CMODE_SIGN) == CMODE_SIGN);
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
	default:
		estr<<prefix<<"Invalid combination of options?\n";
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


