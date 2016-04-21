/*
 * This file is part of the opmsg crypto message framework.
 *
 * (C) 2016 by Sebastian Krahmer,
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

/* Add to your ~/.gnupg/config:
 *
 * keyid-format long
 *
 */

#include <iostream>
#include <memory>
#include <string>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "keystore.h"

using namespace std;
using namespace opmsg;


// Only the first 4k to distinguish between opmsg and gpg
int read_msg(const string &p, string &msg)
{
	msg = "";
	int fd = 0;
	bool was_opened = 0;

	string path = p;
	if (path == "-")
		path = "/dev/stdin";

	if (path != "/dev/stdin") {
		if ((fd = open(path.c_str(), O_RDONLY)) < 0)
			return -1;
		was_opened = 1;
	}

	char buf[0x1000];
	memset(buf, 0, sizeof(buf));

	// pread() to peek on tty's
	ssize_t r = pread(fd, buf, sizeof(buf) - 1, 0);
	if (was_opened)
		close(fd);
	if (r <= 0)
		return -1;
	msg = string(buf, r);
	return 0;
}


// externally invoke the outdated crypto framework
void gpg(char **argv, char **envp)
{
	char gpg[] = "gpg", gpg2[] = "gpg2";

	argv[0] = gpg2;
	execvpe(gpg2, argv, envp);
	argv[0] = gpg;
	execvpe(gpg, argv, envp);

	exit(1);
}


// name or ID inside opmsg keystore?
string has_id(const string &r)
{
	bool return_r = 0;
	string rcpt = r, id = "", cfg = "";

	// if multiple space-separated 0x key id's appear, split off first one
	if (r.find("0x") == 0 && r.find("0x", 1) != string::npos) {
		string::size_type idx = r.find(" ");
		if (idx == string::npos || idx < 3)
			return id;
		rcpt = r.substr(0, idx);
		return_r = 1;
	}


	if (getenv("HOME"))
		cfg = getenv("HOME");
	cfg += "/.opmsg";

	// hash algo not relevant for searching
	unique_ptr<keystore> ks(new (nothrow) keystore("sha256", cfg));
	if (!ks.get() || ks->load() < 0)
		return 0;

	// if hex id as rcpt, try right away
	if (rcpt.find_first_of("0123456789abcdef") == 0) {
		if (rcpt.find("0x") == 0)
			rcpt.erase(0, 2);
		persona *p = ks->find_persona(rcpt);
		if (p)
			id = p->get_id();
	}

	// not found? Try the same as 'name'
	if (id.size() == 0) {
		// try to match via alias name (first match counts)
		for (auto i = ks->first_pers(); i != ks->end_pers(); i = ks->next_pers(i)) {
			if (i->second->get_name().find(rcpt) != string::npos) {
				id = i->second->get_id();
				break;
			}
		}
	}

	// If we found opmsg persona id but have had multiple id's,
	// return them
	if (id.size() > 0 && return_r)
		return r;

	return id;
}


int main(int argc, char **argv, char **envp)
{
	struct option lopts[] = {
	        {"encrypt", no_argument, nullptr, 'e'},
	        {"decrypt", no_argument, nullptr, 'd'},
		{"version", no_argument, nullptr, 'v'},
		{"recipient", required_argument, nullptr, 'r'},
	        {"list-keys", no_argument, nullptr, 'l'},
	        {"output", required_argument, nullptr, 'o'},

		{"passphrase-fd", required_argument, nullptr, 'I'},	// ignore
		{"local-user", required_argument, nullptr, 'I'},
		{"default-key", required_argument, nullptr, 'I'},
		{"charset", required_argument, nullptr, 'I'},
		{"display-charset", required_argument, nullptr, 'I'},
		{"compress-algo", required_argument, nullptr, 'I'},
		{"cipher-algo", required_argument, nullptr, 'I'},
		{"max-output", required_argument, nullptr, 'I'},
		{"status-fd", required_argument, nullptr, 'I'},
		{"digest-algo", required_argument, nullptr, 'I'},
		{"trust-model", required_argument, nullptr, 'I'},
	        {nullptr, 0, nullptr, 0}};

	char opmsg[] = "opmsg", list[] = "--listpgp", dec[] = "--decrypt", enc[] = "--encrypt",
	     in[] = "--in", out[] = "--out", idshort[] = "--short", name[] = "--name";
	char *opmsg_list[] = {opmsg, list, idshort, nullptr, nullptr, nullptr};

	string infile = "-", outfile = "", rcpt = "";
	int c = 0, opt_idx = 0;
	enum { MODE_ENCRYPT = 0, MODE_DECRYPT = 1, MODE_LIST = 2} mode = MODE_DECRYPT;

	// getopt() reorders argv, so save old order
	char **oargv = new (nothrow) char*[argc + 1];
	if (!oargv)
		return -1;
	for (c = 0; c < argc; ++c)
		oargv[c] = argv[c];
	oargv[c] = nullptr;

	// suppress 'invalid option' error messages for gpg options that we
	// do not parse ourselfs
	opterr = 0;
	while ((c = getopt_long(argc, argv, "edvr:lo:", lopts, &opt_idx)) != -1) {
		opterr = 0;

		switch (c) {
		case 'd':
			mode = MODE_DECRYPT;
			break;
		case 'e':
			mode = MODE_ENCRYPT;
			break;
		case 'r':
			rcpt = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'l':
			mode = MODE_LIST;
			break;
		case 'v':
			gpg(argv, envp);
			break;	// neverreached
		default:
			// ignore other options, and only pass it along
			// once gpg detected
			break;
		}
	}

	if (mode == MODE_LIST) {
		if (optind < argc) {
			if (has_id(argv[optind]).size() == 0)
				gpg(oargv, envp);

			opmsg_list[3] = name;
			opmsg_list[4] = strdup(argv[optind]);
			execvpe(opmsg, opmsg_list, envp);
			exit(1);
		}

		pid_t child;
		if ((child = fork()) == 0) {
			execvpe(opmsg, opmsg_list, envp);
			exit(1);
		}

		waitpid(child, nullptr, 0);
		gpg(oargv, envp);
		exit(1);
	}

	if (optind < argc)
		infile = argv[optind];

	if ((mode != MODE_ENCRYPT && mode != MODE_DECRYPT) || (mode == MODE_ENCRYPT && rcpt.size() == 0))
		gpg(oargv, envp);

	if (mode == MODE_DECRYPT) {
		// peek into input file
		string msg = "";
		if (read_msg(infile, msg) < 0)
			gpg(oargv, envp);

		// w/o newline, so opmsg could erase \r which might have erroneously been
		// inserted by MUAs
		if (msg.find("-----BEGIN OPMSG-----") != string::npos) {
			char *opmsg_d[] = {opmsg, dec, in, strdup(infile.c_str()), nullptr, nullptr, nullptr};
			int idx = 3;

			if (outfile.size() > 0) {
				opmsg_d[++idx] = out;
				opmsg_d[++idx] = strdup(outfile.c_str());
			}
			execvpe(opmsg, opmsg_d, envp);
		} else
			gpg(oargv, envp);

		return -1;
	}

	// must be --encrypt at this point


	string opmsg_id = has_id(rcpt);

	if (opmsg_id.size()) {
		char *opmsg_e[] = {opmsg, enc, strdup(opmsg_id.c_str()), in, strdup(infile.c_str()), nullptr, nullptr, nullptr};
		int idx = 4;

		if (outfile.size() > 0) {
			opmsg_e[++idx] = out;
			opmsg_e[++idx] = strdup(outfile.c_str());
		}
		execvpe(opmsg, opmsg_e, envp);
		return -1;
	}

	gpg(oargv, envp);
	return -1;
}

