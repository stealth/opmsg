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
#include <cstdlib>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "keystore.h"

using namespace std;
using namespace opmsg;


// Only the first 64k to distinguish between opmsg and gpg
int read_msg(const string &p, string &tmp_path, string &msg)
{
	msg = "";
	tmp_path = "";
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

	char buf[0x10000];
	memset(buf, 0, sizeof(buf));

	ssize_t r = pread(fd, buf, sizeof(buf), 0);
	int saved_errno = errno;
	if (was_opened)
		close(fd);
	if (r > 0) {
		msg = string(buf, r);
		return 0;
	}

	// cant peek on tty or pipe
	if (r < 0 && saved_errno == ESPIPE) {
		char tmpl[] = "/tmp/opmux.XXXXXX";
		int fd2 = mkstemp(tmpl);
		if (fd2 < 0)
			return -1;
		struct pollfd pfd{fd, POLLIN, 0};
		for (;;) {
			pfd.events = POLLIN;
			pfd.revents = 0;
			poll(&pfd, 1, 2000);
			if ((pfd.revents & POLLIN) != POLLIN)
				break;
			r = read(fd, buf, sizeof(buf));
			if (r <= 0)
				break;
			if (write(fd2, buf, r) != r) {
				close(fd2);
				unlink(tmpl);
				return -1;
			}
			msg += string(buf, r);
		}
		lseek(fd2, SEEK_SET, 0);
		dup2(fd2, 0);
		close(fd2);
		tmp_path = tmpl;
		return 0;
	}

	return -1;
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


void sig_int(int x)
{
	return;
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
		{"local-user", required_argument, nullptr, 'u'},

		{"passphrase-fd", required_argument, nullptr, 'I'},	// ignore
		{"encrypt-to", required_argument, nullptr, 'I'},
		{"hidden-encrypt-to", required_argument, nullptr, 'I'},
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
	pid_t pid = 0;
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
	while ((c = getopt_long(argc, argv, "edvr:lo:u:", lopts, &opt_idx)) != -1) {
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

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_int;
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGPIPE, &sa, nullptr);

	if (mode == MODE_LIST) {
		if (optind < argc) {
			if (has_id(argv[optind]).size() == 0)
				gpg(oargv, envp);

			opmsg_list[3] = name;
			opmsg_list[4] = strdup(argv[optind]);
			execvpe(opmsg, opmsg_list, envp);
			exit(1);
		}

		if ((pid = fork()) == 0) {
			execvpe(opmsg, opmsg_list, envp);
			exit(1);
		}

		waitpid(pid, nullptr, 0);
		gpg(oargv, envp);
		exit(1);
	}

	if (optind < argc)
		infile = argv[optind];

	if ((mode != MODE_ENCRYPT && mode != MODE_DECRYPT) || (mode == MODE_ENCRYPT && rcpt.size() == 0))
		gpg(oargv, envp);

	if (mode == MODE_DECRYPT) {
		// peek into input file
		string msg = "", tmp_p = "";
		int r = read_msg(infile, tmp_p, msg);

		if ((pid = fork()) == 0) {
			// w/o newline, so opmsg could erase \r which might have erroneously been
			// inserted by MUAs
			if (r == 0 && msg.find("-----BEGIN OPMSG-----") != string::npos) {
				char *opmsg_d[] = {opmsg, dec, in, strdup(infile.c_str()), nullptr, nullptr, nullptr};
				int idx = 3;

				if (outfile.size() > 0) {
					opmsg_d[++idx] = out;
					opmsg_d[++idx] = strdup(outfile.c_str());
				}
				execvpe(opmsg, opmsg_d, envp);
			} else
				gpg(oargv, envp);
		}

		int status = 0;
		waitpid(pid, &status, 0);
		if (tmp_p.size() > 0)
			unlink(tmp_p.c_str());
		if (WIFEXITED(status))
			return WEXITSTATUS(status);
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

