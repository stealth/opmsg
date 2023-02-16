/*
 * This file is part of the opmsg crypto message framework.
 *
 * (C) 2016-2021 by Sebastian Krahmer,
 *                  sebastian [dot] krahmer [at] gmail [dot] com
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
#include <map>
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

extern char **environ;


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
void gpg(char **argv)
{
	char gpg[] = "gpg", gpg2[] = "gpg2";

	argv[0] = gpg2;
	execvp(gpg2, argv);
	argv[0] = gpg;
	execvp(gpg, argv);

	exit(1);
}


// hex lower case
string hlc(const string &s)
{
	string r = s;

	for (string::size_type i = 0; i < r.size(); ++i) {
		if (r[i] >= 'A' && r[i] <= 'F')
			r[i] += ('a' - 'A');
	}
	return r;
}


// name or ID inside opmsg keystore?
string has_id(const string &r)
{
	bool return_r = 0, is_hex = 0;
	string rcpt = r, id = "", cfg = "";

	if (r.find("0x") == 0)
		rcpt = hlc(r.substr(2));

	if (is_hex_hash(rcpt))
		is_hex = 1;
	else
		rcpt = r;

	// if multiple space-separated 0x key id's appear, split off first one
	if (r.find("0x") == 0 && r.find("0x", 1) != string::npos) {
		string::size_type idx = r.find(" ");
		if (idx == string::npos || idx < 3)
			return id;
		rcpt = r.substr(0, idx);
		is_hex = 1;
		return_r = 1;
	}


	if (getenv("HOME"))
		cfg = getenv("HOME");
	cfg += "/.opmsg";

	// hash algo not relevant for searching
	unique_ptr<keystore> ks(new (nothrow) keystore("sha256", cfg));
	if (!ks.get() || ks->load("", LFLAGS_ALL & ~LFLAGS_KEX) < 0)
		return 0;

	// if hex id as rcpt, try right away
	if (is_hex) {
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
	if (id.size() > 0) {
		if (return_r)
			return r;
		return rcpt;
	}

	return "";
}


void sig_int(int x)
{
	return;
}


enum {
	OPMSG_OPT_CONFDIR	=	0x1000,
	OPMSG_OPT_BURN		=	0x2000,
	OPMUX_OPT_GPGERROROK	=	0x4000
};


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
		{"status-fd", required_argument, nullptr, 'f'},

		{"confdir", required_argument, nullptr, OPMSG_OPT_CONFDIR},
		{"burn", no_argument, nullptr, OPMSG_OPT_BURN},

		// also print "opmux: SUCCESS" if gpg -d "fails" due to failed
		// signature check; yet still correctly decrypting content.
		// The failed signature check will nevertheless be visible via --status-fd,
		// but mutt would fail to show correctly decrypted content if it doesnt
		// see $pgp_decryption_okay= regex.
		{"gpg-error-ok", no_argument, nullptr, OPMUX_OPT_GPGERROROK},

		{"passphrase-fd", required_argument, nullptr, 'I'},	// ignore
		{"encrypt-to", required_argument, nullptr, 'I'},
		{"hidden-encrypt-to", required_argument, nullptr, 'I'},
		{"default-key", required_argument, nullptr, 'I'},
		{"charset", required_argument, nullptr, 'I'},
		{"display-charset", required_argument, nullptr, 'I'},
		{"compress-algo", required_argument, nullptr, 'I'},
		{"cipher-algo", required_argument, nullptr, 'I'},
		{"max-output", required_argument, nullptr, 'I'},
		{"digest-algo", required_argument, nullptr, 'I'},
		{"trust-model", required_argument, nullptr, 'I'},
	        {nullptr, 0, nullptr, 0}};

	map<string, int> opmsg_argv_only = {{"--confdir", 1}, {"--burn", 0}, {"--gpg-error-ok", 0}};

	char opmsg[] = "opmsg", list[] = "--listpgp", dec[] = "--decrypt", enc[] = "--encrypt",
	     in[] = "--in", out[] = "--out", idshort[] = "--short", name[] = "--name", conf[] = "--confdir";
	char *opmsg_list[] = {opmsg, list, idshort, nullptr, nullptr, nullptr};

	string infile = "-", outfile = "", rcpt = "", burn = "",
	       confdir = "";	// empty confdir treated as default by opmsg
	int i = 0, j = 0, c = 0, opt_idx = 0, status_fd = 2, gpg_error_ok = 0;
	pid_t pid = 0;
	enum { MODE_ENCRYPT = 0, MODE_DECRYPT = 1, MODE_LIST = 2} mode = MODE_DECRYPT;

	// getopt() reorders argv, so save old order to be passed to gpg invocation
	// if we dont find a opmsg persona
	char **oargv = new (nothrow) char*[argc + 1];
	if (!oargv)
		return -1;
	for (i = 0, j = 0; i < argc; ++i) {
		if (opmsg_argv_only.count(argv[i]) > 0) {
			i += opmsg_argv_only[argv[i]];		// jump over optional parameter, maybe
			continue;
		}
		oargv[j++] = argv[i];
	}
	oargv[j] = nullptr;

	// suppress 'invalid option' error messages for gpg options that we
	// do not parse ourselfs
	opterr = 0;
	while ((c = getopt_long(argc, argv, "edvr:lo:u:f:", lopts, &opt_idx)) != -1) {
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
		case 'f':
			status_fd = atoi(optarg);
			if (status_fd < 2 || status_fd > 1000)
				status_fd = 2;
			break;
		case 'v':
			gpg(argv);
			break;	// neverreached
		case OPMSG_OPT_CONFDIR:
			confdir = optarg;
			break;
		case OPMSG_OPT_BURN:
			burn = "--burn";
			break;
		case OPMUX_OPT_GPGERROROK:
			gpg_error_ok = 1;
			break;
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
			string id = "";
			if ((id = has_id(argv[optind])).size() == 0)
				gpg(oargv);

			opmsg_list[3] = name;
			opmsg_list[4] = strdup(id.c_str());
			execvp(opmsg, opmsg_list);
			exit(1);
		}

		if ((pid = fork()) == 0) {
			execvp(opmsg, opmsg_list);
			exit(1);
		} else if (pid < 0)
			exit(1);

		waitpid(pid, nullptr, 0);
		gpg(oargv);
		exit(1);
	}

	if (optind < argc)
		infile = argv[optind];

	if ((mode != MODE_ENCRYPT && mode != MODE_DECRYPT) || (mode == MODE_ENCRYPT && rcpt.size() == 0))
		gpg(oargv);

	if (mode == MODE_DECRYPT) {
		// peek into input file
		bool has_opmsg = 0;
		string msg = "", tmp_p = "";
		int r = read_msg(infile, tmp_p, msg);

		// w/o newline, so opmsg could erase \r which might have erroneously been
		// inserted by MUAs
		if (r == 0)
			has_opmsg = (msg.find("-----BEGIN OPMSG-----") != string::npos);

		if ((pid = fork()) == 0) {
			if (has_opmsg) {
				char *opmsg_d[] = {opmsg, conf, strdup(confdir.c_str()), dec, in, strdup(infile.c_str()),
				                   nullptr, nullptr, nullptr, nullptr};
				int idx = 5;

				if (outfile.size() > 0) {
					opmsg_d[++idx] = out;
					opmsg_d[++idx] = strdup(outfile.c_str());
				}
				if (burn.size() > 0)
					opmsg_d[++idx] = strdup(burn.c_str());

				execvp(opmsg, opmsg_d);
				exit(1);
			} else
				gpg(oargv);
		} else if (pid < 0)
			return -1;

		int status = 0;
		waitpid(pid, &status, 0);
		if (tmp_p.size() > 0)
			unlink(tmp_p.c_str());
		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);

			FILE *status_f = fdopen(status_fd, "a");

			// Add some success message in case of success, to make "pgp_decryption_okay" happy
			if (status_f && (status == 0 || gpg_error_ok)) {

				string mua = "unknown";
				if (getenv("OPMUX_MUA") != nullptr)
					mua = getenv("OPMUX_MUA");

				// thunderbird enigmail is happy with the following:
				if (mua != "mutt" && has_opmsg) {
					fprintf(status_f, "\n[GNUPG:] SIG_ID KEEPAWAYFROMFIRE 1970-01-01 0000000000"
					                "\n[GNUPG:] GOODSIG 7350735073507350 opmsg"
					                "\n[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1970-01-01 00000000000"
					                " 0 4 0 1 8 01 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
							"\n[GNUPG:] TRUST_ULTIMATE\n");
				}
				if (has_opmsg) {
					fprintf(status_f, "\n[GNUPG:] DECRYPTION_OKAY"
					                "\n[GNUPG:] GOODMDC"
					                "\n[GNUPG:] END_DECRYPTION\n");
				}
				fprintf(status_f, "\nopmux: SUCCESS.\n");

				//Not: fclose(status_f);
			}
			return status;
		}
		return -1;
	}

	// must be --encrypt at this point


	string opmsg_id = has_id(rcpt);

	if (opmsg_id.size()) {
		char *opmsg_e[] = {opmsg, conf, strdup(confdir.c_str()), enc, strdup(opmsg_id.c_str()), in, strdup(infile.c_str()),
		                   nullptr, nullptr, nullptr};
		int idx = 6;

		if (outfile.size() > 0) {
			opmsg_e[++idx] = out;
			opmsg_e[++idx] = strdup(outfile.c_str());
		}
		execvp(opmsg, opmsg_e);
		return -1;
	}

	gpg(oargv);
	return -1;
}

