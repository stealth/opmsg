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

#ifndef opmsg_misc_h
#define opmsg_misc_h

#include <string>
#include <sstream>
#include <cstdio>

extern "C" {
#include <openssl/evp.h>
}


namespace opmsg {

std::string &blob2hex(const std::string &, std::string &);

bool is_hex_hash(const std::string &);

bool is_valid_halgo(const std::string &);

bool is_valid_calgo(const std::string &);

void print_calgos(std::ostringstream &);

void print_halgos(std::ostringstream &);

const EVP_CIPHER *algo2cipher(const std::string &);

const EVP_MD *algo2md(const std::string &);

std::string build_error(const std::string &msg);

void rlockf(FILE *);

void rlockf(int);

void wlockf(FILE *);

void wlockf(int);

void unlockf(FILE *);

void unlockf(int);

void hex_dump(const char *, size_t);

extern const std::string prefix;

}

#endif
