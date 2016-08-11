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

#ifndef opmsg_numbers_h
#define opmsg_numbers_h

namespace opmsg {

enum {
	DEFAULT_NEW_DH_KEYS	= 3,
	MIN_NEW_DH_KEYS		= 0,
	MAX_NEW_DH_KEYS		= 33,		// ec_domains * n

	DEFAULT_DH_PLEN		= 2048,
	MIN_DH_PLEN		= 1024,
	MAX_DH_PLEN		= 16000,

	DEFAULT_RSA_LEN		= 4096,
	MIN_RSA_LEN		= 1024,
	MAX_RSA_LEN		= 16000

};

}

#endif



