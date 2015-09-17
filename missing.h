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

#ifndef opmsg_missing_h
#define opmsg_missing_h

#ifdef HAVE_BORINGSSL

extern "C" {
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
}


namespace opmsg {

BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *, point_conversion_form_t, BIGNUM *, BN_CTX *);

EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *, EC_POINT *, BN_CTX *);

}

#endif
#endif

