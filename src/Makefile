# On most Linux distros, this should do. For BSD, please check
# README.md about the defines that you have to pass when invoking "make".
# For OSX or if you want to use non-default distro crypto libs (libressl,
# openssl-dev, openssl-asan etc.), adjust the path names below accordingly.
#

CXX?=c++
CXXSTD?=c++11
DEFS=
INC=

#SSL=/opt/ssl/libressl-3.7.0

# alternate SSL builds such as with LibreSSL need this
#INC+=-I$(SSL)/include
#LIBS+=-L$(SSL)/lib
#LIBS+=-Wl,--rpath=$(SSL)/lib

# Older LibreSSL setups also need this. Newer (>= 3.x ?) don't
#DEFS+=-DHAVE_BN_GENCB_NEW=0

# Cygwin was reported to require this:
#DEFS+=-U__STRICT_ANSI__

# reported to work with OSX brew
#INC+=-I/opt/local/include
#LIBS+=-L/opt/local/lib

# BoringSSL. Be warned, BoringSSL creates incompatible
# PEM files. So this is not recommended and just for
# testing.
#DEFS+=-DHAVE_BN_GENCB_NEW=0
#DEFS+=-DHAVE_BORINGSSL


# Enable chacha20-poly1305 if avail
#DEFS+=-DCHACHA20


###
### No editing should be needed below this line.
###

.PHONY: all build contrib clean distclean

CXXFLAGS=-Wall -O2 -pedantic -std=$(CXXSTD) $(INC) $(DEFS)

LD=$(CXX)
LDFLAGS=
LIBS+=-lcrypto


all: build build/opmsg

contrib: build build/opmux build/opcoin

build/opmsg: build/keystore.o build/opmsg.o build/misc.o build/config.o build/message.o build/marker.o build/base64.o build/deleters.o build/missing.o build/brainkey.o
	$(LD) build/keystore.o build/opmsg.o build/misc.o build/config.o build/message.o build/marker.o build/base64.o build/deleters.o build/missing.o build/brainkey.o $(LDFLAGS) $(LIBS) -o $@

build/opcoin: build/keystore.o build/opcoin.o build/config.o build/deleters.o build/base58.o build/misc.o build/marker.o build/deleters.o build/missing.o build/brainkey.o build/base64.o
	$(LD) build/keystore.o build/opcoin.o build/config.o build/base58.o build/misc.o build/marker.o build/deleters.o build/missing.o build/brainkey.o build/base64.o $(LDFLAGS) $(LIBS) -o $@

build/opmux: build/keystore.o build/opmux.o build/misc.o build/marker.o build/config.o build/deleters.o build/missing.o build/brainkey.o build/base64.o
	$(LD) build/keystore.o build/opmux.o build/misc.o build/marker.o build/config.o build/deleters.o build/missing.o build/brainkey.o build/base64.o $(LDFLAGS) $(LIBS) -o $@

build/opmux.o: contrib/opmux.cc
	$(CXX) -I . -I .. $(CXXFLAGS) -c $< -o build/opmux.o

build/opcoin.o: contrib/opcoin.cc
	$(CXX) -I . -I .. $(CXXFLAGS) -c $< -o build/opcoin.o

build/base58.o: contrib/base58.cc
	$(CXX) -I . -I .. $(CXXFLAGS) -c $< -o build/base58.o

build/opmsg.o: opmsg.cc
	$(CXX) $(CXXFLAGS) -c $< -o build/opmsg.o

build/marker.o: marker.cc marker.h
	$(CXX) $(CXXFLAGS) -c $< -o build/marker.o

build/keystore.o: keystore.cc keystore.h
	$(CXX) $(CXXFLAGS) -c $< -o build/keystore.o

build/base64.o: base64.cc base64.h
	$(CXX) $(CXXFLAGS) -c $< -o build/base64.o

build/misc.o: misc.cc misc.h
	$(CXX) $(CXXFLAGS) -c $< -o build/misc.o

build/config.o: config.cc config.h numbers.h
	$(CXX) $(CXXFLAGS) -c $< -o build/config.o

build/message.o: message.cc message.h numbers.h
	$(CXX) $(CXXFLAGS) -c $< -o build/message.o

build/deleters.o: deleters.cc
	$(CXX) $(CXXFLAGS) -c $< -o build/deleters.o

build/missing.o: missing.cc missing.h
	$(CXX) $(CXXFLAGS) -c $< -o build/missing.o

build/brainkey.o: brainkey.cc brainkey.h
	$(CXX) $(CXXFLAGS) -c $< -o build/brainkey.o

build:
	mkdir build || true

clean:
	rm -rf build/*.o

distclean:
	rm -rf build

