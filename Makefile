CXX=c++
DEFS=
INC=

#this worked for me on OSX
#INC+=-I/usr/local/ssl/include
#LIBS+=-L/usr/local/ssl/lib

#for LibreSSL setups, define your paths here
#INC+=-I/usr/local/libressl/include
#LIBS+=-L/usr/local/libressl/lib64

CXXFLAGS=-Wall -O2 -pedantic -std=c++11 $(INC) $(DEFS)

LD=c++
LDFLAGS=
LIBS+=-lcrypto

all: opmsg

opmsg: keystore.o opmsg.o misc.o config.o message.o marker.o base64.o deleters.o
	$(LD) $(LDFLAGS) keystore.o opmsg.o misc.o config.o message.o marker.o base64.o deleters.o $(LIBS) -o $@

opmsg.o: opmsg.cc
	$(CXX) $(CXXFLAGS) -U__STRICT_ANSI__ -c $<

marker.o: marker.cc marker.h
	$(CXX) $(CXXFLAGS) -c $<

keystore.o: keystore.cc keystore.h
	$(CXX) $(CXXFLAGS) -U__STRICT_ANSI__ -c $<

base64.o: base64.cc base64.h
	$(CXX) $(CXXFLAGS) -c $<

misc.o: misc.cc misc.h
	$(CXX) $(CXXFLAGS) -c $<

config.o: config.cc config.h
	$(CXX) $(CXXFLAGS) -c $<

message.o: message.cc message.h
	$(CXX) $(CXXFLAGS) -c $<

deleters.o: deleters.cc
	$(CXX) $(CXXFLAGS) -c $<

test1.o:
	$(CXX) $(CXXFLAGS) -c -I . test/test1.cc -o test/test1.o

test2.o:
	$(CXX) $(CXXFLAGS) -c -I . test/test2.cc -o test/test2.o

tests: test2.o test1.o keystore.o config.o misc.o message.o base64.o marker.o deleters.o
	$(LD) $(LDFLAGS) test/test1.o keystore.o config.o misc.o marker.o deleters.o $(LIBS) -o test/test1
	$(LD) $(LDFLAGS) test/test2.o keystore.o config.o misc.o base64.o marker.o message.o deleters.o $(LIBS) -o test/test2

clean:
	rm -rf *.o opmsg


