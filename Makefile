CXX=c++
DEFS=

INC=-I/usr/local/ssl/include
LIBS=-L/usr/local/ssl/lib

CXXFLAGS=-Wall -O2 -pedantic -std=c++11 $(INC) $(DEFS)

LD=c++
LDFLAGS=
LIBS+=-lcrypto

all: opmsg

opmsg: keystore.o opmsg.o misc.o config.o message.o marker.o base64.o deleters.o
	$(LD) $(LDFLAGS) $^ $(LIBS) -o opmsg

opmsg.o: opmsg.cc
	$(CXX) $(CXXFLAGS) -c $<

marker.o: marker.cc marker.h
	$(CXX) $(CXXFLAGS) -c $<

keystore.o: keystore.cc keystore.h
	$(CXX) $(CXXFLAGS) -c $<

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

test: test2.cc test1.cc keystore.o config.o misc.o message.o base64.o marker.o deleters.o
	$(CXX) $(CXXFLAGS) test1.cc keystore.o config.o misc.o marker.o deleters.o $(LIBS) -o test1
	$(CXX) $(CXXFLAGS) test2.cc keystore.o config.o misc.o base64.o marker.o message.o deleters.o $(LIBS) -o test2

clean:
	rm -rf *.o


