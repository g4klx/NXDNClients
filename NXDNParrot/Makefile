CC      = cc
CXX     = c++
CFLAGS  = -g -O3 -Wall -std=c++0x -pthread
LIBS    = -lpthread
LDFLAGS = -g

OBJECTS = NXDNNetwork.o NXDNParrot.o Parrot.o StopWatch.o Thread.o Timer.o UDPSocket.o

all:		NXDNParrot

NXDNParrot:	GitVersion.h $(OBJECTS)
		$(CXX) $(OBJECTS) $(CFLAGS) $(LIBS) -o NXDNParrot

%.o: %.cpp
		$(CXX) $(CFLAGS) -c -o $@ $<

NXDNParrot.o: GitVersion.h FORCE

.PHONY: GitVersion.h

FORCE:


install:
		install -m 755 NXDNParrot /usr/local/bin/

clean:
		$(RM) NXDNParrot *.o *.d *.bak *~
		
# Export the current git version if the index file exists, else 000...
GitVersion.h:
ifneq ("$(wildcard ../.git/index)","")
	echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > $@
else
	echo "const char *gitversion = \"0000000000000000000000000000000000000000\";" > $@
endif

