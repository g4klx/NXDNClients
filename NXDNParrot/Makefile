CC      = gcc
CXX     = g++
CFLAGS  = -g -O3 -Wall -std=c++0x -pthread
LIBS    = -lpthread
LDFLAGS = -g

OBJECTS = NXDNNetwork.o NXDNParrot.o Parrot.o StopWatch.o Thread.o Timer.o UDPSocket.o

all:		NXDNParrot

NXDNParrot:	$(OBJECTS)
		$(CXX) $(OBJECTS) $(CFLAGS) $(LIBS) -o NXDNParrot

%.o: %.cpp
		$(CXX) $(CFLAGS) -c -o $@ $<

clean:
		$(RM) NXDNParrot *.o *.d *.bak *~
