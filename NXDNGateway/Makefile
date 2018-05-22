CC      = gcc
CXX     = g++
CFLAGS  = -g -O3 -Wall -std=c++0x -pthread
LIBS    = -lpthread
LDFLAGS = -g

OBJECTS = APRSWriter.o APRSWriterThread.o Conf.o GPSHandler.o IcomNetwork.o Log.o Mutex.o NXDNCRC.o NXDNGateway.o NXDNLookup.o NXDNNetwork.o Reflectors.o \
		  StopWatch.o TCPSocket.o Thread.o Timer.o UDPSocket.o Utils.o Voice.o

all:		NXDNGateway

NXDNGateway:	$(OBJECTS)
		$(CXX) $(OBJECTS) $(CFLAGS) $(LIBS) -o NXDNGateway

%.o: %.cpp
		$(CXX) $(CFLAGS) -c -o $@ $<

clean:
		$(RM) NXDNGateway *.o *.d *.bak *~
 