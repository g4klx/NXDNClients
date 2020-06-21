CC      = gcc
CXX     = g++

# Use the following CFLAGS and LIBS if you don't want to use gpsd.
CFLAGS  = -g -O3 -Wall -std=c++0x -pthread
LIBS    = -lpthread

# Use the following CFLAGS and LIBS if you do want to use gpsd.
CFLAGS  = -g -O3 -Wall -DUSE_GPSD -std=c++0x -pthread
LIBS    = -lpthread -lgps

LDFLAGS = -g

OBJECTS = APRSWriter.o Conf.o GPSHandler.o IcomNetwork.o KenwoodNetwork.o Log.o Mutex.o NXDNCRC.o NXDNGateway.o NXDNLookup.o NXDNNetwork.o \
	  Reflectors.o RptNetwork.o StopWatch.o Thread.o Timer.o UDPSocket.o Utils.o Voice.o

all:		NXDNGateway

NXDNGateway:	$(OBJECTS)
		$(CXX) $(OBJECTS) $(CFLAGS) $(LIBS) -o NXDNGateway

%.o: %.cpp
		$(CXX) $(CFLAGS) -c -o $@ $<

clean:
		$(RM) NXDNGateway *.o *.d *.bak *~
 
