CC      = cc
CXX     = c++
CFLAGS  = -g -O3 -Wall -DHAVE_LOG_H -DUDP_SOCKET_MAX=2 -std=c++0x -pthread
LIBS    = -lpthread
LDFLAGS = -g

OBJECTS = Conf.o IcomNetwork.o KenwoodNetwork.o Log.o Mutex.o NXDNCRC.o NXDNLookup.o NXDNNetwork.o NXDNReflector.o StopWatch.o Thread.o Timer.o UDPSocket.o Utils.o

all:		NXDNReflector

NXDNReflector:	$(OBJECTS)
		$(CXX) $(OBJECTS) $(CFLAGS) $(LIBS) -o NXDNReflector

%.o: %.cpp
		$(CXX) $(CFLAGS) -c -o $@ $<

install:
		install -m 755 NXDNReflector /usr/local/bin/

clean:
		$(RM) NXDNReflector *.o *.d *.bak *~
 
