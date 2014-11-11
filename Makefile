CC=g++
CPFLAGS=-g -Wall -std=c++0x 
LDFLAGS= -lpcap -pthread

VPATH = src

OBJ = \
Starter.o\
Logger.o\
Mutex.o\
ConditionVariable.o\
JobPool.o\
PortScannerUtils.o\
PacketScanner.o\
PacketFactory.o\
Scan.o\
SYNscan.o\
FINscan.o\
ACKscan.o\
NULLscan.o\
XMASscan.o\
UDPscan.o



BIN = portScanner

all: $(BIN)

$(BIN): $(OBJ)	
	$(CC) $(LDFLAGS) $(CPFLAGS)  -o $(BIN) $(OBJ) $(LDFLAGS)

%.o:%.c
	$(CC) $(LDFLAGS) -c $(CPFLAGS) -o $@ $<  

%.o:%.cpp
	$(CC) $(LDFLAGS) -c $(CPFLAGS) -o $@ $<  

clean:
	rm -rf $(OBJ) $(BIN) portScanner.tar LOG.log

tar:
	tar -cvf portScanner.tar Makefile README src

run:
	sudo ./portScanner --ports 80,20  --ip 129.79.247.86  --speedup 1 --scan SYN
