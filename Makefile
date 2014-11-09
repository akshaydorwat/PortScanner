CC=g++
CPFLAGS=-g -Wall -std=c++0x 
LDFLAGS= -lpcap -pthread

VPATH = src

OBJ = \
Starter.o\
Logger.o\
PortScannerUtils.o\
PacketScanner.o\
PacketFactory.o\
Mutex.o\
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
	sudo ./portScanner --ports 1-2,6-10,100,120,150-170 --ip 74.125.225.68 --prefix 127.0.0.1/30 --file ./ipAddresses.txt --speedup 5 --scan UDP SYN
