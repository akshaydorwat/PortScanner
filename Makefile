CC=g++
CPFLAGS=-g -Wall -std=c++0x 
LDFLAGS= -lpcap -pthread

VPATH = src

OBJ = \
Starter.o\
Logger.o\
Mutex.o\
PortStatus.o\
StatsReporter.o\
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
UDPscan.o\
UniquePortGenerator.o\
WHOISvScan.o\
IMAPvScan.o\
SSHvScan.o\
HTTPvScan.o


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

test:
	sudo ./portScanner -v --ports 80 --ip 129.79.247.87 --speedup 50 --scan SYN 

run:
	sudo ./portScanner --log_file LOG.log --ports 22,24,43,80,110,143 --ip 129.79.247.87 --speedup 50 --scan SYN UDP FIN NULL XMAS ACK

service:
	sudo ./portScanner --ports 43 --file service_ip --speedup 50 --scan SYN

stress_test:
	sudo ./portScanner --log_file LOG.log --ports 22,24,80,110,143,43,53,700-1024 --file ip_list --speedup 75 --scan SYN UDP FIN NULL XMAS ACK

valgrind:
	sudo valgrind --tool=memcheck --leak-check=full  --track-origins=yes --log-file=mem.log ./portScanner --log_file LOG.log --ports 1-512 --file ip_list --speedup 100 --scan SYN ACK FIN NULL XMAS UDP
