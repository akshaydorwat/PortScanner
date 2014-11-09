#ifndef PACKET_FATORY_HPP
#define PACKET_FATORY_HPP

// c++ lib
#include <string>
#include <bitset>

// c lib
#include <stdlib.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>

// local lib
#include "Logger.hpp"
#include "Mutex.hpp"

#define MAX_PORT 65535
#define MIN_PORT 4096

using namespace std;

enum PROTOCOL{
	TCP,
	UDP,
	ICMP
};

class PacketFactory{
public:
	PacketFactory(enum PROTOCOL p, char *p_packet){
		protocol = p;
		packet = p_packet;
	}
  
	// set option in packet
	bool setOption(string option, void *val);

private:
	enum PROTOCOL protocol;
	char *packet;
	static bitset<MAX_PORT> portRange;
	static Mutex mLock;
	
	// set TCP packet options
	bool setOptionTCP(string &option, void *val);
	
	// set ICMP packet options
	bool setOptionICMP(string &option, void *val);
	
	// set UDP packet options
	bool setOptionUDP(string &option, void *val);
	
	// TCP checksum calculator
	uint16_t tcpChecksome(struct TCP_pseudo_t *ptr);

	// Genralized checksum calculator
	uint16_t checksumCalculator (const void * addr, unsigned len, uint16_t init);

	// get unused port 
	static uint16_t getUnusedPort();

	// free used ports
	static void freeUsedPort(uint16_t port);
	

};

struct TCP_pseudo_t{
  u_int32_t saddr;
  u_int32_t daddr;
  u_int8_t reserve;
  u_int8_t protocol;
  u_int16_t len;
};

#endif // MACRO
