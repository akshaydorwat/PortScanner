#ifndef PACKET_FATORY_HPP
#define PACKET_FATORY_HPP

// c++ lib
#include <string>
#include <bitset>

// c lib
#include <stdlib.h>

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>

// local lib
#include "Logger.hpp"
#include "Mutex.hpp"
#include "dns.h"

#define DEFAULT_SEQ_NO 2500
#define DEFAULT_ACK_SEQ 0
#define DEFAULT_WINDOW 29200
#define DEFAULT_DATA_OFFSET 5

using namespace std;

enum PROTOCOL{
	TCP,
	UDP,
	DNS
};

class PacketFactory{
public:
	PacketFactory(enum PROTOCOL p, char *p_packet){
		protocol = p;
		packet = p_packet;
	}
  
	// set option in packet
	bool setOption(string option, void *val);

	
	// set dsn question section
	int setQuestion(char *str,  uint16_t qtype, uint16_t qclass);
	

private:
	enum PROTOCOL protocol;
	char *packet;
	
	// set TCP packet options
	bool setOptionTCP(string &option, void *val);
	
	// set DNS packet options
	bool setOptionDNS(string &option, void *val);
	
	// set UDP packet options
	bool setOptionUDP(string &option, void *val);
	
	// TCP checksum calculator
	uint16_t tcpChecksome(struct TCP_pseudo_t *ptr);

	// UDP checksum calculator
	uint16_t udpChecksome(struct UDP_pseudo_t *ptr, int hdr_len);

	// Genralized checksum calculator
	uint16_t checksumCalculator (const void * addr, unsigned len, uint16_t init);

	// dns char to dns string to converter
	int charToDnsString(unsigned char *str, unsigned char *dns);
};

struct TCP_pseudo_t{
	u_int32_t saddr;
	u_int32_t daddr;
	u_int8_t reserve;
	u_int8_t protocol;
	u_int16_t len;
};

struct UDP_pseudo_t{
	u_int32_t saddr;
	u_int32_t daddr;
	u_int8_t reserve;
	u_int8_t protocol;
	u_int16_t len;
};




#endif // MACRO
