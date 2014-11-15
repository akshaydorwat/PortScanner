/*
 *      Author : Rohit Khapare
 *      email  : rkhapare@indiana.edu
 *      Date   : 11-8-2014
 */

#include <string>
#include <map>
#include <functional>

#include <pcap.h>
#include <inttypes.h>
#include <netinet/in.h>

#include "Mutex.hpp"

using namespace std;

#ifndef PACKET_SCANNER_HPP
#define PACKET_SCANNER_HPP

///////////////////////////////////////////////////////////////////////////////////////////////////
//static const string DEFAULT_DEVICE = "eth0";
static const string BASE_PACKET_FILTER = "tcp or udp or icmp";

///////////////////////////////////////////////////////////////////////////////////////////////////
class PacketScanner
{
private:
	//static PacketScanner* packetScanner;
	map<int, function<void(const u_char*)>> callbackMap;
	Mutex mLock;

	PacketScanner(){};								// private constructor
	PacketScanner(PacketScanner const&){};						// private copy constructor
	PacketScanner& operator=(PacketScanner const&);//{ return *packetScanner; };	// private assignment operator

public:
	uint8_t linkHeaderLength;
	struct sockaddr_in deviceIp;

	static PacketScanner& getPacketScanner();	// obtain the singleton instance
	static void* scanForever( void *);
	static void makeCallbacks(u_char *usr, const struct pcap_pkthdr *pkthdr, const u_char *pktptr);
	pcap_t* init();					// initialize on default device


	bool registerCallback(int socket_fd, function<void(const u_char*)> fxn);
	bool unregisterCallback(int socket_fd);

};
///////////////////////////////////////////////////////////////////////////////////////////////////

#endif
