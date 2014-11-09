/*
 *      Author : Rohit Khapare
 *      email  : rkhapare@indiana.edu
 *      Date   : 11-8-2014
 */

#include <string>
#include <vector>

#include <pcap.h>

using namespace std;

static const string DEFAULT_DEVICE = "eth0";
static const string BASE_PACKET_FILTER = "tcp or udp or icmp";

class PacketScanner
{
	private:
		static PacketScanner* packetScanner;

		PacketScanner(){};								// private constructor
		PacketScanner(PacketScanner const&){};						// private copy constructor
		PacketScanner& operator=(PacketScanner const&){ return *packetScanner; };	// private assignment operator

        public:
		static PacketScanner* getPacketScanner();	// obtain the singleton instance
		pcap_t* init();					// initialize on default device
};
