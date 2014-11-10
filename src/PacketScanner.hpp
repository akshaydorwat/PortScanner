/*
 *      Author : Rohit Khapare
 *      email  : rkhapare@indiana.edu
 *      Date   : 11-8-2014
 */

#include <string>
#include <map>

#include <pcap.h>
#include <inttypes.h>

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
//static const string DEFAULT_DEVICE = "eth0";
static const string BASE_PACKET_FILTER = "tcp or udp or icmp";

///////////////////////////////////////////////////////////////////////////////////////////////////
class PacketScanner
{
	private:
		static PacketScanner* packetScanner;		
		map<int, void(*)(PacketScanner*, const struct pcap_pkthdr*, const u_char*)> callbackMap;

		PacketScanner(){};								// private constructor
		PacketScanner(PacketScanner const&){};						// private copy constructor
		PacketScanner& operator=(PacketScanner const&){ return *packetScanner; };	// private assignment operator

        public:
		uint8_t linkHeaderLength;

		static PacketScanner* getPacketScanner();	// obtain the singleton instance
		pcap_t* init();					// initialize on default device
		void scanForever(pcap_t *);

		bool registerCallback(int socket_fd, void (*function)(PacketScanner*, const struct pcap_pkthdr*, const u_char*));
		bool unregisterCallback(int socket_fd);
		static void makeCallbacks(u_char *usr, const struct pcap_pkthdr *pkthdr, const u_char *pktptr);
};
///////////////////////////////////////////////////////////////////////////////////////////////////
