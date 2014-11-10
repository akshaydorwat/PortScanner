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

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
//static const string DEFAULT_DEVICE = "eth0";
static const string BASE_PACKET_FILTER = "tcp or udp or icmp";

///////////////////////////////////////////////////////////////////////////////////////////////////
class PacketScanner
{
private:
		static PacketScanner* packetScanner;
		map<int, function<void(const u_char*)>> callbackMap;

		PacketScanner(){};								// private constructor
		PacketScanner(PacketScanner const&){};						// private copy constructor
		PacketScanner& operator=(PacketScanner const&){ return *packetScanner; };	// private assignment operator

public:
		uint8_t linkHeaderLength;
		struct sockaddr_in deviceIp;

		static PacketScanner* getPacketScanner();	// obtain the singleton instance
		pcap_t* init();					// initialize on default device
		void scanForever(pcap_t *);

		bool registerCallback(int socket_fd, function<void(const u_char*)> fxn);
		bool unregisterCallback(int socket_fd);
		static void makeCallbacks(u_char *usr, const struct pcap_pkthdr *pkthdr, const u_char *pktptr);
};
///////////////////////////////////////////////////////////////////////////////////////////////////
