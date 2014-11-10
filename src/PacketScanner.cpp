/*
 *      Author : Rohit Khapare
 *      email  : rkhapare@indiana.edu
 *      Date   : 11-8-2014
 */

#include "Logger.hpp"
#include "PacketScanner.hpp"

#include <string>
#include <iostream>
#include <vector>
#include <map>

#include <pcap.h>
#include <inttypes.h>

using namespace std;

PacketScanner* PacketScanner::packetScanner = NULL;

///////////////////////////////////////////////////////////////////////////////////////////////////
PacketScanner* PacketScanner::getPacketScanner()
{
	if (!packetScanner)
		packetScanner = new PacketScanner();

	return packetScanner;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
pcap_t* PacketScanner::init()
{
	pcap_t* pd;
	char errbuf[PCAP_ERRBUF_SIZE];	
	uint32_t  devip, devnetmask;
	struct bpf_program  bpf;

	// Open the device for live capture.
	if ((pd = pcap_open_live(DEFAULT_DEVICE.c_str(), BUFSIZ, 1, 0, errbuf)) == NULL)
	{
		LOG(ERROR, "PacketScanner : Failed to open device: " + string(errbuf));
		return NULL;
	}

	// Get network device source IP address and netmask.
	if (pcap_lookupnet(DEFAULT_DEVICE.c_str(), &devip, &devnetmask, errbuf) < 0)
	{
		LOG(ERROR, "PacketScanner : Failed to obtain n/w device info. " + string(errbuf));
		return NULL;
	}

	// Convert the packet filter epxression into a packet filter binary.
	if (pcap_compile(pd, &bpf, BASE_PACKET_FILTER.c_str(), 0, devnetmask))
	{
		LOG(ERROR, "PacketScanner : Failed to compile filter \"" + BASE_PACKET_FILTER + "\"" + string(pcap_geterr(pd)));
		return NULL;
	}

	// Assign the packet filter to the given libpcap socket.
	if (pcap_setfilter(pd, &bpf) < 0)
	{
		LOG(ERROR, "PacketScanner : Failed to set filter " + string(pcap_geterr(pd)));
		return NULL;
	}

	LOG (DEBUG, "PacketScanner : Initialized.");
	return pd;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void PacketScanner::scanForever(pcap_t *pd)
{
	int linktype;

	// Determine the datalink layer type.
	if ((linktype = pcap_datalink(pd)) < 0)
	{
		LOG(ERROR, "PacketScanner : Failed to extract link type. " + string(pcap_geterr(pd)));
		return;
	}

	// Set the datalink layer header size.
	switch (linktype)
	{
		case DLT_NULL:		// loopback
			LOG(DEBUG, "PacketScanner : Link type : LOOPBACK");
			break;

		case DLT_EN10MB:	// ethernet
			LOG(DEBUG, "PacketScanner : Link type : ETHERNET");
			break;

		default:		// unsupported
			LOG(ERROR, "PacketScanner : Unsupported link type #" + to_string(linktype));
			return;
	}

	// Start capturing packets.
	if (pcap_loop(pd, 0, (pcap_handler) makeCallbacks, (u_char*) this) < 0)
		LOG(ERROR, "PacketScanner : Error occurred while looping forever. " + string(pcap_geterr(pd)));
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void PacketScanner::makeCallbacks(u_char *usr, const struct pcap_pkthdr *pkthdr, const u_char *pktptr)
{
	PacketScanner *pktScnr = (PacketScanner *) usr;
	for(map<int, void(*)()>::iterator callbackFunction = pktScnr->callbackMap.begin(); callbackFunction != pktScnr->callbackMap.end(); callbackFunction++)
	{
		callbackFunction->second();//usr, pkthdr, pktptr);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void PacketScanner::registerCallback(int socket_fd, void (*function))
{
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void PacketScanner::unregisterCallback(int socket_fd)
{

}

///////////////////////////////////////////////////////////////////////////////////////////////////
