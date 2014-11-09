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


///////////////////////////////////////////////////////////////////////////////////////////////////
