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
#include <functional>

#include <pcap.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
	int status;
	struct bpf_program  bpf;
	string device;
	pcap_if_t *alldevs;

	// Obtain the default device name
	/*if ((device = pcap_lookupdev(errbuf)) == NULL)
	  {
	  LOG (ERROR, "PacketScanner : Failed to obtain default network device. " + string(errbuf));
	  return NULL;
	  }*/

	// Obtain list of all available network devices
	if ((status = pcap_findalldevs(&alldevs, errbuf)) != 0) 
	{
		LOG (ERROR, "PacketScanner : Failed to obtain all network devices. " + string(errbuf));
		return NULL;
	}
	bool found = false;
	for(pcap_if_t *d=alldevs; !found && d != NULL; d=d->next) 
	{
		for(pcap_addr_t *a=d->addresses; !found && a != NULL; a = a->next)
		{
			if(a->addr->sa_family == AF_INET)
			{
				// store the device with a valid IP address (and assume that's the active connection)
				device = string(d->name);
				deviceIp.sin_addr = ((struct sockaddr_in*)a->addr)->sin_addr;
				found = true;
			}
		}
	}
	pcap_freealldevs(alldevs);

	// Open the device for live capture.
	if ((pd = pcap_open_live(device.c_str(), BUFSIZ, 1, 0, errbuf)) == NULL)
	{
		LOG(ERROR, "PacketScanner : Failed to open device: " + string(errbuf));
		return NULL;
	}

	// Get network device source IP address and netmask.
	if (pcap_lookupnet(device.c_str(), &devip, &devnetmask, errbuf) < 0)
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

	LOG (DEBUG, "PacketScanner : Initialized on " + device + ". IP address " + string(inet_ntoa(deviceIp.sin_addr)));
	return pd;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void* PacketScanner::scanForever( void *p_pd)
{
	PacketScanner *pktScnr = PacketScanner::getPacketScanner();
	pcap_t *pd = (pcap_t*) p_pd;
	int linktype;

	// Determine the datalink layer type.
	if ((linktype = pcap_datalink(pd)) < 0)
	{
		LOG(ERROR, "PacketScanner : Failed to extract link type. " + string(pcap_geterr(pd)));
		return NULL;
	}

	// Set the datalink layer header size.
	switch (linktype)
	{
		/*case DLT_NULL:		// loopback
		  linkHeaderLength = 4;
		  LOG(DEBUG, "PacketScanner : Link type : LOOPBACK");
		  break;*/

		case DLT_EN10MB:	// ethernet
			pktScnr->linkHeaderLength = 14;
			LOG(DEBUG, "PacketScanner : Link type : ETHERNET");
			break;

		default:		// unsupported
			LOG(ERROR, "PacketScanner : Unsupported link type #" + to_string(linktype));
			return NULL;
	}

	// Start capturing packets.
	if (pcap_loop(pd, 0, (pcap_handler) makeCallbacks, (u_char*) pktScnr) < 0)
		LOG(DEBUG, "PacketScanner : Terminating PCAP loop. " + string(pcap_geterr(pd)));

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void PacketScanner::makeCallbacks(u_char *usr, const struct pcap_pkthdr *pkthdr, const u_char *pktptr)
{
	PacketScanner *pktScnr = (PacketScanner *) usr;
	// invoke all the registered callbacks
	pktScnr->mLock.lock();
	for(map<int, function<void(const u_char*)>>::iterator itr = pktScnr->callbackMap.begin(); \
			itr != pktScnr->callbackMap.end(); ++itr)
	{
		itr->second(pktptr);
	}
	pktScnr->mLock.unlock();
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool PacketScanner::registerCallback(int socket_fd, function<void(const u_char*)> fxn)
{
	// if not already registered, register a new callback against the requisite socket
	mLock.lock();
	if (callbackMap.count(socket_fd) == 0)
	{
		callbackMap[socket_fd] = fxn;
		//LOG (DEBUG, "PacketScanner : Registered callback for socket#" + to_string(socket_fd));
		mLock.unlock();
		return true;
	}
	else
	{
		mLock.unlock();
		LOG(WARNING, "PacketScanner : Erroneous overwrite of callback for socket#" + to_string(socket_fd) + " declined !!!");
		return false;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool PacketScanner::unregisterCallback(int socket_fd)
{
	// unregister the callback associated with the requisite socket
	int ret;
	mLock.lock();
	ret = callbackMap.erase(socket_fd);
	mLock.unlock();
	return  ret == 1;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
