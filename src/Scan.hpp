/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef SCAN_HPP
#define SCAN_HPP

// user lib
#include "PacketFactory.hpp"
#include "StatsReporter.hpp"
#include "Logger.hpp"
#include "PacketScanner.hpp"
#include "UniquePortGenerator.hpp"

// c lib
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>

#define MAX_TRY 3
#define DEFAULT_SLEEP_TIME 1
#define BUFFER_SIZE 4096

using namespace std;

class Scan
{
public:
	
	Scan( struct sockaddr_in &p_src, struct sockaddr_in &p_dst, string &type )
		: src(p_src) , 	dst(p_dst) {

		for (size_t i=0; i < KNOWN_SCANS.size(); i++)
		{
			if (KNOWN_SCANS[i] == type)
			{
				scanType = static_cast<SCAN_TECHNIQUE>(i);
				break;
			}
		}

		// set unused port for source 
		src.sin_port = UniquePortGenerator::getInstance()->getUnusedPort();
		// zero the memory
		memset(buff,'\0' ,BUFFER_SIZE);
		// initialise the stats
		numOfPacketSent = 0;
		numOfPacketReceived = 0;
		factory = NULL;
		//debugging
		debugInfo = string(inet_ntoa(dst.sin_addr)) + ":" +	to_string((int)dst.sin_port) + "\t"	+ KNOWN_SCANS[scanType];
	};
	
	virtual ~Scan(){
		if(factory != NULL){
			delete factory;
		}
		UniquePortGenerator::getInstance()->freeUsedPort(src.sin_port);
		close(sfd);
	};

	// Method for thread pool to execute
	virtual void handle() = 0;

	// Filter callback
	virtual void filterCallback(const u_char *ptr) = 0;   
	
	// utility function 
	void toString();

protected:
	char buff[BUFFER_SIZE];
	PacketFactory *factory;
	struct sockaddr_in src;
  	struct sockaddr_in dst;
	enum SCAN_TECHNIQUE scanType;
	enum PORT_STATUS status;
	int numOfPacketSent;
	int numOfPacketReceived;
	int sfd;
	string debugInfo;
	int packetLen;
	
	// basic filter
	const u_char* basicFilter(const u_char *packet, uint8_t &protocol);
	
	// report status to Reporter
	void reportStats();

private:

	// Initial setup 
	virtual bool init() = 0;

	// Send packet 
	virtual bool send() = 0;

	// create packet 
	virtual void createPacket() = 0;

};

#endif
