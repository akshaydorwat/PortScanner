/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef SCAN_HPP
#define SCAN_HPP

#include "PacketFactory.hpp"
#include "StatsReporter.hpp"
#include "Logger.hpp"

#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#define MAX_TRY 3
#define BUFFER_SIZE 4096

using namespace std;

class Scan
{
public:
	
	Scan( struct sockaddr_in &p_src, struct sockaddr_in &p_dst, string &type )
		: src(p_src) , 	dst(p_dst) , scanType(type){

		// set unused port for source 
		src.sin_port = PacketFactory::getUnusedPort();
		memset(buff,'\0' ,BUFFER_SIZE);
	};
	
	virtual ~Scan(){
		delete factory;
		PacketFactory::freeUsedPort(src.sin_port);
		close(sfd);
	};

	// Method for thread pool to execute
	virtual void handle() = 0;

	// Filter callback
	virtual void filterCallback() = 0;   
	
	// utility function 
	void toString();

protected:
	char buff[BUFFER_SIZE];
	PacketFactory *factory;
	struct sockaddr_in src;
  	struct sockaddr_in dst;
	string scanType;
	enum PORT_STATUS status;
	int numOfPacketSent;
	int numOfPacketReceived;
	int sfd;

private:

	// Initial setup 
	virtual void init() = 0;

	// Send packet 
	virtual void send() = 0;

	// report status to Reporter
	virtual void reportStats() = 0;

	// create packet 
	virtual void createPacket() = 0;
};

#endif
