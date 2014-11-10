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

#define MAX_TRY 5

using namespace std;

class Scan
{

public:
	
	Scan( struct sockaddr_in &p_src, struct sockaddr_in &p_dst, string &type )
		: src(p_src) , 	dst(p_dst) , scanType(type){};
	
	virtual ~Scan(){};

	virtual void handle() = 0;
	virtual void filterCallback() = 0;   

private:

	struct sockaddr_in src;
	struct sockaddr_in dst;
	string scanType;
	enum PORT_STATUS status;
	int numOfPacketSent;
	int numOfPacketReceived;
	
	virtual void init() = 0;
	virtual void send() = 0;
	virtual void reportStats() = 0;
};

#endif
