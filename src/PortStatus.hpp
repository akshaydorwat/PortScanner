/*
 *      Authors: Akshay Dorwat, Rohit Khapare
 *      email  : rkhapare@indiana.edu
 *      Date   : 11-10-2014
 */

#ifndef PORTSTATUS_HPP
#define PORTSTATUS_HPP

#include "Starter.hpp"

#include <string>
#include <map>

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
enum PORT_STATUS
{
	OPEN,
	OPEN_FILTERED,
	UNFILTERED,
	FILTERED,
	CLOSED
};

///////////////////////////////////////////////////////////////////////////////////////////////////
class PortStatus
{
	public:
		uint16_t port;
		map<enum SCAN_TECHNIQUE, enum PORT_STATUS> scanStatus;
		string serviceName;
		string protocolVersion;
		
		string getScanStatus(enum SCAN_TECHNIQUE scanType);
		string getConclusion();

	//private:
		static string getStatusString(enum PORT_STATUS sts);
};

#endif
///////////////////////////////////////////////////////////////////////////////////////////////////