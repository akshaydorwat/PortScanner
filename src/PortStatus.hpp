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

#define SVC_COL 50

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
enum PORT_STATUS
{
	OPEN,
	FILTERED,
	OPEN_FILTERED,
	UNFILTERED,	
	CLOSED
};

///////////////////////////////////////////////////////////////////////////////////////////////////
class PortStatus
{
	public:
		uint16_t port;
		map<enum SCAN_TECHNIQUE, enum PORT_STATUS> scanStatus;
		string serviceName;
		//string protocolVersion;

		PortStatus()
		{
			port = 0;
			string unassigned = "Unassigned";
			string blanks(SVC_COL - unassigned.size() - 2, ' ');
			serviceName = unassigned + blanks;
			//protocolVersion = "";
		}
		
		string getScanStatus(enum SCAN_TECHNIQUE scanType);
		string getConclusion();

		static string getStatusString(enum PORT_STATUS sts);
};

#endif
///////////////////////////////////////////////////////////////////////////////////////////////////
