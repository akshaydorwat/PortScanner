/*
 *      Author : Rohit Khapare
 *      email  : rkhapare@indiana.edu
 *      Date   : 11-10-2014
 */

#include "PortStatus.hpp"
#include "Starter.hpp"

#include <string>
#include <map>

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
string PortStatus::getScanStatus(enum SCAN_TECHNIQUE scanType)
{
	for (map<enum SCAN_TECHNIQUE, enum PORT_STATUS>::iterator itr = scanStatus.begin(); \
			itr != scanStatus.end(); ++itr)
	{
		if (scanType == itr->first)
			return getStatusString(itr->second);
	}
	return "UNKNOWN SCAN TECHNIQUE";
}

///////////////////////////////////////////////////////////////////////////////////////////////////
string PortStatus::getConclusion()
{
	int min = CLOSED;
	for (map<enum SCAN_TECHNIQUE, enum PORT_STATUS>::iterator itr = scanStatus.begin(); \
			itr != scanStatus.end(); ++itr)
	{
		if (min > (int) itr->second)
			min = (int) itr->second;
	}
	return getStatusString(static_cast<PORT_STATUS>(min));
}

///////////////////////////////////////////////////////////////////////////////////////////////////
string PortStatus::getStatusString(enum PORT_STATUS sts)
{
	switch(sts)
	{
		case OPEN: return "OPEN";
		case OPEN_FILTERED: return "OPEN|FILTERED";
		case UNFILTERED: return "UNFILTERED";
		case FILTERED: return "FILTERED";
		case CLOSED: return "CLOSED";
		default: return "UNKNOWN SCAN TECHNIQUE";
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////
