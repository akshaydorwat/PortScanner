/*
 *      Author : Rohit Khapare
 *      email  : rkhapare@indiana.edu
 *      Date   : 11-4-2014
 */

#include "PortScannerUtils.hpp"
#include "Logger.hpp"

#include <string>
#include <vector>
#include <iostream>

#include <inttypes.h>

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
bool PortScannerUtils::isValidIp(string ip)
{
	string originalIp = ip;
	size_t dotIdx;
	unsigned int parts = 0;
	while ((dotIdx = ip.find('.')) != string::npos || parts == 3)
	{
		dotIdx = dotIdx == string::npos ? ip.size() : dotIdx;
		if (dotIdx <= 0 || dotIdx > 3) return false;

		int num = atoi(ip.substr(0, dotIdx).c_str());
		if (num < 0 || num > 255) return false;

		parts++;
		if (parts < 4)	ip = ip.substr(dotIdx + 1);
		else if (dotIdx == ip.size()) break;
		else return false;
	}
	LOG (DEBUG, parts == 4 ? "Valid IP : " + originalIp : "Invalid IP : " + originalIp);
	return parts == 4;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/* http://stackoverflow.com/questions/10283703/conversion-of-ip-address-to-integer */
uint32_t PortScannerUtils::ipToInt(string ip) 
{
  	uint32_t ipbytes[4];
  	sscanf(ip.c_str(), "%u.%u.%u.%u", &ipbytes[3], &ipbytes[2], &ipbytes[1], &ipbytes[0]);	
  	return ipbytes[3] << 24 | ipbytes[2] << 16 | ipbytes[1] << 8 | ipbytes[0];
}

string PortScannerUtils::intToIp(uint32_t ipInt)
{
	uint8_t ipBytes[4];
    	ipBytes[0] = ipInt & 0xFF;
    	ipBytes[1] = (ipInt >> 8) & 0xFF;
    	ipBytes[2] = (ipInt >> 16) & 0xFF;
    	ipBytes[3] = (ipInt >> 24) & 0xFF;
	return to_string(ipBytes[3]) + "." + to_string(ipBytes[2]) + "." + to_string(ipBytes[1]) + "." + to_string(ipBytes[0]);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
vector<string> PortScannerUtils::getIpsFromPrefix(string prefix)
{
	vector<string> ips;
	size_t slashIdx;
	if ((slashIdx = prefix.find('/')) != string::npos || prefix.size() > 0)
	{
		int maskNum = slashIdx == string::npos ? 32 : atoi (prefix.substr(slashIdx +1).c_str());
		string ip = slashIdx == string::npos ? prefix : prefix.substr(0, slashIdx);
		uint32_t ipInt = ipToInt(ip);
	
		if (isValidIp(ip) && maskNum >= 0 && maskNum <= 32)
		{
			uint32_t mask = 0xFFFFFFFF << (32 - maskNum);
			uint32_t ipGen = ipInt & mask;

			for (uint32_t i=0; i <= 0xFFFFFFFF - mask; i++)
				ips.push_back(intToIp(ipGen | i));
		}
	}
	return ips;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
