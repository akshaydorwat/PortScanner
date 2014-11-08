/*
 *      Author : Rohit Khapare
 *      email  : rkhapare@indiana.edu
 *      Date   : 11-4-2014
 */

#include <string>
#include <vector>

#include <inttypes.h>

using namespace std;

class PortScannerUtils
{
	public:
		static bool isValidIp(string ip);
		static uint32_t ipToInt(string ip);
		static string intToIp(uint32_t ipInt);
		static vector<string> getIpsFromPrefix(string prefix);
};
