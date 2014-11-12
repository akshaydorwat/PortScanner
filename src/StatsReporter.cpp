/**
 * Author : Rohit Khapare
 * Date      : 11-10-2014
 * Email     : rkhapare@indiana.edu
 **/

#include "StatsReporter.hpp"
#include "PortStatus.hpp"

#include <iostream>
#include <string>
#include <map>
#include <vector>

#include <inttypes.h>
#include <arpa/inet.h>

using namespace std;

PortStatus StatsReporter::getPortStatus(struct in_addr ipAddr, uint16_t port)
{
	// Check whether supplied ipAddr was previously added to report
	string ipAddrStr = string(inet_ntoa(ipAddr));
	if (report.count(ipAddrStr) == 0) // If not, add it to report with an empty port status map
		report[ipAddrStr] = map<string, vector<PortStatus>>();

	// Get the port status map corresponding to the supplied ipAddr
	map<string, vector<PortStatus>> portStsMap = report[ipAddrStr];

	// Check and return and existing PortStatus against the supplied port
	for (map<string, vector<PortStatus>>::iterator itr = portStsMap.begin(); \
			itr != portStsMap.end(); ++itr)
	{
		vector<PortStatus> portStsVctr = itr->second;
		for (size_t i=0; i < portStsVctr.size(); i++)
		{
			if (portStsVctr[i].port == port)
				return portStsVctr[i];
		}
	}

	// If no PortStatus exists for ipAddr:port, create a new CLOSED entry
	string portDefaultSts = "CLOSED";
	if (portStsMap.count(portDefaultSts) == 0)
		portStsMap[portDefaultSts] = vector<PortStatus>();

	PortStatus portSts;
	portSts.port = port;
	portStsMap[portDefaultSts].push_back(portSts);
	return portStsMap[portDefaultSts].back();
}

void StatsReporter::updatePortStatus(struct in_addr ipAddr, uint16_t port, enum SCAN_TECHNIQUE scanType, enum PORT_STATUS portSts)
{
	PortStatus portStatus = getPortStatus(ipAddr, port);
	string oldSts = portStatus.getConclusion();
	portStatus.scanStatus[scanType] = portSts;
	string newSts = portStatus.getConclusion();

	// If status change detected, relocate PortStatus to new status map
	if (oldSts != newSts)
	{
		string ipAddrStr = string(inet_ntoa(ipAddr));
		map<string, vector<PortStatus>> portStsMap = report[ipAddrStr];

		vector<PortStatus> oldStsVctr = portStsMap[oldSts];
		for (size_t i=0; i < oldStsVctr.size(); i++)
		{
			if (oldStsVctr[i].port == port)
			{
				oldStsVctr.erase(oldStsVctr.begin() + i);
			}
		}
		if (portStsMap.count(newSts) == 0)
			portStsMap[newSts] = vector<PortStatus>();

		portStsMap[newSts].push_back(portStatus);
	}
}

void StatsReporter::updateServiceStatus(struct in_addr ipAddr, uint16_t port, string svc, string version)
{
	PortStatus portStatus = getPortStatus(ipAddr, port);
	portStatus.serviceName = svc;
	portStatus.protocolVersion = version;
}

void StatsReporter::displayReport()
{
	cout << endl << "Scan took " << " seconds" << endl;

	for (map<string, map<string, vector<PortStatus>>>::iterator ipItr = report.begin(); \
			ipItr != report.end(); ++ipItr)
	{
		cout << endl << "IP address: " << ipItr->first << endl;
		//map<string, vector<PortStatus>> portStatusMap = ipItr->second;
		for (map<string, vector<PortStatus>>::iterator stsItr = ipItr->second.begin(); \
				stsItr != ipItr->second.end(); ++stsItr)
		{
			if (stsItr->second.size() > 0)
			{
				cout << stsItr->first << " ports:" << endl;
				cout << "------------------------------------------------------------" << endl;

				vector<PortStatus> portStatii = stsItr->second;
				for (size_t i=0; i < portStatii.size(); i++)
				{
					cout << to_string(portStatii[i].port) << "\t";
					for (map<enum SCAN_TECHNIQUE, enum PORT_STATUS>::iterator scnItr = portStatii[i].scanStatus.begin(); \
							scnItr != portStatii[i].scanStatus.end(); ++scnItr)
					{
						cout << KNOWN_SCANS[scnItr->first] << "(" << PortStatus::getStatusString(scnItr->second) << ")  ";
					}
				}
			}
		}
	}
}
