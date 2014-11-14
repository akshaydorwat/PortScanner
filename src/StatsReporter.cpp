/**
 * Author    : Rohit Khapare
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

StatsReporter* StatsReporter::stsRptr = NULL;

void StatsReporter::enterMonitor(string ipPort)
{
	//cout << "Checking monitor for " << ipPort << endl;
	bool goAhead;
	do	// check monitor for existing lock on ipPort
	{
		goAhead = true;
		ipPortMtx.lock();
		for (size_t i=0; i<ipPortMtxVctr.size(); i++)
		{
			if (ipPortMtxVctr[i] == ipPort)
			{
				goAhead = false;
				break;
			}
		}
		if (goAhead)	// add to monitor before goAhead
		{
			//cout << ipPort << " added to monitor." << endl;
			ipPortMtxVctr.push_back(ipPort);
		}
		ipPortMtx.unlock();
	}while(!goAhead);
}

void StatsReporter::exitMonitor(string ipPort)
{
	ipPortMtx.lock();
	for (size_t i=0; i<ipPortMtxVctr.size(); i++)
	{
		if (ipPortMtxVctr[i] == ipPort)
		{
			ipPortMtxVctr.erase(ipPortMtxVctr.begin() + i);
			//cout << ipPort << " removed from monitor." << endl;
			break;
		}
	}
	ipPortMtx.unlock();
}

size_t StatsReporter::getPortStatus(struct in_addr ipAddr, uint16_t port, string &oldSts)
{
	string ipAddrStr = string(inet_ntoa(ipAddr));	

	// Check whether supplied ipAddr was previously added to report	
	if (report.count(ipAddrStr) == 0) // If not, add it to report with an empty port status map
		report[ipAddrStr] = map<string, vector<PortStatus>>();

	// Get the port status map corresponding to the supplied ipAddr
	map<string, vector<PortStatus>> &portStsMap = report[ipAddrStr];
	//cout << "Found IP address " << ipAddrStr << endl;

	// Check and return and existing PortStatus against the supplied port
	for (map<string, vector<PortStatus>>::iterator itr = portStsMap.begin(); \
			itr != portStsMap.end(); ++itr)
	{
		//cout << "Found port-status #" << itr->first << endl;
		oldSts = itr->first;
		vector<PortStatus> &portStsVctr = itr->second;
		for (size_t i=0; i < portStsVctr.size(); i++)
		{
			//cout << "Found " << itr->first << " port #" << to_string(portStsVctr[i].port) << endl;
			if (portStsVctr[i].port == port)
				return i;
		}
	}

	// If no PortStatus exists for ipAddr:port, create a new CLOSED entry
	string portDefaultSts = "CLOSED";
	oldSts = portDefaultSts;
	if (portStsMap.count(portDefaultSts) == 0)
		portStsMap[portDefaultSts] = vector<PortStatus>();

	PortStatus portSts;
	portSts.port = port;
	portStsMap[portDefaultSts].push_back(portSts);
	//cout << "Added port #" << to_string(port) << " to port-status " << portDefaultSts << endl;
	return portStsMap[portDefaultSts].size() - 1;
}

void StatsReporter::updatePortStatus(struct in_addr ipAddr, uint16_t port, enum SCAN_TECHNIQUE scanType, enum PORT_STATUS portSts)
{
	//cout << "Updating " << string(inet_ntoa(ipAddr)) << " port #" << to_string(port) << " scan-type " << KNOWN_SCANS[scanType] << " status " << PortStatus::getStatusString(portSts) << endl;
	string ipAddrStr = string(inet_ntoa(ipAddr));
	string oldSts;
	enterMonitor(ipAddrStr + ":" + to_string(port));
	size_t portStsVctrIdx = getPortStatus(ipAddr, port, oldSts);
	PortStatus &portStatus = report[ipAddrStr][oldSts][portStsVctrIdx];	
	portStatus.scanStatus[scanType] = portSts;
	string newSts = portStatus.getConclusion();

	// If status change detected, relocate PortStatus to new status map
	if (oldSts != newSts)
	{	
		map<string, vector<PortStatus>> &portStsMap = report[ipAddrStr];

		if (portStsMap.count(newSts) == 0)
			portStsMap[newSts] = vector<PortStatus>();
		portStsMap[newSts].push_back(portStatus);

		vector<PortStatus> &oldStsVctr = portStsMap[oldSts];
		for (size_t i=0; i < oldStsVctr.size(); i++)
		{
			if (oldStsVctr[i].port == port)
			{
				oldStsVctr.erase(oldStsVctr.begin() + i);
			}
		}	
		//cout << "Moved port #" << to_string(portStatus.port) << " from " << oldSts << " to " << newSts << endl;
	}	
	exitMonitor(ipAddrStr + ":" + to_string(port));
}

void StatsReporter::updateServiceStatus(struct in_addr ipAddr, uint16_t port, string svc, string version)
{
	string ipAddrStr = string(inet_ntoa(ipAddr));
	string oldSts;
	enterMonitor(ipAddrStr + ":" + to_string(port));
	size_t portStsVctrIdx = getPortStatus(ipAddr, port, oldSts);
	PortStatus &portStatus = report[string(inet_ntoa(ipAddr))][oldSts][portStsVctrIdx];
	portStatus.serviceName = svc;
	portStatus.protocolVersion = version;
	exitMonitor(ipAddrStr + ":" + to_string(port));
}

void StatsReporter::displayReport()
{
	cout << endl << "Scan took " << " seconds" << endl;

	for (map<string, map<string, vector<PortStatus>>>::iterator ipItr = report.begin(); \
			ipItr != report.end(); ++ipItr)
	{
		cout << endl << "IP address: " << ipItr->first << endl;
		//map<string, vector<PortStatus>> &portStatusMap = ipItr->second;
		for (map<string, vector<PortStatus>>::iterator stsItr = ipItr->second.begin(); \
				stsItr != ipItr->second.end(); ++stsItr)
		{
			if (stsItr->second.size() > 0)
			{
				cout << endl << stsItr->first << " ports:" << endl;
				cout << "Port\tScan Results\t\t\t\t\t\t\t\t\t\t\t\t\t\tConclusion" << endl;
				cout << "----------------------------------------------------------------------------------------------------------------------------------------------";

				vector<PortStatus> portStatii = stsItr->second;
				for (size_t i=0; i < portStatii.size(); i++)
				{
					cout << endl << to_string(portStatii[i].port) << "(" << portStatii[i].scanStatus.size() << ")" << "\t";
					bool printConclusion = true;
					uint8_t maxStsOnSameLine = 2;
					for (map<enum SCAN_TECHNIQUE, enum PORT_STATUS>::iterator scnItr = portStatii[i].scanStatus.begin(); \
							scnItr != portStatii[i].scanStatus.end(); ++scnItr)
					{
						cout << KNOWN_SCANS[scnItr->first] << "(" << PortStatus::getStatusString(scnItr->second) << ")  ";
						maxStsOnSameLine--;
						if (printConclusion && (scnItr == portStatii[i].scanStatus.end() || maxStsOnSameLine == 0))
						{
							printConclusion = false;
							cout << "\t\t\t\t\t\t\t\t\t\t\t" << portStatii[i].getConclusion();
						}
						if (maxStsOnSameLine == 0)
						{
							maxStsOnSameLine = 2;
							cout << endl << "     \t";
						}	
					}	
				}
				cout << endl << endl;
			}
		}
	}
}
