/**
 * Author    : Rohit Khapare
 * Date      : 11-10-2014
 * Email     : rkhapare@indiana.edu
 **/

#include "StatsReporter.hpp"
#include "PortStatus.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <map>
#include <vector>
#include <chrono>

#include <inttypes.h>
#include <arpa/inet.h>
#include <netdb.h>

using namespace std;

//StatsReporter* StatsReporter::stsRptr = NULL;

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
			//cout << ipPort << " (+) locked" << endl;//" added to monitor." << endl;
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
			//cout << ipPort << " (-) unlocked" << endl;//" removed from monitor." << endl;
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
	//PortStatus &portStatus = report[ipAddrStr][oldSts][portStsVctrIdx];	
	report[ipAddrStr][oldSts][portStsVctrIdx].scanStatus[scanType] = portSts;
	string newSts = report[ipAddrStr][oldSts][portStsVctrIdx].getConclusion();

	// If status change detected, relocate PortStatus to new status map
	if (oldSts != newSts)
	{	
		//map<string, vector<PortStatus>> &portStsMap = report[ipAddrStr];

		if (report[ipAddrStr].count(newSts) == 0)
			report[ipAddrStr][newSts] = vector<PortStatus>();
		report[ipAddrStr][newSts].push_back(report[ipAddrStr][oldSts][portStsVctrIdx]);//portStatus);

		//vector<PortStatus> &oldStsVctr = report[ipAddrStr][oldSts];
		for (size_t i=0; i < report[ipAddrStr][oldSts].size(); i++)
		{
			if (report[ipAddrStr][oldSts][i].port == port)
			{
				report[ipAddrStr][oldSts].erase(report[ipAddrStr][oldSts].begin() + i);
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
	string svcStr = svc;
	//PortStatus &portStatus = report[string(inet_ntoa(ipAddr))][oldSts][portStsVctrIdx];

	if (report[string(inet_ntoa(ipAddr))][oldSts][portStsVctrIdx].serviceName.size() == 0)
	{	
		if (svcStr.size() == 0)
		{
			svcStr = string("Unassigned");	// default service name = Unassigned

			if (port <= 1024)
			{
				struct servent *service;
				service = getservbyport(htons(port), NULL);
				if (service && service != NULL && service->s_name != NULL)
					svcStr = string(service->s_name);
				endservent();
			}
		}
		//cout << ipAddrStr << ":" << to_string(port) << " service: " << svc << endl;
		report[string(inet_ntoa(ipAddr))][oldSts][portStsVctrIdx].serviceName = svcStr;

		//if (svc == "Unassigned")
		//version = "";
	}

	if (version.size() != 0)
		report[string(inet_ntoa(ipAddr))][oldSts][portStsVctrIdx].protocolVersion = version;
	//cout << ipAddrStr << ":" << to_string(port) << " service: [" << svc << "] actual: [" << report[string(inet_ntoa(ipAddr))][oldSts][portStsVctrIdx].serviceName << "]" << endl;
	//cout << ipAddrStr << ":" << to_string(port) << " version: [" << version << "] actual: [" << report[string(inet_ntoa(ipAddr))][oldSts][portStsVctrIdx].protocolVersion << "]" << endl;
	exitMonitor(ipAddrStr + ":" + to_string(port));
}

void StatsReporter::displayReport()
{
	cout << endl << "Scan took " << fixed << setprecision(2) << ((endTime - startTime) / 1000.0) << " seconds" << endl;

	for (map<string, map<string, vector<PortStatus>>>::iterator ipItr = report.begin(); \
			ipItr != report.end(); ++ipItr)
	{
		// separator
		cout << endl << "+";
		for (size_t i=0; i < PORT_COL + SVC_COL + RSLT_COL + CON_COL; i++)
			cout << "-";
		cout << "+" << endl;

		// IP
		cout << "|" << " IP address: " << left << setw(PORT_COL+SVC_COL+RSLT_COL+CON_COL - 13)  << ipItr->first << "|" << endl;
		// blank
		cout << "|" << right << setw(PORT_COL+SVC_COL+RSLT_COL+CON_COL + 1) << "|";

		for (map<string, vector<PortStatus>>::iterator stsItr = ipItr->second.begin(); \
				stsItr != ipItr->second.end(); ++stsItr)
		{
			if (stsItr->second.size() > 0)
			{
				// table title
				cout << endl << "| " << left << setw(PORT_COL+SVC_COL+RSLT_COL+CON_COL - 1) << (stsItr->first +  " ports ...") << "|" << endl;
				// table header
				cout << left << setw(PORT_COL) << "| Port ";
				cout << left << setw(SVC_COL) << "| Service Name (if applicable) ";
				cout << left << setw(RSLT_COL) << "| Results ";
				cout << left << setw(CON_COL) << "| Conclusion " << " |";
				// separator
				cout << endl << "+";
				for (size_t i=0; i < PORT_COL + SVC_COL + RSLT_COL + CON_COL; i++)
				{
					if (i == PORT_COL-1 || i == PORT_COL+SVC_COL-1 || i == PORT_COL+SVC_COL+RSLT_COL-1)
						cout << "+";
					else
						cout << "-";
				}
				cout << "+";

				vector<PortStatus> &portStatii = stsItr->second;
				for (size_t i=0; i < portStatii.size(); i++)
				{
					// Port
					cout << endl << left << setw(PORT_COL) << ("| " + to_string(portStatii[i].port) + " ");

					// Service Name
					string v = portStatii[i].protocolVersion.size() > 0 ? " " + portStatii[i].protocolVersion + " ": "";
					string svc = portStatii[i].serviceName.size() + v.size() > SVC_COL - 4 ? portStatii[i].serviceName.substr(0, SVC_COL-4-v.size()) : portStatii[i].serviceName;
					cout << left << setw(SVC_COL) << ("| " + svc + v);

					// Results
					bool printConclusion = true;
					for (map<enum SCAN_TECHNIQUE, enum PORT_STATUS>::iterator scnItr = portStatii[i].scanStatus.begin(); \
							scnItr != portStatii[i].scanStatus.end(); ++scnItr)
					{
						if (!printConclusion)
							cout << endl << left << setw(PORT_COL) << "|" << setw(SVC_COL) << "|";

						cout << left << setw(7) << ("| " + KNOWN_SCANS[scnItr->first]) << right << setw(RSLT_COL-7) << ("(" + PortStatus::getStatusString(scnItr->second) + ") ");
						if (printConclusion)
						{
							// Conclusion
							printConclusion = false;
							cout << left << setw(CON_COL) << ("| " + stsItr->first) << " |";
						}
						else
							cout << "|" << right << setw(CON_COL+1) << "|";	
					}
					// separator
					cout << endl << left << setw(PORT_COL) << "|" << setw(SVC_COL) << "|" << setw(RSLT_COL) << "|" << setw(CON_COL) << "|" << " |";
				}
				// blank
				cout << endl << "|" << right << setw(PORT_COL+SVC_COL+RSLT_COL+CON_COL + 1) << "|";
			}
		}
		// separator
		cout << endl << "+";
		for (size_t i=0; i < PORT_COL + SVC_COL + RSLT_COL + CON_COL; i++)
			cout << "-";
		cout << "+" << endl;
		cout << endl;
	}
	cout << endl << endl;
}
