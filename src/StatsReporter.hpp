/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 *
 * Co-author : Rohit Khapare
 * Date	     : 11-10-2014
 * Email     : rkhapare@indiana.edu
 **/

#ifndef STATSREPORTER_HPP
#define STATSREPORTER_HPP

#include <string>
#include <map>
#include <chrono>

#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <time.h>

#include "PortStatus.hpp"
#include "Starter.hpp"
#include "Mutex.hpp"

using namespace std;

#define PORT_COL 7
#define SVC_COL 50
#define RSLT_COL 25
#define CON_COL 15

class StatsReporter
{
	private:
		static StatsReporter *stsRptr;						// singleton instance of StatsReporter

		size_t startTime;
		size_t endTime;
		Mutex ipPortMtx;
		vector<string> ipPortMtxVctr;
		map<string, map<string, vector<PortStatus>>> report;

		StatsReporter(){};							// private constructor
		StatsReporter(StatsReporter const&){};                			// private copy constructor
		StatsReporter& operator=(StatsReporter const&){ return *stsRptr; };	// private assignment operator

		void enterMonitor(string ipPort);
		void exitMonitor(string ipPort);
		size_t getPortStatus(struct in_addr ipAddr, uint16_t port, string &oldSts);

	public:
		static StatsReporter* getStatsReporter()       // obtain the singleton instance
		{
			if (!stsRptr)
			{
				stsRptr = new StatsReporter();
				stsRptr->startTime = chrono::duration_cast<std::chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count();
			}

			return stsRptr;
		}

		void restartStopwatch()	{ startTime = chrono::duration_cast<std::chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count(); }
		void stopStopwatch() { endTime = chrono::duration_cast<std::chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count(); }
		void displayReport();
		void updatePortStatus(struct in_addr ipAddr, uint16_t port, enum SCAN_TECHNIQUE scanType, enum PORT_STATUS portSts);
		void updateServiceStatus(struct in_addr ipAddr, uint16_t port, string svc, string version);
};

#endif
