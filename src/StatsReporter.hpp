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

// c lib
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "PortStatus.hpp"
#include "Starter.hpp"

using namespace std;

class StatsReporter
{
	private:
		static StatsReporter *stsRptr;
		map<string, map<string, vector<PortStatus>>> report;

		StatsReporter(){};							// private constructor
		StatsReporter(StatsReporter const&){};                			// private copy constructor
		StatsReporter& operator=(StatsReporter const&){ return *stsRptr; };	// private assignment operator

		size_t getPortStatus(struct in_addr ipAddr, uint16_t port, string &oldSts);

	public:
		static StatsReporter* getStatsReporter()       // obtain the singleton instance
		{
			if (!stsRptr)
				stsRptr = new StatsReporter();

			return stsRptr;
		}

		void displayReport();
		void updatePortStatus(struct in_addr ipAddr, uint16_t port, enum SCAN_TECHNIQUE scanType, enum PORT_STATUS portSts);
		void updateServiceStatus(struct in_addr ipAddr, uint16_t port, string svc, string version);
};

#endif
