#ifndef STARTER_HPP
#define STARTER_HPP

//c++ header
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

//c header
#include <inttypes.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

// user defined header
#include "Logger.hpp"
#include "PortScannerUtils.hpp"
#include "PacketScanner.hpp"
#include "JobPool.hpp"
#include "SYNscan.hpp"
#include "ACKscan.hpp"
#include "NULLscan.hpp"
#include "XMASscan.hpp"
#include "UDPscan.hpp"
#include "FINscan.hpp"

#define DEFAULT_NUM_OF_THREAD 1

using namespace std;

//////////////////////////////////////////////////////////////////////////////////

// Log file location
const string LOGFILE = "LOG.log";

// Known scan techniques
const vector<string> KNOWN_SCANS = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP"};

// portscanner input data holder 
struct InputData{
	vector<string> scanTechniques;
	vector<unsigned short> ports;
	vector<sockaddr_in> ips;
	int numOfThreads;
};
#endif
