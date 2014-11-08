/*
 *	Author : Rohit Khapare
 *	email  : rkhapare@indiana.edu
 *	Date   : 11-4-2014
 */

#include "Logger.hpp"
#include "PortScannerUtils.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <inttypes.h>
#include <getopt.h>

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
const string LOGFILE = "LOG.log";
const vector<string> KNOWN_SCANS = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP"};

///////////////////////////////////////////////////////////////////////////////////////////////////
void show_help()
{
	string help = "\n portScanner: Port-scan utility. \n"
    			"--help    This help\n"
    			"--ports   Comma delimited list of ports; specify range with - eg. 1,2,3-5\n"
			"--ip 	   IP address eg. 127.0.0.1\n"
			"--prefix  IP address-range specified with subnet prefix eg. 127.0.0.1/30\n"
			"--file    File containing newline delimited list of IP addresses\n"
			"--speedup Number of concurrent threads eg. 10\n"
			"--scan    Space delimited port-scan methods eg. SYN NULL FIN XMAS";
  	cout << help << endl;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
vector<unsigned int> extractPorts(string portStr)
{
	size_t commaIdx, dashIdx;
	vector<unsigned int> ports;
	portStr = portStr + ",";
	while((commaIdx = portStr.find(',')) != string::npos)
	{
		int startNum = -1;
		int endNum = -1;
		if ((dashIdx = portStr.find('-')) != string::npos && dashIdx < commaIdx)
		{	
			startNum = atoi(portStr.substr(0, dashIdx).c_str());
			endNum = atoi(portStr.substr(dashIdx +1, commaIdx).c_str());
		}
		else 
		{
			startNum = atoi(portStr.substr(0, commaIdx).c_str());
		}

		for (int i=startNum; i <= (startNum > endNum ? startNum : endNum); i++)
			ports.push_back((unsigned int) i);

		if (commaIdx +1 == portStr.size()) break;
		else portStr= portStr.substr(commaIdx +1);
	}
	return ports;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool parse_args(int argc, char **argv)
{
	static struct option long_options[] = {
		{"help",     no_argument,         NULL,  'h' },	// --help
		{"ports",    required_argument,   NULL,  'p' },	// --ports 1,2,3-5
		{"ip",       required_argument,   NULL,  'i' },	// --ip 127.0.0.1
		{"prefix",   required_argument,   NULL,  'r' },	// --prefix 127.143.151.123/24
		{"file",     required_argument,   NULL,  'f' },	// --file filename.txt
		{"speedup",  required_argument,   NULL,  's' },	// --speedup 10
		{"scan",     required_argument,   NULL,  'c' },	// --scan SYN NULL FIN XMAS
		{NULL,          0,                NULL,   0 }
	};

	unsigned int numOpts = 0;
	int opt, optIdx;
	unsigned int numOfThreads = 1;
	vector<string> scanTechniques;
	vector<unsigned int> ports;
	vector<string> ips;
	vector<string> ipsFromPrefix;
	string temp;
	ifstream file;

	// accepting nothing but long options by specifying optstring = ""
	while ((opt = getopt_long(argc, argv, "", long_options, &optIdx)) != -1) 
	{
		switch (opt)
		{
			case 'h': // help
				numOpts++;
				show_help();
				break;

			case 'p': // ports
				numOpts++;
				ports = extractPorts(optarg);	
				break;

			case 'i': // ip
				numOpts++;
				if (PortScannerUtils::isValidIp(optarg))
					ips.push_back(optarg);
				break;

			case 'r': // prefix
				numOpts++;
				ipsFromPrefix = PortScannerUtils::getIpsFromPrefix(optarg);
				for (size_t i=0; i < ipsFromPrefix.size(); i++)
					ips.push_back(ipsFromPrefix[i]);
				ipsFromPrefix.clear();
				break;

			case 'f': // file
				numOpts++;
				file.open(optarg);
				if (!file.is_open())
				{
					cout << endl << "portScanner : Failed to open file " << optarg << endl;
					break;
				}
				while(file >> temp)
				{
					ipsFromPrefix = PortScannerUtils::getIpsFromPrefix(temp);
					for (size_t i=0; i < ipsFromPrefix.size(); i++)
						ips.push_back(ipsFromPrefix[i]);
					ipsFromPrefix.clear();
				}
				file.close();
				break;

			case 's': // speedup
				numOpts++;
				numOfThreads = atoi(optarg);
				break;

			case 'c': // scan	
				numOpts++;
				scanTechniques.push_back(optarg);
				break;

			/*case '?': // unsupported option
			default:
				break;*/
		}
	}
	if (ips.size() == 0)
	{
		cout << endl << "portScanner : Kindly enter some target host(s) and try again." << endl;
		return false;
	}

	if (optind < argc) 
	{
    		while (optind < argc)
		{
      			for (size_t i=0; i < KNOWN_SCANS.size(); i++)
				if (KNOWN_SCANS[i].compare(string(argv[optind])) == 0)
					scanTechniques.push_back(KNOWN_SCANS[i]);
			optind++;
		}
  	}
	cout << endl;	

	cout << endl << endl << "========== Target hosts ==========" << endl;
	for (size_t i=0; i<ips.size(); i++)
		cout << endl << ips[i];

	cout << endl << endl << "========== Target ports ==========" << endl;
	if (ports.size() == 0)
	{
		cout << endl << "1-1024 (default)";
		for (size_t i=1; i<=1024; i++)
			ports.push_back(i);
	}
	else
	{		
		for (size_t i=0; i < ports.size(); i++)
			cout << endl << ports[i];
	}

	cout << endl << endl << "========== Port-Scan Techniques ==========" << endl;
	for (size_t i=0; i < scanTechniques.size(); i++)
		cout << endl << scanTechniques[i];

	if (numOfThreads > 1)
		cout << endl << endl << "========== Desired speedup ==========" << endl << endl << numOfThreads << endl;

	return numOpts > 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
int main (int argc, char **argv)
{
	/* Initialize Logger */
	ofstream log_file (LOGFILE, ios::out | ios::trunc);
	Logger *l = Logger::getInstance();

	l->addOutputStream(&cout, INFO, string("%F %T"));
	l->addOutputStream(&log_file, ERROR, string("%F %T"));

	/* parse command line arguments */
	int ret = parse_args(argc, argv);
	if(!ret) exit(EXIT_FAILURE);
}
///////////////////////////////////////////////////////////////////////////////////////////////////
