/*
 *	Author : Rohit Khapare
 *	email  : rkhapare@indiana.edu
 *	Date   : 11-4-2014
 */

#include "Starter.hpp"

using namespace std;


///////////////////////////////////////////////////////////////////////////////////////////////////
void show_help()
{
	string help = "\n portScanner: Port-scan utility. \n"
		"--help    This help\n"
		"--ports   Comma delimited list of ports; specify range with - eg. 1,2,3-5\n"
		"--ip 	   IP address eg. 127.0.0.1\n"
		"--prefix  IP address-range specified with subnet prefix eg. 127.0.0.1/24\n"
		"--file    File containing newline delimited list of IP addresses\n"
		"--speedup Number of concurrent threads eg. 10\n"
		"--scan    Space delimited port-scan methods SYN NULL FIN XMAS UDP ACK\n";
}

///////////////////////////////////////////////////////////////////////////////////////////////////
vector<unsigned short> extractPorts(string portStr)
{
	size_t commaIdx, dashIdx;
	vector<unsigned short> ports;
	portStr = portStr + ",";
	while((commaIdx = portStr.find(',')) != string::npos){
		int startNum = -1;
		int endNum = -1;
		if ((dashIdx = portStr.find('-')) != string::npos && dashIdx < commaIdx){	
			startNum = atoi(portStr.substr(0, dashIdx).c_str());
			endNum = atoi(portStr.substr(dashIdx +1, commaIdx).c_str());
		}else {
			startNum = atoi(portStr.substr(0, commaIdx).c_str());
		}

		for (int i=startNum; i <= (startNum > endNum ? startNum : endNum); i++)
			ports.push_back((unsigned short) i);

		if (commaIdx +1 == portStr.size()) 
			break;
		else 
			portStr= portStr.substr(commaIdx +1);
	}
	return ports;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool parse_args(int argc, char **argv, struct InputData *data)
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
	vector<unsigned short> ports;
	vector<string> ips;
	vector<string> ipsFromPrefix;
	string temp;
	ifstream file;

	// accepting nothing but long options by specifying optstring = ""
	while ((opt = getopt_long(argc, argv, "", long_options, &optIdx)) != -1){ 
		switch (opt){
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
			if (!file.is_open()){
				LOG(ERROR, "portScanner : Failed to open file " + string(optarg) );
				break;
			}
			while(file >> temp){
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

	if (ips.size() == 0){
		LOG(ERROR, "portScanner : Kindly enter some target host(s) and try again.");
		return false;
	}

	if (optind < argc){
		while (optind < argc){
			for (size_t i=0; i < KNOWN_SCANS.size(); i++)
				if (KNOWN_SCANS[i].compare(string(argv[optind])) == 0)
					scanTechniques.push_back(KNOWN_SCANS[i]);
			optind++;
		}
	}

	
	LOG(DEBUG, "========== Target hosts ==========");
	for (size_t i=0; i<ips.size(); i++){
		LOG(DEBUG, ips[i]);
		struct sockaddr_in addr;
		addr.sin_addr.s_addr = inet_addr(ips[i].c_str());
		data->ips.push_back(addr);
	}
	
	LOG(DEBUG, "========== Target ports ==========");
	if (ports.size() == 0){
		LOG(DEBUG, "1-1024 (default)");
		for (size_t i=1; i<=1024; i++)
			ports.push_back(i);
	}else{		
		for (size_t i=0; i < ports.size(); i++)
			LOG(DEBUG, to_string(ports[i]));
	}
	data->ports = ports;
	
	LOG(DEBUG, "========== Port-Scan Techniques ==========");
	for (size_t i=0; i < scanTechniques.size(); i++){
		LOG(DEBUG, scanTechniques[i]);
	}
	data->scanTechniques = scanTechniques;

	LOG(DEBUG, "========== Desired speedup ==========");
	if (numOfThreads > 1){	
		LOG(DEBUG, to_string( numOfThreads));
		data->numOfThreads = numOfThreads;
	}else{
		LOG (DEBUG, to_string(DEFAULT_NUM_OF_THREAD) + " (default)");
		data->numOfThreads = DEFAULT_NUM_OF_THREAD;
	}
	return numOpts > 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
void jobCreator(JobPool &pool, InputData &data){
	
	for(vector<sockaddr_in>::iterator i = data.ips.begin(); i != data.ips.end(); ++i){
		sockaddr_in addr = *i;

		for(vector<unsigned short>::iterator j = data.ports.begin(); j != data.ports.end(); ++j){
			unsigned short port = *j;
			
			for(vector<string>::iterator k = data.scanTechniques.begin(); k != data.scanTechniques.end(); ++k){
				string type = *k;
				Scan *s;
				
				if(type.compare("SYN") == 0){
					//s = new SYNscan();

				} else if(type.compare("NULL") == 0){
					//s = new NULLscan();
					
				} else if(type.compare("FIN") == 0){
					//s = new FINscan();
					
				} else if(type.compare("XMAS") == 0){
					//s = new XMASscan();
					
				} else if(type.compare("ACK") == 0){
					//s = new ACKscan();
					
				} else if(type.compare("UDP") == 0){
					//s = new UDPscan();

				} else {
					LOG(ERROR, "Scan type " + type + " not found");
					continue;
				}
								
				pool.queueJob(s);
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
int main (int argc, char **argv)
{
	/* Initialize Logger */
	ofstream log_file (LOGFILE, ios::out | ios::trunc);
	Logger *l = Logger::getInstance();
	InputData data;

	/*Log handlers*/
	l->addOutputStream(&cout, ERROR, string("%F %T"));
	l->addOutputStream(&log_file, ERROR, string("%F %T"));

	/* parse command line arguments */
	int ret = parse_args(argc, argv, &data);
	if(!ret){
		exit(EXIT_FAILURE);
	}

	/*Packet scanner*/
	PacketScanner* packetScanner = PacketScanner::getPacketScanner();
	pcap_t* pd = packetScanner->init();
	if (pd == NULL){ 
		exit(EXIT_FAILURE);
	}

	/*create Job pool */
	JobPool pool(data.numOfThreads);
	jobCreator(pool, data);
	//pool.init();
	//pool.delpool();
	
}
///////////////////////////////////////////////////////////////////////////////////////////////////
