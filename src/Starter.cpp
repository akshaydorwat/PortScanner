/*
 *	Author : Rohit Khapare
 *	email  : rkhapare@indiana.edu
 *	Date   : 11-4-2014
 */

#include "Starter.hpp"

// user defined header
#include "Logger.hpp"
#include "UniquePortGenerator.hpp"
#include "PortScannerUtils.hpp"
#include "PacketScanner.hpp"
#include "JobPool.hpp"
#include "SYNscan.hpp"
#include "ACKscan.hpp"
#include "NULLscan.hpp"
#include "XMASscan.hpp"
#include "UDPscan.hpp"
#include "FINscan.hpp"
#include "WHOISvScan.hpp"
#include "IMAPvScan.hpp"
#include "SSHvScan.hpp"
#include "HTTPvScan.hpp"
#include "POPvScan.hpp"
#include "SMTPvScan.hpp"

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
		{"log_file", required_argument,   NULL,  'o' },	// --file filename.txt
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
	while ((opt = getopt_long(argc, argv, "v", long_options, &optIdx)) != -1){ 
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

			case 'v':
				numOpts++;
				data->verbose = true;
				break;

			case 'o':
				numOpts++;
				data->log_file = optarg;
				break;

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
		addr.sin_family = AF_INET;
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

	LOG(DEBUG, "====== Port-Scan Techniques ======");
	for (size_t i=0; i < scanTechniques.size(); i++){
		LOG(DEBUG, scanTechniques[i]);
	}
	data->scanTechniques = scanTechniques;

	LOG(DEBUG, "========= Desired speedup ========");
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
void jobCreator(JobPool &pool, InputData &data, struct sockaddr_in &in){

	Scan *s;
	in.sin_family = AF_INET;
	pool.jobPoolSize = data.ports.size();
	for(vector<unsigned short>::iterator j = data.ports.begin(); j != data.ports.end(); ++j)
	{
		unsigned short port = *j;
		switch(port)
		{
			case SSH:
			case SMTP:
			case HTTP:
			case WHOIS: 
			case POP:
			case IMAP:
				pool.jobPoolSize++;
				break;
			default: break;
		}
	}
	pool.jobPoolSize = pool.jobPoolSize * data.ips.size() * data.scanTechniques.size();

	cout << "Scan Jobs         : " << pool.jobPoolSize << endl;
	cout << "Number of workers : " << data.numOfThreads << endl;
	cout << "Scanning          : ---------------------------------------------------------------------------------------------------- 0%";
	cout.flush();

	for(vector<sockaddr_in>::iterator i = data.ips.begin(); i != data.ips.end(); ++i)
	{
		struct sockaddr_in addr = *i;
		for(vector<unsigned short>::iterator j = data.ports.begin(); j != data.ports.end(); ++j)
		{
			unsigned short port = *j;
			addr.sin_port = port;
			string str = "";
			switch(port){
				
			case SSH :
				s = new SSHvScan(in, addr, str);
				pool.queueJob(s);
				break;

			case SMTP :
				s = new SMTPvScan(in, addr, str);
				pool.queueJob(s);
				break;

			case HTTP :
			       s = new HTTPvScan(in, addr, str);
			       pool.queueJob(s);
			       break;

			case WHOIS : 
				s = new WHOISvScan(in, addr, str);
				pool.queueJob(s);
				break;

			case POP :
				s = new POPvScan(in, addr, str);
				pool.queueJob(s);
				break;

			case IMAP :
				s = new IMAPvScan(in, addr, str);
				pool.queueJob(s);
				break;
			}

			for(vector<string>::iterator k = data.scanTechniques.begin(); k != data.scanTechniques.end(); ++k){

				string type = *k;
				if(type.compare("SYN") == 0){
					s = new SYNscan(in, addr, type);

				} else if(type.compare("NULL") == 0){
					s = new NULLscan(in, addr, type);

				} else if(type.compare("FIN") == 0){
					s = new FINscan(in, addr, type);

				} else if(type.compare("XMAS") == 0){
					s = new XMASscan(in, addr, type);

				} else if(type.compare("ACK") == 0){
					s = new ACKscan(in, addr, type);

				} else if(type.compare("UDP") == 0){
					s = new UDPscan(in, addr, type);

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

	Logger *l = Logger::getInstance();
	InputData data;
	ofstream log_file;
	data.verbose = false;

	/* parse command line arguments */
	int ret = parse_args(argc, argv, &data);
	if(!ret){
		exit(EXIT_FAILURE);
	}

	/*Log handlers*/
	if(data.verbose){
		l->addOutputStream(&cout, ERROR, string("%F %T"));
	}else{
		l->addOutputStream(&cout, INFO, string("%F %T"));
	}

	if(data.log_file.size() > 0){
		log_file.open(data.log_file, ios::out | ios::trunc);
		l->addOutputStream(&log_file, ERROR, string("%F %T"));
	}

	/* create stat reporter*/
	StatsReporter &stsRptr = StatsReporter::getStatsReporter();

	/*Packet scanner*/
	PacketScanner &packetScanner = PacketScanner::getPacketScanner();
	pcap_t* pd = packetScanner.init();
	if (pd == NULL){ 
		exit(EXIT_FAILURE);
	}

	pthread_t tid;
	pthread_create(&tid, NULL, PacketScanner::scanForever, (void*)pd);

	/*create Job pool */
	for (size_t i=0; i<100; i++)
		cout << "\n";
	cout << "For detailed logs refer " << data.log_file << endl;	

	JobPool pool(data.numOfThreads);
	pool.init();
	stsRptr.restartStopwatch();
	jobCreator(pool, data, packetScanner.deviceIp);
	pool.delPool(false);
	stsRptr.stopStopwatch();

	/*join the expensive pcap loop thread*/
	pcap_breakloop(pd);
	pthread_join(tid, NULL);
	pcap_close(pd);

	/*Display status*/
	stsRptr.displayReport();

	/*free memory*/
	delete Logger::getInstance();
	delete UniquePortGenerator::getInstance();
}
///////////////////////////////////////////////////////////////////////////////////////////////////
