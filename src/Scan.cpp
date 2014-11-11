#include "Scan.hpp"

void Scan::toString(){
		LOG(DEBUG, \
			"\n\t\t\tSource IP and Port      : " + string(inet_ntoa(src.sin_addr)) + " : " + to_string((int)src.sin_port) + "\n" \
			"\t\t\tDestination IP and Port : " + string(inet_ntoa(dst.sin_addr)) + " : " +  to_string((int)dst.sin_port) + "\n" \
			"\t\t\tScan Type               : " + scanType);
}

 
