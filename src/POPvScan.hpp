/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef POP_V_SCAN_HPP
#define POP_V_SCAN_HPP

#include "Scan.hpp"
#include <sys/time.h>

using namespace std;

class POPvScan : public Scan {
	
public:
	POPvScan( struct sockaddr_in &p_src, struct sockaddr_in &p_dst, string &type ) 
		: Scan(p_src, p_dst, type){
		debugInfo = debugInfo + " POP ";
	};
	
	void handle();
	void filterCallback(const u_char *ptr);

private:

    bool init();
    bool send();
	void createPacket();
	string getVersion(const char * buff, int &size);
	
};

#endif
