/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef NULL_SCAN_HPP
#define NULL_SCAN_HPP

#include "Scan.hpp"

using namespace std;

class NULLscan: public Scan{
  
public:
	NULLscan( struct sockaddr_in &p_src, struct sockaddr_in &p_dst, string &type ) 
		: Scan(p_src, p_dst, type){};

	void handle();
	void filterCallback(const u_char *ptr);

private:

    void init();
    void send();
    void reportStats();
	void createPacket();
	
};
#endif
