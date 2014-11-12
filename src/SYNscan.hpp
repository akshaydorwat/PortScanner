/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef SYN_SCAN_HPP
#define SYN_SCAN_HPP

#include "Scan.hpp"

using namespace std;

class SYNscan : public Scan {
	
public:
	SYNscan( struct sockaddr_in &p_src, struct sockaddr_in &p_dst, string &type ) 
		: Scan(p_src, p_dst, type){
		factory = new PacketFactory(TCP, buff);
	};
	
	void handle();
	void filterCallback(const u_char *ptr);

private:

    void init();
    void send();
	void createPacket();
};

#endif
