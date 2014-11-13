/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef UDP_SCAN_HPP
#define UDP_SCAN_HPP

#include "Scan.hpp"
#include "unistd.h"

using namespace std;

class UDPscan: public Scan{
  
public:
	UDPscan( struct sockaddr_in &p_src, struct sockaddr_in &p_dst, string &type ) 
		: Scan(p_src, p_dst, type){
		factory = new PacketFactory(DNS, buff);
	};

	void handle();
	void filterCallback(const u_char *ptr);

private:

    void init();
    void send();
    void createPacket();
};
#endif
