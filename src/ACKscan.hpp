/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef ACK_SCAN_HPP
#define ACK_SCAN_HPP

#include "Scan.hpp"

using namespace std;

class ACKscan: public Scan{
  
public:
	ACKscan( struct sockaddr_in &p_src, struct sockaddr_in &p_dst, string &type ) 
		: Scan(p_src, p_dst, type){
		factory = new PacketFactory(TCP, buff);
	};

	void handle();
	void filterCallback(const u_char *ptr);

private:

    bool init();
    bool send();
    void createPacket();

};
#endif
