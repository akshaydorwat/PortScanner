/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef UDP_SCAN_HPP
#define UDP_SCAN_HPP

#include "Scan.hpp"

using namespace std;

class UDPscan: public Scan{
  
public:
	UDPscan( struct sockaddr_in &p_src, struct sockaddr_in &p_dst, string &type ) 
		: Scan(p_src, p_dst, type){};

	void handle();
	void filterCallback();

private:

    void init();
    void send();
    void reportStats();
};
#endif
