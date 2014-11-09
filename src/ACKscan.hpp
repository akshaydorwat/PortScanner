/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef ACK_SCAN_HPP
#define ACK_SCAN_HPP

#include "Scan.hpp"

class ACKscan: public Scan{
  
public:
	
	void handle();
	void filterCallback();

private:

    void init();
    void send();
    void reportStats();

};
#endif
