/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef UDP_SCAN_HPP
#define UDP_SCAN_HPP

#include "Scan.hpp"

class UDPscan: public Scan{
  
  public:
	
	void handle();
	void filterCallback();

private:

    void init();
    void send();
    void reportStats();
};
#endif
