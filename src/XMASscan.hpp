/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/


#ifndef XMAS_SCAN_HPP
#define XMAS_SCAN_HPP

#include "Scan.hpp"

class XMASscan: public Scan{
  
  public:
	
	void handle();
	void filterCallback();

private:

    void init();
    void send();
    void reportStats();
};
#endif
