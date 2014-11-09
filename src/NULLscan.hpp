/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef NULL_SCAN_HPP
#define NULL_SCAN_HPP

#include "Scan.hpp"

class NULLscan: public Scan{
  
public:
	
	void handle();
	void filterCallback();

private:

    void init();
    void send();
    void reportStats();
  
};
#endif
