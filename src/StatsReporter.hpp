/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef STATS_REPORTER_HPP
#define STATS_REPORTER_HPP

// c++ lib
#include <string>
#include <map>

// c lib
#include <netinet/in.h>

// user lib
#include "Stat.hpp"

using namespace std;

class StatsRporter{
public:
	map<string, Stat> report;
};

#endif
