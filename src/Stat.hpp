#ifndef STAT_HPP
#define STAT_HPP

#include <string>
#include <map>

using namespace std;

enum PORT_STATUS{
	OPEN,
	CLOSED,
	FILTERED,
	UNFILTERED,
	OPEN_FILTERED
};

class Stat{
	
public:
	uint16_t port;
	map<string, enum PORT_STATUS> results;
	string serviceName;
	string protocolVersion;
	enum PORT_STATUS conclusion;

 	// helper function to convert port status t
	static string portStatusToString(enum PORT_STATUS);
};

#endif
