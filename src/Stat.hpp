#ifndef STAT_HPP
#define STAT_HPP

#include <string>

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
	map<string,enum PORT_STATUS> results;
	string serviceName;
	string protocolVersion;
	enum PORT_STATUS conclusion;
};

#endif
