#ifndef UNIQUE_PORT_GENERATOR_HPP
#define UNIQUE_PORT_GENERATOR_HPP

#include <time.h>
#include  <bitset>
#include "Mutex.hpp"
#include "Logger.hpp"

#define MAX_PORT 65535
#define MIN_PORT 4096

using namespace std;

class UniquePortGenerator{

public:
	uint16_t getUnusedPort();
	void freeUsedPort(uint16_t port);
	static UniquePortGenerator* getInstance();
	
private:
	bitset<MAX_PORT> portRange;
	Mutex mLock;
	static UniquePortGenerator *instance;
};


#endif 
