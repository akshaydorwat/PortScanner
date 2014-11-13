#include "UniquePortGenerator.hpp"

// static variable init 
UniquePortGenerator *UniquePortGenerator::instance = NULL;

// get instance 
UniquePortGenerator* UniquePortGenerator::getInstance(){
	if(instance == NULL){
		instance = new UniquePortGenerator();
	}
	return instance;
}

// get unused port 
uint16_t UniquePortGenerator::getUnusedPort(){
	
	int random;
	srand (time(NULL));
	random = rand() % ( MIN_PORT + (MAX_PORT - MIN_PORT));
	mLock.lock();
	while(portRange[random]){
		random++;
		if (random > MAX_PORT){
			random = MIN_PORT;
		}
	}
	portRange[random] = 1;
	mLock.unlock();
	return (uint16_t)random;
}

//free used port
void UniquePortGenerator::freeUsedPort(uint16_t port){
	mLock.lock();
	portRange[(int)port] = 0;
	mLock.unlock();
}
