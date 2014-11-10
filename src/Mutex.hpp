/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef MUTE_HPP
#define MUTE_HPP

#include <pthread.h>

class Mutex{
	
public:
	Mutex();
	~Mutex();
	
	void lock();
	void unlock();
	pthread_mutex_t* getPtr();

private:
	bool locked;
	pthread_mutex_t mLock;
};

#endif
