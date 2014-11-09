/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include <pthread.h>

class Mutex{
	
public:
	Mutex();
	~Mutex();
	
	void lock();
	void unlock();

private:
	bool locked;
	pthread_mutex_t mLock;
};
