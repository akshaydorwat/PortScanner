/**
 * Author    : Akshay Dorwat
 * Date      : 11-09-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef CONDITION_VARIABLE_HPP
#define CONDITION_VARIABLE_HPP

#include <pthread.h>
#include "Mutex.hpp"

class ConditionVariable{

public:
	ConditionVariable();
	
	~ConditionVariable();
	
	void wait(Mutex &m);
	
	void signal();

	void broadcast();

private:
	pthread_cond_t condVar;
};
#endif
