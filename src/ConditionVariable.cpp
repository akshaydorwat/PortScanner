/**
 * Author    : Akshay Dorwat
 * Date      : 11-09-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "ConditionVariable.hpp"

ConditionVariable::ConditionVariable(){
	pthread_cond_init(&condVar, NULL);
}
	
ConditionVariable::~ConditionVariable(){
	pthread_cond_destroy(&condVar);
}
	
void ConditionVariable::wait(Mutex m){
	pthread_cond_wait(&condVar, m.getPtr());
}
	
void ConditionVariable::signal(){
	pthread_cond_signal(&condVar); 
}

void ConditionVariable::broadcast(){
	pthread_cond_broadcast(&condVar);
}
