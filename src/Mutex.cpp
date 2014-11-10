/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "Mutex.hpp"

Mutex::Mutex(){
	pthread_mutex_init(&mLock, NULL);
    locked = false;
}

Mutex::~Mutex(){
	if(locked){
		unlock();
	}
	pthread_mutex_destroy(&mLock);
}

void Mutex::lock(){
	
    pthread_mutex_lock(&mLock);
    locked = true;
}

void Mutex::unlock(){
    
	pthread_mutex_unlock(&mLock);
    locked = false;
}

pthread_mutex_t * Mutex::getPtr(){
	return &mLock;
}
