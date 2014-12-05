/**
 * Author    : Akshay Dorwat
 * Date      : 11-09-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "JobPool.hpp"

#include <iostream>
#include <iomanip>

JobPool::JobPool(int size){
	numOfThreads = size;
	state = STOPPED;
	done = false;
	jobPoolSize = 0;
	completedJobs = 0;
	lastPercentCompleted = 0.0;
}

JobPool::~JobPool(){
	if (state != STOPPED) {
		delPool(true);
	}
}
	
bool JobPool::init(){

	int ret;
	// error check
	if(numOfThreads <= 0){
		LOG(ERROR, "Invalid pool size : " + to_string(numOfThreads));
		return false;
	}
	
	// start threads
	for(int i=0 ; i < numOfThreads; i++){
		pthread_t id;
		// create thread
		ret = pthread_create(&id, NULL, JobPool::helper, (void*) this);
		if (ret != 0) {
			LOG(ERROR, "Error while creating thread ");
			return false;
		}
		// push threads in vector
		threads.push_back(id);
	}
	
	//change the state
	state = STARTED;
	LOG(DEBUG, "Created thread pool with size : " + to_string(numOfThreads));
	
	return true;
}

void JobPool::queueJob(Scan *s){

	//Acquire lock
	mutex.lock();

	// queue the task
	pool.push_back(s);

	// signal the thread
	condVar.signal();

	// release lock
	mutex.unlock();

	//LOG(DEBUG, "Job added sucessfully, Total jobs : " + to_string((int)pool.size()));
}

bool JobPool::delPool(bool forceful){
	// acquire lock
	mutex.lock();
	// change state
	if(forceful){
		state = STOPPED;
	}else{
		done = true;
	}
	// release lock
	mutex.unlock();

	// wakeup all the threads
	condVar.broadcast();

	joinAll();
	LOG(DEBUG, "Thread pool deleted successfully.");
	return true;
}
	
void JobPool::joinAll(){
	int i, ret;
	for(i=0; i< numOfThreads; i++ ){
		ret = pthread_join(threads[i], NULL);
		if(ret != 0){
			LOG(ERROR, "Error while joining the thread.");
		}
	}
}

void JobPool::run(){
	
	Scan *s;
   
	while(true){
		
		// Check the pool status if empty wait 
		mutex.lock();
		while(pool.empty()){
			if(done){
				state = STOPPED;
				break;
			}else{
				condVar.wait(mutex);
			}
		}

		// Stop thread if state changed
		if(state == STOPPED){
			mutex.unlock();
			pthread_exit(NULL);
		}

		// retrieve job from the pool
		s = pool.front();
		pool.pop_front();
		
		completedJobs++;
		double percentCompleted = (100.0 * completedJobs) / jobPoolSize;	
		cout << "\rScanning          : ";
		for (double i=0.0; 100.0 - i > 0.001; i+=1.0)
		{
			if (percentCompleted - i > 0.001)
				cout << "#";
			else
				cout << "-";
		}
		
		cout << " " << fixed << setprecision(2) << percentCompleted << "%";
		cout.flush();

		mutex.unlock();
	
		// call actual function
		s->handle();	

		//grabage collection 
		delete s;
	}
}

void* JobPool::helper(void *arg){

	JobPool *j = (JobPool*) arg;
	j->run();
	return NULL;
}
