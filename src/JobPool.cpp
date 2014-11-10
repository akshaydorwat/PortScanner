/**
 * Author    : Akshay Dorwat
 * Date      : 11-09-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "JobPool.hpp"


JobPool::JobPool(int size){
	numOfThreads = size;
	state = STOPPED;
		
	// little performance improvment measure
	pool.resize(DEFAULT_DEQUE_SIZE);
}

JobPool::~JobPool(){
	
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
	LOG(INFO, "Created thread pool with size : " + to_string(numOfThreads));
	
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

	LOG(DEBUG, "Job added sucessfully, Total jobs : " + to_string((int)pool.size()));
}

bool JobPool::delpool(){
	
	int ret;
	int i;

	// acquire lock
	mutex.lock();
	// change state
	state = STOPPED;
	// release lock
	mutex.unlock();

	// wakeup all the threads
	condVar.broadcast();

	for(i=0; i< numOfThreads; i++ ){
		ret = pthread_join(threads[i], NULL);
		if(ret != 0){
			LOG(ERROR, "Error while joining the thread");
		}
	}
	LOG(DEBUG, "Thread pool deleted sccucessfully");
	return true;
}
	

void JobPool::run(){
	
	Scan *s;

	while(true){
		mutex.lock();
		while((state != STOPPED) && (pool.empty())){
			// TODO: It might cause error passing private variable to another class
			LOG(DEBUG, "Thread waiting");
			condVar.wait(mutex);
			LOG(DEBUG, "Thread recieved signal");
		}

		// Stop thread if state changed
		if(state == STOPPED){
			mutex.unlock();
			pthread_exit(NULL);
		}

		// retrieve job from the pool
		s = pool.front();
		pool.pop_front();
		mutex.unlock();
		
		// call actual function
		s->handle();

		//grabage collection 
		delete s;
	}
}

void* JobPool::helper(void *arg){
	return NULL;
}
