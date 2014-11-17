/**
 * Author    : Akshay Dorwat
 * Date      : 11-09-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "JobPool.hpp"
#include "iostream"

JobPool::JobPool(int size){
	numOfThreads = size;
	state = STOPPED;
	done = false;
	jobPoolSize = 0;
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
	
	int ret;
	int i;

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

	for(i=0; i< numOfThreads; i++ ){
		ret = pthread_join(threads[i], NULL);
		if(ret != 0){
			LOG(ERROR, "Error while joining the thread");
		}
	}
	LOG(DEBUG, "Thread pool deleted sccucessfully");
	return true;
}
	
void JobPool::joinAll(){
	int i, ret;
	for(i=0; i< numOfThreads; i++ ){
		ret = pthread_join(threads[i], NULL);
		if(ret != 0){
			LOG(ERROR, "Error while joining the thread");
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
		size_t remainingPoolSize = pool.size();
		double percentCompleted = 100.0 * (jobPoolSize - remainingPoolSize) / (jobPoolSize);
		if (percentCompleted - lastPercentCompleted >= 1.0)
		{
			lastPercentCompleted += 1.0;
			cout << "#";
		}
		/*if (lastPercentCompleted - 100.0 < 0.1)
			cout << endl;*/
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
