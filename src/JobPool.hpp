/**
 * Author    : Akshay Dorwat
 * Date      : 11-09-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#ifndef JOB_POOL_HPP
#define JOB_POOL_HPP

#include <queue>
#include "Mutex.hpp"
#include "ConditionVariable.hpp"
#include "Scan.hpp"
#include "Logger.hpp"

#define DEFAULT_DEQUE_SIZE 1024

using namespace std;

enum POOL_STATE{
	STARTED,
	STOPPED
};

class JobPool{
public:
	JobPool(int size);
	~JobPool();
	
	bool init();
	void queueJob(Scan *s);
	bool delPool(bool forceful);
	void joinAll();
	
private:
	enum POOL_STATE state;
	int numOfThreads;
	vector<pthread_t> threads;
	deque<Scan*> pool;
	Mutex mutex;
	ConditionVariable condVar;
	bool done;

	void run();
	static void* helper(void *arg);

};

#endif
