/*==============================
   Author : Akshay Dorwat
   Email ID: adorwat@indiana.edu
   created on: 09/22/2014
=================================*/

#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <list>
#include <string>
#include <iostream>
#include <fstream>
#include <mutex>
#include <iostream>

#define FLAG 0


#define LOG(INFO , MESSAGE)			\
  Logger::getInstance()->log(INFO, MESSAGE)

using namespace std;

/*
 * This is a naive implementation of logger functionality. It has lot of impovement scope.
 *
*/

enum LOG_LEVEL{
  INFO,
  WARNING,
  DEBUG,
  ERROR
};

class Logger{

public:
  ~Logger(){
    for (list<Logger::BaseLogger>::iterator it=streamLoggers.begin(); it != streamLoggers.end(); ++it){
      Logger::BaseLogger b = (Logger::BaseLogger) *it;
      ofstream *stream = dynamic_cast<ofstream*>(b.stream);
      if(stream != NULL){
	stream->close();
      }
    }
  }
  
  bool addOutputStream(ostream *s, enum LOG_LEVEL level, string time_format);
  void log(enum LOG_LEVEL level, string str);
  static Logger* getInstance();

private:

  class BaseLogger{
  public:
    ostream *stream;
    enum LOG_LEVEL level;
    string timeFormat;
    
    BaseLogger(ostream *s, enum LOG_LEVEL l, string format){
      stream = s;
      level = l;
      timeFormat = format;
    }
  };

  mutex m_lock;
  static Logger* logger;
  list<BaseLogger> streamLoggers;

  string getTimeStamp(const char *timeFormat );
  void printLog(enum LOG_LEVEL &level, string &str);
  void printErr(enum LOG_LEVEL &level, string &str);

};

#endif


