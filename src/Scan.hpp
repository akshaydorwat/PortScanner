#ifndef SCAN_HPP
#definde SCAN_HPP

class Scan
{

 public:
  virtual ~Scan();

  // make interface with a pure virtual method
  virtual void init() = 0;
  virtual void send() = 0;
  virtual void handle() = 0;
  virtual void filterCallback() = 0;   
};


#endif
