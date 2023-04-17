#include <iostream>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <pcap/pcap.h>
#include "Output.h"

class TimeRanger { 
protected:
 time_t timePoint;
 time_t timePeriod;
 size_t tickCount;
public:
 TimeRanger(time_t period);
 void Tick(std::vector<Output> hosts);
};

TimeRanger::TimeRanger (time_t period) : timePoint(time(NULL)), timePeriod(period), tickCount(0) { }

void TimeRanger::Tick(std::vector<Output> hosts) {
 time_t now = time(NULL);
 if ((now - timePoint) >= timePeriod) {
  for(int i = 0; i < hosts.size(); i++){
        hosts[i].Print();
    }
    for(int i = 0; i < hosts.size(); i++){
        std::cout << "\33[A\33[2K";
    }
  timePoint = now;
 }
}