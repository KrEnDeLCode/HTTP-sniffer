#pragma once
#include <ctime>
#include <vector>
#include "Output.hpp"

class TimeRanger { 
protected:
 time_t timePoint;
 time_t timePeriod;
 size_t tickCount;
public:
 TimeRanger(time_t period);
 void Tick(std::vector<Output> hosts);
};