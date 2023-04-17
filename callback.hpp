#pragma once
#include <iostream>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <pcap/pcap.h>
#include "Timer.hpp"
#include "Output.hpp"

void my_callback(u_char *args, const struct pcap_pkthdr * pkthdr, const u_char * packet);