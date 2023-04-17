#pragma once
#include <iostream>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <pcap/pcap.h>

class Output{
private:
    struct sockaddr_in haddr;
    std::string hostname;
    int packet_in, packet_out;
    int traffic_in, traffic_out;

public:
    Output(std::string hostname, in_addr ifaddr, const in_addr srcaddr, const in_addr dstaddr, 
    u_short sport, u_short dport, const struct pcap_pkthdr *pkthdr);
    
    in_addr GetHostaddr();
    std::string GetHostname();
    int GetPacketIn();
    int GetPacketOut();
    int GetTrafficIn();
    int GetTrafficOut();
    void SetPacketIn(int a);
    void SetPacketOut(int a);
    void SetTrafficIn(int a);
    void SetTrafficOut(int a);
    

    void Print();
};