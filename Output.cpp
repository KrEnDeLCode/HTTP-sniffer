#include <iostream>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <pcap/pcap.h>
#include "Output.hpp"


    Output::Output(std::string hostname, in_addr ifaddr, const in_addr srcaddr, const in_addr dstaddr, 
    u_short sport, u_short dport, const struct pcap_pkthdr *pkthdr){
        if (dstaddr.s_addr == ifaddr.s_addr){ // is incoming packet?
            this->haddr.sin_addr = srcaddr;
            this->haddr.sin_port = sport;
            this->hostname = hostname;
            this->packet_in = 1;
            this->packet_out = 0;
            this->traffic_in = pkthdr->len;
            this->traffic_out = 0;
        }
        else{
            this->haddr.sin_addr = dstaddr;
            this->haddr.sin_port = dport;
            this->hostname = hostname;
            this->packet_in = 0;
            this->packet_out = 1;
            this->traffic_in = 0;
            this->traffic_out = pkthdr->len;
            
        }
    }
    
    in_addr Output::GetHostaddr(){return this->haddr.sin_addr;}
    std::string Output::GetHostname(){return this->hostname;}
    int Output::GetPacketIn(){return this->packet_in;}
    int Output::GetPacketOut(){return this->packet_out;}
    int Output::GetTrafficIn(){return this->traffic_in;}
    int Output::GetTrafficOut(){return this->traffic_out;}
    void Output::SetPacketIn(int a){this->packet_in += a;}
    void Output::SetPacketOut(int a){this->packet_out += a;}
    void Output::SetTrafficIn(int a){this->traffic_in += a;}
    void Output::SetTrafficOut(int a){this->traffic_out += a;}
    

    void Output::Print(){
        //std::cout << inet_ntoa(haddr.sin_addr) <<"\t"
        std::cout << hostname <<"\t\t\t"
        << packet_in + packet_out << " packets (" << packet_in << " IN / " << packet_out << " OUT)\t"
        <<"Traffic: ";
        if((traffic_in + traffic_out)/(1024*1024*1024)){std::cout << (traffic_in + traffic_out)/(1024*1024*1024) << "GB";}
        else if((traffic_in + traffic_out)/(1024*1024)){std::cout << (traffic_in + traffic_out)/(1024*1024) << "MB";}
        else if((traffic_in + traffic_out)/1024){std::cout << (traffic_in + traffic_out)/1024 << "KB";}
        else{std::cout << traffic_in + traffic_out << "B";} 
        std::cout << " (";
        if((traffic_in)/(1024*1024*1024)){std::cout << (traffic_in)/(1024*1024*1024) << "GB";}
        else if((traffic_in)/(1024*1024)){std::cout << (traffic_in)/(1024*1024) << "MB";}
        else if((traffic_in)/1024){std::cout << (traffic_in)/1024 << "KB";}
        else{std::cout << traffic_in << "B";}
        std::cout << " IN / "; 
        if((traffic_out)/(1024*1024*1024)){std::cout << (traffic_out)/(1024*1024*1024) << "GB";}
        else if((traffic_out)/(1024*1024)){std::cout << (traffic_out)/(1024*1024) << "MB";}
        else if((traffic_out)/1024){std::cout << (traffic_out)/1024 << "KB";}
        else{std::cout << traffic_out << "B";} 
        std::cout << " OUT)" << std::endl;
    }