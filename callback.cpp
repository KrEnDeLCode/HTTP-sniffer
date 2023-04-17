#include <iostream>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <pcap/pcap.h>
#include "Timer.hpp"
#include "PtcHeaders.hpp"
#include "Output.hpp"

void my_callback(u_char *args, const struct pcap_pkthdr * pkthdr, const u_char * packet) 
{
	static in_addr ifaddr;
    static TimeRanger myWatch (5);
    ifaddr.s_addr = inet_addr((const char*)args);
    in_addr checkip;
    std::string hostname;
    bool isNew = true;
    bool incom = false;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    

    static std::vector<Output> hosts;

    const char *address = inet_ntoa(checkip);

    struct addrinfo filter = {0};
    filter.ai_family = AF_INET;
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    struct addrinfo *result;

    getaddrinfo(address, NULL, &filter, &result);

    for (struct addrinfo *aip = result; aip != NULL; aip = aip->ai_next){
        getnameinfo(aip->ai_addr, aip->ai_addrlen, host, sizeof(host), serv, sizeof(serv), 0);
    }

    hostname = host;
    int pos = hostname.rfind(".");
    pos = hostname.rfind(".", pos - 1);
    hostname = hostname.erase(0, pos + 1);

    if(hosts.empty()){
        Output host(hostname, ifaddr, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport, pkthdr);
        hosts.push_back(host);
    }
    if(ifaddr.s_addr == ip->ip_dst.s_addr){ 
        checkip = ip->ip_src; incom = true;
    }else{checkip = ip->ip_dst;}
    
    for(int i = 0; i < hosts.size(); i++){
        if(hosts[i].GetHostname() == hostname){
            isNew = false;
            if(incom){
                hosts[i].SetPacketIn(1);
                hosts[i].SetTrafficIn(pkthdr->len);
            }else{
                hosts[i].SetPacketOut(1);
                hosts[i].SetTrafficOut(pkthdr->len);
            }
        }
    }

    if(isNew){
        Output host(hostname, ifaddr, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport, pkthdr);
        hosts.push_back(host);
    }

    myWatch.Tick(hosts);
}