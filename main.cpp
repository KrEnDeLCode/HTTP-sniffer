#include <iostream>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <pcap/pcap.h>
#include "callback.h"
//#include "PtcHeaders.h"
//#include "Output.h"

int main(int argc, char *argv[]) {

    char *device;
    pcap_t *descr;
    pcap_if_t *alldevs;
    struct bpf_program fp;
    time_t start = time(NULL);
    char *ifip;
    char mask[13];
    bpf_u_int32 ip_raw;
    bpf_u_int32 mask_raw;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string filterstr = "port 80 or 443";
    char *filter_exp;
    u_char *address;
    const u_char *packet;
    struct pcap_pkthdr header;
    static int pckcnt = 1;


    pcap_findalldevs(&alldevs, errbuf);
    for(pcap_addr_t *a=alldevs->addresses; a!=NULL; a=a->next) {
        if(a->addr->sa_family == AF_INET)
            
            ifip =inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
            std::cout << "Set IP" << std::endl;
    } 
    std::string dev = alldevs->name;
    std::string ntaddr = ifip;
    std::cout << "Device: " << dev << "\t";
    device = &*dev.begin();
    address = (u_char*)&*ntaddr.begin();
    pcap_freealldevs(alldevs);
    

    pcap_lookupnet(device, &ip_raw, &mask_raw, errbuf);
    descr = pcap_open_live(device, BUFSIZ, 1, -1, errbuf);
    if (descr == NULL){
        std::cout << "pcap_open_life()\n" << errbuf << std::endl;
        return 1;
    }

    std::cout << "IP: " << ntaddr << "\t";
    
    filter_exp = &*filterstr.begin();
    if(pcap_compile(descr, &fp, filter_exp, 0, mask_raw) == -1) {
		std::cout << "\nError calling pcap_compile\n";
		return 1;
	}
    
    if(pcap_setfilter(descr, &fp) == -1) {
		std::cout << "\nError setting filter\n";
		return 1;
	}
    std::cout << "Filter: " << filter_exp << "\n";
   
    pcap_loop(descr, -1, my_callback, address);
    
    pcap_close(descr);
    std::cout << "\n";
    return 0;
}

