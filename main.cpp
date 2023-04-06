#include <iostream>
#include <cstdlib>
#include <string.h>
#include <pcap/pcap.h>
#include "PtcHeaders.cpp"

void my_callback(u_char *args, const struct pcap_pkthdr * pkthdr, const u_char * packet) 
{ 
	static int count = 1;
    //system("clear");
	std::cout << "Packet №: " <<  count++ << std::endl;
    std::cout << "Packet length: " << pkthdr->len << std::endl;
	std::cout << "Data length " <<  pkthdr->caplen << std::endl;
    std::cout << std::endl;
	fflush(stdout);
}

int main(int argc, char *argv[]) {

    char *device;
    pcap_t *descr;
    pcap_if_t *alldevs;
    struct bpf_program fp;
    char ip[13];
    char mask[13];
    bpf_u_int32 ip_raw;
    bpf_u_int32 mask_raw;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string filterstr = "port 80 or 443";
    char *filter_exp;
    struct in_addr address;
    const u_char *packet;
    struct pcap_pkthdr header;
    static int pckcnt = 1;


    pcap_findalldevs(&alldevs, errbuf);
    /* if (pcap_findalldevs(&alldevs, errbuf) != -1)
    {
        auto device = alldevs;
        int i = 0;
        for(pcap_if_t *d = alldevs; d != NULL; d = d->next)
        {
            std::cout << d->name << "\t" << d->addresses << "\t" << d->flags << std::endl;
        }
    } */
    std::string dev = alldevs->name;
    pcap_freealldevs(alldevs);
    std::cout << "Device: " << dev << "\t";
    device = &*dev.begin();

    pcap_lookupnet(device, &ip_raw, &mask_raw, errbuf);
    descr = pcap_open_live(device, BUFSIZ, 1, -1, errbuf);
    if (descr == NULL){
        std::cout << "pcap_open_life()\n" << errbuf << std::endl;
        return 1;
    }

    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa");
        return 1;
    }
    std::cout << "IP: " << ip << "\t";

    address.s_addr = mask_raw;
    strcpy(mask, inet_ntoa(address));
    if (mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }
    std::cout << "Netmask: " << mask << "\t";

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
    /* for(int i = 0; i < 1000; i++){
        packet = pcap_next(descr, &header);
        if (packet == NULL){ 
            std::cout << "No packet found.\n";
            continue;
        }
        std::cout << "Packet length: " << header.len << std::endl;
        std::cout << "Captured packet length: " << header.caplen << std::endl;
    } */
    pcap_loop(descr, -1, my_callback, NULL);
    pcap_close(descr);
    std::cout << "\n";
    return 0;
}