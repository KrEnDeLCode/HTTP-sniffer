#include <iostream>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <pcap/pcap.h>

#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};



class Output{
private:
    struct sockaddr_in haddr;
    std::string hostname;
    int packet_in, packet_out;
    int traffic_in, traffic_out;

public:
    Output(std::string hostname, in_addr ifaddr, const in_addr srcaddr, const in_addr dstaddr, 
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
    
    in_addr GetHostaddr(){return this->haddr.sin_addr;}
    std::string GetHostname(){return this->hostname;}
    int GetPacketIn(){return this->packet_in;}
    int GetPacketOut(){return this->packet_out;}
    int GetTrafficIn(){return this->traffic_in;}
    int GetTrafficOut(){return this->traffic_out;}
    void SetPacketIn(int a){this->packet_in += a;}
    void SetPacketOut(int a){this->packet_out += a;}
    void SetTrafficIn(int a){this->traffic_in += a;}
    void SetTrafficOut(int a){this->traffic_out += a;}
    

    void Print(){
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
};

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

void my_callback(u_char *args, const struct pcap_pkthdr * pkthdr, const u_char * packet) 
{ 
	static int count = 1;
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

    count++;
}

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

