#include <iostream>
#include <iomanip>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

typedef struct ether_header_t{
    BYTE des_hw_addr[6];
    BYTE src_hw_addr[6];
    WORD frametype;
} ether_header_t;

typedef struct ip_header_t{
    BYTE hlen_ver;
    BYTE tos;
    WORD total_len;
    WORD id;
    WORD flag;
    BYTE ttl;
    BYTE protocol;
    WORD checksum;
    DWORD src_ip;
    DWORD des_ip;
} ip_header_t;
 
typedef struct arp_header_t{
    WORD hw_type;
    WORD prot_type;
    BYTE hw_addr_len;
    BYTE prot_addr_len;
    WORD flag;
    BYTE send_hw_addr[6];
    DWORD send_prot_addr;
    BYTE des_hw_addr[6];
    DWORD des_prot_addr;
} arp_header_t;
 
typedef struct tcp_header_t{
    WORD src_port;
    WORD des_port;
    DWORD seq;
    DWORD ack;
    BYTE len_res;
    BYTE flag;
    WORD window;
    WORD checksum;
    WORD urp;
} tcp_header_t;
 
typedef struct udp_header_t{
    WORD src_port;
    WORD des_port;
    WORD len;
    WORD checksum;
} udp_header_t;

typedef struct icmp_header_t{
    BYTE type;
    BYTE code;
    WORD checksum;
    WORD id;
    WORD seq;
} icmp_header_t;

typedef struct arp_packet_t{
    struct ether_header_t etherheader;
    struct arp_header_t arpheader; 
} arp_packet_t;

typedef struct ip_packet_t{
    struct ether_header_t etherheader;
    struct ip_header_t ipheader; 
} ip_packet_t;

typedef struct icmp_packet_t{
    struct ether_header_t etherheader;
    struct ip_header_t ipheader;
    struct icmp_header_t icmpheader;
} icmp_packet_t;

typedef struct tcp_packet_t{
    struct ether_header_t etherheader;
    struct ip_header_t ipheader;
    struct tcp_header_t tcpheader;
} tcp_packet_t;

typedef struct udp_packet_t{
    struct ether_header_t etherheader;
    struct ip_header_t ipheader;
    struct udp_header_t udpheader;
} udp_packet_t;

typedef struct filter
{
    unsigned long sip;
    unsigned long dip;
    unsigned int protocol;
} filter;

class rawsocket
{
private:
    int sockfd;

public:
    rawsocket(const int protocol);
    ~rawsocket();
    bool dopromisc(char *nif);
    int receive(char *recvbuf, int buflen, struct sockaddr_in *from, int *addrlen);
};

rawsocket::rawsocket(const int protocol)
{
    sockfd = socket(PF_PACKET, SOCK_RAW, protocol);
    if(sockfd < 0)
    {
        perror("socket error: ");
    }
}

rawsocket::~rawsocket()
{
    close(sockfd);
}

bool rawsocket::dopromisc(char*nif)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, nif, strlen(nif) + 1);
    if((ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1))
    {
        perror("ioctlread: ");
        return false;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if(ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1 )
    {
        perror("ioctlset: ");
        return false;
    }
    return true;
}

int rawsocket::receive(char *recvbuf,int buflen, struct sockaddr_in *from,int *addrlen)
{
    int recvlen;
    recvlen = recvfrom(sockfd, recvbuf, buflen, 0,(struct sockaddr *)from, (socklen_t *)addrlen);
    recvbuf[recvlen] = '\0';
    return recvlen;
}

class rawsocsniffer: public rawsocket
{
private:
    filter simfilter;
    char *packet;
    const int max_packet_len;
public:
    rawsocsniffer(int protocol);
    ~rawsocsniffer();
    bool init();
    void setfilter(filter myfilter);
    bool testbit(const unsigned int p, int k);
    void setbit(unsigned int &p, int k);
    void sniffer();
    void analyze();
    void ParseRARPPacket();
    void ParseARPPacket();
    void ParseIPPacket();
    void ParseTCPPacket();
    void ParseUDPPacket();
    void ParseICMPPacket();
    void print_hw_addr(const unsigned char *ptr);
    void print_ip_addr(const unsigned long ip);
};

rawsocsniffer::rawsocsniffer(int protocol):rawsocket(protocol), max_packet_len(1024)
{
    cout << "rawsocsniffer" << endl;
}

rawsocsniffer::~rawsocsniffer(){};

void rawsocsniffer::setfilter(filter myfilter)
{
    simfilter.protocol = myfilter.protocol;
    simfilter.sip = myfilter.sip;
    simfilter.dip = myfilter.dip;
}

bool rawsocsniffer::testbit(const unsigned int p, int k)
{
    if((p >> (k - 1)) & 0x0001)
        return true;
    else
        return false;
}

void rawsocsniffer::setbit(unsigned int &p, int k)
{
    p = (p) | ((0x0001) << (k - 1));
}

void rawsocsniffer::sniffer()
{
    struct sockaddr_in from;
    int sockaddr_len = sizeof(struct sockaddr_in);
    int recvlen = 0;
    while(1)
    {
        recvlen=receive(packet,max_packet_len,&from,&sockaddr_len);
        if(recvlen>0)
        {
            analyze();
        }
        else
        {
            continue;
        }
    }
}

void rawsocsniffer::analyze()
{
    cout << "analyze" << endl;
    ether_header_t *etherpacket = (ether_header_t *)packet;
    if(simfilter.protocol == 0)
        simfilter.protocol = 0xff;
    cout << "111" << endl;
    switch (ntohs(etherpacket->frametype))
    {
    case 0x0800:
        if(((simfilter.protocol)>>1))
        {
            cout << "\n\n/*---------------ip packet--------------------*/" << endl;
            ParseIPPacket();
        }
        break;
    case 0x0806:
        if(testbit(simfilter.protocol, 1))
        {
            cout << "\n\n/*--------------arp packet--------------------*/" << endl;
            ParseARPPacket();
        }
        break;
    case 0x0835:
        if(testbit(simfilter.protocol, 5))
        {
            cout << "\n\n/*--------------RARP packet--------------------*/" << endl;
            ParseRARPPacket();
        }
        break;
    default:
        cout << "\n\n/*--------------Unknown packet----------------*/" << endl;
        cout << "Unknown ethernet frametype!" << endl;
        break;
    }
    cout << "222" << endl;
}

void rawsocsniffer::ParseRARPPacket()
{
    arp_packet_t *arppacket =( arp_packet_t *)packet;
    print_hw_addr(arppacket->arpheader.des_hw_addr);
    print_hw_addr(arppacket->arpheader.send_hw_addr);
    cout << endl;
    print_ip_addr(arppacket->arpheader.send_prot_addr);
    print_ip_addr(arppacket->arpheader.des_prot_addr);
}

void rawsocsniffer::ParseARPPacket()
{
    arp_packet_t *arppacket =( arp_packet_t *)packet;
    print_hw_addr(arppacket->arpheader.des_hw_addr);
    print_hw_addr(arppacket->arpheader.send_hw_addr);
    cout << endl;
    print_ip_addr(arppacket->arpheader.send_prot_addr);
    print_ip_addr(arppacket->arpheader.des_prot_addr);
}

void rawsocsniffer::ParseIPPacket()
{
    ip_packet_t *ippacket = (ip_packet_t *)packet;
    cout << "ipheader.protocol: " << int(ippacket->ipheader.protocol) << endl;
    if(simfilter.sip != 0)
    {
        if(simfilter.sip != (ippacket->ipheader.src_ip))
            return;
    }
    if(simfilter.dip != 0)
    {
        if(simfilter.dip!=(ippacket->ipheader.des_ip))
            return;
    }
    switch (int(ippacket->ipheader.protocol))
    {
    case 1:
        if(testbit(simfilter.protocol, 4))
        {
            cout << "Received an ICMP packet" << endl;
            ParseICMPPacket();
        }
        break;
    case 6:
        if(testbit(simfilter.protocol, 2))
        {
            cout << "Received an TCP packet" << endl;
            ParseTCPPacket();
        }
        break;
    case 17:
        if(testbit(simfilter.protocol,3))
        {
            cout << "Received an UDP packet" << endl;
            ParseUDPPacket();
        }
        break;
    default:
        cout << "Other packet types" << endl;
    }
}

void rawsocsniffer::ParseICMPPacket()
{
    icmp_packet_t *icmppacket = (icmp_packet_t *)packet;
    cout << setw(20) << "MAC address: from ";
    print_hw_addr(icmppacket->etherheader.src_hw_addr);
    cout << "to ";
    print_hw_addr(icmppacket->etherheader.des_hw_addr);
    cout << endl << setw(20) << "IP address: from ";
    print_ip_addr(icmppacket->ipheader.src_ip);
    cout <<"to ";
    print_ip_addr(icmppacket->ipheader.des_ip);
    cout << endl;
    cout << setw(12) << "icmp type: " << int(icmppacket->icmpheader.type) << " icmp code: " << int(icmppacket->icmpheader.code) << endl;
    cout << setw(12) << "icmp id: " << ntohs(icmppacket->icmpheader.id) << " icmp seq: " << ntohs(icmppacket->icmpheader.seq) << endl;
}

void rawsocsniffer::ParseTCPPacket()
{
    tcp_packet_t *tcppacket = (tcp_packet_t *)packet;
    cout << setw(20) << "MAC address: from ";
    print_hw_addr(tcppacket->etherheader.src_hw_addr);
    cout << "to ";
    print_hw_addr(tcppacket->etherheader.des_hw_addr);
    cout << endl << setw(20) << "IP address: from ";
    print_ip_addr(tcppacket->ipheader.src_ip);
    cout << "to ";
    print_ip_addr(tcppacket->ipheader.des_ip);
    cout << endl;
    cout << setw(10) << "srcport: " << ntohs(tcppacket->tcpheader.src_port) << " desport: " << ntohs(tcppacket->tcpheader.des_port) << endl;
    cout << "seq: " << ntohl(tcppacket->tcpheader.seq) << " ack: " << ntohl(tcppacket->tcpheader.ack) << endl;
}

void rawsocsniffer::ParseUDPPacket()
{
    udp_packet_t *udppacket = (udp_packet_t *)packet;
    cout << setw(20) << "MAC address: from ";
    print_hw_addr(udppacket->etherheader.src_hw_addr);
    cout << "to ";
    print_hw_addr(udppacket->etherheader.des_hw_addr);
    cout << endl << setw(20) << "IP address: from ";
    print_ip_addr(udppacket->ipheader.src_ip);
    cout << "to ";
    print_ip_addr(udppacket->ipheader.des_ip);
    cout << endl;
    cout << setw(10) << "srcport: " << ntohs(udppacket->udpheader.src_port) << " desport: " << ntohs(udppacket->udpheader.des_port) << " length:" << ntohs(udppacket->udpheader.len) << endl;
}

void rawsocsniffer::print_hw_addr(const unsigned char *ptr)
{
    cout << "print_hw_addr" << endl;
}

void rawsocsniffer::print_ip_addr(const unsigned long ip)
{
    cout << "print_ip_addr" << endl;
}

void start();

int main(){
    start();
    return 0;
}

void start(){
    cout << "Hello" << endl;
    int p;
    cin >> p;
    rawsocsniffer rss(p);
    rss.analyze();
    return;
}