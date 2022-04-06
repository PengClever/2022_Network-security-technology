#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>

using namespace std;

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

#pragma pack(1)

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

#pragma pack()

void Packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    local_tv_sec = pkt_header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    printf("--------------------------------------------------------------\n");
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    printf(" Time:\n");
    printf("                  ");
    printf(" %s.%.3d\n", timestr, (int)pkt_header->ts.tv_usec);
    printf(" Length:\n");
    printf("                  ");
    printf(" %d\n", pkt_header->len);

    ether_header_t *eh;
    ip_header_t *ih;

    eh = (ether_header_t *)pkt_data;
    printf(" Ether_header:\n");
    printf("                  ");
    printf(" ether_type: 0x%x\n", ntohs(eh->frametype));
    printf("                  ");
 	printf(" Source MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", eh->src_hw_addr[0], eh->src_hw_addr[1], eh->src_hw_addr[2], eh->src_hw_addr[3], eh->src_hw_addr[4], eh->src_hw_addr[5]);
    printf("                  ");
    printf(" Destination MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", eh->des_hw_addr[0], eh->des_hw_addr[1], eh->des_hw_addr[2], eh->des_hw_addr[3], eh->des_hw_addr[4], eh->des_hw_addr[5]);
	
    ih = (ip_header_t *)(pkt_data + 14);
    printf(" IP_header:\n");
    printf("                  ");
    printf(" version: %X\n", (ih->hlen_ver & 0xF0) >> 4);
    printf("                  ");
    printf(" IHL: %X\n", (ih->hlen_ver & 0xF));
    printf("                  ");
    printf(" tos: %X\n", ih->tos);
    printf("                  ");
    printf(" totlen: %X\n", ntohs(ih->total_len));
    printf("                  ");
    printf(" identification: %X\n", ntohs(ih->id));
    printf("                  ");
    printf(" flags: %X\n", (ntohs(ih->flag) & 0xE000) >> 13);
    printf("                  ");
    printf(" offsetfrag: %X\n", (ntohs(ih->flag) & 0x1FFF));
    printf("                  ");
    printf(" TTL: %X\n", ih->ttl);
    printf("                  ");
    printf(" proto: %X\n", ih->protocol);
    printf("                  ");
    printf(" check_sum: %X\n", ntohs(ih->checksum));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
	sin.sin_addr.s_addr = ih->src_ip;
    printf("                  ");
    printf(" Source IP address: %s\n", inet_ntoa(sin.sin_addr));
    memset(&sin, 0, sizeof(sin));
	sin.sin_addr.s_addr = ih->des_ip;
    printf("                  ");
    printf(" Destination IP address: %s\n", inet_ntoa(sin.sin_addr));

}

void ifprint(pcap_if_t *devices, char *devname){
    for (pcap_if_t * d = devices; d != NULL; d = d->next)
    {
        for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next)
        {
            if (a->addr->sa_family == AF_INET && d->name != "lo")
            {
                strcpy(devname, d->name);
                printf(" %s", devname);
                printf("(%s)\n", inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
                return;
            }   
        }
    }
}

int main()
{
    pcap_if_t *devices;
    pcap_t *dev_handle_pcap;

    char errbuf[PCAP_ERRBUF_SIZE];
    char devname[10];
    
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;

    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "ip and tcp";
    
    /* 1 */
    if(pcap_findalldevs(&devices, errbuf) == -1)
    {
        printf("Error in pcap_findalldevs() : %s \n", errbuf);
        return -1;
    }
    else
    {
        printf("Find the following devices on your machine: \n");
        ifprint(devices, devname);
    }
    /* 2 */
    if(pcap_lookupnet(devname, &net_ip, &net_mask, errbuf) == -1)
    {
	    printf("Error in the pcap_lookupnet: %s \n", errbuf);
	    return -1;
    }
    /* 3 */
    if((dev_handle_pcap = pcap_open_live(devname, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
	    printf("Error in the pcap_open_live! \n");
	    return -1;
    }
    /* 4 */
    if((pcap_compile(dev_handle_pcap, &bpf_filter, bpf_filter_string, 0, net_ip)) == -1)
    {
	    printf("Error in the pcap_compile! \n");
	    return -1;
    }
    else
    {
	    if((pcap_setfilter(dev_handle_pcap, &bpf_filter)) == -1)
	    {
	        printf("Error in the pcap_setfilter ! \n");
	        return -1;
	    }
    }
    /* 5 */
    pcap_loop(dev_handle_pcap, 10, Packet_handler, NULL);
    /* 6 */
    pcap_close(dev_handle_pcap);

    return 0;
}
