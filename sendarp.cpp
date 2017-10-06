//
// Created by 김세희 on 2017. 10. 6..
//

#include "sendarp.h"


void arprequest(char *dev,uint8_t *my_mac,uint8_t *my_addr){


    struct libnet_arp_hdr *arp_h=(libnet_arp_hdr *)malloc(LIBNET_ARP_H);
    struct libnet_ethernet_hdr *eth_h=(libnet_ethernet_hdr *)malloc(LIBNET_ETH_H);
    struct my_ip_hdr *ip_h=(my_ip_hdr *)malloc(LIBNET_ARP_ETH_IP_H-LIBNET_ARP_H);
    uint8_t packet[200];

    memset(eth_h->ether_dhost,0xff,6); // arp request's dest mac ff:ff:ff:ff:ff:ff
    puts("here");
    memcpy(eth_h->ether_shost,my_mac,ETHER_ADDR_LEN);
    puts("here");

    eth_h->ether_type=0x0608;   //type : arp 0x0806

    arp_h->ar_hrd=0x0100;    // hardware type : ethernet 1
    arp_h->ar_pro=0x0008;    // protocol type : IPv4 0x800
    arp_h->ar_hln=6;    // hardware size
    arp_h->ar_pln=4;    // protocol size
    arp_h->ar_op=0x100;     // opcode : arp request = 1
    memcpy(ip_h->sender_mac,my_mac,ETHER_ADDR_LEN);
    memcpy(ip_h->sender_ip,my_addr,4);
    memset(ip_h->target_mac,0,ETHER_ADDR_LEN);
    memcpy(ip_h->target_ip,my_addr,4);

    memcpy(packet,eth_h,LIBNET_ETH_H);
    memcpy(packet+LIBNET_ETH_H,arp_h,LIBNET_ARP_H);
    memcpy(packet+LIBNET_ETH_H+LIBNET_ARP_H,ip_h,MY_IP_HDR);
    for(int i=0;i<10;i++) {
        send_packet(dev, packet, LIBNET_ETH_H + LIBNET_ARP_H + MY_IP_HDR);
        printf("%d\n",i);
    }

}

void myinfo(uint8_t * mac_addr, uint8_t * ip,const char* if_name)
{
    ifaddrs* iflist;
    bool found = false;
    void * tmpAddrPtr=NULL;

    if (getifaddrs(&iflist) == 0) {
        for (ifaddrs* cur = iflist; cur; cur = cur->ifa_next) {
            if ((cur->ifa_addr->sa_family == AF_LINK) && (strcmp(cur->ifa_name, if_name) == 0) && cur->ifa_addr) {
                sockaddr_dl* sdl = (sockaddr_dl*)cur->ifa_addr;
                memcpy(mac_addr, LLADDR(sdl), sdl->sdl_alen);
            }
            if ((cur->ifa_addr->sa_family == AF_INET) && (strcmp(cur->ifa_name, if_name) == 0) && cur->ifa_addr) {
                memcpy(ip,&((struct sockaddr_in *)cur->ifa_addr)->sin_addr,4);
            }
        }

        freeifaddrs(iflist);
    }
    return;
}

int send_packet(char *dev,u_char *packet,int length){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    if(pcap_sendpacket(handle,packet,length)){
        printf("error");
    }
}

