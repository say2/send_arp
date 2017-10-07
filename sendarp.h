//
// Created by 김세희 on 2017. 10. 6..
//
#pragma once

#include <pcap.h>

#include <sys/socket.h>
#include <net/if.h>
#include<net/if_dl.h>
#include<netinet/in.h>
#include <string.h>
#include<sys/ioctl.h>
#include <ifaddrs.h>
#include <libnet.h>
#include <stdlib.h>

struct my_ip_hdr{
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};
#define MY_IP_HDR 20

void myinfo(uint8_t *mac_addr, uint8_t *ip,const char* if_name);
void arprequest(char *dev,uint8_t *my_mac,uint8_t *my_addr,uint8_t *target_mac);
int send_packet(char *dev,u_char *packet,int length);
bool receive_packet(pcap_t* handle,uint8_t *target_mac);
void mac(uint8_t *mac);
void arpreply(char *dev,uint8_t *src_ip,uint8_t *des_ip,uint8_t *my_mac,uint8_t *target_mac);

