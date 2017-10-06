#include <iostream>

#include <pcap.h>

#include "sendarp.h"




void usage(){
    puts("./send_arp <interface> <send ip> <target ip>");
}

int main(int argc, char* argv[]) {
    if (argc == 4) {
        usage();
        return -1;
    }
    char *dev="en0";//argv[1]; debug mode
    uint8_t my_mac[6];
    uint8_t my_ip[4];
    myinfo(my_mac,my_ip,dev);
    arprequest(dev,my_mac,my_ip);
    //arp_reply();
}