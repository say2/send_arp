
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
    uint8_t my_mac[6],target_mac[6];
    uint8_t my_ip[4],src_ip[4],des_ip[4];

    myinfo(my_mac,my_ip,dev);
    mac(my_mac);

    arprequest(dev,my_mac,my_ip,target_mac);
    mac(target_mac);

    inet_pton(AF_INET,argv[2],src_ip);
    inet_pton(AF_INET,argv[3],des_ip);

    arpreply(dev,src_ip,des_ip,my_mac,target_mac);
}