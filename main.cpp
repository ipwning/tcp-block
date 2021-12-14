#include "tcp-block.h"

extern uint8_t *MY_MAC;
extern uint8_t *MY_IP;

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

void error(const char *msg) {
    warnx("Error: %s\n", msg);
    exit(-1);
}

int main (int argc, char *argv[], char *envp[]) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *iface = argv[1];
    char *pattern;
    const u_char *packet;
    int offset; 
    uint8_t my_mac[6];
    uint32_t my_ip;
    uint8_t is_target;
    struct pcap_pkthdr* header;
    const uint8_t *data;
    tcp_header *t_h;

    if(argc != 3) {
        usage();
        exit(-1);
    }

    pattern = strdup(argv[2]);

    setvbuf(stdout, 0LL, 1, 0LL);    
    setvbuf(stderr, 0LL, 1, 0LL); 

    get_my_mac(iface, my_mac);
    get_my_ip(iface, &my_ip);

    MY_MAC = my_mac;
    MY_IP = (uint8_t*)&MY_IP;

    printf("MY IP   : "IP_STR,  IP_ARG( ( (uint8_t*)&my_ip) ) );
    printf("MY MAC  : "MAC_STR, MAC_ARG(my_mac));
    
    pcap = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", iface, errbuf);
        return -1;
    }

    while(true) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
            error("pcap_next_ex error");       
        res = check_protocol(packet, &offset);
        if(res == NONE) continue;
        packet_filter(pcap, header, packet, (const char *)pattern, offset, res);
    }
}

