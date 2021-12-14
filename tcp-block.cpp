#include "tcp-block.h"

uint8_t *MY_MAC;
uint8_t *MY_IP;

char *strnstr(const char *str, const char *substr, size_t len) {
    int sl = strlen(substr);
    for(int i = 0; i <= len - sl; ++i) {
        if(strncmp(str, substr, sl) == 0) {
            return (char*)str;
        }
        ++str;
    }
    return (char*)NULL;
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int get_my_mac(char *_ifr_name, uint8_t *dst) {
    int nSD; // Socket descriptor
    struct ifreq *ifr; // Interface request
    struct ifconf ifc;
    int i, numif;
    struct ifreq *r;
    struct sockaddr_in *sin;
    memset(&ifc, 0, sizeof(struct ifconf));
    ifc.ifc_ifcu.ifcu_req = NULL;
    ifc.ifc_len = 0;

    // Create a socket that we can use for all of our ioctls
    nSD = socket( PF_INET, SOCK_DGRAM, 0 );
    
    if ( nSD < 0 )  return 1;
    
    if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
    
    if ((ifr = (ifreq*)  malloc(ifc.ifc_len)) == NULL) {
        return 1;
    }

    else {
        ifc.ifc_ifcu.ifcu_req = ifr;

        if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0) {
            return 1;
        }
        numif = ifc.ifc_len / sizeof(struct ifreq);
        
        for (i = 0; i < numif; i++) {
            r = &ifr[i];
            sin = (struct sockaddr_in *)&r->ifr_addr;
        
            if (strcmp(r->ifr_name, _ifr_name))
                continue; // skip wrong interface
    
            if(ioctl(nSD, SIOCGIFHWADDR, r) < 0) 
                return 1;
            memcpy(dst, r->ifr_hwaddr.sa_data, 6);
            break;
        }
    }
    close(nSD);
    free(ifr);
 
    return 0;
}

int get_my_ip (char *_ifr_name, uint32_t *my_ip) {
    struct ifreq ifr;
    char ipstr[40];
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, _ifr_name, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        return 1;
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                ipstr,sizeof(struct sockaddr));
        *my_ip = inet_addr(ipstr);
    }
    return 0;
}

void ip_debug(ip_header *ip) {
    ip_fragment frag;
    *(uint16_t*)&frag = ntohs(*(uint16_t*)&ip->frag);
    printf("=========================================\n");
    printf("ver=%d\n", ip->ver);
    printf("header_len=%#x\n", ip->h_len);
    printf("type_of_service=%#x\n", ip->tos);
    printf("total_len=%d\n", ntohs(ip->total_len));
    printf("id=%#x\n", ntohs(ip->id));
    printf("reserved flags=%#x\n", frag.reserved_bit);
    printf("no fragment flags=%#x\n", frag.no_fragment_bit);
    printf("more fragment flags=%#x\n", frag.more_fragment_bit);
    printf("fragment_offset=%#x\n", frag.f_off);
    printf("ttl=%#x\n", ip->ttl);
    printf("protocol=%#x\n", ip->protocol);
    printf("checksum=%#x\n", ntohs(ip->checksum));
    printf("source ip="IP_STR"\n", IP_ARG( ( (uint8_t*)&ip->sip) ) );
    printf("destination ip="IP_STR"\n", IP_ARG( ( (uint8_t*)&ip->dip) ) );
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
}

void tcp_debug(tcp_header *tcp) {
    tcp_flags flags;
    *(uint16_t*)&flags = htons(*(uint16_t*)&tcp->flags);
    printf("=========================================\n");
    printf("source port=%d\n", ntohs(tcp->sport));
    printf("destination port=%d\n", ntohs(tcp->dport));
    printf("sequence number=%#x\n", ntohl(tcp->seq_num));
    printf("ack number=%d\n", ntohl(tcp->ack_num));
    printf("offset=%#x\n", flags.offset);
    printf("reserved flags=%#x\n", flags.reserved);
    printf("ns flags=%#x\n", flags.ns);
    printf("cwr flags=%#x\n", flags.cwr);
    printf("ece flags=%#x\n", flags.ece);
    printf("urg flags=%#x\n", flags.urg);
    printf("ack flags=%#x\n", flags.ack);
    printf("psh flags=%#x\n", flags.psh);
    printf("rst flags=%#x\n", flags.rst);
    printf("syn flags=%#x\n", flags.syn);
    printf("fin flags=%#x\n", flags.fin);
    printf("window size=%#x\n", tcp->window);
    printf("checksum=%#x\n", ntohs(tcp->checksum));
    printf("urgent pointer=%#x\n", ntohs(tcp->urgent_ptr));
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
}


int check_protocol(const u_char *packet, int *_offset) {
    eth_header eth;
    ip_header ip;
    tcp_header tcp;
    int ip_hdr_size;
    int state = NONE;
    int offset = 0;
    memcpy(&eth, packet + offset, sizeof(eth_header));
    if(ntohs(eth.type) == IPV4) { 
        offset += sizeof(eth_header);
        memcpy(&ip, packet + offset, sizeof(ip_header));
        //ip_debug(&ip);
        if(ip.protocol == TCP) {
            offset += ip.h_len * 4;
            memcpy(&tcp, packet + offset, sizeof(tcp_header));
            tcp.dport = ntohs(tcp.dport);
            //tcp_debug(&tcp);
            if(tcp.dport == 80) state = HTTP;
            else if (tcp.dport == 443) state = HTTPS;
            *_offset = offset;
        }
    }
    return state;
}
uint16_t ip_checksum(ip_header* ip) {
    uint32_t sum = 0;
    uint16_t *ptr;

    ptr = (uint16_t*)ip;
    for (int i = 0; i < sizeof(ip_header) / 2; i++) {
        sum += ntohs(*ptr);
        ptr++;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;

    return (uint16_t)sum;
}

uint16_t pre_csum(uint16_t *ptr, int nbytes) {
    uint32_t sum;
    uint16_t oddbyte;
    uint16_t answer;
    printf("%d\n", nbytes);
    sum = 0;
    while(nbytes > 1) {
            sum += *ptr++;
            nbytes -= 2;
    }
    if(nbytes == 1) {
            oddbyte = 0;
            oddbyte = *ptr;
            sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (uint16_t)~sum;
    
    return(answer);
}

uint16_t tcp_checksum(ip_header* ip, tcp_header* tcp, int d_len) {
	uint32_t sum = 0;
    checksum_header ch;
    uint32_t n1;
    uint32_t n2;
    ch.sip = ip->sip;
    ch.dip = ip->dip;
    ch.protocol = TCP;
    ch.reserved = 0;
    ch.tcp_len = sizeof(tcp_header);
    n1 = pre_csum((uint16_t*)&ch, sizeof(checksum_header));
    n2 = pre_csum((uint16_t*)tcp, sizeof(tcp_header) + d_len);
    sum = n1 + n2;
    if(sum > 0x10000) sum = sum - 0x10000 + 1;
    sum = htons(sum ^ 0xffff);

    return ~(uint16_t)sum;
}

void make_forward(uint8_t *pkt, const u_char *org, int pkt_len, int protocol) {
    eth_header *pkt_eth;
    ip_header *pkt_ip;
    tcp_header *pkt_tcp;
    eth_header *org_eth;
    ip_header *org_ip;
    tcp_header *org_tcp;

    tcp_flags flags;

    uint8_t *pkt_pay;  
    int data_size;

    pkt_eth = (eth_header*)pkt;
    pkt_ip = (ip_header*)((uint8_t*)pkt_eth + sizeof(eth_header));
    pkt_tcp = (tcp_header*)((uint8_t*)pkt_ip + sizeof(ip_header));
    org_eth = (eth_header*)org;
    org_ip = (ip_header*)((uint8_t*)org_eth + sizeof(eth_header));
    org_tcp = (tcp_header*)((uint8_t*)org_ip + sizeof(ip_header));
    *(uint16_t*)&flags = htons(*(uint16_t*)&org_tcp->flags);
    
    data_size = org_ip->total_len - org_ip->h_len * 4 - flags.offset * 4;

    memcpy(pkt, org, pkt_len);
    pkt_pay = pkt + sizeof(eth_header) + sizeof(ip_header) + sizeof(tcp_header);

    memcpy(pkt_eth->src_mac, MY_MAC, 6);

    pkt_ip->total_len = ntohs(sizeof(ip_header) + sizeof(tcp_header));
    pkt_tcp->seq_num = org_tcp->seq_num + htonl(data_size);
    flags.rst |= 1;
    flags.syn &= 0;
    flags.psh &= 0;
    flags.ack |= 1;
    *(uint16_t*)&pkt_tcp->flags = htons(*(uint16_t*)&flags);
    pkt_ip->checksum = 0;
    pkt_tcp->checksum = 0;
    
    pkt_ip->checksum = htons(ip_checksum(pkt_ip));
    pkt_tcp->checksum = htons(tcp_checksum(pkt_ip, pkt_tcp, 0));
}

void make_backward(uint8_t *pkt, const u_char *org, int pkt_len, int protocol) {
    eth_header *pkt_eth;
    ip_header *pkt_ip;
    tcp_header *pkt_tcp;
    eth_header *org_eth;
    ip_header *org_ip;
    tcp_header *org_tcp;

    tcp_flags flags;

    uint8_t *pkt_pay;  
    int data_size;
    uint16_t l = 0;
    
    pkt_eth = (eth_header*)pkt;
    pkt_ip = (ip_header*)((uint8_t*)pkt_eth + sizeof(eth_header));
    pkt_tcp = (tcp_header*)((uint8_t*)pkt_ip + sizeof(ip_header));
    org_eth = (eth_header*)org;
    org_ip = (ip_header*)((uint8_t*)org_eth + sizeof(eth_header));
    org_tcp = (tcp_header*)((uint8_t*)org_ip + sizeof(ip_header));
    *(uint16_t*)&flags = htons(*(uint16_t*)&org_tcp->flags);

    data_size = org_ip->total_len - org_ip->h_len * 4 - flags.offset * 4;

    memcpy(pkt, org, pkt_len);
    pkt_pay = pkt + sizeof(eth_header) + sizeof(ip_header) + sizeof(tcp_header);

    memcpy(pkt_eth->src_mac, MY_MAC, 6);
    memcpy(pkt_eth->dst_mac, org_eth->src_mac, 6);
    
    pkt_ip->total_len = htons(sizeof(ip_header) + sizeof(tcp_header));
    pkt_ip->ttl = 128;
    pkt_ip->sip = org_ip->dip;
    pkt_ip->dip = org_ip->sip;
    pkt_tcp->dport = org_tcp->sport;
    pkt_tcp->sport = org_tcp->dport;
    pkt_tcp->ack_num = org_tcp->seq_num;
    pkt_tcp->seq_num = org_tcp->ack_num;

    *(uint16_t*)&pkt_tcp->flags = 0;
    pkt_tcp->flags.offset = flags.offset;
    if(protocol == HTTP) {
        l = strlen(WARNING);
        pkt_ip->total_len += htons(l);
        flags.fin |= 1;
        flags.syn &= 0;
        flags.ack |= 1;
        flags.psh |= 1;
        memcpy(pkt_pay, WARNING, l);
    } else if(protocol == HTTPS) {
        flags.rst |= 1;
        flags.syn &= 0;
        flags.psh &= 0;
        flags.ack |= 1;
    }

    *(uint16_t*)&pkt_tcp->flags = htons(*(uint16_t*)&flags);

    pkt_ip->checksum = 0;
    pkt_tcp->checksum = 0;
    pkt_ip->checksum = htons(ip_checksum(pkt_ip));
    pkt_tcp->checksum = htons(tcp_checksum(pkt_ip, pkt_tcp, l));
    //puts("==================BACKWARD!!==================");
    //ip_debug((ip_header*)(pkt_ip));
    //tcp_debug((tcp_header*)(pkt_tcp));
}

void packet_filter(pcap_t *pcap, struct pcap_pkthdr *header, const u_char *packet, const char*pattern, int offset, int protocol) {
    uint8_t forward[0x800];
    uint8_t backward[0x800];
    int res;

    memset(forward, 0, sizeof(forward));
    memset(backward, 0, sizeof(backward));

    if(strnstr((const char*)packet, pattern, header->caplen)) {
        make_forward(forward, packet, header->caplen, protocol);
        make_backward(backward, packet, header->caplen, protocol);
        //puts("==================FORWARD!!==================");
        //ip_debug((ip_header*)(forward + 14));
        //tcp_debug((tcp_header*)(forward + 34));
        puts("forward 패킷 슝");
        res = pcap_sendpacket(pcap, forward, htons( ( (ip_header*)(forward + 14) )->total_len ) + 14 );
        if (res != 0) {
            fprintf(stderr, "Send Forward Failed return %d error=%s\n", res, pcap_geterr(pcap));
            exit(-1);
        }
        
        puts("backward 패킷 슝");
        res = pcap_sendpacket(pcap, backward, htons( ( (ip_header*)(backward + 14) )->total_len ) + 14 );
        if (res != 0){
            fprintf(stderr, "Send Forward Failed return %d error=%s\n", res, pcap_geterr(pcap));
            exit(-1);
        }
    }
}