#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <err.h>

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <pcap.h>

#include "header.h" 

#define TCP 6
#define IPV4 0x0800

#define IP_STR "%hhu.%hhu.%hhu.%hhu\n"
#define IP_ARG(ip) ip[0], ip[1], ip[2], ip[3]
#define MAC_STR "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n"
#define MAC_ARG(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

#define NONE 0
#define HTTP 1
#define HTTPS 2

#define WARNING "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n"

int check_protocol(const u_char *packet, int *_offset);
int get_my_mac(char *_ifr_name, uint8_t *dst);
int get_my_ip (char *_ifr_name, uint32_t *my_ip);
void packet_filter(pcap_t *pcap, struct pcap_pkthdr *header, const u_char *packet, const char*pattern, int offset, int protocol);