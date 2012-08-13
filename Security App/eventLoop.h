#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#include <unistd.h>
#include "../dependencies/include/libnet/libnet.h"
#include "../dependencies/include/libpcap/pcap.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518
#define FILTER_BUFFER 1024
#define SIZE_ETHERNET 14
#define SIZE_UDP_HEADER 8

void pcapLoop(void *data);
void covertTx(FILE *fp, int delay, const char * dest);
void systemFatal(const char* message);


struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct sniff_udp {
    u_short udp_sport;
    u_short udp_dport;
    u_short udp_len;
    u_short udp_sum;
};

#endif
