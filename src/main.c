//
// Created by Leo on 2018/10/15.
//

#include <pcap.h>
#include <funcattrs.h>
#include <netdissect.h>
#include <tcp.h>

#include "ether.h"
#include "main.h"

void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data) {
    FILE *csv = (void *) param;

    const struct ether_header *ether;
    const struct ip *ip;
    const struct tcphdr *tcp;
    const uint8_t *payload;
    uint16_t sport, dport;
    uint32_t ip_len, tcp_len;

    /* convert the timestamp to readable format */
//    char timestr[256];
//    struct tm ltime;
//    time_t local_tv_sec;
//    local_tv_sec = header->ts.tv_sec;
//    localtime_s(&ltime, &local_tv_sec);
//    strftime(timestr, sizeof timestr, "%Y/%m/%d %H:%M:%S", &ltime);

    ether = (struct ether_header *) pkt_data;

    ip = (struct ip *) ((uint8_t *) ether + ETHER_HDRLEN);
    ip_len = (uint32_t) (IP_HL(ip) * 4);

    tcp = (struct tcphdr *) ((uint8_t *) ip + ip_len);
    tcp_len = (uint32_t) (TH_OFF(tcp) * 4);

    payload = (uint8_t *) tcp + tcp_len;

    /* convert from network byte order to host byte order */
    sport = EXTRACT_BE_U_2(tcp->th_sport);
    dport = EXTRACT_BE_U_2(tcp->th_dport);

    /* print MAC address */
//    fprintf(stdout, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X -> %.2X-%.2X-%.2X-%.2X-%.2X-%.2X (0x%.4X)\n",
//            ether->ether_shost[0],
//            ether->ether_shost[1],
//            ether->ether_shost[2],
//            ether->ether_shost[3],
//            ether->ether_shost[4],
//            ether->ether_shost[5],
//            ether->ether_dhost[0],
//            ether->ether_dhost[1],
//            ether->ether_dhost[2],
//            ether->ether_dhost[3],
//            ether->ether_dhost[4],
//            ether->ether_dhost[5],
//            EXTRACT_BE_U_2(ether->ether_length_type)
//    );

    //timestamp
    fprintf(csv, "%ld.%ld,", header->ts.tv_sec, header->ts.tv_usec);
    //length
    fprintf(csv, "%d,", header->len);
    //protocol
    fprintf(csv, "%d,", EXTRACT_U_1(ip->ip_p));
    //src_ip
    fprintf(csv, "%d.%d.%d.%d,",
            ip->ip_src[0],
            ip->ip_src[1],
            ip->ip_src[2],
            ip->ip_src[3]);
    //dst_ip
    fprintf(csv, "%d.%d.%d.%d,",
            ip->ip_dst[0],
            ip->ip_dst[1],
            ip->ip_dst[2],
            ip->ip_dst[3]);
    //src_port
    fprintf(csv, "%u,", sport);
    //dst_port
    fprintf(csv, "%u,", dport);
    //data
    for (uint32_t i = 1; (i < header->caplen + 1); i++) {
        fprintf(csv, "%.2X", pkt_data[i - 1]);
    }

    fprintf(csv, "\n");
}

int main(int argc, char **argv) {
//    pcap_if_t *alldevs, *d;
//    int i = 0;
//    if (pcap_findalldevs(&alldevs, NULL) == -1) {
//        fprintf(stderr, "Error in pcap_findalldevs.\n");
//        return -1;
//    }
//    for (d = alldevs; d; d = d->next) {
//        printf("%d. %s (%s)\n", ++i, d->name, d->description ? d->description : "No description available");
//    }
//    if (i == 0) {
//        fprintf(stderr, "No interfaces found! Make sure WinPcap is installed.\n");
//        return -1;
//    }

    pcap_t *pcap;
    FILE *csv;
    char *packet_filter = argc >= 4 ? argv[3] : NULL; // "ip and udp"
    struct bpf_program fcode;

    if (argc < 3) {
        fprintf(stderr, "Usage:\n%s <cap> <csv> [filter]\n", argv[0]);
        return -1;
    }

    if ((pcap = pcap_open_offline(argv[1], NULL)) == NULL) {
        fprintf(stderr, "cap file open failed.\n");
        return -1;
    }

    if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "This program works only on Ethernet networks.\n");
        return -1;
    }

    /* set filter begin*/
    if (pcap_compile(pcap, &fcode, packet_filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "Unable to compile the packet filter. Check the syntax.\n");
        return -1;
    }

    if (pcap_setfilter(pcap, &fcode) < 0) {
        fprintf(stderr, "Error setting the filter.\n");
        return -1;
    }

    pcap_freecode(&fcode);
    /* set filter end */

    if (fopen_s(&csv, argv[2], "wb") != 0) {
        fprintf(stderr, "csv file open failed.\n");
        return -1;
    }

    fprintf(csv, "timestamp,length,protocol,src_ip,dst_ip,src_port,dst_port,data\n");

    pcap_loop(pcap, 0, packet_handler, (void *) csv);

    pcap_close(pcap);

    fclose(csv);

    return 0;
}

/* MAC头 + IP头 + TCP/UDP头
 * https://www.tcpdump.org/pcap.html
 * https://nmap.org/npcap/guide/npcap-tutorial.html
 * https://zh.m.wikipedia.org/zh-cn/以太类型
 * https://zh.m.wikipedia.org/zh-cn/IP协议号列表
 * https://zh.m.wikipedia.org/zh-cn/IPv4#首部
 * https://zh.m.wikipedia.org/zh-cn/用户数据报协议#UDP的分组结构
 * https://zh.m.wikipedia.org/zh-cn/传输控制协议#封包結構
 * https://en.m.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
 */

/* VLAN
 * https://en.m.wikipedia.org/wiki/IEEE_802.1Q
 * https://github.com/the-tcpdump-group/tcpdump/blob/0906b438b66d6897804c0f03e201d6229326ac2b/addrtoname.c#L1304
 */
