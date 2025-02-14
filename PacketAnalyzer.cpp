#include "PacketAnalyzer.h"

#define ETHERNET_HEADER 14

PacketAnalyzer::PacketAnalyzer(FlowStatistics &stats) : stats(stats) {}

void PacketAnalyzer::analyzePacket(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ether_header *ethHeader = (struct ether_header *)packet;
    if (ntohs(ethHeader->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    struct ip *ipHeader = (struct ip *)(packet + ETHERNET_HEADER);
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dest_ip, INET_ADDRSTRLEN);

    uint16_t src_port = 0, dst_port = 0;

    if (ipHeader->ip_p == IPPROTO_TCP)
    {
        struct tcphdr *tcpHeader = (struct tcphdr *)(packet + ETHERNET_HEADER + ipHeader->ip_hl * 4);
        src_port = ntohs(tcpHeader->source);
        dst_port = ntohs(tcpHeader->dest);
    }
    else if (ipHeader->ip_p == IPPROTO_UDP)
    {
        struct udphdr *udpHeader = (struct udphdr *)(packet + ETHERNET_HEADER + ipHeader->ip_hl * 4);
        src_port = ntohs(udpHeader->source);
        dst_port = ntohs(udpHeader->dest);
    }
    else
    {
        return;
    }

    stats.updateFlow(src_ip, dest_ip, src_port, dst_port, pkthdr->len);
}
