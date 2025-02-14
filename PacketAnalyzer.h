#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "FlowStatistics.h"

class PacketAnalyzer
{
public:
    PacketAnalyzer(FlowStatistics &stats);
    void analyzePacket(const struct pcap_pkthdr *pkthdr, const u_char *packet);

private:
    FlowStatistics &stats;
};

#endif // PACKET_ANALYZER_H
