#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <pcap.h>
#include "PacketAnalyzer.h"

#define PCOUNT BUFSIZ

class PcapReader
{
private:
    PacketAnalyzer &analyzer;
    static void packetHandler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

public:
    PcapReader(PacketAnalyzer &analyzer);
    bool readFromFile(const std::string &filename);
    bool readFromInterface();
};

#endif // PCAP_READER_H
