#include "PcapReader.h"
#include <iostream>

PcapReader::PcapReader(PacketAnalyzer &analyzer) : analyzer(analyzer) {}

void PcapReader::packetHandler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    auto *analyzer = reinterpret_cast<PacketAnalyzer *>(user);
    analyzer->analyzePacket(pkthdr, packet);
}

bool PcapReader::readFromFile(const std::string &filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename.c_str(), errbuf);
    if (!handle)
    {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return false;
    }
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char *>(&analyzer));
    pcap_close(handle);
    return true;
}

bool PcapReader::readFromInterface()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return false;
    }

    int i = 0, dev_number;
    pcap_if_t *dev;
    std::cout << "Available devices:\n";
    for (dev = alldevs; dev != NULL; dev = dev->next)
        std::cout << ++i << ". " << dev->name << std::endl;

    std::cout << "Choose device: ";
    std::cin >> dev_number;
    if (dev_number < 1 || dev_number > i)
        return false;

    for (dev = alldevs, i = 1; dev != NULL && i < dev_number; dev = dev->next, i++)
        ;

    pcap_t *handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        std::cerr << "error " << errbuf << std::endl;
        return false;
    }

    pcap_loop(handle, PCOUNT, packetHandler, reinterpret_cast<u_char *>(&analyzer));
    pcap_close(handle);
    return true;
}
