#include <iostream>
#include "PcapReader.h"

int main()
{
    FlowStatistics stats;
    PacketAnalyzer analyzer(stats);
    PcapReader reader(analyzer);

    std::cout << "Choose option:\n1. Read pcap file\n2. Read network interface\n";
    int opt;
    std::cin >> opt;

    if (opt == 1)
    {
        std::string filename;
        std::cout << "Enter pcap file path: ";
        std::cin >> filename;
        reader.readFromFile(filename);
    }
    else if (opt == 2)
    {
        reader.readFromInterface();
    }

    stats.writeToCSV("flows.csv");
    return 0;
}
