#include "FlowStatistics.h"
#include <fstream>

void FlowStatistics::updateFlow(const std::string &src_ip, const std::string &dst_ip, uint16_t src_port, uint16_t dst_port, int bytes)
{
    auto key = std::make_tuple(src_ip, dst_ip, src_port, dst_port);
    stats_flow[key].first++;
    stats_flow[key].second += bytes;
}

void FlowStatistics::writeToCSV(const std::string &filename) const
{
    std::ofstream file(filename);
    file << "Source IP,Destination IP,Source Port,Destination Port,Packet Count,Bytes Transferred\n";
    for (const auto &entry : stats_flow)
    {
        file << std::get<0>(entry.first) << ","
             << std::get<1>(entry.first) << ","
             << std::get<2>(entry.first) << ","
             << std::get<3>(entry.first) << ","
             << entry.second.first << ","
             << entry.second.second << "\n";
    }
    file.close();
}
