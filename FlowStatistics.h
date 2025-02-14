#ifndef FLOW_STATISTICS_H
#define FLOW_STATISTICS_H

#include <map>
#include <tuple>
#include <string>

class FlowStatistics
{
private:
    std::map<std::tuple<std::string, std::string, uint16_t, uint16_t>, std::pair<int, int>> stats_flow;

public:
    void updateFlow(const std::string &src_ip, const std::string &dst_ip, uint16_t src_port, uint16_t dst_port, int bytes);
    void writeToCSV(const std::string &filename) const;
};

#endif // FLOW_STATISTICS_H
