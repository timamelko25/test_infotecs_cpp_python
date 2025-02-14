import csv

class IPStatistics:
    """_summary_
    """
    def __init__(self, ip):
        self.ip = ip
        self.received_packets = 0
        self.received_bytes = 0
        self.sent_packets = 0
        self.sent_bytes = 0

    def update_sent(self, packets, bytes_transferred):
        self.sent_packets += packets
        self.sent_bytes += bytes_transferred

    def update_received(self, packets, bytes_transferred):
        self.received_packets += packets
        self.received_bytes += bytes_transferred

    def to_csv_row(self):
        return [self.ip, self.received_packets, self.received_bytes, self.sent_packets, self.sent_bytes]


class TrafficAnalyzer:
    """_summary_
    """
    def __init__(self):
        self.ip_stats = {}

    def process_flow_data(self, flows):
        for row in flows:
            src_ip = row["Source IP"]
            dst_ip = row["Destination IP"]
            packets = int(row["Packet Count"])
            bytes_transferred = int(row["Bytes Transferred"])

            if src_ip not in self.ip_stats:
                self.ip_stats[src_ip] = IPStatistics(src_ip)
            if dst_ip not in self.ip_stats:
                self.ip_stats[dst_ip] = IPStatistics(dst_ip)

            self.ip_stats[src_ip].update_sent(packets, bytes_transferred)
            self.ip_stats[dst_ip].update_received(packets, bytes_transferred)

    def get_statistics(self):
        return [stat.to_csv_row() for stat in self.ip_stats.values()]


class CSVHandler:
    """_summary_

    Returns:
        _type_: _description_
    """
    @staticmethod
    def read_csv(filename):
        with open(filename, newline='') as file:
            return list(csv.DictReader(file))

    @staticmethod
    def write_csv(filename, data, headers):
        with open(filename, mode="w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(data)


def main():
    input_file = "flows.csv"
    output_file = "ip_statistics.csv"

    flows = CSVHandler.read_csv(input_file)

    analyzer = TrafficAnalyzer()
    analyzer.process_flow_data(flows)

    headers = ["IP Address", "Received Packets", "Received Bytes", "Sent Packets", "Sent Bytes"]
    CSVHandler.write_csv(output_file, analyzer.get_statistics(), headers)


if __name__ == "__main__":
    main()
