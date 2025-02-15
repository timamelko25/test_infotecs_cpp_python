import csv

class IPStatistics:
    """
    Class to store and track IP traffic statistics, including received and sent packets and bytes.

    Attributes:
        ip (str): The IP address associated with the statistics.
        received_packets (int): Number of packets received by the IP.
        received_bytes (int): Number of bytes received by the IP.
        sent_packets (int): Number of packets sent by the IP.
        sent_bytes (int): Number of bytes sent by the IP.
    """
    def __init__(self, ip):
        """
        Initializes the IPStatistics object for a given IP address.

        Args:
            ip (str): The IP address for which statistics are being tracked.
        """
        self.ip = ip
        self.received_packets = 0
        self.received_bytes = 0
        self.sent_packets = 0
        self.sent_bytes = 0

    def update_sent(self, packets, bytes_transferred):
        """
        Updates the sent traffic statistics for the current IP address.

        Args:
            packets (int): The number of packets sent.
            bytes_transferred (int): The number of bytes sent.
        """
        self.sent_packets += packets
        self.sent_bytes += bytes_transferred

    def update_received(self, packets, bytes_transferred):
        """
        Updates the received traffic statistics for the current IP address.

        Args:
            packets (int): The number of packets received.
            bytes_transferred (int): The number of bytes received.
        """
        self.received_packets += packets
        self.received_bytes += bytes_transferred

    def to_csv_row(self):
        """
        Converts the IP statistics to a list format suitable for writing to a CSV.

        Returns:
            list: A list containing IP address, received packets, received bytes,
                  sent packets, and sent bytes.
        """
        return [self.ip, self.received_packets, self.received_bytes, self.sent_packets, self.sent_bytes]


class TrafficAnalyzer:
    """
    Class to analyze network traffic flows and update statistics for each IP address.

    Attributes:
        ip_stats (dict): A dictionary where keys are IP addresses and values are IPStatistics objects.
    """
    def __init__(self):
        """
        Initializes the TrafficAnalyzer object with an empty dictionary for storing IP statistics.
        """
        self.ip_stats = {}

    def process_flow_data(self, flows):
        """
        Processes flow data from CSV and updates IP statistics accordingly.

        Args:
            flows (list of dict): A list of dictionaries representing network flow data.
                                  Each dictionary must contain keys "Source IP", "Destination IP",
                                  "Packet Count", and "Bytes Transferred".
        """
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
        """
        Retrieves the IP traffic statistics as a list of rows, each corresponding to an IP address.

        Returns:
            list of list: A list of lists, where each inner list contains the statistics for one IP.
        """
        return [stat.to_csv_row() for stat in self.ip_stats.values()]


class CSVHandler:
    """
    A utility class for handling CSV files, including reading and writing.

    Methods:
        read_csv(filename): Reads the data from a CSV file and returns it as a list of dictionaries.
        write_csv(filename, data, headers): Writes data to a CSV file with the provided headers.
    """
    @staticmethod
    def read_csv(filename):
        """
        Reads the data from a CSV file and returns it as a list of dictionaries.

        Args:
            filename (str): The name of the CSV file to read.

        Returns:
            list of dict: A list of dictionaries representing the rows in the CSV file.
        """
        with open(filename, newline='') as file:
            return list(csv.DictReader(file))

    @staticmethod
    def write_csv(filename, data, headers):
        """
        Writes the provided data to a CSV file with the given headers.

        Args:
            filename (str): The name of the CSV file to write to.
            data (list of list): A list of rows (lists) to write to the CSV.
            headers (list of str): A list of column headers for the CSV file.
        """
        with open(filename, mode="w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(data)


def main():
    """
    Main function to read flow data from a CSV, process it to calculate IP traffic statistics,
    and then write the results to a new CSV file.
    """
    input_file = "flows.csv"
    output_file = "ip_statistics.csv"

    flows = CSVHandler.read_csv(input_file)

    analyzer = TrafficAnalyzer()
    analyzer.process_flow_data(flows)

    headers = ["IP Address", "Received Packets", "Received Bytes", "Sent Packets", "Sent Bytes"]

    CSVHandler.write_csv(output_file, analyzer.get_statistics(), headers)


if __name__ == "__main__":
    main()
