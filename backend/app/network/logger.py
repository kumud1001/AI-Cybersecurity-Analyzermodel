import csv
import os

FILE = "network_logs.csv"


def log_packet(packet):

    file_exists = os.path.isfile(FILE)

    with open(FILE, "a", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "src_ip",
                "dst_ip",
                "protocol",
                "src_port",
                "dst_port",
                "packet_size"
            ]
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(packet)