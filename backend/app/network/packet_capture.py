from scapy.all import sniff
from app.network.packet_parser import parse_packet
from app.network.logger import log_packet

PACKET_COUNT = 0


def process_packet(packet):
    global PACKET_COUNT

    PACKET_COUNT += 1

    data = parse_packet(packet)

    log_packet(data)

    print(data)


def start_capture():

    print("Starting Packet Capture...")

    sniff(
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_capture().venv