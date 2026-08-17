from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = packet[IP].proto
    packet_length = len(packet)

    source_port = 0
    destination_port = 0

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    print(
        f"[{datetime.now()}] "
        f"{source_ip}:{source_port} -> "
        f"{destination_ip}:{destination_port} "
        f"Protocol={protocol} "
        f"Length={packet_length}"
    )


def start_capture(packet_count=20):

    print("=" * 60)
    print("AI CYBERSECURITY NETWORK CAPTURE")
    print("=" * 60)
    print(f"Capturing {packet_count} packets...")
    print("Press Ctrl+C to stop.")
    print()

    sniff(
        prn=process_packet,
        count=packet_count,
        store=False
    )


if __name__ == "__main__":
    start_capture(20)