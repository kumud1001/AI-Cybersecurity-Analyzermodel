from collections import defaultdict
from datetime import datetime
from scapy.all import IP, TCP, UDP, sniff


flows = defaultdict(list)


def get_flow_key(packet):
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    src_port = 0
    dst_port = 0
    protocol = packet[IP].proto

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Bidirectional flow key
    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)

    if endpoint1 <= endpoint2:
        return (
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol
        )

    return (
        dst_ip,
        dst_port,
        src_ip,
        src_port,
        protocol
    )


def process_packet(packet):

    key = get_flow_key(packet)

    if key is None:
        return

    flows[key].append(packet)


def summarize_flow(key, packets):

    first_packet = packets[0]
    last_packet = packets[-1]

    start_time = float(first_packet.time)
    end_time = float(last_packet.time)

    duration = end_time - start_time

    if duration <= 0:
        duration = 0.000001

    first_src_ip = first_packet[IP].src

    forward_packets = []
    backward_packets = []

    for packet in packets:

        if IP not in packet:
            continue

        if packet[IP].src == first_src_ip:
            forward_packets.append(packet)

        else:
            backward_packets.append(packet)

    forward_bytes = sum(
        len(packet)
        for packet in forward_packets
    )

    backward_bytes = sum(
        len(packet)
        for packet in backward_packets
    )

    destination_port = 0

    if TCP in first_packet:
        destination_port = first_packet[TCP].dport

    elif UDP in first_packet:
        destination_port = first_packet[UDP].dport

    return {
        "destination_port": destination_port,

        "flow_duration": duration,

        "total_fwd_packets":
            len(forward_packets),

        "total_backward_packets":
            len(backward_packets),

        "total_length_of_fwd_packets":
            forward_bytes,

        "total_length_of_bwd_packets":
            backward_bytes,

        "flow_bytes_s":
            (forward_bytes + backward_bytes) / duration,

        "flow_packets_s":
            len(packets) / duration,

        "source_ip":
            first_src_ip,

        "destination_ip":
            first_packet[IP].dst,

        "protocol":
            first_packet[IP].proto,

        "packet_count":
            len(packets)
    }


def print_flows():

    print()
    print("=" * 70)
    print("NETWORK FLOWS")
    print("=" * 70)

    for key, packets in flows.items():

        flow = summarize_flow(
            key,
            packets
        )

        print()
        print(
            f"{flow['source_ip']} → "
            f"{flow['destination_ip']}"
        )

        print(
            f"Destination Port: "
            f"{flow['destination_port']}"
        )

        print(
            f"Protocol: "
            f"{flow['protocol']}"
        )

        print(
            f"Packets: "
            f"{flow['packet_count']}"
        )

        print(
            f"Forward Packets: "
            f"{flow['total_fwd_packets']}"
        )

        print(
            f"Backward Packets: "
            f"{flow['total_backward_packets']}"
        )

        print(
            f"Forward Bytes: "
            f"{flow['total_length_of_fwd_packets']}"
        )

        print(
            f"Backward Bytes: "
            f"{flow['total_length_of_bwd_packets']}"
        )

        print(
            f"Flow Duration: "
            f"{flow['flow_duration']:.6f}"
        )


def start_capture(packet_count=50):

    print("=" * 70)
    print("AI CYBERSECURITY FLOW EXTRACTOR")
    print("=" * 70)

    print(
        f"Capturing {packet_count} packets..."
    )

    sniff(
        prn=process_packet,
        count=packet_count,
        store=False
    )

    print_flows()


if __name__ == "__main__":

    start_capture(50)