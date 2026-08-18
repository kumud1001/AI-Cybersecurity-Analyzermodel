"""
packet_parser.py

Convert Scapy packets into structured cybersecurity features.

Input:
    Scapy packet

Output:
    Dictionary containing network features
"""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from datetime import datetime


def get_protocol(packet):
    """
    Identify packet protocol
    """

    if packet.haslayer(TCP):
        return "TCP"

    elif packet.haslayer(UDP):
        return "UDP"

    elif packet.haslayer(ARP):
        return "ARP"

    elif packet.haslayer(IPv6):
        return "IPv6"

    elif packet.haslayer(IP):
        return "IP"

    else:
        return "OTHER"



def parse_packet(packet):
    """
    Main packet parser

    Args:
        packet: Scapy packet

    Returns:
        dict
    """

    data = {

        # Time information
        "timestamp": datetime.now().isoformat(),

        # Packet size
        "packet_size": len(packet),

        # Protocol
        "protocol": get_protocol(packet),

        # Default values
        "src_ip": None,
        "dst_ip": None,

        "src_port": None,
        "dst_port": None,

        "src_mac": None,
        "dst_mac": None,

        "tcp_flags": None,

        "payload_size": 0
    }


    # Ethernet layer

    if packet.haslayer(Ether):

        data["src_mac"] = packet[Ether].src
        data["dst_mac"] = packet[Ether].dst



    # IPv4 layer

    if packet.haslayer(IP):

        ip_layer = packet[IP]

        data["src_ip"] = ip_layer.src
        data["dst_ip"] = ip_layer.dst



    # IPv6 layer

    elif packet.haslayer(IPv6):

        ipv6_layer = packet[IPv6]

        data["src_ip"] = ipv6_layer.src
        data["dst_ip"] = ipv6_layer.dst



    # TCP information

    if packet.haslayer(TCP):

        tcp = packet[TCP]

        data["src_port"] = tcp.sport
        data["dst_port"] = tcp.dport

        data["tcp_flags"] = str(tcp.flags)

        data["payload_size"] = len(tcp.payload)



    # UDP information

    elif packet.haslayer(UDP):

        udp = packet[UDP]

        data["src_port"] = udp.sport
        data["dst_port"] = udp.dport

        data["payload_size"] = len(udp.payload)



    return data



# Test function

if __name__ == "__main__":

    from scapy.all import sniff


    def packet_handler(packet):

        parsed = parse_packet(packet)

        print(parsed)


    print("Starting packet parser test...")

    sniff(
        prn=packet_handler,
        count=10,
        store=False
    )