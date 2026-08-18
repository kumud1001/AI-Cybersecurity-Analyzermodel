"""
features.py

Convert parsed network packets into
machine learning features for anomaly detection.
"""


from collections import defaultdict
import time


# Track traffic statistics
traffic_stats = {

    "packet_count": 0,

    "total_bytes": 0,

    "src_ip_count": defaultdict(int),

    "dst_ip_count": defaultdict(int),

    "dst_port_count": defaultdict(int)

}


def extract_features(packet_data):
    """
    Convert parsed packet into ML features

    Input:
        packet_data from packet_parser.py

    Output:
        ML feature dictionary
    """


    features = {}


    # Basic packet features

    features["packet_size"] = packet_data.get(
        "packet_size",
        0
    )


    features["protocol"] = encode_protocol(
        packet_data.get("protocol")
    )


    features["src_port"] = packet_data.get(
        "src_port",
        0
    ) or 0


    features["dst_port"] = packet_data.get(
        "dst_port",
        0
    ) or 0



    # TCP flag features

    flags = packet_data.get(
        "tcp_flags"
    )


    features["syn_flag"] = 1 if flags and "S" in flags else 0

    features["ack_flag"] = 1 if flags and "A" in flags else 0

    features["fin_flag"] = 1 if flags and "F" in flags else 0

    features["rst_flag"] = 1 if flags and "R" in flags else 0



    # Payload information

    features["payload_size"] = packet_data.get(
        "payload_size",
        0
    )



    # Traffic statistics

    src_ip = packet_data.get("src_ip")

    dst_ip = packet_data.get("dst_ip")

    dst_port = packet_data.get("dst_port")



    traffic_stats["packet_count"] += 1


    traffic_stats["total_bytes"] += (
        packet_data.get("packet_size",0)
    )



    if src_ip:

        traffic_stats["src_ip_count"][src_ip] += 1



    if dst_ip:

        traffic_stats["dst_ip_count"][dst_ip] += 1



    if dst_port:

        traffic_stats["dst_port_count"][dst_port] += 1



    # Network behavior features

    features["packets_seen"] = (
        traffic_stats["packet_count"]
    )


    features["total_bytes"] = (
        traffic_stats["total_bytes"]
    )


    features["src_ip_frequency"] = (
        traffic_stats["src_ip_count"].get(src_ip,0)
    )


    features["dst_ip_frequency"] = (
        traffic_stats["dst_ip_count"].get(dst_ip,0)
    )


    features["dst_port_frequency"] = (
        traffic_stats["dst_port_count"].get(dst_port,0)
    )


    return features



def encode_protocol(protocol):

    """
    Convert protocol name to numeric value
    """

    mapping = {

        "TCP": 6,

        "UDP": 17,

        "ARP": 1,

        "IPv6": 41,

        "IP": 0,

        "OTHER": -1

    }


    return mapping.get(
        protocol,
        -1
    )



if __name__ == "__main__":


    from packet_parser import parse_packet
    from scapy.all import sniff



    def process(packet):

        parsed = parse_packet(packet)

        features = extract_features(parsed)

        print("\nParsed:")
        print(parsed)

        print("\nML Features:")
        print(features)



    print("Starting feature extraction...")


    sniff(
        prn=process,
        count=10,
        store=False
    )