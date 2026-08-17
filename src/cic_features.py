import math
import statistics


def safe_mean(values):
    if not values:
        return 0.0
    return sum(values) / len(values)


def safe_std(values):
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def safe_min(values):
    if not values:
        return 0.0
    return min(values)


def safe_max(values):
    if not values:
        return 0.0
    return max(values)


def calculate_iat(packets):
    """
    Calculate inter-arrival times between packets.
    """

    if len(packets) < 2:
        return []

    timestamps = sorted(
        float(packet.time)
        for packet in packets
    )

    return [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]


def calculate_packet_lengths(packets):

    return [
        len(packet)
        for packet in packets
    ]


def calculate_tcp_flags(packets):

    flags = {
        "fin": 0,
        "syn": 0,
        "rst": 0,
        "psh": 0,
        "ack": 0,
        "urg": 0,
        "ece": 0,
        "cwe": 0
    }

    for packet in packets:

        if not packet.haslayer("TCP"):
            continue

        tcp = packet["TCP"]

        flag_string = str(tcp.flags)

        if "F" in flag_string:
            flags["fin"] += 1

        if "S" in flag_string:
            flags["syn"] += 1

        if "R" in flag_string:
            flags["rst"] += 1

        if "P" in flag_string:
            flags["psh"] += 1

        if "A" in flag_string:
            flags["ack"] += 1

        if "U" in flag_string:
            flags["urg"] += 1

        if "E" in flag_string:
            flags["ece"] += 1

        if "C" in flag_string:
            flags["cwe"] += 1

    return flags


def extract_cic_features(
    packets,
    forward_packets,
    backward_packets,
    destination_port
):
    """
    Convert captured packets into CIC-IDS2017-style
    network-flow features.
    """

    if not packets:
        raise ValueError(
            "No packets supplied."
        )

    first_time = min(
        float(packet.time)
        for packet in packets
    )

    last_time = max(
        float(packet.time)
        for packet in packets
    )

    flow_duration = (
        last_time - first_time
    )

    if flow_duration <= 0:
        flow_duration = 0.000001

    # ---------------------------------------------------------
    # Packet lengths
    # ---------------------------------------------------------

    fwd_lengths = calculate_packet_lengths(
        forward_packets
    )

    bwd_lengths = calculate_packet_lengths(
        backward_packets
    )

    all_lengths = (
        fwd_lengths +
        bwd_lengths
    )

    # ---------------------------------------------------------
    # Inter-arrival times
    # ---------------------------------------------------------

    flow_iat = calculate_iat(
        packets
    )

    fwd_iat = calculate_iat(
        forward_packets
    )

    bwd_iat = calculate_iat(
        backward_packets
    )

    # ---------------------------------------------------------
    # Bytes
    # ---------------------------------------------------------

    total_fwd_bytes = sum(
        fwd_lengths
    )

    total_bwd_bytes = sum(
        bwd_lengths
    )

    # ---------------------------------------------------------
    # TCP flags
    # ---------------------------------------------------------

    flags = calculate_tcp_flags(
        packets
    )

    fwd_flags = calculate_tcp_flags(
        forward_packets
    )

    bwd_flags = calculate_tcp_flags(
        backward_packets
    )

    # ---------------------------------------------------------
    # Header lengths
    # ---------------------------------------------------------

    fwd_header_length = 0

    for packet in forward_packets:

        if packet.haslayer("TCP"):

            fwd_header_length += (
                int(packet["TCP"].dataofs or 5)
                * 4
            )

        elif packet.haslayer("UDP"):

            fwd_header_length += 8

    bwd_header_length = 0

    for packet in backward_packets:

        if packet.haslayer("TCP"):

            bwd_header_length += (
                int(packet["TCP"].dataofs or 5)
                * 4
            )

        elif packet.haslayer("UDP"):

            bwd_header_length += 8

    # ---------------------------------------------------------
    # Rates
    # ---------------------------------------------------------

    total_packets = len(
        packets
    )

    flow_bytes = (
        total_fwd_bytes +
        total_bwd_bytes
    )

    flow_bytes_s = (
        flow_bytes /
        flow_duration
    )

    flow_packets_s = (
        total_packets /
        flow_duration
    )

    fwd_packets_s = (
        len(forward_packets) /
        flow_duration
    )

    bwd_packets_s = (
        len(backward_packets) /
        flow_duration
    )

    # ---------------------------------------------------------
    # Packet statistics
    # ---------------------------------------------------------

    packet_length_mean = safe_mean(
        all_lengths
    )

    packet_length_std = safe_std(
        all_lengths
    )

    packet_length_variance = (
        packet_length_std ** 2
    )

    average_packet_size = (
        packet_length_mean
    )

    # ---------------------------------------------------------
    # Down / up ratio
    # ---------------------------------------------------------

    if len(forward_packets) > 0:

        down_up_ratio = (
            len(backward_packets) /
            len(forward_packets)
        )

    else:

        down_up_ratio = 0.0

    # ---------------------------------------------------------
    # IAT statistics
    # ---------------------------------------------------------

    result = {

        "destination_port":
            destination_port,

        "flow_duration":
            flow_duration,

        "total_fwd_packets":
            len(forward_packets),

        "total_backward_packets":
            len(backward_packets),

        "total_length_of_fwd_packets":
            total_fwd_bytes,

        "total_length_of_bwd_packets":
            total_bwd_bytes,

        "fwd_packet_length_max":
            safe_max(fwd_lengths),

        "fwd_packet_length_min":
            safe_min(fwd_lengths),

        "fwd_packet_length_mean":
            safe_mean(fwd_lengths),

        "fwd_packet_length_std":
            safe_std(fwd_lengths),

        "bwd_packet_length_max":
            safe_max(bwd_lengths),

        "bwd_packet_length_min":
            safe_min(bwd_lengths),

        "bwd_packet_length_mean":
            safe_mean(bwd_lengths),

        "bwd_packet_length_std":
            safe_std(bwd_lengths),

        "flow_bytes_s":
            flow_bytes_s,

        "flow_packets_s":
            flow_packets_s,

        "flow_iat_mean":
            safe_mean(flow_iat),

        "flow_iat_std":
            safe_std(flow_iat),

        "flow_iat_max":
            safe_max(flow_iat),

        "flow_iat_min":
            safe_min(flow_iat),

        "fwd_iat_total":
            sum(fwd_iat),

        "fwd_iat_mean":
            safe_mean(fwd_iat),

        "fwd_iat_std":
            safe_std(fwd_iat),

        "fwd_iat_max":
            safe_max(fwd_iat),

        "fwd_iat_min":
            safe_min(fwd_iat),

        "bwd_iat_total":
            sum(bwd_iat),

        "bwd_iat_mean":
            safe_mean(bwd_iat),

        "bwd_iat_std":
            safe_std(bwd_iat),

        "bwd_iat_max":
            safe_max(bwd_iat),

        "bwd_iat_min":
            safe_min(bwd_iat),

        "fwd_psh_flags":
            fwd_flags["psh"],

        "bwd_psh_flags":
            bwd_flags["psh"],

        "fwd_urg_flags":
            fwd_flags["urg"],

        "bwd_urg_flags":
            bwd_flags["urg"],

        "fwd_header_length":
            fwd_header_length,

        "bwd_header_length":
            bwd_header_length,

        "fwd_packets_s":
            fwd_packets_s,

        "bwd_packets_s":
            bwd_packets_s,

        "min_packet_length":
            safe_min(all_lengths),

        "max_packet_length":
            safe_max(all_lengths),

        "packet_length_mean":
            packet_length_mean,

        "packet_length_std":
            packet_length_std,

        "packet_length_variance":
            packet_length_variance,

        "fin_flag_count":
            flags["fin"],

        "syn_flag_count":
            flags["syn"],

        "rst_flag_count":
            flags["rst"],

        "psh_flag_count":
            flags["psh"],

        "ack_flag_count":
            flags["ack"],

        "urg_flag_count":
            flags["urg"],

        "cwe_flag_count":
            flags["cwe"],

        "ece_flag_count":
            flags["ece"],

        "down_up_ratio":
            down_up_ratio,

        "average_packet_size":
            average_packet_size,

        "avg_fwd_segment_size":
            safe_mean(fwd_lengths),

        "avg_bwd_segment_size":
            safe_mean(bwd_lengths),

        "fwd_header_length.1":
            fwd_header_length,

        "fwd_avg_bytes_bulk":
            0.0,

        "fwd_avg_packets_bulk":
            0.0,

        "fwd_avg_bulk_rate":
            0.0,

        "bwd_avg_bytes_bulk":
            0.0,

        "bwd_avg_packets_bulk":
            0.0,

        "bwd_avg_bulk_rate":
            0.0,

        "subflow_fwd_packets":
            len(forward_packets),

        "subflow_fwd_bytes":
            total_fwd_bytes,

        "subflow_bwd_packets":
            len(backward_packets),

        "subflow_bwd_bytes":
            total_bwd_bytes,

        "init_win_bytes_forward":
            0.0,

        "init_win_bytes_backward":
            0.0,

        "act_data_pkt_fwd":
            len(forward_packets),

        "min_seg_size_forward":
            safe_min(fwd_lengths),

        "active_mean":
            0.0,

        "active_std":
            0.0,

        "active_max":
            0.0,

        "active_min":
            0.0,

        "idle_mean":
            0.0,

        "idle_std":
            0.0,

        "idle_max":
            0.0,

        "idle_min":
            0.0
    }

    return result