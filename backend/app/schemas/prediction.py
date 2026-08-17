from pydantic import BaseModel


class NetworkFlow(BaseModel):
    destination_port: float = 0
    flow_duration: float = 0
    total_fwd_packets: float = 0
    total_backward_packets: float = 0
    total_length_of_fwd_packets: float = 0
    total_length_of_bwd_packets: float = 0
    fwd_packet_length_max: float = 0
    fwd_packet_length_min: float = 0
    fwd_packet_length_mean: float = 0
    fwd_packet_length_std: float = 0
    bwd_packet_length_max: float = 0
    bwd_packet_length_min: float = 0
    bwd_packet_length_mean: float = 0
    bwd_packet_length_std: float = 0
    flow_bytes_s: float = 0
    flow_packets_s: float = 0
    flow_iat_mean: float = 0
    flow_iat_std: float = 0
    flow_iat_max: float = 0
    flow_iat_min: float = 0
    fwd_iat_total: float = 0
    fwd_iat_mean: float = 0
    fwd_iat_std: float = 0
    fwd_iat_max: float = 0
    fwd_iat_min: float = 0
    bwd_iat_total: float = 0
    bwd_iat_mean: float = 0
    bwd_iat_std: float = 0
    bwd_iat_max: float = 0
    bwd_iat_min: float = 0
    fwd_psh_flags: float = 0
    bwd_psh_flags: float = 0
    fwd_urg_flags: float = 0
    bwd_urg_flags: float = 0
    fwd_header_length: float = 0
    bwd_header_length: float = 0
    fwd_packets_s: float = 0
    bwd_packets_s: float = 0
    min_packet_length: float = 0
    max_packet_length: float = 0
    packet_length_mean: float = 0
    packet_length_std: float = 0
    packet_length_variance: float = 0
    fin_flag_count: float = 0
    syn_flag_count: float = 0
    rst_flag_count: float = 0
    psh_flag_count: float = 0
    ack_flag_count: float = 0
    urg_flag_count: float = 0
    cwe_flag_count: float = 0
    ece_flag_count: float = 0
    down_up_ratio: float = 0
    average_packet_size: float = 0
    avg_fwd_segment_size: float = 0
    avg_bwd_segment_size: float = 0
    fwd_header_length_1: float = 0
    fwd_avg_bytes_bulk: float = 0
    fwd_avg_packets_bulk: float = 0
    fwd_avg_bulk_rate: float = 0
    bwd_avg_bytes_bulk: float = 0
    bwd_avg_packets_bulk: float = 0
    bwd_avg_bulk_rate: float = 0
    subflow_fwd_packets: float = 0
    subflow_fwd_bytes: float = 0
    subflow_bwd_packets: float = 0
    subflow_bwd_bytes: float = 0
    init_win_bytes_forward: float = 0
    init_win_bytes_backward: float = 0
    act_data_pkt_fwd: float = 0
    min_seg_size_forward: float = 0
    active_mean: float = 0
    active_std: float = 0
    active_max: float = 0
    active_min: float = 0
    idle_mean: float = 0
    idle_std: float = 0
    idle_max: float = 0
    idle_min: float = 0


class PredictionResponse(BaseModel):
    attack_type: str
    confidence: float
    severity: str
    risk_score: float