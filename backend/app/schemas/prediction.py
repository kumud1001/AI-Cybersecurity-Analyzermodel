from pydantic import BaseModel, Field


class NetworkFlow(BaseModel):

    destination_port: float = Field(
        default=0
    )

    flow_duration: float = Field(
        default=0
    )

    total_fwd_packets: float = Field(
        default=0
    )

    total_backward_packets: float = Field(
        default=0
    )

    total_length_of_fwd_packets: float = Field(
        default=0
    )

    total_length_of_bwd_packets: float = Field(
        default=0
    )

    flow_bytes_s: float = Field(
        default=0
    )

    flow_packets_s: float = Field(
        default=0
    )

    syn_flag_count: float = Field(
        default=0
    )

    ack_flag_count: float = Field(
        default=0
    )

    fin_flag_count: float = Field(
        default=0
    )

    rst_flag_count: float = Field(
        default=0
    )

    average_packet_size: float = Field(
        default=0
    )


class PredictionResponse(BaseModel):

    attack_type: str

    confidence: float

    severity: str

    risk_score: float