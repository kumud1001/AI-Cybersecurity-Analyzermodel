import os
import joblib
import pandas as pd
import numpy as np


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = (
    "models/xgboost.pkl"
)

LABEL_PATH = (
    "data/processed/ml/label_classes.csv"
)


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading XGBoost model...")

model = joblib.load(
    MODEL_PATH
)

print("XGBoost model loaded.")


# ============================================================
# LOAD LABEL MAPPING
# ============================================================

label_mapping = pd.read_csv(
    LABEL_PATH
)

label_classes = (
    label_mapping["attack_label"]
    .tolist()
)


# ============================================================
# MODEL FEATURES
# ============================================================

MODEL_FEATURES = [
    "destination_port",
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "flow_bytes_s",
    "flow_packets_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    "fwd_psh_flags",
    "bwd_psh_flags",
    "fwd_urg_flags",
    "bwd_urg_flags",
    "fwd_header_length",
    "bwd_header_length",
    "fwd_packets_s",
    "bwd_packets_s",
    "min_packet_length",
    "max_packet_length",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "cwe_flag_count",
    "ece_flag_count",
    "down_up_ratio",
    "average_packet_size",
    "avg_fwd_segment_size",
    "avg_bwd_segment_size",
    "fwd_header_length.1",
    "fwd_avg_bytes_bulk",
    "fwd_avg_packets_bulk",
    "fwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk",
    "bwd_avg_packets_bulk",
    "bwd_avg_bulk_rate",
    "subflow_fwd_packets",
    "subflow_fwd_bytes",
    "subflow_bwd_packets",
    "subflow_bwd_bytes",
    "init_win_bytes_forward",
    "init_win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "active_mean",
    "active_std",
    "active_max",
    "active_min",
    "idle_mean",
    "idle_std",
    "idle_max",
    "idle_min"
]


# ============================================================
# SEVERITY
# ============================================================

def calculate_severity(
    attack_type: str,
    confidence: float
):

    if attack_type.upper() == "BENIGN":
        return "LOW"

    if confidence >= 0.90:
        return "CRITICAL"

    if confidence >= 0.75:
        return "HIGH"

    if confidence >= 0.50:
        return "MEDIUM"

    return "LOW"


# ============================================================
# PREDICTION
# ============================================================

def predict_attack(
    flow_data: dict
):

    row = {}

    for feature in MODEL_FEATURES:

        value = flow_data.get(
            feature,
            0
        )

        row[feature] = value

    df = pd.DataFrame(
        [row],
        columns=MODEL_FEATURES
    )

    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    df = df.fillna(0)

    probabilities = (
        model.predict_proba(df)[0]
    )

    predicted_class = int(
        np.argmax(probabilities)
    )

    confidence = float(
        probabilities[predicted_class]
    )

    if (
        predicted_class
        < len(label_classes)
    ):

        attack_type = (
            label_classes[
                predicted_class
            ]
        )

    else:

        attack_type = (
            str(predicted_class)
        )

    severity = calculate_severity(
        attack_type,
        confidence
    )

    # Risk score
    if attack_type.upper() == "BENIGN":

        risk_score = 0.0

    else:

        risk_score = confidence

    return {
        "attack_type": attack_type,
        "confidence": round(
            confidence,
            4
        ),
        "severity": severity,
        "risk_score": round(
            risk_score,
            4
        )
    }