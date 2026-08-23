import os
import sys
import time
import signal
import traceback
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import requests
import matplotlib.pyplot as plt

from scapy.all import sniff, IP, TCP, UDP


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "xgboost.pkl"
)

RESULTS_DIR = os.path.join(
    PROJECT_ROOT,
    "live_results"
)

GRAPH_DIR = os.path.join(
    RESULTS_DIR,
    "graphs"
)

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(GRAPH_DIR, exist_ok=True)


# ============================================================
# API CONFIGURATION
# ============================================================

API_URL = "http://127.0.0.1:8000/api/analyze"


# ============================================================
# LIVE MONITOR SETTINGS
# ============================================================

ANALYSIS_INTERVAL = 10

DUPLICATE_WINDOW = 60

RUNNING = True


# ============================================================
# XGBOOST EXPECTED FEATURES
# ============================================================

EXPECTED_FEATURES = [
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
    "idle_min",
]


# ============================================================
# ATTACK LABELS
# ============================================================

CLASS_NAMES = {
    0: "BENIGN",
    1: "FTP-Patator",
    2: "SSH-Patator",
    3: "DoS slowloris",
    4: "DoS Slowhttptest",
    5: "DoS Hulk",
    6: "DoS GoldenEye",
    7: "Heartbleed",
    8: "Web Attack",
    9: "Infiltration",
    10: "Bot",
    11: "PortScan",
    12: "DDoS",
}


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 70)
print("LOADING XGBOOST MODEL")
print("=" * 70)

try:
    model = joblib.load(MODEL_PATH)

    print("XGBoost model loaded successfully.")

except Exception as exc:

    print("ERROR: Could not load XGBoost model.")
    print(exc)

    sys.exit(1)


# ============================================================
# CHECK MODEL FEATURES
# ============================================================

try:

    model_features = list(model.feature_names_in_)

except Exception:

    model_features = EXPECTED_FEATURES.copy()


print(f"Expected features: {len(model_features)}")

if len(model_features) != 78:

    print(
        f"WARNING: Model reports {len(model_features)} "
        f"features instead of 78."
    )


# ============================================================
# STORAGE
# ============================================================

live_records = []

seen_flows = {}

flow_counter = 0

start_time = datetime.now()


# ============================================================
# SIGNAL HANDLER
# ============================================================

def stop_monitor(signal_number=None, frame=None):

    global RUNNING

    if not RUNNING:
        return

    print()
    print("=" * 70)
    print("STOPPING LIVE MONITOR")
    print("=" * 70)

    RUNNING = False


signal.signal(signal.SIGINT, stop_monitor)


# ============================================================
# SAFE PRINT
# ============================================================

def safe_print(text):

    """
    Windows-safe console printing.
    Avoids the charmap error caused by Unicode arrows.
    """

    try:

        print(text)

    except UnicodeEncodeError:

        print(
            text.replace("→", "->")
                .replace("←", "<-")
        )


# ============================================================
# FLOW KEY
# ============================================================

def get_flow_key(packet):

    if IP not in packet:

        return None

    src = packet[IP].src
    dst = packet[IP].dst

    protocol = "OTHER"

    sport = 0
    dport = 0

    if TCP in packet:

        protocol = "TCP"

        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)

    elif UDP in packet:

        protocol = "UDP"

        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)

    return (
        src,
        dst,
        sport,
        dport,
        protocol
    )


# ============================================================
# PACKET COLLECTION
# ============================================================

current_packets = []


def packet_callback(packet):

    if IP not in packet:

        return

    current_packets.append(packet)


# ============================================================
# BASIC FLOW FEATURE EXTRACTION
# ============================================================

def calculate_flow_features(packets):

    """
    Calculate the 78 CIC-IDS2017/XGBoost-compatible features
    from captured Scapy packets.

    The first packet source is treated as the forward direction.
    All packets from the opposite source are treated as backward.
    """

    if not packets:
        return None

    rows = []

    # ---------------------------------------------------------
    # Build packet dataframe
    # ---------------------------------------------------------

    for packet in packets:

        if IP not in packet:
            continue

        try:
            timestamp = float(
                getattr(packet, "time", time.time())
            )
        except Exception:
            timestamp = time.time()

        length = float(len(packet))

        protocol = 0
        sport = 0
        dport = 0

        if TCP in packet:

            protocol = 6
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)

        elif UDP in packet:

            protocol = 17
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)

        rows.append(
            {
                "time": timestamp,
                "length": length,
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "sport": sport,
                "dport": dport,
                "protocol": protocol,
            }
        )

    if not rows:
        return None

    df = pd.DataFrame(rows)

    # ---------------------------------------------------------
    # Make absolutely sure length exists
    # ---------------------------------------------------------

    if "length" not in df.columns:
        df["length"] = 0.0

    df["length"] = pd.to_numeric(
        df["length"],
        errors="coerce"
    ).fillna(0.0)

    # ---------------------------------------------------------
    # Flow duration
    # ---------------------------------------------------------

    duration = max(
        float(df["time"].max() - df["time"].min()),
        0.000001
    )

    # ---------------------------------------------------------
    # Forward / backward direction
    # ---------------------------------------------------------

    first_src = df.iloc[0]["src"]

    fwd = df[
        df["src"] == first_src
    ].copy()

    bwd = df[
        df["src"] != first_src
    ].copy()

    # ---------------------------------------------------------
    # Safety protection for empty dataframes
    # ---------------------------------------------------------

    if "length" not in fwd.columns:
        fwd["length"] = 0.0

    if "length" not in bwd.columns:
        bwd["length"] = 0.0

    if "time" not in fwd.columns:
        fwd["time"] = pd.Series(
            dtype="float64"
        )

    if "time" not in bwd.columns:
        bwd["time"] = pd.Series(
            dtype="float64"
        )

    # ---------------------------------------------------------
    # Length series
    # ---------------------------------------------------------

    if len(fwd) > 0:

        fwd_lengths = fwd["length"]

    else:

        fwd_lengths = pd.Series(
            [0.0],
            dtype="float64"
        )

    if len(bwd) > 0:

        bwd_lengths = bwd["length"]

    else:

        bwd_lengths = pd.Series(
            [0.0],
            dtype="float64"
        )

    all_lengths = df["length"]

    # ---------------------------------------------------------
    # Safe statistics
    # ---------------------------------------------------------

    def mean(series):

        if len(series) == 0:
            return 0.0

        return float(
            series.mean()
        )

    def std(series):

        if len(series) <= 1:
            return 0.0

        value = series.std()

        if pd.isna(value):
            return 0.0

        return float(value)

    def maxv(series):

        if len(series) == 0:
            return 0.0

        return float(
            series.max()
        )

    def minv(series):

        if len(series) == 0:
            return 0.0

        return float(
            series.min()
        )

    # ---------------------------------------------------------
    # Packet counts
    # ---------------------------------------------------------

    total_fwd_packets = len(fwd)

    total_bwd_packets = len(bwd)

    total_packets = len(df)

    # ---------------------------------------------------------
    # Byte counts
    # ---------------------------------------------------------

    total_fwd_bytes = float(
        fwd["length"].sum()
    )

    total_bwd_bytes = float(
        bwd["length"].sum()
    )

    total_bytes = float(
        df["length"].sum()
    )

    # ---------------------------------------------------------
    # Flow rates
    # ---------------------------------------------------------

    flow_bytes_s = (
        total_bytes / duration
    )

    flow_packets_s = (
        total_packets / duration
    )

    # ---------------------------------------------------------
    # Flow IAT
    # ---------------------------------------------------------

    iats = (
        df["time"]
        .sort_values()
        .diff()
        .dropna()
    )

    if len(iats) > 0:

        flow_iat_mean = mean(iats)
        flow_iat_std = std(iats)
        flow_iat_max = maxv(iats)
        flow_iat_min = minv(iats)

    else:

        flow_iat_mean = 0.0
        flow_iat_std = 0.0
        flow_iat_max = 0.0
        flow_iat_min = 0.0

    # ---------------------------------------------------------
    # Forward IAT
    # ---------------------------------------------------------

    if len(fwd) > 1:

        fwd_iats = (
            fwd["time"]
            .sort_values()
            .diff()
            .dropna()
        )

    else:

        fwd_iats = pd.Series(
            dtype="float64"
        )

    if len(fwd_iats) > 0:

        fwd_iat_total = float(
            fwd_iats.sum()
        )

        fwd_iat_mean = mean(
            fwd_iats
        )

        fwd_iat_std = std(
            fwd_iats
        )

        fwd_iat_max = maxv(
            fwd_iats
        )

        fwd_iat_min = minv(
            fwd_iats
        )

    else:

        fwd_iat_total = 0.0
        fwd_iat_mean = 0.0
        fwd_iat_std = 0.0
        fwd_iat_max = 0.0
        fwd_iat_min = 0.0

    # ---------------------------------------------------------
    # Backward IAT
    # ---------------------------------------------------------

    if len(bwd) > 1:

        bwd_iats = (
            bwd["time"]
            .sort_values()
            .diff()
            .dropna()
        )

    else:

        bwd_iats = pd.Series(
            dtype="float64"
        )

    if len(bwd_iats) > 0:

        bwd_iat_total = float(
            bwd_iats.sum()
        )

        bwd_iat_mean = mean(
            bwd_iats
        )

        bwd_iat_std = std(
            bwd_iats
        )

        bwd_iat_max = maxv(
            bwd_iats
        )

        bwd_iat_min = minv(
            bwd_iats
        )

    else:

        bwd_iat_total = 0.0
        bwd_iat_mean = 0.0
        bwd_iat_std = 0.0
        bwd_iat_max = 0.0
        bwd_iat_min = 0.0

    # ---------------------------------------------------------
    # TCP flags
    # ---------------------------------------------------------

    fin_flag_count = 0
    syn_flag_count = 0
    rst_flag_count = 0
    psh_flag_count = 0
    ack_flag_count = 0
    urg_flag_count = 0
    cwe_flag_count = 0
    ece_flag_count = 0

    fwd_psh_flags = 0
    bwd_psh_flags = 0

    fwd_urg_flags = 0
    bwd_urg_flags = 0

    # ---------------------------------------------------------
    # Inspect TCP flags
    # ---------------------------------------------------------

    for packet in packets:

        if TCP not in packet:
            continue

        flags = packet[TCP].flags

        if "F" in flags:
            fin_flag_count += 1

        if "S" in flags:
            syn_flag_count += 1

        if "R" in flags:
            rst_flag_count += 1

        if "P" in flags:
            psh_flag_count += 1

        if "A" in flags:
            ack_flag_count += 1

        if "U" in flags:
            urg_flag_count += 1

        if "C" in flags:
            cwe_flag_count += 1

        if "E" in flags:
            ece_flag_count += 1

        if IP in packet:

            if packet[IP].src == first_src:

                if "P" in flags:
                    fwd_psh_flags += 1

                if "U" in flags:
                    fwd_urg_flags += 1

            else:

                if "P" in flags:
                    bwd_psh_flags += 1

                if "U" in flags:
                    bwd_urg_flags += 1

    # ---------------------------------------------------------
    # Safe variance
    # ---------------------------------------------------------

    if len(all_lengths) > 1:

        packet_length_variance = float(
            all_lengths.var()
        )

    else:

        packet_length_variance = 0.0

    # ---------------------------------------------------------
    # Destination port
    # ---------------------------------------------------------

    destination_port = int(
        df.iloc[0]["dport"]
    )

    # ---------------------------------------------------------
    # Final 78 features
    # ---------------------------------------------------------

    features = {

        "destination_port":
            destination_port,

        "flow_duration":
            duration,

        "total_fwd_packets":
            total_fwd_packets,

        "total_backward_packets":
            total_bwd_packets,

        "total_length_of_fwd_packets":
            total_fwd_bytes,

        "total_length_of_bwd_packets":
            total_bwd_bytes,

        "fwd_packet_length_max":
            maxv(fwd_lengths),

        "fwd_packet_length_min":
            minv(fwd_lengths),

        "fwd_packet_length_mean":
            mean(fwd_lengths),

        "fwd_packet_length_std":
            std(fwd_lengths),

        "bwd_packet_length_max":
            maxv(bwd_lengths),

        "bwd_packet_length_min":
            minv(bwd_lengths),

        "bwd_packet_length_mean":
            mean(bwd_lengths),

        "bwd_packet_length_std":
            std(bwd_lengths),

        "flow_bytes_s":
            flow_bytes_s,

        "flow_packets_s":
            flow_packets_s,

        "flow_iat_mean":
            flow_iat_mean,

        "flow_iat_std":
            flow_iat_std,

        "flow_iat_max":
            flow_iat_max,

        "flow_iat_min":
            flow_iat_min,

        "fwd_iat_total":
            fwd_iat_total,

        "fwd_iat_mean":
            fwd_iat_mean,

        "fwd_iat_std":
            fwd_iat_std,

        "fwd_iat_max":
            fwd_iat_max,

        "fwd_iat_min":
            fwd_iat_min,

        "bwd_iat_total":
            bwd_iat_total,

        "bwd_iat_mean":
            bwd_iat_mean,

        "bwd_iat_std":
            bwd_iat_std,

        "bwd_iat_max":
            bwd_iat_max,

        "bwd_iat_min":
            bwd_iat_min,

        "fwd_psh_flags":
            fwd_psh_flags,

        "bwd_psh_flags":
            bwd_psh_flags,

        "fwd_urg_flags":
            fwd_urg_flags,

        "bwd_urg_flags":
            bwd_urg_flags,

        "fwd_header_length":
            total_fwd_packets * 20,

        "bwd_header_length":
            total_bwd_packets * 20,

        "fwd_packets_s":
            total_fwd_packets / duration,

        "bwd_packets_s":
            total_bwd_packets / duration,

        "min_packet_length":
            minv(all_lengths),

        "max_packet_length":
            maxv(all_lengths),

        "packet_length_mean":
            mean(all_lengths),

        "packet_length_std":
            std(all_lengths),

        "packet_length_variance":
            packet_length_variance,

        "fin_flag_count":
            fin_flag_count,

        "syn_flag_count":
            syn_flag_count,

        "rst_flag_count":
            rst_flag_count,

        "psh_flag_count":
            psh_flag_count,

        "ack_flag_count":
            ack_flag_count,

        "urg_flag_count":
            urg_flag_count,

        "cwe_flag_count":
            cwe_flag_count,

        "ece_flag_count":
            ece_flag_count,

        "down_up_ratio":
            total_bwd_packets /
            max(total_fwd_packets, 1),

        "average_packet_size":
            mean(all_lengths),

        "avg_fwd_segment_size":
            mean(fwd_lengths),

        "avg_bwd_segment_size":
            mean(bwd_lengths),

        "fwd_header_length.1":
            total_fwd_packets * 20,

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
            total_fwd_packets,

        "subflow_fwd_bytes":
            total_fwd_bytes,

        "subflow_bwd_packets":
            total_bwd_packets,

        "subflow_bwd_bytes":
            total_bwd_bytes,

        "init_win_bytes_forward":
            0.0,

        "init_win_bytes_backward":
            0.0,

        "act_data_pkt_fwd":
            total_fwd_packets,

        "min_seg_size_forward":
            20.0,

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
            0.0,
    }

    # ---------------------------------------------------------
    # Guarantee model compatibility
    # ---------------------------------------------------------

    for feature in model_features:

        if feature not in features:

            features[feature] = 0.0

    return features


# ============================================================
# MODEL PREDICTION
# ============================================================

def predict(features):

    row = pd.DataFrame(
        [features],
        columns=model_features
    )

    row = row.replace(
        [np.inf, -np.inf],
        0
    )

    row = row.fillna(0)

    probabilities = model.predict_proba(row)[0]

    prediction = int(
        np.argmax(probabilities)
    )

    confidence = float(
        probabilities[prediction]
    )

    attack_name = CLASS_NAMES.get(
        prediction,
        str(prediction)
    )

    return (
        prediction,
        attack_name,
        confidence,
        probabilities
    )


# ============================================================
# SEVERITY
# ============================================================

def calculate_severity(
    attack_name,
    confidence
):

    if attack_name == "BENIGN":

        return "LOW", 0

    if confidence >= 0.90:

        return "CRITICAL", 90

    if confidence >= 0.75:

        return "HIGH", 75

    if confidence >= 0.50:

        return "MEDIUM", 50

    return "LOW", 25


# ============================================================
# API SAVE
# ============================================================

def save_to_api(
    src_ip,
    dst_ip,
    port,
    packets,
    attack,
    confidence,
    severity,
    risk_score,
    class_id
):

    payload = {

        "source_ip": src_ip,

        "destination_ip": dst_ip,

        "port": int(port),

        "packets": int(packets),

        "attack": attack,

        "confidence": float(confidence),

        "severity": severity,

        "risk_score": int(risk_score),

        "class_id": int(class_id),

    }

    try:

        response = requests.post(
            API_URL,
            json=payload,
            timeout=5
        )

        if response.status_code in (200, 201):

            try:

                data = response.json()

                alert_id = (
                    data.get("id")
                    or data.get("alert_id")
                )

            except Exception:

                alert_id = None

            return True, alert_id

        return False, None

    except Exception as exc:

        safe_print(
            f"[API ERROR] {exc}"
        )

        return False, None


# ============================================================
# SAVE RAW FLOW
# ============================================================

def save_flow_record(record):

    live_records.append(record)

    path = os.path.join(
        RESULTS_DIR,
        "live_flows.csv"
    )

    df = pd.DataFrame(live_records)

    df.to_csv(
        path,
        index=False,
        encoding="utf-8-sig"
    )


# ============================================================
# TOP PREDICTIONS
# ============================================================

def get_top_predictions(probabilities):

    pairs = []

    for class_id, probability in enumerate(
        probabilities
    ):

        name = CLASS_NAMES.get(
            class_id,
            f"CLASS_{class_id}"
        )

        pairs.append(
            (
                name,
                float(probability)
            )
        )

    pairs.sort(
        key=lambda x: x[1],
        reverse=True
    )

    return pairs[:3]


# ============================================================
# ANALYZE FLOW
# ============================================================

def analyze_flow(
    flow_key,
    packets
):

    global flow_counter

    try:

        features = calculate_flow_features(
            packets
        )

        if features is None:

            return

        (
            class_id,
            attack_name,
            confidence,
            probabilities
        ) = predict(features)

        severity, risk_score = calculate_severity(
            attack_name,
            confidence
        )

        src_ip = flow_key[0]
        dst_ip = flow_key[1]

        sport = flow_key[2]
        dport = flow_key[3]

        protocol = flow_key[4]

        flow_counter += 1

        timestamp = datetime.now()

        top_predictions = get_top_predictions(
            probabilities
        )

        api_saved, alert_id = save_to_api(
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=dport,
            packets=len(packets),
            attack=attack_name,
            confidence=confidence,
            severity=severity,
            risk_score=risk_score,
            class_id=class_id
        )

        record = {

            "flow_id":
                flow_counter,

            "timestamp":
                timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "source_ip":
                src_ip,

            "destination_ip":
                dst_ip,

            "source_port":
                sport,

            "destination_port":
                dport,

            "protocol":
                protocol,

            "packets":
                len(packets),

            "attack":
                attack_name,

            "class_id":
                class_id,

            "confidence":
                confidence * 100,

            "severity":
                severity,

            "risk_score":
                risk_score,

            "database_saved":
                api_saved,

            "alert_id":
                alert_id,

            "top_prediction_1":
                top_predictions[0][0],

            "top_prediction_1_confidence":
                top_predictions[0][1] * 100,

            "top_prediction_2":
                top_predictions[1][0],

            "top_prediction_2_confidence":
                top_predictions[1][1] * 100,

            "top_prediction_3":
                top_predictions[2][0],

            "top_prediction_3_confidence":
                top_predictions[2][1] * 100,

        }

        save_flow_record(record)

        print()

        safe_print("=" * 70)

        safe_print(
            f"FLOW: {src_ip} -> {dst_ip}"
        )

        print(
            f"PORT: {dport}"
        )

        print(
            f"PROTOCOL: {protocol}"
        )

        print(
            f"PACKETS: {len(packets)}"
        )

        print(
            f"ATTACK: {attack_name}"
        )

        print(
            f"CONFIDENCE: "
            f"{confidence * 100:.2f}%"
        )

        print(
            f"SEVERITY: {severity}"
        )

        print(
            f"RISK SCORE: {risk_score}"
        )

        print(
            f"CLASS: {class_id}"
        )

        print(
            "TOP PREDICTIONS:"
        )

        for name, prob in top_predictions:

            print(
                f"  {name}: "
                f"{prob * 100:.2f}%"
            )

        print(
            f"DATABASE SAVED: "
            f"{api_saved}"
        )

        if alert_id is not None:

            print(
                f"ALERT ID: {alert_id}"
            )

        safe_print("=" * 70)

    except Exception as exc:

        safe_print(
            f"[FLOW ERROR] {exc}"
        )

        traceback.print_exc()


# ============================================================
# CAPTURE WINDOW
# ============================================================

def capture_window():

    global current_packets

    current_packets = []

    sniff(
        prn=packet_callback,
        store=False,
        timeout=ANALYSIS_INTERVAL
    )

    packets = current_packets

    current_packets = []

    return packets


# ============================================================
# PROCESS CAPTURED PACKETS
# ============================================================

def process_packets(packets):

    if not packets:

        return

    flows = {}

    for packet in packets:

        key = get_flow_key(packet)

        if key is None:

            continue

        flows.setdefault(
            key,
            []
        ).append(packet)

    now = time.time()

    for flow_key, flow_packets in flows.items():

        last_seen = seen_flows.get(
            flow_key
        )

        if (
            last_seen is not None
            and now - last_seen < DUPLICATE_WINDOW
        ):

            continue

        seen_flows[flow_key] = now

        safe_print(
            f"[NEW FLOW] {flow_key}"
        )

        analyze_flow(
            flow_key,
            flow_packets
        )

    # Remove old duplicate entries

    expired = [

        key

        for key, timestamp in seen_flows.items()

        if now - timestamp > DUPLICATE_WINDOW

    ]

    for key in expired:

        del seen_flows[key]


# ============================================================
# CSV REPORT HELPERS
# ============================================================

def save_group_table(
    df,
    column,
    filename
):

    if df.empty:

        return

    result = (
        df[column]
        .value_counts()
        .reset_index()
    )

    result.columns = [
        column,
        "count"
    ]

    result["percentage"] = (
        result["count"]
        / len(df)
        * 100
    )

    result.to_csv(
        os.path.join(
            RESULTS_DIR,
            filename
        ),
        index=False,
        encoding="utf-8-sig"
    )


# ============================================================
# GENERATE REPORT
# ============================================================

def generate_reports():

    print()
    print("=" * 70)
    print("GENERATING LIVE EXPERIMENT REPORT")
    print("=" * 70)

    path = os.path.join(
        RESULTS_DIR,
        "live_flows.csv"
    )

    if not os.path.exists(path):

        print(
            "No live flow data available."
        )

        return

    df = pd.read_csv(path)

    if df.empty:

        print(
            "Live flow file is empty."
        )

        return

    # --------------------------------------------------------
    # ATTACK DISTRIBUTION
    # --------------------------------------------------------

    save_group_table(
        df,
        "attack",
        "attack_distribution.csv"
    )

    # --------------------------------------------------------
    # SEVERITY
    # --------------------------------------------------------

    save_group_table(
        df,
        "severity",
        "severity_distribution.csv"
    )

    # --------------------------------------------------------
    # PROTOCOL
    # --------------------------------------------------------

    save_group_table(
        df,
        "protocol",
        "protocol_distribution.csv"
    )

    # --------------------------------------------------------
    # PORT
    # --------------------------------------------------------

    save_group_table(
        df,
        "destination_port",
        "port_distribution.csv"
    )

    # --------------------------------------------------------
    # TOP SOURCES
    # --------------------------------------------------------

    sources = (
        df["source_ip"]
        .value_counts()
        .reset_index()
    )

    sources.columns = [
        "source_ip",
        "flow_count"
    ]

    sources.head(20).to_csv(
        os.path.join(
            RESULTS_DIR,
            "top_sources.csv"
        ),
        index=False,
        encoding="utf-8-sig"
    )

    # --------------------------------------------------------
    # TOP DESTINATIONS
    # --------------------------------------------------------

    destinations = (
        df["destination_ip"]
        .value_counts()
        .reset_index()
    )

    destinations.columns = [
        "destination_ip",
        "flow_count"
    ]

    destinations.head(20).to_csv(
        os.path.join(
            RESULTS_DIR,
            "top_destinations.csv"
        ),
        index=False,
        encoding="utf-8-sig"
    )

    # --------------------------------------------------------
    # CONFIDENCE STATISTICS
    # --------------------------------------------------------

    confidence = df["confidence"]

    confidence_table = pd.DataFrame(
        {
            "metric": [
                "mean",
                "median",
                "minimum",
                "maximum",
                "standard_deviation",
            ],

            "value": [
                confidence.mean(),
                confidence.median(),
                confidence.min(),
                confidence.max(),
                confidence.std(),
            ]
        }
    )

    confidence_table.to_csv(
        os.path.join(
            RESULTS_DIR,
            "confidence_statistics.csv"
        ),
        index=False,
        encoding="utf-8-sig"
    )

    # --------------------------------------------------------
    # RISK DISTRIBUTION
    # --------------------------------------------------------

    risk_bins = [
        -1,
        24,
        49,
        74,
        100
    ]

    risk_labels = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    risk_categories = pd.cut(
        df["risk_score"],
        bins=risk_bins,
        labels=risk_labels
    )

    risk_table = (
        risk_categories
        .value_counts()
        .sort_index()
        .reset_index()
    )

    risk_table.columns = [
        "risk_category",
        "count"
    ]

    risk_table["percentage"] = (
        risk_table["count"]
        / len(df)
        * 100
    )

    risk_table.to_csv(
        os.path.join(
            RESULTS_DIR,
            "risk_distribution.csv"
        ),
        index=False,
        encoding="utf-8-sig"
    )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    runtime_seconds = (
        datetime.now() - start_time
    ).total_seconds()

    summary = pd.DataFrame(
        {
            "metric": [

                "total_flows",

                "total_packets",

                "average_packets_per_flow",

                "maximum_packets_per_flow",

                "minimum_packets_per_flow",

                "average_confidence_percent",

                "minimum_confidence_percent",

                "maximum_confidence_percent",

                "average_risk_score",

                "maximum_risk_score",

                "runtime_seconds",

                "database_saved_flows",

                "database_failed_flows",

            ],

            "value": [

                len(df),

                df["packets"].sum(),

                df["packets"].mean(),

                df["packets"].max(),

                df["packets"].min(),

                df["confidence"].mean(),

                df["confidence"].min(),

                df["confidence"].max(),

                df["risk_score"].mean(),

                df["risk_score"].max(),

                runtime_seconds,

                df["database_saved"].astype(str)
                .str.lower()
                .eq("true")
                .sum(),

                df["database_saved"].astype(str)
                .str.lower()
                .eq("false")
                .sum(),

            ]
        }
    )

    summary.to_csv(
        os.path.join(
            RESULTS_DIR,
            "live_summary.csv"
        ),
        index=False,
        encoding="utf-8-sig"
    )

    # ========================================================
    # GRAPH 1
    # ATTACK DISTRIBUTION
    # ========================================================

    plt.figure(
        figsize=(12, 7)
    )

    attack_counts = (
        df["attack"]
        .value_counts()
    )

    attack_counts.plot(
        kind="bar"
    )

    plt.title(
        "Live Network Attack Classification"
    )

    plt.xlabel(
        "Attack Class"
    )

    plt.ylabel(
        "Number of Flows"
    )

    plt.xticks(
        rotation=45,
        ha="right"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "01_attack_distribution.png"
        ),
        dpi=300
    )

    plt.close()

    # ========================================================
    # GRAPH 2
    # SEVERITY DISTRIBUTION
    # ========================================================

    plt.figure(
        figsize=(10, 7)
    )

    severity_counts = (
        df["severity"]
        .value_counts()
        .reindex(
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ],
            fill_value=0
        )
    )

    severity_counts.plot(
        kind="bar"
    )

    plt.title(
        "Live Security Alert Severity"
    )

    plt.xlabel(
        "Severity"
    )

    plt.ylabel(
        "Number of Flows"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "02_severity_distribution.png"
        ),
        dpi=300
    )

    plt.close()

    # ========================================================
    # GRAPH 3
    # CONFIDENCE DISTRIBUTION
    # ========================================================

    plt.figure(
        figsize=(10, 7)
    )

    plt.hist(
        df["confidence"],
        bins=20
    )

    plt.title(
        "XGBoost Prediction Confidence"
    )

    plt.xlabel(
        "Confidence (%)"
    )

    plt.ylabel(
        "Number of Flows"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "03_confidence_distribution.png"
        ),
        dpi=300
    )

    plt.close()

    # ========================================================
    # GRAPH 4
    # RISK DISTRIBUTION
    # ========================================================

    plt.figure(
        figsize=(10, 7)
    )

    df["risk_score"].plot(
        kind="hist",
        bins=10
    )

    plt.title(
        "Live Network Risk Score Distribution"
    )

    plt.xlabel(
        "Risk Score"
    )

    plt.ylabel(
        "Number of Flows"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "04_risk_distribution.png"
        ),
        dpi=300
    )

    plt.close()

    # ========================================================
    # GRAPH 5
    # PACKETS PER FLOW
    # ========================================================

    plt.figure(
        figsize=(12, 7)
    )

    plt.hist(
        df["packets"],
        bins=30
    )

    plt.title(
        "Packets per Network Flow"
    )

    plt.xlabel(
        "Packets"
    )

    plt.ylabel(
        "Number of Flows"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "05_packets_per_flow.png"
        ),
        dpi=300
    )

    plt.close()

    # ========================================================
    # GRAPH 6
    # PREDICTIONS OVER TIME
    # ========================================================

    time_df = df.copy()

    time_df["timestamp"] = pd.to_datetime(
        time_df["timestamp"],
        errors="coerce"
    )

    time_df = (
        time_df
        .dropna(
            subset=["timestamp"]
        )
        .sort_values("timestamp")
    )

    if len(time_df):

        time_df["flow_number"] = (
            np.arange(len(time_df)) + 1
        )

        plt.figure(
            figsize=(14, 7)
        )

        plt.plot(
            time_df["flow_number"],
            time_df["confidence"]
        )

        plt.title(
            "Live Prediction Confidence Over Time"
        )

        plt.xlabel(
            "Flow Number"
        )

        plt.ylabel(
            "Confidence (%)"
        )

        plt.tight_layout()

        plt.savefig(
            os.path.join(
                GRAPH_DIR,
                "06_predictions_over_time.png"
            ),
            dpi=300
        )

        plt.close()

    # ========================================================
    # FINISHED
    # ========================================================

    print()
    print("=" * 70)
    print("REPORT GENERATION COMPLETE")
    print("=" * 70)

    print(
        f"Total flows: {len(df)}"
    )

    print(
        f"Total packets: "
        f"{df['packets'].sum()}"
    )

    print(
        f"Average confidence: "
        f"{df['confidence'].mean():.2f}%"
    )

    print(
        f"Average risk score: "
        f"{df['risk_score'].mean():.2f}"
    )

    print(
        f"Database saved: "
        f"{df['database_saved'].astype(str).str.lower().eq('true').sum()}"
    )

    print()
    print(
        f"Results directory:"
    )

    print(
        RESULTS_DIR
    )

    print()
    print(
        f"Graphs directory:"
    )

    print(
        GRAPH_DIR
    )

    print("=" * 70)


# ============================================================
# MAIN LIVE MONITOR
# ============================================================

def main():

    print()
    print("=" * 70)
    print("AI CYBERSECURITY CONTINUOUS NETWORK MONITOR")
    print("=" * 70)

    print(
        "Capture started."
    )

    print(
        f"Analysis interval: "
        f"{ANALYSIS_INTERVAL} seconds"
    )

    print(
        f"Flow duplicate window: "
        f"{DUPLICATE_WINDOW} seconds"
    )

    print(
        "Model: XGBoost"
    )

    print(
        f"Model features: "
        f"{len(model_features)}"
    )

    print(
        "Press Ctrl+C to stop."
    )

    print()

    while RUNNING:

        try:

            packets = capture_window()

            process_packets(
                packets
            )

        except KeyboardInterrupt:

            stop_monitor()

            break

        except Exception as exc:

            safe_print(
                f"[CAPTURE ERROR] {exc}"
            )

            time.sleep(2)

    generate_reports()

    print()
    print(
        "Live analyzer stopped."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()