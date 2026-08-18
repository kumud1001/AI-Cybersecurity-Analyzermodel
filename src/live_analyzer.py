import time
import threading

import joblib
import numpy as np
import requests

from scapy.all import sniff, IP, TCP, UDP

from src.flow_extractor import (
    flows,
    process_packet,
    summarize_flow
)

from src.cic_features import extract_cic_features
from src.model_features import prepare_model_features


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = "models/xgboost.pkl"

API_URL = "http://127.0.0.1:8000/api/analyze"

CAPTURE_INTERFACE = None

ANALYSIS_INTERVAL = 10


# ============================================================
# ATTACK LABELS
# ============================================================

ATTACK_LABELS = {
    0: "BENIGN",
    1: "Bot",
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slowhttptest",
    6: "DoS slowloris",
    7: "FTP-Patator",
    8: "Heartbleed",
    9: "Infiltration",
    10: "PortScan",
    11: "SSH-Patator",
    12: "Web Attack - Brute Force",
    13: "Web Attack - SQL Injection",
    14: "Web Attack - XSS",
}


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading XGBoost model...")

model = joblib.load(MODEL_PATH)

print("XGBoost model loaded.")

print(
    f"Expected features: "
    f"{getattr(model, 'n_features_in_', 'UNKNOWN')}"
)


# ============================================================
# TRACK PROCESSED FLOWS
# ============================================================

processed_flows = set()

flows_lock = threading.Lock()


# ============================================================
# SEND DATA TO FASTAPI
# ============================================================

def send_to_api(features):

    payload = features.copy()

    # CIC feature name → Pydantic name
    payload["fwd_header_length_1"] = payload.pop(
        "fwd_header_length.1",
        0
    )

    try:

        response = requests.post(
            API_URL,
            json=payload,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    except requests.exceptions.RequestException as exc:

        print(
            f"[API ERROR] {exc}"
        )

        return None


# ============================================================
# ANALYZE ONE FLOW
# ============================================================

def analyze_flow(key, packets):

    try:

        if not packets:
            return

        if IP not in packets[0]:
            return

        summary = summarize_flow(
            key,
            packets
        )

        source_ip = packets[0][IP].src

        forward_packets = []

        backward_packets = []

        for packet in packets:

            if IP not in packet:
                continue

            if packet[IP].src == source_ip:

                forward_packets.append(packet)

            else:

                backward_packets.append(packet)

        # ----------------------------------------------------
        # Destination port
        # ----------------------------------------------------

        destination_port = 0

        for packet in forward_packets:

            if TCP in packet:

                destination_port = int(
                    packet[TCP].dport
                )

                break

            if UDP in packet:

                destination_port = int(
                    packet[UDP].dport
                )

                break

        # ----------------------------------------------------
        # Extract 78 features
        # ----------------------------------------------------

        features = extract_cic_features(
            packets=packets,
            forward_packets=forward_packets,
            backward_packets=backward_packets,
            destination_port=destination_port
        )

        model_features = prepare_model_features(
            features
        )

        if len(model_features) != 78:

            raise ValueError(
                f"Expected 78 features, "
                f"got {len(model_features)}"
            )

        X = np.array(
            [model_features],
            dtype=float
        )

        # ----------------------------------------------------
        # XGBoost
        # ----------------------------------------------------

        predicted_class = int(
            model.predict(X)[0]
        )

        probabilities = model.predict_proba(X)[0]

        confidence = float(
            max(probabilities)
        )

        attack_type = ATTACK_LABELS.get(
            predicted_class,
            f"UNKNOWN-{predicted_class}"
        )

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        if attack_type == "BENIGN":

            severity = "LOW"
            risk_score = 0

        elif confidence >= 0.90:

            severity = "CRITICAL"
            risk_score = 90

        elif confidence >= 0.75:

            severity = "HIGH"
            risk_score = 75

        elif confidence >= 0.50:

            severity = "MEDIUM"
            risk_score = 50

        else:

            severity = "LOW"
            risk_score = 25

        # ----------------------------------------------------
        # Display
        # ----------------------------------------------------

        print()
        print("=" * 70)

        print(
            f"FLOW: "
            f"{summary['source_ip']} "
            f"→ "
            f"{summary['destination_ip']}"
        )

        print(
            f"PORT: {destination_port}"
        )

        print(
            f"PACKETS: {len(packets)}"
        )

        print(
            f"ATTACK: {attack_type}"
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
            f"CLASS: {predicted_class}"
        )

        # ----------------------------------------------------
        # Save to FastAPI / MySQL
        # ----------------------------------------------------

        api_result = send_to_api(
            features
        )

        if api_result:

            database_info = api_result.get(
                "database",
                {}
            )

            print(
                f"DATABASE SAVED: "
                f"{database_info.get('saved')}"
            )

            print(
                f"ALERT ID: "
                f"{database_info.get('alert_id')}"
            )

        else:

            print(
                "DATABASE SAVED: False"
            )

        print("=" * 70)

    except Exception as exc:

        print(
            f"[FLOW ERROR] {exc}"
        )


# ============================================================
# PERIODIC ANALYSIS
# ============================================================

def analysis_loop():

    while True:

        time.sleep(
            ANALYSIS_INTERVAL
        )

        with flows_lock:

            current_flows = dict(
                flows
            )

        for key, packets in current_flows.items():

            if key in processed_flows:
                continue

            if len(packets) < 2:
                continue

            analyze_flow(
                key,
                packets
            )

            processed_flows.add(
                key
            )


# ============================================================
# PACKET CAPTURE
# ============================================================

def start_capture():

    print()
    print("=" * 70)
    print("AI CYBERSECURITY CONTINUOUS NETWORK MONITOR")
    print("=" * 70)

    print(
        "Capture started."
    )

    print(
        "Analysis interval: "
        f"{ANALYSIS_INTERVAL} seconds"
    )

    print(
        "Press Ctrl+C to stop."
    )

    print()

    sniff(
        iface=CAPTURE_INTERFACE,
        prn=process_packet,
        store=False
    )


# ============================================================
# MAIN
# ============================================================

def main():

    flows.clear()

    processed_flows.clear()

    analyzer_thread = threading.Thread(
        target=analysis_loop,
        daemon=True
    )

    analyzer_thread.start()

    try:

        start_capture()

    except KeyboardInterrupt:

        print()
        print(
            "Stopping network monitor..."
        )

    finally:

        print(
            "Network monitor stopped."
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()