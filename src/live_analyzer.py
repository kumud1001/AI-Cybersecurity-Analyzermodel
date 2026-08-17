import requests
import joblib
import numpy as np

from scapy.all import sniff, IP, TCP, UDP

from src.flow_extractor import (
    flows,
    process_packet,
    summarize_flow
)

from src.cic_features import extract_cic_features
from src.model_features import prepare_model_features


MODEL_PATH = "models/xgboost.pkl"
API_URL = "http://127.0.0.1:8000/api/analyze"

model = joblib.load(MODEL_PATH)
def send_to_api(features):
    """
    Send extracted network-flow features to FastAPI.
    """

    try:
        response = requests.post(
            API_URL,
            json=features,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    except requests.exceptions.RequestException as exc:

        print(
            f"API connection error: {exc}"
        )

        return None
def analyze_flows():

    print()
    print("=" * 70)
    print("ANALYZING CAPTURED FLOWS")
    print("=" * 70)

    if not flows:
        print("No flows captured.")
        return

    for key, packets in flows.items():

        try:

            if not packets:
                continue

            # -------------------------------------------------
            # Basic flow information
            # -------------------------------------------------

            summary = summarize_flow(
                key,
                packets
            )

            # -------------------------------------------------
            # Determine forward/backward packets
            # -------------------------------------------------

            if IP not in packets[0]:
                continue

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

            # -------------------------------------------------
            # Destination port
            # -------------------------------------------------

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

            # -------------------------------------------------
            # Extract 78 features
            # -------------------------------------------------

            features = extract_cic_features(
                packets=packets,
                forward_packets=forward_packets,
                backward_packets=backward_packets,
                destination_port=destination_port
            )

            # -------------------------------------------------
            # Verify feature count
            # -------------------------------------------------

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

            # -------------------------------------------------
            # XGBoost prediction
            # -------------------------------------------------

            predicted_class = int(
                model.predict(X)[0]
            )

            probabilities = model.predict_proba(X)[0]

            confidence = float(
                max(probabilities)
            )

            # -------------------------------------------------
            # Get class name
            # -------------------------------------------------

            classes = model.classes_

            class_index = list(classes).index(
                predicted_class
            )

            attack_type = str(
                classes[class_index]
            )

            # -------------------------------------------------
            # Severity
            # -------------------------------------------------

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

            # -------------------------------------------------
            # Display result
            # -------------------------------------------------

            print()
            print("-" * 70)

            print(
                f"Flow: "
                f"{summary['source_ip']} → "
                f"{summary['destination_ip']}"
            )

            print(
                f"Destination Port: "
                f"{destination_port}"
            )

            print(
                f"Packets: "
                f"{len(packets)}"
            )

            print(
                f"Attack Type: "
                f"{attack_type}"
            )

            print(
                f"Confidence: "
                f"{confidence * 100:.2f}%"
            )

            print(
                f"Severity: "
                f"{severity}"
            )

            print(
                f"Risk Score: "
                f"{risk_score}"
            )

            print(
                f"Predicted Class: "
                f"{predicted_class}"
            )

            # -------------------------------------------------
            # Send real flow to FastAPI / MySQL
            # -------------------------------------------------

            api_result = send_to_api(
                features
            )

            if api_result:

                database_info = api_result.get(
                    "database",
                    {}
                )

                print(
                    f"Database Saved: "
                    f"{database_info.get('saved')}"
                )

                print(
                    f"Alert ID: "
                    f"{database_info.get('alert_id')}"
                )

            else:

                print(
                    "Database Saved: False"
                )

        except Exception as exc:

            print(
                f"Flow analysis error: {exc}"
            )

def main():

    packet_count = 100

    print("=" * 70)
    print("AI CYBERSECURITY LIVE TRAFFIC ANALYZER")
    print("=" * 70)

    print(
        f"Capturing {packet_count} packets..."
    )

    print(
        "Generate some browser/network traffic "
        "while capture is running."
    )

    print()

    # Clear previous flows
    flows.clear()

    sniff(
        prn=process_packet,
        count=packet_count,
        store=False
    )

    analyze_flows()


if __name__ == "__main__":
    main()