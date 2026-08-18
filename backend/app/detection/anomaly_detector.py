"""
anomaly_detector.py

Real-time AI Network Threat Detection Engine

Input:
    Scapy packets

Pipeline:
    Packet
      |
      v
    Parser
      |
      v
    Features
      |
      v
    Rule Detection + ML Detection
      |
      v
    Security Alert
"""


from collections import defaultdict
import time


from app.network.packet_parser import parse_packet
from app.network.features import extract_features
from app.ml.anomaly_model import predict_anomaly
from app.database.database import SessionLocal
from app.database.crud import create_alert


from scapy.all import sniff



# -----------------------------
# Traffic memory
# -----------------------------

port_tracker = defaultdict(set)

packet_tracker = defaultdict(list)

syn_tracker = defaultdict(list)


# Prevent duplicate alerts

last_alert = {}

db = SessionLocal()



# -----------------------------
# Alert deduplication
# -----------------------------

def allow_alert(alert_type, source_ip):

    key = f"{alert_type}_{source_ip}"

    now = time.time()


    if key in last_alert:

        if now - last_alert[key] < 60:

            return False


    last_alert[key] = now

    return True



# -----------------------------
# Rule Based Detection
# -----------------------------

def rule_detection(features):


    alerts = []


    src_ip = features.get(
        "src_ip",
        "unknown"
    )


    dst_port = features.get(
        "dst_port",
        0
    )


    syn_flag = features.get(
        "syn_flag",
        0
    )


    current_time = time.time()



    # -------------------------
    # Port Scan Detection
    # -------------------------

    port_tracker[src_ip].add(
        dst_port
    )


    if len(port_tracker[src_ip]) > 15:


        if allow_alert(
            "PORT_SCAN",
            src_ip
        ):

            alerts.append({

                "type":"PORT_SCAN",

                "severity":"HIGH",

                "source":src_ip,

                "message":
                f"Accessed {len(port_tracker[src_ip])} ports"

            })



    # -------------------------
    # SYN Flood Detection
    # -------------------------

    if syn_flag == 1:


        syn_tracker[src_ip].append(
            current_time
        )


        recent_syn = [

            t for t in syn_tracker[src_ip]

            if current_time - t < 10

        ]


        if len(recent_syn) > 100:


            if allow_alert(
                "SYN_FLOOD",
                src_ip
            ):


                alerts.append({

                    "type":"SYN_FLOOD",

                    "severity":"HIGH",

                    "source":src_ip,

                    "message":
                    f"{len(recent_syn)} SYN packets in 10 seconds"

                })



    return alerts




# -----------------------------
# AI Detection
# -----------------------------

def ml_detection(features):


    result = predict_anomaly(
        features
    )


    if result["anomaly"]:


        return {


            "type":
            "AI_ANOMALY",


            "severity":
            "MEDIUM",


            "source":
            features.get(
                "src_ip"
            ),


            "score":
            result["score"],


            "message":
            result["message"]

        }



    return None




# -----------------------------
# Packet Processing
# -----------------------------

def process_packet(packet):


    # Parse packet

    parsed = parse_packet(
        packet
    )


    # Extract ML features

    features = extract_features(
        parsed
    )


    # Add IP information

    features["src_ip"] = parsed.get(
        "src_ip"
    )


    features["dst_ip"] = parsed.get(
        "dst_ip"
    )



    # Rule alerts

    rule_alerts = rule_detection(
        features
    )


    for alert in rule_alerts:

        print("\n🚨 RULE ALERT")

        print(alert)



    # AI alert

    ai_alert = ml_detection(
        features
    )


    if ai_alert:


        print("\n🤖 AI ANOMALY ALERT")

        print(ai_alert)



# -----------------------------
# Start Monitor
# -----------------------------

if __name__ == "__main__":


    print(
        "Starting AI Security Monitor..."
    )


    sniff(

        prn=process_packet,

        store=False

    )