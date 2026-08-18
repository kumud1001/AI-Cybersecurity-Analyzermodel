from app.network.port_scan_detector import detect_port_scan
from app.network.brute_force_detector import detect_bruteforce
from app.network.ddos_detector import detect_ddos


def analyze(packet):

    alerts = []

    if detect_port_scan(
        packet["src_ip"],
        packet["dst_port"]
    ):
        alerts.append("Port Scan")

    if detect_ddos(
        packet["src_ip"]
    ):
        alerts.append("DDoS")

    return alerts