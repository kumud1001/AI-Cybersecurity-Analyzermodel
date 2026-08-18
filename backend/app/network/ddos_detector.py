import time

packet_counter = {}

WINDOW = 10


def detect_ddos(ip):

    now = time.time()

    packet_counter.setdefault(ip, [])

    packet_counter[ip] = [
        t for t in packet_counter[ip]
        if now - t < WINDOW
    ]

    packet_counter[ip].append(now)

    if len(packet_counter[ip]) > 500:

        return True

    return False