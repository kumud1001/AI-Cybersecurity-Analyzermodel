from collections import defaultdict

port_history = defaultdict(set)


def detect_port_scan(src_ip, dst_port):

    port_history[src_ip].add(dst_port)

    if len(port_history[src_ip]) > 20:

        return True

    return False