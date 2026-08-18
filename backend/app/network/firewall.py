blocked_ips = {
    "192.168.1.100",
    "10.10.10.10"
}


def is_blocked(ip):

    return ip in blocked_ips


def block_ip(ip):

    blocked_ips.add(ip)


def unblock_ip(ip):

    blocked_ips.discard(ip)