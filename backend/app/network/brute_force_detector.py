from collections import defaultdict

login_attempts = defaultdict(int)


def detect_bruteforce(ip):

    login_attempts[ip] += 1

    if login_attempts[ip] > 5:

        return True

    return False