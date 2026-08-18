protocols = {

    1: "ICMP",

    6: "TCP",

    17: "UDP"

}


def get_protocol(number):

    return protocols.get(number, "UNKNOWN")