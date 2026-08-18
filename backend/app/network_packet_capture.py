from scapy.all import sniff

def process(packet):

    print(packet.summary())

sniff(
    prn=process,
    count=20
)