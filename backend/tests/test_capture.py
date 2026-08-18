from scapy.all import sniff

print("Capturing packets...")

def show_packet(packet):
    print(packet.summary())

sniff(
    prn=show_packet,
    count=20
)

print("Done")