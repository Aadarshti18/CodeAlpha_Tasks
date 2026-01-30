from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_analyzer(packet):
    print("=" * 60)

    # Check if packet has IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)

        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Packet Length  : {length}")

        # TCP Packet
        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        # UDP Packet
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        # ICMP Packet
        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print("Protocol       : Other")

    else:
        print("Non-IP Packet Captured")

print("Starting Network Sniffer...")
print("Capturing 20 packets...\n")

sniff(prn=packet_analyzer, count=20)
