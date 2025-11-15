from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            proto_name = "TCP"
        elif UDP in packet:
            proto_name = "UDP"
        else:
            proto_name = "Other"

        print(f"[{proto_name}] {src} --> {dst}")

def start_sniffer():
    print("🔍 Packet Sniffer Started... (Press Ctrl + C to stop)")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffer()
