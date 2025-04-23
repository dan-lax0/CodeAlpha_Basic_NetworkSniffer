# ENHANCED BASIC NETWORK SNIFFER IN PYTHON
# FEATURES: TCP FILTERING, PACKET COUNTING, TIMESTAMP, LOGGING

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

# INITIALIZE PACKET COUNT DICTIONARY
packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

# OPEN A FILE TO SAVE CAPTURED PACKET SUMMARIES
log_file = open("captured_packets_log.txt", "a")

# FUNCTION TO PROCESS EACH PACKET
def process_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in packet:
        ip_layer = packet[IP]
        proto = "Other"

        # DETERMINE PROTOCOL TYPE AND COUNT
        if packet.haslayer(TCP):
            proto = "TCP"
            packet_counts["TCP"] += 1
        elif packet.haslayer(UDP):
            proto = "UDP"
            packet_counts["UDP"] += 1
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            packet_counts["ICMP"] += 1
        else:
            packet_counts["Other"] += 1

        # PRINT TO CONSOLE
        print("\n[+] Packet Captured")
        print(f"Time          : {timestamp}")
        print(f"Protocol      : {proto}")
        print(f"Source IP     : {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        if proto == "TCP":
            print(f"TCP Ports     : {packet[TCP].sport} → {packet[TCP].dport}")

        # LOG TO FILE
        log_file.write(f"{timestamp} | {proto} | {ip_layer.src} -> {ip_layer.dst}\n")

        # PRINT CURRENT PACKET COUNTS
        print(f"Count - TCP: {packet_counts['TCP']} | UDP: {packet_counts['UDP']} | ICMP: {packet_counts['ICMP']}")

# START SNIFFING (FILTERED ONLY TO TCP FOR SIMPLICITY; CHANGE AS NEEDED)
print("🔍 Starting Enhanced Network Sniffer (TCP packets only)...")
print("📂 Logging to 'captured_packets_log.txt'. Press Ctrl+C to stop.\n")

try:
    sniff(filter="tcp", prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\n🛑 Sniffing stopped by user.")
finally:
    log_file.close()
