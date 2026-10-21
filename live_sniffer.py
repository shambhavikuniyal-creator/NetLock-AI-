import os
import sys
import time
import joblib
import numpy as np
from scapy.all import IP, TCP, UDP, sniff
from c_bridge import FirewallEngine  # Import C Engine Bridge

# 1. Load C Engine and Saved ML Model
firewall = FirewallEngine()

if not os.path.exists("netlock_model.pkl"):
    print("Error: 'netlock_model.pkl' not found. Please run train_cicids.py first!")
    sys.exit(1)

model = joblib.load("netlock_model.pkl")
print(" [Live Sniffer] AI Model loaded successfully. Sniffing live packets...")

# Flow tracking dictionary to compute packet rates live
# Structure: { ip_address: [first_timestamp, packet_count, total_bytes] }
ip_tracker = {}

def process_packet(packet):
    """Callback function triggered every time Scapy captures a network packet."""
    if not packet.haslayer(IP):
        return  # Ignore non-IP traffic

    src_ip = packet[IP].src
    packet_len = len(packet)
    current_time = time.time()

    # 1. FAST PATH: Check if IP is already blocked in C memory
    if firewall.check_ip(src_ip):
        print(f"[C-Engine Fast Path] Blocked IP {src_ip} dropped packet ({packet_len} Bytes) in O(1) time!")
        return

    # 2. Extract Real-Time Flow Features for Unseen IP
    if src_ip not in ip_tracker:
        ip_tracker[src_ip] = [current_time, 1, packet_len]
        return  # Need at least 2 packets to calculate rate & flow duration

    first_seen, pkt_count, total_bytes = ip_tracker[src_ip]
    pkt_count += 1
    total_bytes += packet_len
    
    flow_duration = max((current_time - first_seen) * 1000, 1.0)  # in ms
    pkt_rate = pkt_count / (flow_duration / 1000.0)

    # Update tracker
    ip_tracker[src_ip] = [first_seen, pkt_count, total_bytes]

    # Prepare feature vector matching our trained model:
    # ["Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets", "Flow Packets/s"]
    feature_vector = np.array([[flow_duration, pkt_count, total_bytes, pkt_rate]])

    # 3. AI Inference
    prediction = model.predict(feature_vector)[0]

    if prediction == -1:
        # Anomaly / Threat Detected!
        raw_score = model.score_samples(feature_vector)[0]
        threat_score = int(min(max((0.5 - raw_score) * 100, 50), 99))

        print(f"\n [LIVE THREAT DETECTED] Source IP: {src_ip} | Threat Score: {threat_score}%")
        print(f"    Stats -> Length: {total_bytes}B | Duration: {flow_duration:.1f}ms | Rate: {pkt_rate:.1f} pkts/s")
        
        # Block IP dynamically in C Hash Table
        firewall.block_ip(src_ip, threat_score)
    else:
        print(f"[Clean Traffic] {src_ip} -> Length: {packet_len}B | Rate: {pkt_rate:.1f} pkts/s")

# Start Live Packet Sniffing
if __name__ == "__main__":
    print("\n--- STARTING REAL-TIME NETWORK PACKET CAPTURE ---")
    print("Press Ctrl+C to stop sniffing at any time.\n")
    
    # Sniff 30 packets from active network adapter (Filter: IP packets only)
    try:
        sniff(filter="ip", prn=process_packet, count=30, store=0)
    except PermissionError:
        print("Note: Scapy raw packet sniffing on Windows may require running VS Code / Terminal as Administrator.")