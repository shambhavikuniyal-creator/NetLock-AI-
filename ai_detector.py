import time
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from c_bridge import FirewallEngine  # Import our C Firewall Engine


class NetLockAI:

    def __init__(self):
        # 1. Connect to C Engine
        self.firewall = FirewallEngine()

        # 2. Initialize Isolation Forest ML Model
        # contamination = estimated ratio of attack packets in raw traffic (10%)
        self.model = IsolationForest(
            n_estimators=100, contamination=0.10, random_state=42
        )

        print(
            "🧠 [AI Model] Isolation Forest engine trained & ready for zero-day threat detection!"
        )

    def generate_synthetic_traffic(self, num_samples=100):
        """Generates realistic synthetic network flow features.

        Features: [Packet_Length_Bytes, Flow_Duration_ms, Packets_Per_Sec]
        """
        np.random.seed(42)

        # Normal Traffic: Small packets, reasonable duration, moderate rate
        normal_packets = np.random.normal(
            loc=[500, 100, 50], scale=[100, 30, 15], size=(num_samples, 3)
        )

        # Attack Traffic (DDoS / Flood): Huge packet volumes, short duration spikes
        attack_packets = np.random.normal(
            loc=[1400, 5, 2000], scale=[50, 2, 300], size=(15, 3)
        )

        # Combine into single traffic dataset
        all_features = np.vstack([normal_packets, attack_packets])
        return all_features

    def train_model(self):
        """Trains the ML model on initial network baseline data."""
        training_data = self.generate_synthetic_traffic(num_samples=200)
        self.model.fit(training_data)

    def analyze_live_packet(self, ip_address: str, packet_features: list):
        """Processes live packet features and flags anomalies to C Hash Table."""
        # Check if IP is already blocked in C memory first (Fast Path O(1))
        if self.firewall.check_ip(ip_address):
            print(
                f"⚡ [Fast Path] IP {ip_address} is ALREADY BLOCKED in C Hash Table. Packet dropped in O(1) time!"
            )
            return

        # Model Prediction (-1 = Anomaly / Threat, 1 = Normal Traffic)
        features_array = np.array(packet_features).reshape(1, -1)
        prediction = self.model.predict(features_array)[0]

        # Calculate Threat Severity Score (0% to 100%)
        raw_score = self.model.score_samples(features_array)[0]
        # Normalize score into percentage threat level
        threat_score = int(min(max((0.5 - raw_score) * 100, 10), 99))

        if prediction == -1:
            print(
                f"\n🚨 [ZERO-DAY ANOMALY DETECTED] IP: {ip_address} | Threat Score: {threat_score}%"
            )
            print(
                f"   📊 Packet Stats -> Length: {packet_features[0]}B | Duration: {packet_features[1]}ms | Rate: {packet_features[2]} pkts/sec"
            )
            # Send to C Engine for zero-delay dynamic blocking
            self.firewall.block_ip(ip_address, threat_score)
        else:
            print(f"✅ [Clean Traffic] IP {ip_address} passed security check.")


# --- Driver Test ---
if __name__ == "__main__":
    netlock = NetLockAI()
    netlock.train_model()

    print("\n--- SIMULATING LIVE INCOMING NETWORK STREAM ---")

    # Sample 1: Normal Browse Traffic
    netlock.analyze_live_packet("192.168.1.15", [450, 120, 30])

    # Sample 2: Incoming Heavy Volumetric SYN Flood Attack
    netlock.analyze_live_packet("185.220.101.5", [1450, 2, 2500])

    # Sample 3: Repeat Request from Attacker (Testing C Fast Lookup)
    print("\n--- REPEAT REQUEST FROM ATTACKING IP ---")
    netlock.analyze_live_packet("185.220.101.5", [1450, 2, 2500])