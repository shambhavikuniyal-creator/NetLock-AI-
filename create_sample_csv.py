import numpy as np
import pandas as pd

# Generate 500 realistic CICIDS2017-style network flow rows
np.random.seed(42)

# 450 Benign (Normal) flows
benign_duration = np.random.normal(loc=120, scale=30, size=450)
benign_fwd_pkts = np.random.randint(1, 10, size=450)
benign_fwd_len = np.random.normal(loc=500, scale=100, size=450)
benign_rate = np.random.normal(loc=50, scale=15, size=450)
benign_labels = ["BENIGN"] * 450

# 50 Attack (DDoS / Volumetric) flows
attack_duration = np.random.normal(loc=2, scale=1, size=50)
attack_fwd_pkts = np.random.randint(100, 500, size=50)
attack_fwd_len = np.random.normal(loc=1450, scale=50, size=50)
attack_rate = np.random.normal(loc=2500, scale=300, size=50)
attack_labels = ["DDoS"] * 50

# Merge into DataFrame
df = pd.DataFrame(
    {
        "Flow Duration": np.concatenate([benign_duration, attack_duration]),
        "Total Fwd Packets": np.concatenate(
            [benign_fwd_pkts, attack_fwd_pkts]
        ),
        "Total Length of Fwd Packets": np.concatenate(
            [benign_fwd_len, attack_fwd_len]
        ),
        "Flow Packets/s": np.concatenate([benign_rate, attack_rate]),
        " Label": np.concatenate([benign_labels, attack_labels]),
    }
)

df.to_csv("CICIDS2017_sample.csv", index=False)
print("✅ 'CICIDS2017_sample.csv' created successfully in your project folder!")