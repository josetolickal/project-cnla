"""
Stress test: feeds real CIC-IDS-2017 rows through the full pipeline
as if they were arriving live. No malware, no risk, 100% real data.
"""

import json
import time
import requests
import pandas as pd
import numpy as np

FEATURES = json.load(open("models/feature_names.json"))
SOC_URL = "http://127.0.0.1:5000/api/sensor/ingest"

# Load real attack data
print("Loading real attack flows...")
df = pd.read_parquet(
    "data/processed/cicids2017_binary/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"
)

# Get 20 real attack rows and 20 real benign rows
attacks = df[df["is_malicious"] == 1].head(20)
benign = df[df["is_malicious"] == 0].head(20)
test_data = pd.concat([attacks, benign]).sample(frac=1, random_state=42)

print(f"Sending {len(test_data)} real flows to dashboard (mix of attack + benign)...")
correct = 0
total = 0

for idx, row in test_data.iterrows():
    flow = {f: float(row[f]) for f in FEATURES}
    flow["_flow_key"] = {
        "src_ip": "203.0.113.45" if row["is_malicious"] else "192.168.1.105",
        "dst_ip": "192.168.1.100",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": 6,
    }

    payload = {
        "sensor_id": "stress-tester",
        "location": "Stress-Test-Node",
        "flows": [flow],
    }

    try:
        r = requests.post(SOC_URL, json=payload, timeout=5)
        result = r.json()
        detected = result["malicious_detected"]
        expected = int(row["is_malicious"])
        correct += detected == expected
        total += 1
        status = "CORRECT" if detected == expected else "WRONG"
        label = "ATTACK" if expected else "BENIGN"
        print(
            f"  [{status}] Real {label} -> Model said: {'MALICIOUS' if detected else 'BENIGN'}"
        )
        time.sleep(0.5)  # pace it so dashboard shows live streaming
    except Exception as e:
        print(f"  [ERROR] {e}")

print(
    f"\nResults: {correct}/{total} correct ({correct / total * 100:.1f}% accuracy on real unseen rows)"
)
print("Check dashboard at http://127.0.0.1:5000 for live alerts")
