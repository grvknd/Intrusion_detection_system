from scapy.all import sniff
import pandas as pd
import numpy as np
from joblib import load

# Load the trained model and scaler
model = load("ids_model.pkl")
scaler = load("scaler.pkl")

# Callback function to process packets
def process_packet(packet):
    if packet.haslayer("IP"):
        # Extract key features (example features, modify as per need)
        data = {
            "duration": 0,  # You might need to calculate duration between packets
            "protocol_type": str(packet.proto),
            "src_bytes": len(packet),
            "dst_bytes": len(packet.payload),
            "flag": str(packet.flags) if hasattr(packet, "flags") else "0",
            "wrong_fragment": 0,  # Update as per extracted values
            "hot": 0,  # Modify if needed
        }

        # Convert to DataFrame
        real_time_df = pd.DataFrame([data])

        # One-hot encoding
        real_time_df = pd.get_dummies(real_time_df, columns=["protocol_type", "flag"], drop_first=True)

        # Add missing columns
        missing_cols = set(scaler.feature_names_in_) - set(real_time_df.columns)
        for col in missing_cols:
            real_time_df[col] = 0

        # Reorder columns to match the training data
        real_time_df = real_time_df.reindex(columns=scaler.feature_names_in_, fill_value=0)

        # Scale data
        real_time_scaled = scaler.transform(real_time_df)

        # Make prediction
        prediction = model.predict(real_time_scaled)

        if prediction[0] == 0:
            print(" No intrusion detected (Normal Traffic)")
        else:
            print(" Intrusion detected! (Attack Traffic)")

# Sniff packets in real time
print("Listening for real-time traffic... Press Ctrl+C to stop.")
sniff(filter="ip", prn=process_packet, store=False, count=5)


