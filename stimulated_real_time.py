
import joblib
import numpy as np
import pandas as pd


#  Load the trained model and scaler

model = joblib.load("ids_model.pkl")
scaler = joblib.load("scaler.pkl")

print("✅ Model and scaler loaded successfully for real-time intrusion detection.")


#  Simulated real-time network traffic data

real_time_data = np.array([
    [0, "tcp", "ftp_data", "SF", 491, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 150, 25, 0.17, 0.03, 0.17, 0.0, 0.0, 0.0, 0.05, 0.0]
])


# Define correct column names (WITHOUT difficulty)

columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

# Create DataFrame
real_time_df = pd.DataFrame(real_time_data, columns=columns)


#  Apply encoding for categorical features

real_time_df = pd.get_dummies(real_time_df, columns=["protocol_type", "service", "flag"], drop_first=True)


#  Align columns with training features
-
# Add any missing columns with zero
missing_cols = set(scaler.feature_names_in_) - set(real_time_df.columns)
for col in missing_cols:
    real_time_df[col] = 0

# Reorder columns to match training columns
real_time_df = real_time_df.reindex(columns=scaler.feature_names_in_, fill_value=0)


#  Scale the data correctly using the pre-trained scaler

real_time_scaled = scaler.transform(real_time_df)


# Make prediction

prediction = model.predict(real_time_scaled)


#  Display result
if prediction[0] == 0:
    print(" No intrusion detected (Normal Traffic)")
else:
    print(" Intrusion detected! (Attack Traffic)")


