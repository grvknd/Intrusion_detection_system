import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from joblib import dump, load

# Load dataset
df = pd.read_csv("D:\python\project\ids\KDDTrain+.txt", header=None)  # Replace with actual file path

columns_name = [
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
    "dst_host_srv_rerror_rate", "label", "difficulty"
]


df.columns = columns_name


from sklearn.preprocessing import LabelEncoder

# Apply one-hot encoding on categorical features
df = pd.get_dummies(df, columns=["protocol_type", "service", "flag"], drop_first=True)


# Convert labels: Normal = 0, Attack = 1
df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)



# Separate features (X) and target (y)
X = df.drop("label", axis=1)
y = df["label"]




# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
dump(scaler, "scaler.pkl")

print("✅ Scaler saved successfully as scaler.pkl!")


# Split data into Train-Test sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=0)

# Train a Random Forest Model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)


clf.score(X_test, y_test)

# Save the trained model


# Save model to a file
dump(clf, "ids_model.pkl")
print("✅ Model saved successfully using joblib!")
