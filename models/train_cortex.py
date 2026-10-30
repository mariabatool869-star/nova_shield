import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

# 1. Create a tiny synthetic dataset
# failed_logins_60s: how many failed attempts in 60 seconds
# is_root_target: 1 if targeting 'root', 0 otherwise
# src_ip_unseen: 1 if we've never seen this IP before, 0 otherwise
# label: 1 = attack, 0 = normal

data = [
    # Normal traffic
    [0, 0, 0, 0], [1, 0, 0, 0], [2, 0, 0, 0], [0, 0, 1, 0], 
    [1, 0, 1, 0], [3, 0, 0, 0], [0, 0, 0, 0], [1, 0, 0, 0],
    # Attack traffic
    [10, 1, 1, 1], [15, 1, 1, 1], [8, 1, 1, 1], [20, 1, 0, 1],
    [12, 0, 1, 1], [5, 1, 1, 1], [30, 1, 1, 1], [9, 1, 1, 1]
]

df = pd.DataFrame(data, columns=["failed_logins_60s", "is_root_target", "src_ip_unseen", "label"])

# 2. Train the model
X = df.drop("label", axis=1)
y = df["label"]

model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X, y)

# 3. Save the trained brain to a file
with open("models/cortex_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("CORTEX brain trained and saved to models/cortex_model.pkl")