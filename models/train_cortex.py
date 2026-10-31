import pandas as pd
import numpy as np
import pickle
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# 1. Load the enterprise dataset
print("Loading enterprise dataset...")
df = pd.read_csv("models/datasets/cic_enterprise.csv")

# 2. Drop non-numeric columns (Attack_Type is a label, not a feature)
feature_cols = [c for c in df.columns if c not in ["Label", "Attack_Type"]]
X = df[feature_cols]
y = df["Label"]

print(f"Training on {len(X)} rows and {len(feature_cols)} features.")

# 3. Time-based split (80/20) - Use first 80% for training, last 20% for testing
# This prevents data leakage (a critical mistake in ML security)
split_idx = int(len(df) * 0.8)
X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]

print(f"Training set: {len(X_train)} rows | Test set: {len(X_test)} rows")

# 4. Train LightGBM (faster and more accurate than Random Forest)
print("\nTraining LightGBM model...")
model = lgb.LGBMClassifier(
    n_estimators=200,
    max_depth=10,
    learning_rate=0.1,
    num_leaves=31,
    random_state=42,
    n_jobs=-1  # Use all CPU cores
)

model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    eval_metric="binary_logloss",
    callbacks=[lgb.early_stopping(stopping_rounds=20), lgb.log_evaluation(0)]
)

# 5. Evaluate the model
print("\n--- Model Evaluation on Held-Out Test Set ---")
predictions = model.predict(X_test)
print(classification_report(y_test, predictions, target_names=["BENIGN", "ATTACK"]))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# 6. Save the trained model
with open("models/cortex_model.pkl", "wb") as f:
    pickle.dump(model, f)

# 7. Save the feature names (critical for SHAP later)
with open("models/feature_names.pkl", "wb") as f:
    pickle.dump(feature_cols, f)

print(f"\n✅ CORTEX Enterprise Model trained and saved.")
print(f"   Features: {len(feature_cols)}")
print(f"   Model file: models/cortex_model.pkl")