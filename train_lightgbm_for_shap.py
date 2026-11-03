import pandas as pd
import numpy as np
import lightgbm as lgb
import pickle
from sklearn.preprocessing import LabelEncoder
from datetime import datetime

print("\n" + "="*80)
print("TRAINING LIGHTGBM FOR SHAP EXPLANATIONS")
print("="*80 + "\n")

# Load combined dataset
print("Loading combined CIC-IDS 2017 + 2018 data...")
try:
    df = pd.read_csv('models/datasets/TRAIN_SET.csv')
    print(f"OK Loaded {len(df)} training samples\n")
except:
    print("ERROR: TRAIN_SET.csv not found")
    exit(1)

# Separate features and labels
print("Preparing data...")
X = df.iloc[:, :-1].values
y = df.iloc[:, -1]

print(f"Features: {X.shape[1]}")
print(f"Samples: {X.shape[0]}")
print(f"Attack types: {len(y.unique())}\n")

# Encode labels
print("Encoding labels...")
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

print(f"Classes: {len(label_encoder.classes_)}\n")
for i, label in enumerate(label_encoder.classes_):
    count = (y_encoded == i).sum()
    pct = (count / len(y_encoded)) * 100
    print(f"  {i}. {label:<30} {count:>10} ({pct:>5.1f}%)")

# Train LightGBM
print("\n" + "="*80)
print("TRAINING LIGHTGBM")
print("="*80 + "\n")

train_data = lgb.Dataset(X, label=y_encoded)

params = {
    'objective': 'multiclass',
    'num_class': len(label_encoder.classes_),
    'metric': 'multi_logloss',
    'num_leaves': 31,
    'learning_rate': 0.05,
    'feature_fraction': 0.8,
    'bagging_fraction': 0.8,
    'bagging_freq': 5,
    'verbose': 100
}

print("Training LightGBM (this may take 5-10 minutes)...\n")
model = lgb.train(
    params,
    train_data,
    num_boost_round=200,
)

print("\nOK LightGBM training complete!\n")

# Save model
print("Saving LightGBM model...")
with open('models/cortex_model.pkl', 'wb') as f:
    pickle.dump(model, f)
print("OK Saved: models/cortex_model.pkl\n")

# Save label encoder
print("Saving label encoder...")
with open('models/label_encoder_lgb.pkl', 'wb') as f:
    pickle.dump(label_encoder, f)
print("OK Saved: models/label_encoder_lgb.pkl\n")

print("="*80)
print("TRAINING COMPLETE!")
print("="*80)
print("\nModels ready for SHAP explanations:")
print("  - models/cortex_model.pkl (LightGBM)")
print("  - models/label_encoder_lgb.pkl")
print("\nNext: Update Cortex to load both models\n")
