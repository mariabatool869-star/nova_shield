import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    precision_recall_curve, roc_auc_score
)
import lightgbm as lgb

# Load data
df = pd.read_csv('models/datasets/cic_2018/wednesday_dos2.csv', 
                  encoding='latin-1', low_memory=False)
df.columns = df.columns.str.strip()

print("=" * 70)
print("HONEST EVALUATION - TIME-BASED SPLIT")
print("=" * 70)

# Parse timestamp or use creation order
df['order'] = range(len(df))
split_idx = int(len(df) * 0.7)

print(f"\nDataset size: {len(df):,}")
print(f"Train samples: {split_idx:,} (70%)")
print(f"Test samples: {len(df) - split_idx:,} (30%)")

X_train = df.iloc[:split_idx].drop('Label', axis=1)
y_train = df.iloc[:split_idx]['Label']

X_test = df.iloc[split_idx:].drop('Label', axis=1)
y_test = df.iloc[split_idx:]['Label']

print(f"\nTrain label distribution:")
print(y_train.value_counts())

print(f"\nTest label distribution:")
print(y_test.value_counts())

# Train model
print("\n" + "=" * 70)
print("TRAINING MODEL")
print("=" * 70)

model = lgb.LGBMClassifier(
    n_estimators=200,
    max_depth=10,
    learning_rate=0.05,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42
)

model.fit(X_train, y_train)

# Evaluate
print("\n" + "=" * 70)
print("RESULTS - HONEST METRICS")
print("=" * 70)

y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred, digits=4))

print("\nPer-class metrics:")
for label in model.classes_:
    mask = y_test == label
    if mask.sum() > 0:
        class_pred = y_pred[mask]
        recall = (class_pred == label).sum() / mask.sum()
        print(f"  {label}: Recall = {recall:.4f}")

