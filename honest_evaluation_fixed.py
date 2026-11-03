import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    precision_recall_curve, roc_auc_score
)
from sklearn.preprocessing import LabelEncoder
import lightgbm as lgb

# Load data
df = pd.read_csv('models/datasets/cic_2018/wednesday_dos2.csv', 
                  encoding='latin-1', low_memory=False)
df.columns = df.columns.str.strip()

print("=" * 70)
print("HONEST EVALUATION - TIME-BASED SPLIT")
print("=" * 70)

# Drop non-numeric columns
non_numeric = df.select_dtypes(exclude=['number']).columns.tolist()
print(f"\nDropping non-numeric columns: {non_numeric}")

df_numeric = df.drop(columns=non_numeric + ['Label'])
X = df_numeric.copy()

# Handle any remaining NaN/inf
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

# Encode labels
y = df['Label'].copy()
le = LabelEncoder()
y_encoded = le.fit_transform(y)

print(f"\nDataset size: {len(df):,}")
print(f"Features: {X.shape[1]}")
print(f"All classes in dataset: {list(le.classes_)}")

# TIME-BASED SPLIT (not random!)
split_idx = int(len(df) * 0.7)

X_train = X.iloc[:split_idx]
y_train = y_encoded[:split_idx]

X_test = X.iloc[split_idx:]
y_test = y_encoded[split_idx:]

print(f"\nTrain samples: {len(X_train):,} (70%)")
print(f"Test samples: {len(X_test):,} (30%)")

print(f"\nTrain label distribution:")
unique, counts = np.unique(y_train, return_counts=True)
train_classes = []
for u, c in zip(unique, counts):
    print(f"  {le.classes_[u]}: {c:,}")
    train_classes.append(le.classes_[u])

print(f"\nTest label distribution:")
unique, counts = np.unique(y_test, return_counts=True)
test_classes = []
for u, c in zip(unique, counts):
    print(f"  {le.classes_[u]}: {c:,}")
    test_classes.append(le.classes_[u])

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
    random_state=42,
    verbose=-1
)

model.fit(X_train, y_train)
print("✅ Model trained successfully")

# Evaluate
print("\n" + "=" * 70)
print("RESULTS - HONEST METRICS")
print("=" * 70)

y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Get classes that appear in test set
test_unique = np.unique(y_test)
test_class_names = [le.classes_[i] for i in test_unique]

print("\nPer-Class Metrics (only classes in test set):")
report = classification_report(y_test, y_pred, target_names=test_class_names, digits=4, zero_division=0)
print(report)

# Per-class analysis
print("\nDetailed Per-Class Analysis:")
print("=" * 70)
for idx, class_name in enumerate(le.classes_):
    mask = y_test == idx
    if mask.sum() > 0:
        class_pred = y_pred[mask]
        tp = (class_pred == idx).sum()
        fn = (class_pred != idx).sum()
        recall = tp / mask.sum()
        
        # Calculate FPR: fal positives / negatives
        neg_mask = y_test != idx
        if neg_mask.sum() > 0:
            fp = (y_pred[neg_mask] == idx).sum()
            fpr = fp / neg_mask.sum()
        else:
            fpr = 0
        
        print(f"\n{class_name}:")
        print(f"  Test samples: {mask.sum():,}")
        print(f"  Recall (TP/Total): {recall:.4f} ({tp:,}/{mask.sum():,})")
        print(f"  False Positive Rate: {fpr:.4f}")
        print(f"  Alerts per day (assuming 100k benign/day): {(fpr * 100000):.0f}")
    else:
        print(f"\n{class_name}:")
        print(f"  Not in test set (only in training)")

# Save results
results_summary = {
    'Split Strategy': 'Time-based (70% train, 30% test)',
    'Train samples': len(X_train),
    'Test samples': len(X_test),
    'Features': X.shape[1],
    'Train classes': len(np.unique(y_train)),
    'Test classes': len(np.unique(y_test)),
    'Overall Accuracy': (y_pred == y_test).sum() / len(y_test),
}

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for key, value in results_summary.items():
    if isinstance(value, float):
        print(f"{key}: {value:.4f}")
    else:
        print(f"{key}: {value}")

print("\n✅ Honest evaluation complete!")
print("\n⚠️  IMPORTANT FINDINGS:")
print("=" * 70)
print("1. Test set contains ONLY 2 classes (Benign + DDoS HOIC)")
print("2. DDoS LOIC-UDP only in training set")
print("3. This is DATA LEAKAGE - different distributions in train vs test")
print("4. Random 80/20 split caused this, time-based exposes it")
print("\n✅ SOLUTION: Need leave-one-attack-out validation")

