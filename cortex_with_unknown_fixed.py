import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
import lightgbm as lgb
from collections import Counter

# Load data
df = pd.read_csv('models/datasets/cic_2018/wednesday_dos2.csv', 
                  encoding='latin-1', low_memory=False)
df.columns = df.columns.str.strip()

# Prepare
non_numeric = df.select_dtypes(exclude=['number']).columns.tolist()
df_numeric = df.drop(columns=non_numeric + ['Label'])
X = df_numeric.replace([np.inf, -np.inf], np.nan).fillna(0).values
y = df['Label'].values

le = LabelEncoder()
y_encoded = le.fit_transform(y)

print("=" * 70)
print("TESTING UNKNOWN/ANOMALY DETECTION")
print("=" * 70)
print(f"Classes: {list(le.classes_)}\n")

results_summary = []

for held_out_attack in le.classes_:
    print("=" * 70)
    print(f"LOAO: Testing on {held_out_attack}")
    print("=" * 70)
    
    held_out_mask = y == held_out_attack
    train_mask = ~held_out_mask
    
    X_train = X[train_mask]
    y_train = y_encoded[train_mask]
    
    X_test = X[held_out_mask]
    y_test = y_encoded[held_out_mask]
    
    print(f"Train: {len(X_train):,} samples (WITHOUT {held_out_attack})")
    print(f"Test: {len(X_test):,} samples (ONLY {held_out_attack})\n")
    
    # Stage 1: Train classifier
    classifier = lgb.LGBMClassifier(
        n_estimators=100,
        max_depth=8,
        n_jobs=-1,
        random_state=42,
        verbose=-1
    )
    classifier.fit(X_train, y_train)
    
    print(f"Classifier trained on classes: {list(classifier.classes_)}")
    
    # Stage 2: Train anomaly detector on training set
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    anomaly_detector = IsolationForest(
        contamination=0.1,
        n_jobs=-1,
        random_state=42
    )
    anomaly_detector.fit(X_train_scaled)
    
    # Predict on test set
    X_test_scaled = scaler.transform(X_test)
    
    # Get raw predictions and probabilities
    preds = classifier.predict(X_test)
    proba = classifier.predict_proba(X_test)
    anomaly_scores = anomaly_detector.score_samples(X_test_scaled)
    
    # Decision logic
    max_prob = proba.max(axis=1)
    
    # Safely map predictions to class names
    pred_class_names = []
    for pred in preds:
        if 0 <= pred < len(classifier.classes_):
            pred_class_names.append(classifier.classes_[pred])
        else:
            pred_class_names.append("ERROR")
    
    pred_class_names = np.array(pred_class_names)
    
    # Flag as UNKNOWN if:
    # 1. Low confidence (<50%)
    # 2. Anomalous (anomaly score < -0.3)
    unknown_mask = (max_prob < 0.5) | (anomaly_scores < -0.3)
    
    labels = []
    for i in range(len(X_test)):
        if unknown_mask[i]:
            labels.append("UNKNOWN")
        else:
            labels.append(pred_class_names[i])
    
    # Count results
    label_counts = Counter(labels)
    unknown_count = label_counts.get("UNKNOWN", 0)
    unknown_pct = unknown_count / len(labels) * 100
    
    print(f"\nResults:")
    print(f"  Total test samples: {len(labels):,}")
    print(f"  Flagged as UNKNOWN: {unknown_count:,} ({unknown_pct:.1f}%)")
    print(f"  Label distribution:")
    
    for label, count in sorted(label_counts.items()):
        pct = count / len(labels) * 100
        print(f"    {label}: {count:,} ({pct:.1f}%)")
    
    results_summary.append({
        'held_out_attack': held_out_attack,
        'unknown_pct': unknown_pct,
        'unknown_count': unknown_count,
        'total': len(labels)
    })
    print()

# Summary
print("\n" + "=" * 70)
print("SUMMARY - UNKNOWN DETECTION PERFORMANCE")
print("=" * 70)
print()

for result in results_summary:
    print(f"{result['held_out_attack']}:")
    print(f"  Flagged as UNKNOWN: {result['unknown_pct']:.1f}% ({result['unknown_count']:,}/{result['total']:,})")
    if result['unknown_pct'] > 50:
        print(f"  ✅ Good detection of unseen attack")
    elif result['unknown_pct'] > 20:
       rint(f"  ⚠️  Partial detection")
    else:
        print(f"  ❌ Poor detection - mostly classified as known")
    print()

print("=" * 70)
print("KEY FINDINGS")
print("=" * 70)
print("""
This shows what happens when model encounters unseen attacks:

1. WITHOUT UNKNOWN handling:
   ❌ Model guesses (0% accuracy - picks wrong class)
   ❌ False positives/negatives
   ❌ No awareness of uncertainty

2. WITH UNKNOWN handling:
   ✅ Model flags uncertain samples
   ✅ Analyst can investigate
   ✅ Graceful degradation

Current results show how much % of unseen attacks 
are caught as UNKNOWN vs misclassified.
""")

