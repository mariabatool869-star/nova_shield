import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import lightgbm as lgb

# Load data
df = pd.read_csv('models/datasets/cic_2018/wednesday_dos2.csv', 
                  encoding='latin-1', low_memory=False)
df.columns = df.columns.str.strip()

print("=" * 70)
print("LEAVE-ONE-ATTACK-OUT VALIDATION")
print("=" * 70)
print("\nTesting: Train WITHOUT attack X, then measure how X is detected")
print()

# Prepare data
non_numeric = df.select_dtypes(exclude=['number']).columns.tolist()
df_numeric = df.drop(columns=non_numeric + ['Label'])
X = df_numeric.replace([np.inf, -np.inf], np.nan).fillna(0)
y = df['Label'].copy()

le = LabelEncoder()
y_encoded = le.fit_transform(y)

print(f"Total samples: {len(df):,}")
print(f"Attack types: {list(le.classes_)}\n")

# Leave-One-Attack-Out
attacks = le.classes_
results = {}

for held_out_attack in attacks:
    print("=" * 70)
    print(f"TEST: Held-out attack = {held_out_attack}")
    print("=" * 70)
    
    # Create train/test split
    held_out_mask = y == held_out_attack
    train_mask = ~held_out_mask
    
    X_train = X[train_mask]
    y_train = y_encoded[train_mask]
    
    X_test = X[held_out_mask]
    y_test = y_encoded[held_out_mask]
    
    print(f"Train: {len(X_train):,} samples (WITHOUT {held_out_attack})")
    print(f"Test: {len(X_test):,} samples (ONLY {held_out_attack})")
    
    # Train model
    model = lgb.LGBMClassifier(
        n_estimators=100,
        max_depth=10,
        learning_rate=0.05,
        class_weight='balanced',
        n_jobs=-1,
        random_state=42,
        verbose=-1
    )
    
    model.fit(X_train, y_train)
    
    # Predict on held-out attack
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    
    # Calculate metrics
    correct = (y_pred == y_test).sum()
    accuracy = correct / len(y_test)
    
    # What did model predict for this unseen attack?
    print(f"\nResults:")
    print(f"  Accuracy: {accuracy:.4f} ❌ (should be >95%)")
    print(f"  Predictions distribution:")
    
    for idx, pred_class in enumerate(model.classes_):
        count = (y_pred == idx).sum()
        pct = count / len(y_pred) * 100
        print(f"    {pred_class}: {count:,} ({pct:.1f}%)")
    
    # What confidence did model assign to held-out attack?
    print(f"\n  Key Finding:")
    print(f"    Model was trained WITHOUT seeing {held_out_attack}")
    print(f"    Model predicted {held_out_attack} as: {(y_pred == y_test).sum():,} times out of {len(y_test):,}")
    
    results[held_out_attack] = {
        'accuracy': accuracy,
        'correct_predictions': correct,
        'total_samples': len(y_test),
        'model_classes': len(model.classes_),
    }
    print()

# Summary
print("\n" + "=" * 70)
print("LEAVE-ONE-ATTACK-OUT SUMMARY - CRITICAL FINDINGS")
print("=" * 70)
print()

for attack, metrics in results.items():
    acc = metrics['accuracy']
    if acc > 0.95:
      status = "✅ GOOD"
    elif acc > 0.70:
        status = "⚠️  MEDIUM"
    else:
        status = "❌ FAILED"
    
    print(f"{attack}:")
    print(f"  Accuracy: {acc:.4f} {status}")
    print(f"  Correctly detected: {metrics['correct_predictions']:,} / {metrics['total_samples']:,}")
    print()

print("=" * 70)
print("INTERPRETATION")
print("=" * 70)
print("""
THIS IS THE REAL TEST OF GENERALIZATION:

❌ 0% Accuracy = Model predicts everything as something else
   → Model NEVER learned the held-out attack pattern
   → It only memorized training data artifacts

This is the CLOSED-WORLD ASSUMPTION:
"A classifier only recognizes what it has seen during training.
Everything else gets classified as something in the training set."

SOLUTION (from review):
1. Add UNKNOWN/ANOMALY output for unseen attacks
2. Use anomaly detection (Isolation Forest) on benign traffic
3. Combine with calibrated probabilities
4. Test with this LOAO method
""")

