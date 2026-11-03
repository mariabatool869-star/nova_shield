import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import lightgbm as lgb
from scipy.stats import entropy

class CortexWithUnknown:
    """
    Fixed Cortex: Known attacks + UNKNOWN for unseen patterns
    """
    
    def __init__(self):
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.threshold = 0.6
    
    def train(self, X_train, y_train):
        """
        1. Train classifier on known attacks
        2. Train anomaly detector on benign samples
        """
        print("Training classifier on known attacks...")
        self.classifier = lgb.LGBMClassifier(
            n_estimators=100,
            n_jobs=-1,
            random_state=42
        )
        self.classifier.fit(X_train, y_train)
        
        print("Training anomaly detector on benign samples...")
        benign_mask = y_train == 0  # Assuming 0 = Benign
        X_benign = X_train[benign_mask]
        
        X_scaled = self.scaler.fit_transform(X_benign)
        self.anomaly_detector = IsolationForest(
            contamination=0.05,
            n_jobs=-1,
            random_state=42
        )
        self.anomaly_detector.fit(X_scaled)
    
    def predict(self, X):
        """
        Multi-stage prediction:
        1. Check if anomalous (vs benign)
        2. If not anomalous: classify
        3. If low confidence: mark as UNKNOWN
        """
        predictions = []
        confidences = []
        labels = []
        
        for idx, sample in enumerate(X):
            sample_df = sample.reshape(1, -1)
            
            # Stage 1: Anomaly detection
            anomaly_score = self.anomaly_detector.score_samples(
                self.scaler.transform(sample_df)
            )[0]
            is_anomalous = anomaly_score < -0.5  # Threshold
            
            if is_anomalous:
                # Likely an attack
                pred = self.classifier.predict(sample_df)[0]
                conf = self.classifier.predict_proba(sample_df)[0]
                max_conf = conf.max()
                
                # Stage 2: Confidence check
                if max_conf < self.threshold:
                    label = "UNKNOWN"
                    confidence = 1 - max_conf
                else:
                    label = pred
                    confidence = max_conf
            else:
                # Likely benign
                label = "BENIGN"
                confidence = 1.0
            
            predictions.append(pred if label != "UNKNOWN" else -1)
            confidences.append(confidence)
            labels.append(label)
        
        return np.array(predictions), np.array(confidences), labels
    
    def evaluate_loao(self, X_train, y_train, X_test, y_test, attack_name):
        """
        Evaluate on held-out attack
        """
        print(f"\n{'='*70}")
        print(f"LOAO: Testing on {attack_name}")
        print(f"{'='*70}")
        
        # Train without this attack
        self.train(X_train, y_train)
        
        # Predict
        preds, confs, labels = self.predict(X_test)
        
        # Count UNKNOWN detections
        unknown_count = sum(1 for l in labels if l == "UNKNOWN")
        unknown_pct = unknown_count / len(labels) * 100
        
        print(f"\nResults:")
        print(f"  Total test samples: {len(labels):,}")
        print(f"  Flagged as UNKNOWN: {unknown_count:,} ({unknown_pct:.1f}%)")
        print(f"  Label distribution:")
        
        from collections import Counter
        label_counts = Counter(labels)
        for label, count in sorted(label_counts.items()):
            pct = count / len(labels) * 100
            print(f"    {label}: {count:,} ({pct:.1f}%)")
        
        return unknown_pct, label_counts

# Test it
print("="*70)
print("TESTING UNKNOWN/ANOMALY DETECTION")
print("="*70)

# Load data
df = pd.read_csv('models/datasets/cic_2018/wednesday_dos2.csv', 
                  encoding='latin-1', low_memory=False)
df.columns = df.columns.str.strip()

# Prepare
non_numeric = df.select_dtypes(exclude=['number']).columns.tolist()
df_numeric = df.drop(columns=non_numeric + ['Label'])
X = df_numeric.replace([np.inf, -np.inf], np.nan).fillna(0)
y = df['Label'].copy()

# Encode labels
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# LOAO test
cortex = CortexWithUnknown()

for held_out_attack in le.classes_:
    held_out_mask = y == held_out_attack
    train_mask = ~held_out_mask
    
    X_train = X[train_mask].values
    y_train = y_encoded[train_mask]
    
    X_test = X[held_out_mask].values
    y_test = y_encoded[held_out_mask]
    
    unknown_pct, counts = cortex.evaluate_loao(
        X_train, y_train, X_test, y_test, held_out_attack
    )

print("\n" + "="*70)
print("KEY INSIGHT")
print("="*70)
print("""
✅ w model has THREE outcomes:
   1. KNOWN ATTACK (high confidence)
   2. BENIGN (anomaly score low)
   3. UNKNOWN (suspicious but not in training set)

This is what production IDS systems do!
""")

