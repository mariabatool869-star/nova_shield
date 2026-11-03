import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
import pickle
import os
import warnings
warnings.filterwarnings('ignore')

print("\n" + "="*80)
print("TRAINING MODEL WITH FULL FEATURES")
print("="*80 + "\n")

# Load the full-featured datasets instead
print("Loading full-featured data from CIC-IDS 2017...")
data_files = [
    '/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2017/Monday-WorkingHours.pcap_ISCX.csv',
    '/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2017/Tuesday-WorkingHours.pcap_ISCX.csv',
    '/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2017/Wednesday-workingHours.pcap_ISCX.csv',
    '/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    '/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    '/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2017/Friday-WorkingHours-Morning.pcap_ISCX.csv',
    '/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    '/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
]

# Load and combine data
dfs = []
for file in data_files:
    try:
        df = pd.read_csv(file)
        print(f"  ✓ Loaded {file.split('/')[-1]} - {len(df)} samples, {df.shape[1]} features")
        dfs.append(df)
    except Exception as e:
        print(f"  ✗ Error loading {file}: {e}")

data = pd.concat(dfs, ignore_index=True)
print(f"\nTotal combined data: {len(data)} samples\n")

# Remove infinite values and handle missing data
print("Cleaning data...")
data = data.replace([np.inf, -np.inf], np.nan)
data = data.dropna()
print(f"After cleaning: {len(data)} samples\n")

# Separate features and labels
X = data.iloc[:, :-1]
y = data.iloc[:, -1]

print(f"Features: {X.shape[1]}")
print(f"Samples: {X.shape[0]}\n")

# Encode labels
print("Encoding labels...")
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

print(f"Attack types found: {len(label_encoder.classes_)}\n")
for i, label in enumerate(label_encoder.classes_):
    count = (y_encoded == i).sum()
    percentage = (count / len(y_encoded)) * 100
    print(f"  {i}. {label:<35} {count:>10} ({percentage:>5.1f}%)")

# Split data (80% train, 20% test)
X_train, X_test, y_train_encoded, y_test_encoded = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print(f"\nTrain samples: {len(X_train)}")
print(f"Test samples: {len(X_test)}\n")

# Standardize features
print("Standardizing features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train model with class weighting
print("Training RandomForest with full features (5-10 minutes)...\n")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=30,
    n_jobs=-1,
    random_state=42,
    class_weight='balanced',
    verbose=1
)
model.fit(X_train_scaled, y_train_encoded)

# Evaluate
print("\n" + "="*80)
print("MODEL EVALUATION")
print("="*80 + "\n")

y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test_encoded, y_pred)

print(f"Overall Accuracy: {accuracy:.4f}\n")

print("Classification Report:\n")
print(classification_report(
    y_test_encoded,
    y_pred,
    target_names=label_encoder.classes_,
    zero_division=0
))

# Save model and preprocessing objects
print("\nSaving model and preprocessing objects...")
os.makedirs('/Users/a3mlab/Documents/nov@shield/models', exist_ok=True)

with open('/Users/a3mlab/Documents/nov@shield/models/model_full_features.pkl', 'wb') as f:
    pickle.dump(model, f)

with open('/Users/a3mlab/Documents/nov@shield/models/label_encoder.pkl', 'wb') as f:
    pickle.dump(label_encoder, f)

with open('/Users/a3mlab/Documents/nov@shield/models/scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

# Feature importance
print("\n" + "="*80)
print("TOP 20 IMPORTANT FEATURES")
print("="*80 + "\n")

feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

for idx, row in feature_importance.head(20).iterrows():
    print(f"  {row['feature']:<40} {row['importance']:.6f}")

print("\n✅ Model training complete!")
print("✅ Saved: model_full_features.pkl, label_encoder.pkl, scaler.pkl")

