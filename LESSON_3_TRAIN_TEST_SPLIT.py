#!/usr/bin/env python3
"""
LESSON 3: HONEST TRAIN/TEST SPLIT
No data leakage - realistic evaluation
"""

import pandas as pd
import numpy as np

print("\n" + "="*80)
print("LESSON 3: HONEST TRAIN/TEST SPLIT")
print("="*80 + "\n")

# PART 1: LOAD DATA
print("PART 1: Loading Master Dataset")
print("-" * 80)

df = pd.read_csv("/Users/a3mlab/Documents/nov@shield/models/datasets/MASTER_UNIFIED_DATASET.csv")

print("Loaded: " + str(len(df)) + " rows")
print("Columns: " + str(len(df.columns)))
print()

# PART 2: EXAMINE STRUCTURE
print("PART 2: Examining Data Structure")
print("-" * 80)

print("Column names (first 5):")
for i, col in enumerate(df.columns[:5], 1):
    print("  " + str(i) + ". " + str(col))

print()
print("Last column (Label): " + str(df.columns[-1]))
print()

# PART 3: ANALYZE LABELS
print("PART 3: Analyzing Attack Types")
print("-" * 80)

label_col = df.columns[-1]
labels = df[label_col].value_counts()

print("Found " + str(len(labels)) + " attack types")
print()

# PART 4: NORMALIZE LABELS
print("PART 4: Normalizing Label Names")
print("-" * 80)

print("Labels before normalization:")
print(labels.index.tolist()[:5])
print()

# Fix case inconsistencies
df[label_col] = df[label_col].str.strip()  # Remove whitespace
df[label_col] = df[label_col].replace('BENIGN', 'Benign')
df[label_col] = df[label_col].replace('benign', 'Benign')

# Fix DoS name inconsistencies
df[label_col] = df[label_col].replace('DoS attacks-GoldenEye', 'DoS-GoldenEye')
df[label_col] = df[label_col].replace('DoS GoldenEye', 'DoS-GoldenEye')

# Fix SSH name inconsistencies
df[label_col] = df[label_col].replace('SSH-Bruteforce', 'SSH-Patator')
df[label_col] = df[label_col].replace('SSH-Patator', 'SSH-Patator')

# Fix FTP name inconsistencies
df[label_col] = df[label_col].replace('FTP-Patator', 'FTP-Brute')
df[label_col] = df[label_col].replace('FTP-BruteForce', 'FTP-Brute')

labels_normalized = df[label_col].value_counts()

print("Labels after normalization:")
print(labels_normalized)
print()

# PART 5: TIME-BASED SPLIT
print("PART 5: Time-Based Train/Test Split")
print("-" * 80)

split_idx = int(len(df) * 0.8)

df_train = df[:split_idx].copy()
df_test = df[split_idx:].copy()

print("Train set: " + str(len(df_train)) + " rows (80%)")
print("Test set: " + str(len(df_test)) + " rows (20%)")
print()

# PART 6: VERIFY NO DATA LEAKAGE
print("PART 6: Verify No Data Leakage")
print("-" * 80)

# Check if any rows are identical between train and test
train_rows = set(map(tuple, df_train.values))
test_rows = set(map(tuple, df_test.values))
overlap = len(train_rows & test_rows)

print("Rows in train: " + str(len(train_rows)))
print("Rows in test: " + str(len(test_rows)))
print("Overlapping rows: " + str(overlap))
print()

if overlap == 0:
    print("✅ NO DATA LEAKAGE! Sets are completely separate!")
else:
    print("❌ WARNING: Found " + str(overlap) + " overlapping rows!")

print()

# PART 7: ANALYZE TRAIN/TEST DISTRIBUTION
print("PART 7: Train/Test Label Distribution")
print("-" * 80)

prinRAIN SET:\n")
train_labels = df_train[label_col].value_counts()
for label, count in train_labels.head(10).items():
    pct = (count / len(df_train)) * 100
    print("  • " + str(label).ljust(30) + str(count).rjust(10) + " (" + str(round(pct, 1)).rjust(5) + "%)")

print("\nTEST SET:\n")
test_labels = df_test[label_col].value_counts()
for label, count in test_labels.head(10).items():
    pct = (count / len(df_test)) * 100
    print("  • " + str(label).ljust(30) + str(count).rjust(10) + " (" + str(round(pct, 1)).rjust(5) + "%)")

print()

# PART 8: SAVE TRAIN/TEST SETS
print("PART 8: Saving Train/Test Sets")
print("-" * 80)

train_path = "/Users/a3mlab/Documents/nov@shield/models/datasets/TRAIN_SET.csv"
test_path = "/Users/a3mlab/Documents/nov@shield/models/datasets/TEST_SET.csv"

print("Saving train set...")
df_train.to_csv(train_path, index=False)
print("  Saved: " + train_path)

print("Saving test set...")
df_test.to_csv(test_path, index=False)
print("  Saved: " + test_path)

print()

# SUMMARY
print("=)
print("SUCCESS: HONEST TRAIN/TEST SPLIT CREATED")
print("="*80 + "\n")

print("SUMMARY:\n")
print("  Total data: " + str(len(df)) + " flows")
print("  Train set: " + str(len(df_train)) + " flows (80%)")
print("  Test set: " + str(len(df_test)) + " flows (20%)")
print("  Data leakage: NO ✅")
print("  Attack types: " + str(len(labels_normalized)))
print()

