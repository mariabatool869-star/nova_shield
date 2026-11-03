#!/usr/bin/env python3
"""
CREATE MASTER UNIFIED DATASET
Combines CIC 2017 + CIC 2018 with all attack types
"""

import pandas as pd
import os
from pathlib import Path

print("\n" + "="*80)
print("CREATING MASTER UNIFIED DATASET")
print("="*80 + "\n")

# PART 1: LOAD CIC 2018 FILES
print("PART 1: Loading CIC 2018 Files")
print("-" * 80)

cic2018_path = "/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2018"
cic2018_files = sorted(Path(cic2018_path).glob("*.csv"))

dfs_2018 = []
total_2018 = 0

for csv_file in cic2018_files:
    filename = csv_file.name
    print("Loading: " + filename)
    
    try:
        df = pd.read_csv(csv_file)
        print("  Rows: " + str(len(df)))
        dfs_2018.append(df)
        total_2018 += len(df)
    except Exception as e:
        print("  ERROR: " + str(e))

print("Total CIC 2018 rows: " + str(total_2018) + "\n")

# PART 2: LOAD CIC 2017 FILES
print("PART 2: Loading CIC 2017 Files")
print("-" * 80)

cic2017_path = "/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2017"
cic2017_files = sorted(Path(cic2017_path).glob("*.csv"))

dfs_2017 = []
total_2017 = 0

for csv_file in cic2017_files:
    filename = csv_file.name
    print("Loading: " + filename)
    
    try:
        df = pd.read_csv(csv_file)
        print("  Rows: " + str(len(df)))
        dfs_2017.append(df)
        total_2017 += len(df)
    except Exception as e:
        print("  ERROR: " + str(e))

print("Total CIC 2017 rows: " + str(total_2017) + "\n")

# PART 3: COMBINE WITHIN EACH DATASET
print("PART 3: Combining CIC 2017 + CIC 2018")
print("-" * 80)

print("Combining CIC 2018 files...")
combined_2018 = pd.concat(dfs_2018, ignore_index=True)
print("Combined: " + str(len(combined_2018)) + " rows\n")

print("Combining CIC 2017 files...")
combined_2017 = pd.concat(dfs_2017, ignore_index=True)
print("Combined: " + str(len(combined_2017)) + " rows\n")

# PART 4: STANDARDIZE COLUMNS
print("PART 4: Standardizing Columns")
print("-" * 80)

print("CIC 2018 columns: " + str(len(combined_2018.columns)))
print("CIC 2017 columns: " + str(len(combined_2017.columns)))
print()

if ' Label' in combined_2017.columns:
    combined_2017 = combined_2017.rename(columns={' Label': 'Label'})
    print("Renamed ' Label' to 'Label' in CIC 2017")

print()

# PART 5: COMBINE BOTH DATASETS
print("PART 5: Combining CIC 2017 + CIC 2018")
print("-" * 80)

common_cols = list(set(combined_2018.columns) & set(combined_2017.columns))
common_cols.sort()

print("Common columns: " + str(len(common_cols)))
print()

combined_2018_subset = combined_2018[common_cols]
combined_2017_subset = combined_2017[common_cols]

master_df = pd.concat([combined_2018_subset, combined_2017_subset], ignore_index=True)

print("Master dataset shape: " + str(master_df.shape[0]) + " rows x " + str(master_df.shape[1]) + " columns")
print()

# PART 6: DATA QUALITY CHECK
print("PART 6: Data Quality Check")
print("-" * 80)

missing = master_df.isnull().sum().sum()
print("Missing values: " + str(missing))

duplicates = master_df.duplicated().sum()
print("Duplicate rows: " + str(duplicates))

print()

# PART 7: ANALYZE ATTACK TYPES
print("PART 7: Attack Types Analysis")
print("-" * 80)

if 'Label' in master_df.columns:
    labels = master_df['Label'].value_counts()
    print("Total unique attack types: " + str(len(labels)) + "\n")
    
    print("Attack distribution:\n")
    for label, count in labels.items():
        pct = (count / len(master_df)) * 100
        print("  • " + str(label).ljust(35) + str(count).rjust(10) + " (" + str(round(pct, 1)).rjust(5) + "%)")

print()

# PART 8: SAVE MASTER DATASET
print("PART 8: Saving Master Dataset")
print("-" * 80)

output_path = "/Users/a3mlab/Documents/nov@shield/models/datasets/MASTER_UNIFIED_DATASET.csv"

print("Saving to: " + output_path)
master_df.to_csv(output_path, index=False)

output_size_mb = os.path.getsize(output_path) / (1024*1024)
print("File saved!")
print("  Size: " + str(round(output_size_mb, 1)) + " MB")
print("  Rows: + str(master_df.shape[0]))
print("  Columns: " + str(master_df.shape[1]))

print()

print("="*80)
print("SUCCESS: MASTER UNIFIED DATASET CREATED!")
print("="*80 + "\n")

print("SUMMARY:\n")
print("  CIC 2018 rows: " + str(len(combined_2018_subset)))
print("  CIC 2017 rows: " + str(len(combined_2017_subset)))
print("  Total rows: " + str(len(master_df)))
print("  Features: " + str(len(common_cols) - 1))
print("  Attack types: " + str(len(labels)))
print()

