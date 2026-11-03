#!/usr/bin/env python3
"""
Search for missing attack types in ALL your datasets
"""

import pandas as pd
from pathlib import Path

print("\n" + "="*80)
print("SEARCHING FOR MISSING ATTACK TYPES")
print("="*80 + "\n")

# Search in all datasets
all_files = list(Path("/Users/a3mlab/Documents/nov@shield/models/datasets/").rglob("*.csv"))

all_attacks = {}

for csv_file in sorted(all_files):
    filename = str(csv_file).split("/")[-1]
    folder = str(csv_file).split("/")[-2]
    
    try:
        df = pd.read_csv(csv_file, nrows=1000)
        
        if 'Label' in df.columns:
            labels = df['Label'].unique()
            
            print("FILE: " + folder + "/" + filename)
            for label in labels:
                print("  - " + str(label))
                all_attacks[str(label)] = folder + "/" + filename
            print()
    except:
        pass

print("\n" + "="*80)
print("ALL UNIQUE ATTACK TYPES ACROSS ALL YOUR DATA:")
print("="*80 + "\n")

for i, attack in enumerate(sorted(set(all_attacks.keys())), 1):
    print("  " + str(i) + ". " + str(attack))

