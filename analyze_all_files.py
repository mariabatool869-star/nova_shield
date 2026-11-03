#!/usr/bin/env python3
"""
ANALYZE ALL YOUR CSV FILES
See what attack types are in EACH file
"""

import pandas as pd
import os
from pathlib import Path

print("\n" + "="*80)
print("ANALYZING ALL YOUR DATA FILES")
print("="*80 + "\n")

base_path = "/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2018"

# List all CSV files
csv_files = sorted(Path(base_path).glob("*.csv"))

print("Found " + str(len(csv_files)) + " CSV files\n")

# Analyze each file
all_attack_types = set()

for csv_file in csv_files:
    filename = csv_file.name
    file_size_mb = os.path.getsize(csv_file) / (1024*1024)
    
    print("-" * 80)
    print("FILE: " + filename)
    print("SIZE: " + str(round(file_size_mb, 1)) + " MB")
    print()
    
    try:
        # Load just first 1000 rows (faster)
        df = pd.read_csv(csv_file, nrows=1000)
        
        if 'Label' in df.columns:
            labels = df['Label'].value_counts()
            print("Attack types in this file:\n")
            
            for attack_type, count in labels.items():
                pct = (count / len(df)) * 100
                print("  • " + str(attack_type).ljust(40) + str(count).rjust(4) + " (" + str(round(pct, 1)) + "%)")
                all_attack_types.add(attack_type)
        else:
            print("No 'Label' column found")
        
        print()
        
    except Exception as e:
        print("ERROR reading file: " + str(e))
        print()

# Summary
print("="*80)
print("SUMMARY: ALL ATTACK TYPES IN YOUR DATA")
print("="*80 + "\n")

print("Unique attack types across ALL files:\n")
for i, attack_type in enumerate(sorted(all_attack_types), 1):
    print("  " + str(i) + ". " + str(attack_type))

print("\nTotal unique attack types: " + str(len(all_attack_types)))
print()

