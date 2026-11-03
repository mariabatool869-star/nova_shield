#!/usr/bin/env python3
import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path

print("\n" + "="*80)
print("CYBER DEFENSE SYSTEM DIAGNOSTIC REPORT")
print("="*80 + "\n")

# STEP 1: ENVIRONMENT CHECK
print("STEP 1: ENVIRONMENT CHECK")
print("-" * 80)
print("Python version: " + str(sys.version))
print("Working directory: " + os.getcwd())
print("OS: " + sys.platform)
print()

# Check libraries
required_libs = {
    'pandas': 'Data handling',
    'numpy': 'Numerical computing',
    'sklearn': 'Machine learning',
}

print("Required Libraries:")
for lib, purpose in required_libs.items():
    try:
        mod = __import__(lib)
        version = getattr(mod, '__version__', 'unknown')
        print("  OK " + lib + " v" + str(version) + " (" + purpose + ")")
    except ImportError:
        print("  MISSING " + lib + " (" + purpose + ")")

print("\n")

# STEP 2: DATA DISCOVERY
print("STEP 2: DATA DISCOVERY")
print("-" * 80)

data_paths = ['data/', './', '../data/', 'datasets/']
csv_files = []

for path in data_paths:
    if os.path.exists(path):
        files = list(Path(path).glob('*.csv'))
        csv_files.extend(files)

if csv_files:
    print("Found " + str(len(csv_files)) + " CSV files:")
    print()
    for i, f in enumerate(csv_files, 1):
        size_mb = os.path.getsize(f) / (1024*1024)
        print("  " + str(i) + ". " + f.name + " (" + str(round(size_mb, 1)) + " MB)")
else:
    print("NO CSV files found!")

print("\n")

# STEP 3: DATA ANALYSIS
print("STEP 3: DATA STRUCTURE ANALYSIS")
print("-" * 80)

if csv_files:
    for csv_file in csv_files[:1]:
        print("Analyzing: " + csv_file.name)
        print()
        try:
            df = pd.read_csv(csv_file, nrows=1000)
            print("Shape: " + str(df.shape[0]) + " rows x " + str(df.shape[1]) + " columns")
            print("Memory: " + str(round(df.memory_usage(deep=True).sum() / (1024*1024), 1)) + " MB")
            print()
            
            print("Columns:")
            for i, col in enumerate(df.columns, 1):
                dtype = str(df[col].dtype)
                nulls = df[col].isnull().sum()
                print("  " + str(i) + ". " + col + " (" + dtype + ", " + str(nulls) + " nulls)")
            
            print()
            
            if 'Label' in df.columns:
                print("Label Distribution:")
                label_dist = df['Label'].value_counts()
                for label, count in label_dist.items():
                    pct = (count / len(df)) * 100
                    print("  " + str(label) + ": " + str(count) + " (" + str(round(pct, 1)) + "%)")
            else:
                print("WARNING: No 'Label' column found")
        except Exception as e:
            print("ERROR: " + str(e))

print("\n")

# STEP 4: SCRIPTS CHECK
print("STEP 4: PYTHON SCRIPTS")
print("-" * 80)

py_files = list(Path('.').glob('*.py'))
print("Python scripts in directory: " + str(len(py_files)))
print()

scripts_to_check = [
    'cortex_with_unknown_fixed.py',
    'honest_evaluation.py',
    'leave_one_attack_out.py'
]

for script in scripts_to_check:
    exists = "OK" if os.path.exists(script) else "MISSING"
    print("  " + script + " ... " + exists)

print("\n")
print("="*80)
print("DIAGNOSTIC COMPLETE")
print("="*80 + "\n")
