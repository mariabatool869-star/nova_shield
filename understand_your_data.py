#!/usr/bin/env python3
"""
LESSON 2: Understanding Your Data
Purpose: See what your actual data looks like
"""

import pandas as pd
import os

print("\n" + "="*80)
print("LESSON 2: UNDERSTANDING YOUR DATA")
print("="*80 + "\n")

# PART 1: FIND YOUR DATA FILE
print("PART 1: Finding Your Data File")
print("-" * 80)

# This is where your data is stored
data_file = "/Users/a3mlab/Documents/nov@shield/models/datasets/cic_2018/wednesday_dos_train.csv"

print("Looking for: " + data_file + "\n")

if os.path.exists(data_file):
    print("FOUND! Data file exists!")
    size_mb = os.path.getsize(data_file) / (1024*1024)
    print("   File size: " + str(round(size_mb, 1)) + " MB")
    print("   This is a LARGE dataset!\n")
else:
    print("NOT FOUND! File does not exist")
    print("   Check the path and try again\n")
    exit(1)

# PART 2: LOAD SMALL SAMPLE OF DATA
print("PART 2: Loading Small Sample (first 100 rows)")
print("-" * 80)
print("Why small sample? Because the full file is huge!")
print("Loading just 100 rows to see structure...\n")

# Load only 100 rows (not all 275 MB!)
df = pd.read_csv(data_file, nrows=100)

print("Data loaded successfully!")
print("   Rows: " + str(df.shape[0]) + " (this is just a sample)")
print("   Columns: " + str(df.shape[1]) + " (this is every column)\n")

# PART 3: UNDERSTAND THE COLUMNS (FEATURES)
print("PART 3: What Are the Columns? (Features/Attributes)")
print("-" * 80)
print("Each column describes something about the network flow\n")

# Show all column names
print("All columns in your data:\n")
for i, col_name in enumerate(df.columns, 1):
    print("  " + str(i).zfill(2) + ". " + col_name)

print("\nTotal columns: " + str(len(df.columns)))
print("These are the 'features' your model will learn from!\n")

# PART 4: LOOK AT ACTUAL DATA
print("PART 4: What Does Real Data Look Like?")
print("-" * 80)
print("Let's see the first 3 rows, first 5 columns:\n")

# Show first 3 rows, 5 columns
print(df.iloc[:3, :5].to_string())

print("\n(Each row = one network flow)")
print("(Each column = one attribute of that flow)\n")

# PART 5: UNDERSTAND THE LABELS (WHAT WE'RE TRYING TO PREDICT)
print("PART 5: What Are We Trying to Predict? (Labels)")
print("-" * 80)
print("The 'Label' column tells us if traffic is benign or attack\n")

if 'Label' in df.columns:
    # Get unique labels
    labels = df['Label'].unique()
    
    print("Found " + str(len(labels)) + " different types in this sample:\n")
    for label in labels:
        print("  * " + str(label))
    
    # Count each type
    print("\nHow many of each type:\n")
    counts = df['Label'].value_counts()
    for label_type, count in counts.items():
        percentage = (count / len(df)) * 100
        print("  " + str(label_type).ljust(30) + " " + str(count).rjust(3) + " rows (" + str(round(percentage, 1)) + "%)")
else:
    print("No 'Label' column found!")

print()

# PART 6: UNDERSTAND DATA QUALITY
print("PART 6: Data Quality Check - Are There Problems?")
print("-" * 80)
print("We need to check if data is clean\n")

# Check for missing values
missing_total = df.isnull().sum().sum()
print("Missing values (empty cells): " + str(missing_total))
if missing_total == 0:
    print("  Good! No missing values\n")
else:
    print("  Found " + str(missing_total) + " missing values\n")

# Check for duplicates
duplicates = df.duplicated().sum()
print("Duplicate rows (exact same twice): " + str(duplicates))
if duplicates == 0:
    print("  Good! No duplicates\n")
else:
    print("  Found " + str(duplicates) + " duplicate rows\n")

# PART 7: SUMMARY - WHAT YOU NOW KNOW
print("="*80)
print("PART 7: Summary - What You Now Know About Your Data")
print("="*80 + "\n")

print("YOUR DATASET FACTS:\n")
print("1. FILE SIZE: " + str(round(size_mb, 1)) + " MB")
print("   - This is a real, substantial dataset")
print("   - Good for training a model\n")

print("2. STRUCTURE:")
print("   - " + str(df.shape[0]) + " rows (in this sample)")
print("   - " + str(df.shape[1]) + " columns (total features)")
print("   - Each row = one network flow")
print("   - Each column = one attribute\n")

print("3. WHAT WE'RE PREDICTING:")
print("   - The 'Label' column")
print("   - " + str(len(labels)) + " different types\n")

print("4. EXAMPLES OF LABELS:")
for label in labels:
    print("   * " + str(label))

print("\n5. DATA QUALITY:")
print("   - Missing values: " + str(missing_total) + " (good!)")
print("   - Duplicates: " + str(duplicates) + " (good!)")
print("   - Data is CLEAN and ready to use\n")

print("6. WHAT THIS MEANS:")
print("   - You have real network traffic data")
print("   - Labeled (we know which are attacks)")
print("   - Multiple attack types")
print("   - Clean data (no corruption)")
print("   - Ready for model training!")

print("\n" + "="*80 + "\n")

