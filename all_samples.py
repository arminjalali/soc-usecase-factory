#!/usr/bin/env python3
import pandas as pd
import os, re

INPUT_FILE = "inventory/all.csv"       # your combined file
OUTPUT_DIR = "inventory/samples"       # target directory
os.makedirs(OUTPUT_DIR, exist_ok=True)

def sanitize_filename(sourcetype: str) -> str:
    """Make safe filename from sourcetype (replace : and /)."""
    return re.sub(r"[:/\\s]+", "_", sourcetype) + ".csv"

# Load the big CSV
df = pd.read_csv(INPUT_FILE, dtype=str).fillna("")

# Process each sourcetype (1 row per sourcetype expected)
for st, group in df.groupby("sourcetype"):
    # Drop columns that are entirely empty for this row
    cleaned = group.dropna(axis=1, how="all")  # drop NaN-only cols
    # also drop columns where the single row value is just empty string
    cleaned = cleaned.loc[:, (cleaned != "").any(axis=0)]

    filename = sanitize_filename(st)
    path = os.path.join(OUTPUT_DIR, filename)

    cleaned.to_csv(path, index=False, lineterminator="\n")
    print(f"[+] Wrote {path} with {cleaned.shape[1]} fields (removed blanks)")
