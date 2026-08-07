import sys
import glob
import pandas as pd
import numpy as np

DATA_DIR = "datasets/cic-ids-2017"

files = sorted(glob.glob(f"{DATA_DIR}/*.csv"))
print(f"found {len(files)} csv files\n")

sample = files[0]
print(f"=== inspecting {sample} ===\n")
df = pd.read_csv(sample, nrows=100000)

print(f"shape (first 100k rows): {df.shape}")
print(f"\n=== columns ({len(df.columns)}) ===")
for c in df.columns:
    print(repr(c))

print("\n=== dtypes ===")
print(df.dtypes.value_counts())

print("\n=== label column values (note whitespace) ===")
label_col = [c for c in df.columns if c.strip().lower() == "label"][0]
print(f"label column is: {repr(label_col)}")
print(df[label_col].value_counts())

print("\n=== NaN / infinity check across numeric columns ===")
numeric = df.select_dtypes(include=[np.number])
n_nan = numeric.isna().sum().sum()
n_inf = np.isinf(numeric.to_numpy()).sum()
print(f"total NaN cells: {n_nan}")
print(f"total infinity cells: {n_inf}")
cols_with_nan = numeric.columns[numeric.isna().any()].tolist()
cols_with_inf = [c for c in numeric.columns if np.isinf(numeric[c]).any()]
print(f"columns containing NaN: {cols_with_nan}")
print(f"columns containing inf: {cols_with_inf}")
