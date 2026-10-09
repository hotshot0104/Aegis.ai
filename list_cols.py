import pandas as pd
import glob

f = glob.glob("/kaggle/input/**/Benign-Monday*.parquet", recursive=True)
if not f:
    f = glob.glob("*.parquet")
if not f:
    print("No parquet found.")
else:
    df = pd.read_parquet(f[0])
    print(df.columns.tolist())
