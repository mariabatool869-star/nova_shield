from pathlib import Path
import pandas as pd

DATA = Path("models/datasets/cic_2017")

def load_batches(batch_size=10000):
    for file in sorted(DATA.glob("*.csv")):
        for batch in pd.read_csv(file, chunksize=batch_size, low_memory=False):
            batch.columns = batch.columns.str.strip()
            if "Label" not in batch.columns:
                raise ValueError(f"Missing Label: {file.name}")
            batch["Label"] = batch["Label"].astype(str).str.strip()
            yield file.name, batch

if __name__ == "__main__":
    print("NOVASHIELD CIC-IDS2017 LOADER")
    name, batch = next(load_batches())
    print("File:", name)
    print("Rows loaded:", len(batch))
    print("Columns:", len(batch.columns))
    print("Classes:", batch["Label"].value_counts().to_dict())
    print("TEST PASSED")
