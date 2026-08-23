import pandas as pd
import os

DATA_DIR = "data/processed/ml"

print("=" * 60)
print("CIC-IDS2017 TRAIN/TEST DISTRIBUTION")
print("=" * 60)

for file in ["X_train.csv", "X_test.csv", "y_train.csv", "y_test.csv"]:
    path = os.path.join(DATA_DIR, file)

    if not os.path.exists(path):
        print(f"\nERROR: File not found: {path}")
        continue

    df = pd.read_csv(path)
    print(f"\n{file}")
    print(f"Rows    : {df.shape[0]}")
    print(f"Columns : {df.shape[1]}")

print("\n" + "=" * 60)
print("LABEL DISTRIBUTION")
print("=" * 60)

for file in ["y_train.csv", "y_test.csv"]:

    path = os.path.join(DATA_DIR, file)

    if not os.path.exists(path):
        print(f"\nERROR: File not found: {path}")
        continue

    y = pd.read_csv(path).iloc[:, 0]

    counts = y.value_counts().sort_index()
    percentages = y.value_counts(normalize=True).sort_index() * 100

    print(f"\n{file}")
    print("-" * 40)

    for label in counts.index:
        print(
            f"Class {label}: "
            f"{counts[label]:,} samples "
            f"({percentages[label]:.4f}%)"
        )

    print(f"Total: {len(y):,}")

print("\n" + "=" * 60)
print("DONE")
print("=" * 60)