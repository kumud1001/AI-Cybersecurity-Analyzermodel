import os
import glob
import pandas as pd
import numpy as np


# ============================================================
# PATHS
# ============================================================

RAW_DIR = "data/raw"
PROCESSED_DIR = "data/processed"

OUTPUT_FILE = os.path.join(
    PROCESSED_DIR,
    "cicids2017_cleaned.csv"
)


# ============================================================
# FIND CSV FILES
# ============================================================

def find_csv_files():

    pattern = os.path.join(
        RAW_DIR,
        "*.csv"
    )

    files = glob.glob(pattern)

    if not files:
        raise FileNotFoundError(
            "No CSV files found in data/raw/"
        )

    print("\nCSV files found:")

    for file in files:
        print(" -", os.path.basename(file))

    print(
        f"\nTotal CSV files: {len(files)}"
    )

    return files


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset(files):

    dataframes = []

    print("\nLoading CIC-IDS2017 files...")

    for file in files:

        print(
            f"\nReading: {os.path.basename(file)}"
        )

        df = pd.read_csv(
            file,
            low_memory=False
        )

        print(
            f"Rows: {len(df):,}"
        )

        print(
            f"Columns: {len(df.columns)}"
        )

        dataframes.append(df)

    print("\nCombining datasets...")

    combined_df = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(
        "\nCombined dataset shape:"
    )

    print(
        combined_df.shape
    )

    return combined_df


# ============================================================
# CLEAN COLUMN NAMES
# ============================================================

def clean_column_names(df):

    print(
        "\nCleaning column names..."
    )

    df.columns = (
        df.columns
        .str.strip()
        .str.lower()
        .str.replace(" ", "_")
        .str.replace("/", "_")
        .str.replace("-", "_")
    )

    return df


# ============================================================
# CLEAN NUMERIC DATA
# ============================================================

def clean_numeric_values(df):

    print(
        "\nCleaning numeric values..."
    )

    # Convert infinite values to NaN

    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Count missing values

    missing_before = (
        df.isnull()
        .sum()
        .sum()
    )

    print(
        f"Missing values before cleaning: "
        f"{missing_before:,}"
    )

    # Replace missing numeric values
    # using column median

    numeric_columns = (
        df.select_dtypes(
            include=["number"]
        ).columns
    )

    for column in numeric_columns:

        median = df[column].median()

        df[column] = (
            df[column]
            .fillna(median)
        )

    missing_after = (
        df.isnull()
        .sum()
        .sum()
    )

    print(
        f"Missing values after cleaning: "
        f"{missing_after:,}"
    )

    return df


# ============================================================
# REMOVE DUPLICATES
# ============================================================

def remove_duplicates(df):

    print(
        "\nChecking duplicate rows..."
    )

    before = len(df)

    df = df.drop_duplicates()

    after = len(df)

    removed = before - after

    print(
        f"Duplicate rows removed: "
        f"{removed:,}"
    )

    print(
        f"Remaining rows: "
        f"{after:,}"
    )

    return df


# ============================================================
# FIND LABEL COLUMN
# ============================================================

def find_label_column(df):

    possible_labels = [
        "label",
        "attack",
        "attack_type",
        "class",
        "target"
    ]

    for column in possible_labels:

        if column in df.columns:

            print(
                f"\nTarget column found: "
                f"{column}"
            )

            return column

    raise ValueError(
        "\nCould not find the Label column."
        "\nAvailable columns:"
        f"\n{list(df.columns)}"
    )


# ============================================================
# CLEAN LABELS
# ============================================================

def clean_labels(df, label_column):

    print(
        "\nCleaning attack labels..."
    )

    df[label_column] = (
        df[label_column]
        .astype(str)
        .str.strip()
    )

    print(
        "\nAttack distribution:"
    )

    print(
        df[label_column]
        .value_counts()
    )

    return df


# ============================================================
# REMOVE EMPTY LABELS
# ============================================================

def remove_empty_labels(
    df,
    label_column
):

    print(
        "\nRemoving empty labels..."
    )

    before = len(df)

    df = df[
        df[label_column].notna()
    ]

    df = df[
        df[label_column] != ""
    ]

    after = len(df)

    print(
        f"Rows removed: "
        f"{before - after:,}"
    )

    return df


# ============================================================
# SAVE DATASET
# ============================================================

def save_dataset(df):

    os.makedirs(
        PROCESSED_DIR,
        exist_ok=True
    )

    print(
        "\nSaving cleaned dataset..."
    )

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        "\nDataset saved successfully:"
    )

    print(
        OUTPUT_FILE
    )


# ============================================================
# MAIN PREPROCESSING PIPELINE
# ============================================================

def main():

    print(
        "========================================"
    )

    print(
        " CIC-IDS2017 DATA PREPROCESSING"
    )

    print(
        "========================================"
    )

    # 1. Find CSV files

    files = find_csv_files()

    # 2. Load CSV files

    df = load_dataset(files)

    # 3. Clean column names

    df = clean_column_names(df)

    # 4. Find target label

    label_column = find_label_column(df)

    # 5. Remove duplicate rows

    df = remove_duplicates(df)

    # 6. Clean numeric values

    df = clean_numeric_values(df)

    # 7. Remove empty labels

    df = remove_empty_labels(
        df,
        label_column
    )

    # 8. Clean attack labels

    df = clean_labels(
        df,
        label_column
    )

    # 9. Display final information

    print(
        "\n========================================"
    )

    print(
        " FINAL DATASET INFORMATION"
    )

    print(
        "========================================"
    )

    print(
        f"Rows: {len(df):,}"
    )

    print(
        f"Columns: {len(df.columns)}"
    )

    print(
        "\nFeatures:"
    )

    for column in df.columns:

        print(
            " -",
            column
        )

    # 10. Save

    save_dataset(df)

    print(
        "\n========================================"
    )

    print(
        " PREPROCESSING COMPLETED"
    )

    print(
        "========================================"
    )


# ============================================================
# RUN PROGRAM
# ============================================================

if __name__ == "__main__":
    main()