import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


# ============================================================
# PATHS
# ============================================================

INPUT_FILE = "data/processed/cicids2017_cleaned.csv"

OUTPUT_DIR = "data/processed/ml"

X_TRAIN_FILE = os.path.join(
    OUTPUT_DIR,
    "X_train.csv"
)

X_TEST_FILE = os.path.join(
    OUTPUT_DIR,
    "X_test.csv"
)

Y_TRAIN_FILE = os.path.join(
    OUTPUT_DIR,
    "y_train.csv"
)

Y_TEST_FILE = os.path.join(
    OUTPUT_DIR,
    "y_test.csv"
)

ENCODER_FILE = os.path.join(
    OUTPUT_DIR,
    "label_classes.csv"
)


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_labels(df):

    print("\nNormalizing attack labels...")

    replacements = {

        "Web Attack � Brute Force":
            "Web Attack - Brute Force",

        "Web Attack � XSS":
            "Web Attack - XSS",

        "Web Attack � Sql Injection":
            "Web Attack - SQL Injection"
    }

    df["label"] = df["label"].replace(
        replacements
    )

    return df


# ============================================================
# LOAD DATA
# ============================================================

def load_data():

    print("\nLoading cleaned dataset...")

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False
    )

    print(
        f"Rows loaded: {len(df):,}"
    )

    print(
        f"Columns loaded: {len(df.columns)}"
    )

    return df


# ============================================================
# CLEAN NUMERIC FEATURES
# ============================================================

def clean_features(df):

    print("\nCleaning numeric features...")

    # Separate target

    y = df["label"]

    X = df.drop(
        columns=["label"]
    )

    # Keep only numeric features

    X = X.select_dtypes(
        include=["number"]
    )

    print(
        f"Numeric features: {len(X.columns)}"
    )

    # Replace infinite values

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Check missing values

    missing = (
        X.isnull()
        .sum()
        .sum()
    )

    print(
        f"Missing numeric values: {missing:,}"
    )

    # Fill missing values with median

    X = X.fillna(
        X.median()
    )

    # Remove negative flow duration

    if "flow_duration" in X.columns:

        invalid_count = (
            X["flow_duration"] < 0
        ).sum()

        print(
            "Negative flow duration records:",
            invalid_count
        )

        X.loc[
            X["flow_duration"] < 0,
            "flow_duration"
        ] = 0

    return X, y


# ============================================================
# STRATIFIED SAMPLING
# ============================================================

def create_stratified_sample(
    X,
    y,
    max_samples_per_class=20000
):

    print(
        "\nCreating stratified experimental dataset..."
    )

    combined = X.copy()

    combined["label"] = (
        y.values
    )

    samples = []

    for label, group in (
        combined.groupby("label")
    ):

        if len(group) > max_samples_per_class:

            group = group.sample(
                n=max_samples_per_class,
                random_state=42
            )

        samples.append(group)

        print(
            f"{label}: {len(group):,}"
        )

    sampled = pd.concat(
        samples,
        ignore_index=True
    )

    sampled = sampled.sample(
        frac=1,
        random_state=42
    ).reset_index(
        drop=True
    )

    y_sample = sampled["label"]

    X_sample = sampled.drop(
        columns=["label"]
    )

    print(
        "\nFinal experimental dataset:"
    )

    print(
        f"Rows: {len(X_sample):,}"
    )

    print(
        f"Features: {len(X_sample.columns)}"
    )

    return X_sample, y_sample


# ============================================================
# ENCODE LABELS
# ============================================================
def encode_labels(y):

    print(
        "\nEncoding attack labels..."
    )

    # Make sure output directory exists
    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    encoder = LabelEncoder()

    y_encoded = encoder.fit_transform(
        y
    )

    print("\nLabel mapping:")

    for number, label in enumerate(
        encoder.classes_
    ):

        print(
            f"{number} -> {label}"
        )

    mapping = pd.DataFrame({
        "encoded_value":
            range(len(encoder.classes_)),

        "attack_label":
            encoder.classes_
    })

    mapping.to_csv(
        ENCODER_FILE,
        index=False
    )

    return y_encoded



    encoder = LabelEncoder()

    y_encoded = encoder.fit_transform(
        y
    )

    print("\nLabel mapping:")

    for number, label in enumerate(
        encoder.classes_
    ):

        print(
            f"{number} -> {label}"
        )

    mapping = pd.DataFrame({
        "encoded_value":
            range(len(encoder.classes_)),

        "attack_label":
            encoder.classes_
    })

    mapping.to_csv(
        ENCODER_FILE,
        index=False
    )

    return y_encoded


# ============================================================
# TRAIN TEST SPLIT
# ============================================================

def split_dataset(X, y):

    print(
        "\nCreating train/test split..."
    )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y
        )
    )

    print(
        f"Training records: {len(X_train):,}"
    )

    print(
        f"Testing records: {len(X_test):,}"
    )

    return (
        X_train,
        X_test,
        y_train,
        y_test
    )


# ============================================================
# SAVE DATA
# ============================================================

def save_data(
    X_train,
    X_test,
    y_train,
    y_test
):

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    print(
        "\nSaving ML datasets..."
    )

    X_train.to_csv(
        X_TRAIN_FILE,
        index=False
    )

    X_test.to_csv(
        X_TEST_FILE,
        index=False
    )

    pd.DataFrame({
        "label": y_train
    }).to_csv(
        Y_TRAIN_FILE,
        index=False
    )

    pd.DataFrame({
        "label": y_test
    }).to_csv(
        Y_TEST_FILE,
        index=False
    )

    print(
        "\nFiles saved:"
    )

    print(X_TRAIN_FILE)
    print(X_TEST_FILE)
    print(Y_TRAIN_FILE)
    print(Y_TEST_FILE)


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "========================================"
    )

    print(
        " CIC-IDS2017 ML DATA PREPARATION"
    )

    print(
        "========================================"
    )

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    # Load
    df = load_data()
    # Load

    

    # Normalize labels

    df = normalize_labels(
        df
    )

    # Clean features

    X, y = clean_features(
        df
    )

    # Create balanced experimental sample

    X, y = create_stratified_sample(
        X,
        y,
        max_samples_per_class=20000
    )

    # Encode labels

    y = encode_labels(
        y
    )

    # Split

    (
        X_train,
        X_test,
        y_train,
        y_test
    ) = split_dataset(
        X,
        y
    )

    # Save

    save_data(
        X_train,
        X_test,
        y_train,
        y_test
    )

    print(
        "\n========================================"
    )

    print(
        " ML DATA PREPARATION COMPLETED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()