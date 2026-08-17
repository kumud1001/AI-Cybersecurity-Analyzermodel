import os
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# PATHS
# ============================================================

DATA_DIR = "data/processed/ml"

MODEL_DIR = "models"

RESULTS_DIR = "experiments/results"

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "isolation_forest.pkl"
)

RESULT_FILE = os.path.join(
    RESULTS_DIR,
    "isolation_forest_results.csv"
)


# ============================================================
# LOAD DATA
# ============================================================

def load_data():

    print("\nLoading data...")

    X_train = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "X_train.csv"
        )
    )

    X_test = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "X_test.csv"
        )
    )

    y_train = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "y_train.csv"
        )
    )["label"]

    y_test = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "y_test.csv"
        )
    )["label"]

    print(
        f"Training samples: {len(X_train):,}"
    )

    print(
        f"Testing samples: {len(X_test):,}"
    )

    print(
        f"Features: {X_train.shape[1]}"
    )

    return (
        X_train,
        X_test,
        y_train,
        y_test
    )


# ============================================================
# CREATE BINARY LABEL
# ============================================================

def create_binary_labels(y):

    # 0 = BENIGN
    # 1 = ATTACK

    return np.where(
        y == 0,
        0,
        1
    )


# ============================================================
# TRAIN ISOLATION FOREST
# ============================================================

def train_model(X_train):

    print(
        "\n========================================"
    )

    print(
        " TRAINING ISOLATION FOREST"
    )

    print(
        "========================================"
    )

    model = IsolationForest(

        n_estimators=200,

        contamination=0.10,

        random_state=42,

        n_jobs=-1,

        max_samples="auto"
    )

    start_time = time.time()

    model.fit(
        X_train
    )

    training_time = (
        time.time()
        - start_time
    )

    print(
        f"\nTraining time: "
        f"{training_time:.2f} seconds"
    )

    return (
        model,
        training_time
    )


# ============================================================
# EVALUATE
# ============================================================

def evaluate_model(
    model,
    X_test,
    y_test
):

    print(
        "\n========================================"
    )

    print(
        " EVALUATING ISOLATION FOREST"
    )

    print(
        "========================================"
    )

    start_time = time.time()

    predictions = model.predict(
        X_test
    )

    inference_time = (
        time.time()
        - start_time
    )

    # Isolation Forest:
    #
    # +1 = normal
    # -1 = anomaly
    #
    # Convert:
    #
    # +1 -> 0 BENIGN
    # -1 -> 1 ATTACK

    predictions = np.where(
        predictions == 1,
        0,
        1
    )

    # Actual binary labels

    y_binary = create_binary_labels(
        y_test
    )

    # Metrics

    accuracy = accuracy_score(
        y_binary,
        predictions
    )

    precision = precision_score(
        y_binary,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_binary,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_binary,
        predictions,
        zero_division=0
    )

    print(
        "\n========================================"
    )

    print(
        " ISOLATION FOREST RESULTS"
    )

    print(
        "========================================"
    )

    print(
        f"Accuracy       : {accuracy:.4f}"
    )

    print(
        f"Precision      : {precision:.4f}"
    )

    print(
        f"Recall         : {recall:.4f}"
    )

    print(
        f"F1-score       : {f1:.4f}"
    )

    print(
        f"Inference Time : "
        f"{inference_time:.4f} seconds"
    )

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_binary,
            predictions,
            target_names=[
                "BENIGN",
                "ATTACK"
            ],
            zero_division=0
        )
    )

    print(
        "\nConfusion Matrix:"
    )

    matrix = confusion_matrix(
        y_binary,
        predictions
    )

    print(
        matrix
    )

    results = {

        "model":
            "Isolation Forest",

        "accuracy":
            accuracy,

        "precision":
            precision,

        "recall":
            recall,

        "f1":
            f1,

        "training_time_seconds":
            0,

        "inference_time_seconds":
            inference_time
    }

    return (
        results,
        matrix
    )


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(model):

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_FILE
    )

    print(
        "\nModel saved:"
    )

    print(
        MODEL_FILE
    )


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(
    results,
    training_time
):

    os.makedirs(
        RESULTS_DIR,
        exist_ok=True
    )

    results[
        "training_time_seconds"
    ] = training_time

    df = pd.DataFrame(
        [results]
    )

    df.to_csv(
        RESULT_FILE,
        index=False
    )

    print(
        "\nResults saved:"
    )

    print(
        RESULT_FILE
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "========================================"
    )

    print(
        " CIC-IDS2017 ISOLATION FOREST"
    )

    print(
        " Experiment 3.3.0"
    )

    print(
        "========================================"
    )

    (
        X_train,
        X_test,
        y_train,
        y_test
    ) = load_data()

    model, training_time = train_model(
        X_train
    )

    (
        results,
        matrix
    ) = evaluate_model(
        model,
        X_test,
        y_test
    )

    save_model(
        model
    )

    save_results(
        results,
        training_time
    )

    print(
        "\n========================================"
    )

    print(
        " ISOLATION FOREST EXPERIMENT COMPLETED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()