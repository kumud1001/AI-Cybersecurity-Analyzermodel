import os
import time
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# PATHS
# ============================================================

DATA_DIR = "data/processed/ml"

MODEL_DIR = "models"

RESULTS_DIR = "experiments/results"

FIGURES_DIR = "experiments/figures"

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "random_forest.pkl"
)

RESULT_FILE = os.path.join(
    RESULTS_DIR,
    "random_forest_results.csv"
)


# ============================================================
# LOAD DATA
# ============================================================

def load_data():

    print("\nLoading training and testing data...")

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
        f"Features: {len(X_train.columns)}"
    )

    return (
        X_train,
        X_test,
        y_train,
        y_test
    )


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

def train_model(
    X_train,
    y_train
):

    print(
        "\n========================================"
    )

    print(
        " TRAINING RANDOM FOREST"
    )

    print(
        "========================================"
    )

    model = RandomForestClassifier(

        n_estimators=100,

        random_state=42,

        n_jobs=-1,

        class_weight="balanced",

        max_features="sqrt"
    )

    start_time = time.time()

    model.fit(
        X_train,
        y_train
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
# EVALUATE MODEL
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
        " EVALUATING RANDOM FOREST"
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

    # Metrics

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision_macro = precision_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    recall_macro = recall_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    f1_macro = f1_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    precision_weighted = precision_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    recall_weighted = recall_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    f1_weighted = f1_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    print(
        "\n========================================"
    )

    print(
        " RANDOM FOREST RESULTS"
    )

    print(
        "========================================"
    )

    print(
        f"Accuracy          : {accuracy:.4f}"
    )

    print(
        f"Macro Precision   : {precision_macro:.4f}"
    )

    print(
        f"Macro Recall      : {recall_macro:.4f}"
    )

    print(
        f"Macro F1          : {f1_macro:.4f}"
    )

    print(
        f"Weighted Precision: {precision_weighted:.4f}"
    )

    print(
        f"Weighted Recall   : {recall_weighted:.4f}"
    )

    print(
        f"Weighted F1       : {f1_weighted:.4f}"
    )

    print(
        f"Inference Time    : "
        f"{inference_time:.4f} seconds"
    )

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print(
        "\nConfusion Matrix:"
    )

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print(matrix)

    results = {

        "model":
            "Random Forest",

        "accuracy":
            accuracy,

        "macro_precision":
            precision_macro,

        "macro_recall":
            recall_macro,

        "macro_f1":
            f1_macro,

        "weighted_precision":
            precision_weighted,

        "weighted_recall":
            recall_weighted,

        "weighted_f1":
            f1_weighted,

        "training_time_seconds":
            0,

        "inference_time_seconds":
            inference_time
    }

    return (
        results,
        predictions,
        matrix
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
# MAIN
# ============================================================

def main():

    print(
        "========================================"
    )

    print(
        " CIC-IDS2017 RANDOM FOREST EXPERIMENT"
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
        X_train,
        y_train
    )

    (
        results,
        predictions,
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
        " EXPERIMENT COMPLETED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()