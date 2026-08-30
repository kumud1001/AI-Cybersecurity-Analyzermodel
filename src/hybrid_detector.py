import os
import time
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from tensorflow.keras.models import load_model

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    roc_auc_score
)


# ============================================================
# PATHS
# ============================================================

DATA_DIR = "data/processed/ml"
MODEL_DIR = "models"
RESULTS_DIR = "experiments/results"

RF_MODEL_FILE = os.path.join(
    MODEL_DIR,
    "random_forest.pkl"
)

XGB_MODEL_FILE = os.path.join(
    MODEL_DIR,
    "xgboost.pkl"
)

IF_MODEL_FILE = os.path.join(
    MODEL_DIR,
    "isolation_forest.pkl"
)

LSTM_MODEL_FILE = os.path.join(
    MODEL_DIR,
    "lstm_autoencoder.keras"
)

LSTM_SCALER_FILE = os.path.join(
    MODEL_DIR,
    "lstm_scaler.pkl"
)

X_TEST_FILE = os.path.join(
    DATA_DIR,
    "X_test.csv"
)

Y_TEST_FILE = os.path.join(
    DATA_DIR,
    "y_test.csv"
)

RESULT_FILE = os.path.join(
    RESULTS_DIR,
    "hybrid_results.csv"
)


# ============================================================
# SETTINGS
# ============================================================

RANDOM_STATE = 42

TEST_SAMPLE_SIZE = 20000

# Hybrid weights
XGB_WEIGHT = 0.40
RF_WEIGHT = 0.30
IF_WEIGHT = 0.15
LSTM_WEIGHT = 0.15

HYBRID_THRESHOLD = 0.50

LSTM_THRESHOLD_PERCENTILE = 95


# ============================================================
# LOAD DATA
# ============================================================

def load_data():

    print("\n========================================")
    print(" LOADING TEST DATA")
    print("========================================")

    X_test = pd.read_csv(
        X_TEST_FILE
    )

    y_test = pd.read_csv(
        Y_TEST_FILE
    )["label"]

    print(
        f"Available test samples: "
        f"{len(X_test):,}"
    )

    if len(X_test) > TEST_SAMPLE_SIZE:

        rng = np.random.RandomState(
            RANDOM_STATE
        )

        indices = rng.choice(
            len(X_test),
            size=TEST_SAMPLE_SIZE,
            replace=False
        )

        X_test = X_test.iloc[
            indices
        ].reset_index(drop=True)

        y_test = y_test.iloc[
            indices
        ].reset_index(drop=True)

    print(
        f"Hybrid test samples: "
        f"{len(X_test):,}"
    )

    return X_test, y_test


# ============================================================
# LOAD MODELS
# ============================================================

def load_models():

    print("\n========================================")
    print(" LOADING TRAINED MODELS")
    print("========================================")

    print("Loading Random Forest...")

    rf_model = joblib.load(
        RF_MODEL_FILE
    )

    print("Loading XGBoost...")

    xgb_model = joblib.load(
        XGB_MODEL_FILE
    )

    print("Loading Isolation Forest...")

    if_model = joblib.load(
        IF_MODEL_FILE
    )

    print("Loading LSTM Autoencoder...")

    lstm_model = load_model(
        LSTM_MODEL_FILE
    )

    print("Loading LSTM scaler...")

    lstm_scaler = joblib.load(
        LSTM_SCALER_FILE
    )

    print("All models loaded successfully.")

    return (
        rf_model,
        xgb_model,
        if_model,
        lstm_model,
        lstm_scaler
    )


# ============================================================
# LOAD TRAINING DATA FOR LSTM THRESHOLD
# ============================================================

def load_benign_training_data():

    print(
        "\nLoading benign training data "
        "for LSTM threshold..."
    )

    X_train = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "X_train.csv"
        )
    )

    y_train = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "y_train.csv"
        )
    )["label"]

    # Keep only BENIGN
    X_benign = X_train[
        y_train == 0
    ].copy()

    print(
        f"Benign training samples: "
        f"{len(X_benign):,}"
    )

    return X_benign


# ============================================================
# LSTM RECONSTRUCTION ERRORS
# ============================================================

def get_lstm_anomaly_scores(
    lstm_model,
    scaler,
    X_benign,
    X_test
):

    print(
        "\n========================================"
    )

    print(
        " CALCULATING LSTM ANOMALY SCORES"
    )

    print(
        "========================================"
    )

    # Scale benign training flows

    X_benign_scaled = scaler.transform(
        X_benign
    )

    X_benign_scaled = np.nan_to_num(
        X_benign_scaled,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )

    X_benign_scaled = np.expand_dims(
        X_benign_scaled,
        axis=1
    )

    # Calculate normal reconstruction errors

    benign_reconstructed = (
        lstm_model.predict(
            X_benign_scaled,
            verbose=0
        )
    )

    benign_errors = np.mean(
        np.square(
            X_benign_scaled -
            benign_reconstructed
        ),
        axis=(1, 2)
    )

    threshold = np.percentile(
        benign_errors,
        LSTM_THRESHOLD_PERCENTILE
    )

    # Scale test data

    X_test_scaled = scaler.transform(
        X_test
    )

    X_test_scaled = np.nan_to_num(
        X_test_scaled,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )

    X_test_scaled = np.expand_dims(
        X_test_scaled,
        axis=1
    )

    test_reconstructed = (
        lstm_model.predict(
            X_test_scaled,
            verbose=0
        )
    )

    test_errors = np.mean(
        np.square(
            X_test_scaled -
            test_reconstructed
        ),
        axis=(1, 2)
    )

    lstm_anomaly = np.where(
        test_errors > threshold,
        1.0,
        0.0
    )

    print(
        f"LSTM threshold: {threshold:.6f}"
    )

    print(
        f"LSTM anomalies detected: "
        f"{int(lstm_anomaly.sum()):,}"
    )

    return (
        lstm_anomaly,
        threshold
    )


# ============================================================
# GET MODEL SCORES
# ============================================================

def generate_scores(
    rf_model,
    xgb_model,
    if_model,
    lstm_model,
    lstm_scaler,
    X_test
):

    print(
        "\n========================================"
    )

    print(
        " GENERATING MODEL SCORES"
    )

    print(
        "========================================"
    )

    # --------------------------------------------------------
    # XGBoost
    # --------------------------------------------------------

    print("Calculating XGBoost scores...")

    xgb_probabilities = (
        xgb_model.predict_proba(
            X_test
        )
    )

    # Class 0 = BENIGN
    # 1 - P(BENIGN) = attack probability

    xgb_attack_probability = (
        1.0 -
        xgb_probabilities[:, 0]
    )

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    print("Calculating Random Forest scores...")

    rf_probabilities = (
        rf_model.predict_proba(
            X_test
        )
    )

    rf_attack_probability = (
        1.0 -
        rf_probabilities[:, 0]
    )

    # --------------------------------------------------------
    # Isolation Forest
    # --------------------------------------------------------

    print("Calculating Isolation Forest scores...")

    if_predictions = if_model.predict(
        X_test
    )

    if_anomaly = np.where(
        if_predictions == -1,
        1.0,
        0.0
    )

    print(
        f"Isolation Forest anomalies: "
        f"{int(if_anomaly.sum()):,}"
    )

    # --------------------------------------------------------
    # LSTM
    # --------------------------------------------------------

    X_benign = load_benign_training_data()

    (
        lstm_anomaly,
        lstm_threshold
    ) = get_lstm_anomaly_scores(
        lstm_model,
        lstm_scaler,
        X_benign,
        X_test
    )

    # --------------------------------------------------------
    # Hybrid score
    # --------------------------------------------------------

    hybrid_score = (
        XGB_WEIGHT * xgb_attack_probability
        +
        RF_WEIGHT * rf_attack_probability
        +
        IF_WEIGHT * if_anomaly
        +
        LSTM_WEIGHT * lstm_anomaly
    )

    # Hybrid classification
    hybrid_prediction = np.where(
        hybrid_score >= HYBRID_THRESHOLD,
        1,
        0
    )

    return (
        xgb_attack_probability,
        rf_attack_probability,
        if_anomaly,
        lstm_anomaly,
        hybrid_score,
        hybrid_prediction,
        lstm_threshold
    )


# ============================================================
# EVALUATION
# ============================================================

def evaluate(
    y_test,
    hybrid_prediction,
    hybrid_score
):

    print(
        "\n========================================"
    )

    print(
        " HYBRID AI RESULTS"
    )

    print(
        "========================================"
    )

    # Actual:
    # 0 = BENIGN
    # anything else = ATTACK

    y_binary = np.where(
        y_test == 0,
        0,
        1
    )

    accuracy = accuracy_score(
        y_binary,
        hybrid_prediction
    )

    precision = precision_score(
        y_binary,
        hybrid_prediction,
        zero_division=0
    )

    recall = recall_score(
        y_binary,
        hybrid_prediction,
        zero_division=0
    )

    f1 = f1_score(
        y_binary,
        hybrid_prediction,
        zero_division=0
    )

    matrix = confusion_matrix(
        y_binary,
        hybrid_prediction
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
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_binary,
            hybrid_prediction,
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

    print(
        matrix
    )

    return (
        accuracy,
        precision,
        recall,
        f1,
        matrix
    )


# ============================================================
# ROC CURVE
# ============================================================

def generate_roc_curve(
    y_test,
    hybrid_score
):

    print(
        "\n========================================"
    )

    print(
        " GENERATING ROC CURVE"
    )

    print(
        "========================================"
    )

    # Convert CIC-IDS2017 labels to binary
    # 0 = BENIGN
    # 1 = ATTACK

    y_binary = np.where(
        y_test == 0,
        0,
        1
    )

    # Calculate ROC curve

    fpr, tpr, thresholds = roc_curve(
        y_binary,
        hybrid_score
    )

    # Calculate AUC

    auc_score = roc_auc_score(
        y_binary,
        hybrid_score
    )

    print(
        f"ROC-AUC: {auc_score:.6f}"
    )

    # --------------------------------------------------------
    # Save ROC numerical data
    # --------------------------------------------------------

    os.makedirs(
        RESULTS_DIR,
        exist_ok=True
    )

    roc_data = pd.DataFrame({
        "False Positive Rate": fpr,
        "True Positive Rate": tpr,
        "Threshold": thresholds
    })

    roc_data.to_csv(
        os.path.join(
            RESULTS_DIR,
            "hybrid_roc_data.csv"
        ),
        index=False
    )

    # --------------------------------------------------------
    # Plot ROC curve
    # --------------------------------------------------------

    plt.figure(
        figsize=(8, 6)
    )

    plt.plot(
        fpr,
        tpr,
        linewidth=2,
        label=f"Hybrid AI (AUC = {auc_score:.6f})"
    )

    plt.plot(
        [0, 1],
        [0, 1],
        linestyle="--",
        linewidth=1,
        label="Random Classifier"
    )

    plt.xlabel(
        "False Positive Rate"
    )

    plt.ylabel(
        "True Positive Rate"
    )

    plt.title(
        "ROC Curve - Hybrid AI Threat Detection"
    )

    plt.legend(
        loc="lower right"
    )

    plt.grid(
        True,
        alpha=0.3
    )

    plt.tight_layout()

    roc_file = os.path.join(
        RESULTS_DIR,
        "hybrid_roc_curve.png"
    )

    plt.savefig(
        roc_file,
        dpi=300,
        bbox_inches="tight"
    )

    plt.show()

    print(
        f"ROC curve saved: {roc_file}"
    )

    return (
        fpr,
        tpr,
        thresholds,
        auc_score
    )


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(
    accuracy,
    precision,
    recall,
    f1,
    lstm_threshold,
    auc_score
):

    os.makedirs(
        RESULTS_DIR,
        exist_ok=True
    )

    result = {

        "model":
            "Hybrid AI",

        "xgboost_weight":
            XGB_WEIGHT,

        "random_forest_weight":
            RF_WEIGHT,

        "isolation_forest_weight":
            IF_WEIGHT,

        "lstm_weight":
            LSTM_WEIGHT,

        "hybrid_threshold":
            HYBRID_THRESHOLD,

        "accuracy":
            accuracy,

        "precision":
            precision,

        "recall":
            recall,

        "f1":
            f1,

        "roc_auc":
            auc_score,

        "lstm_threshold":
            lstm_threshold
    }

    df = pd.DataFrame(
        [result]
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
        " CIC-IDS2017 HYBRID AI DETECTOR"
    )

    print(
        " Experiment 3.6.0"
    )

    print(
        "========================================"
    )

    start_time = time.time()

    # --------------------------------------------------------
    # Load data
    # --------------------------------------------------------

    X_test, y_test = load_data()

    # --------------------------------------------------------
    # Load models
    # --------------------------------------------------------

    (
        rf_model,
        xgb_model,
        if_model,
        lstm_model,
        lstm_scaler
    ) = load_models()

    # --------------------------------------------------------
    # Generate component scores
    # --------------------------------------------------------

    (
        xgb_score,
        rf_score,
        if_score,
        lstm_score,
        hybrid_score,
        hybrid_prediction,
        lstm_threshold
    ) = generate_scores(
        rf_model,
        xgb_model,
        if_model,
        lstm_model,
        lstm_scaler,
        X_test
    )

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    (
        accuracy,
        precision,
        recall,
        f1,
        matrix
    ) = evaluate(
        y_test,
        hybrid_prediction,
        hybrid_score
    )

    # --------------------------------------------------------
    # Generate ROC Curve
    # --------------------------------------------------------

    (
        fpr,
        tpr,
        thresholds,
        auc_score
    ) = generate_roc_curve(
        y_test,
        hybrid_score
    )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    save_results(
        accuracy,
        precision,
        recall,
        f1,
        lstm_threshold,
        auc_score
    )

    total_time = (
        time.time() - start_time
    )

    print(
        f"\nTotal experiment time: "
        f"{total_time:.2f} seconds"
    )

    print(
        "\n========================================"
    )

    print(
        " HYBRID AI EXPERIMENT COMPLETED"
    )

    print(
        "========================================"
    )

    print(
        f"\nFinal ROC-AUC: {auc_score:.6f}"
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()