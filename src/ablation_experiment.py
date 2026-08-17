import os
import time
import joblib
import numpy as np
import pandas as pd

from tensorflow.keras.models import load_model

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)


# ============================================================
# PATHS
# ============================================================

DATA_DIR = "data/processed/ml"
MODEL_DIR = "models"
RESULTS_DIR = "experiments/results"
FIGURES_DIR = "experiments/figures"

X_TEST_FILE = os.path.join(
    DATA_DIR,
    "X_test.csv"
)

Y_TEST_FILE = os.path.join(
    DATA_DIR,
    "y_test.csv"
)

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

RESULT_FILE = os.path.join(
    RESULTS_DIR,
    "ablation_results.csv"
)


# ============================================================
# SETTINGS
# ============================================================

RANDOM_STATE = 42
TEST_SAMPLE_SIZE = 20000

HYBRID_THRESHOLD = 0.50
LSTM_THRESHOLD_PERCENTILE = 95


# ============================================================
# LOAD TEST DATA
# ============================================================

def load_test_data():

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
        f"Available test samples: {len(X_test):,}"
    )

    # Same deterministic sampling approach
    # as Experiment 3.6.0

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
        f"Samples used: {len(X_test):,}"
    )

    return X_test, y_test


# ============================================================
# LOAD MODELS
# ============================================================

def load_models():

    print("\nLoading models...")

    rf_model = joblib.load(
        RF_MODEL_FILE
    )

    xgb_model = joblib.load(
        XGB_MODEL_FILE
    )

    if_model = joblib.load(
        IF_MODEL_FILE
    )

    lstm_model = load_model(
        LSTM_MODEL_FILE
    )

    scaler = joblib.load(
        LSTM_SCALER_FILE
    )

    print("All models loaded.")

    return (
        rf_model,
        xgb_model,
        if_model,
        lstm_model,
        scaler
    )


# ============================================================
# LOAD BENIGN TRAINING DATA
# ============================================================

def load_benign_training_data():

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

    X_benign = X_train[
        y_train == 0
    ].copy()

    return X_benign


# ============================================================
# XGBOOST SCORE
# ============================================================

def get_xgb_score(
    model,
    X
):

    probabilities = model.predict_proba(
        X
    )

    # class 0 = BENIGN
    # 1 - P(BENIGN) = P(ATTACK)

    return (
        1.0 -
        probabilities[:, 0]
    )


# ============================================================
# RANDOM FOREST SCORE
# ============================================================

def get_rf_score(
    model,
    X
):

    probabilities = model.predict_proba(
        X
    )

    return (
        1.0 -
        probabilities[:, 0]
    )


# ============================================================
# ISOLATION FOREST SCORE
# ============================================================

def get_if_score(
    model,
    X
):

    predictions = model.predict(
        X
    )

    return np.where(
        predictions == -1,
        1.0,
        0.0
    )


# ============================================================
# LSTM SCORE
# ============================================================

def get_lstm_score(
    model,
    scaler,
    X_benign,
    X_test
):

    # --------------------------------------------------------
    # BENIGN TRAINING DATA
    # --------------------------------------------------------

    benign_scaled = scaler.transform(
        X_benign
    )

    benign_scaled = np.nan_to_num(
        benign_scaled,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )

    benign_scaled = np.expand_dims(
        benign_scaled,
        axis=1
    )

    benign_reconstructed = model.predict(
        benign_scaled,
        verbose=0
    )

    benign_errors = np.mean(
        np.square(
            benign_scaled -
            benign_reconstructed
        ),
        axis=(1, 2)
    )

    threshold = np.percentile(
        benign_errors,
        LSTM_THRESHOLD_PERCENTILE
    )

    # --------------------------------------------------------
    # TEST DATA
    # --------------------------------------------------------

    test_scaled = scaler.transform(
        X_test
    )

    test_scaled = np.nan_to_num(
        test_scaled,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )

    test_scaled = np.expand_dims(
        test_scaled,
        axis=1
    )

    test_reconstructed = model.predict(
        test_scaled,
        verbose=0
    )

    test_errors = np.mean(
        np.square(
            test_scaled -
            test_reconstructed
        ),
        axis=(1, 2)
    )

    anomaly = np.where(
        test_errors > threshold,
        1.0,
        0.0
    )

    return anomaly, threshold


# ============================================================
# EVALUATION FUNCTION
# ============================================================

def evaluate_configuration(
    name,
    score,
    y_true
):

    predictions = np.where(
        score >= HYBRID_THRESHOLD,
        1,
        0
    )

    accuracy = accuracy_score(
        y_true,
        predictions
    )

    precision = precision_score(
        y_true,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_true,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        predictions,
        zero_division=0
    )

    print(
        f"{name:<35}"
        f" Accuracy={accuracy:.4f} "
        f"Precision={precision:.4f} "
        f"Recall={recall:.4f} "
        f"F1={f1:.4f}"
    )

    return {
        "configuration": name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "========================================"
    )

    print(
        " EXPERIMENT 3.7.0"
    )

    print(
        " HYBRID MODEL ABLATION STUDY"
    )

    print(
        "========================================"
    )

    start_time = time.time()

    # --------------------------------------------------------
    # Load data
    # --------------------------------------------------------

    X_test, y_test = load_test_data()

    y_binary = np.where(
        y_test == 0,
        0,
        1
    )

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

    print("\nGenerating component scores...")

    xgb_score = get_xgb_score(
        xgb_model,
        X_test
    )

    rf_score = get_rf_score(
        rf_model,
        X_test
    )

    if_score = get_if_score(
        if_model,
        X_test
    )

    X_benign = load_benign_training_data()

    (
        lstm_score,
        lstm_threshold
    ) = get_lstm_score(
        lstm_model,
        lstm_scaler,
        X_benign,
        X_test
    )

    print(
        f"LSTM threshold: "
        f"{lstm_threshold:.6f}"
    )

    # --------------------------------------------------------
    # ABLATION CONFIGURATIONS
    # --------------------------------------------------------
    #
    # Each combination uses equal weights among
    # the components included.
    #
    # This makes the ablation comparison easier to interpret.
    # --------------------------------------------------------

    configurations = {}

    # 1. XGBoost only
    configurations[
        "XGBoost Only"
    ] = xgb_score

    # 2. Random Forest only
    configurations[
        "Random Forest Only"
    ] = rf_score

    # 3. XGBoost + Random Forest
    configurations[
        "XGBoost + Random Forest"
    ] = (
        0.50 * xgb_score +
        0.50 * rf_score
    )

    # 4. XGBoost + RF + Isolation Forest
    configurations[
        "XGBoost + RF + Isolation Forest"
    ] = (
        (1 / 3) * xgb_score +
        (1 / 3) * rf_score +
        (1 / 3) * if_score
    )

    # 5. XGBoost + RF + LSTM
    configurations[
        "XGBoost + RF + LSTM"
    ] = (
        (1 / 3) * xgb_score +
        (1 / 3) * rf_score +
        (1 / 3) * lstm_score
    )

    # 6. XGBoost + RF + IF + LSTM
    configurations[
        "Full Hybrid AI"
    ] = (
        0.25 * xgb_score +
        0.25 * rf_score +
        0.25 * if_score +
        0.25 * lstm_score
    )

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    print(
        "\n========================================"
    )

    print(
        " ABLATION RESULTS"
    )

    print(
        "========================================"
    )

    results = []

    for name, score in configurations.items():

        result = evaluate_configuration(
            name,
            score,
            y_binary
        )

        results.append(
            result
        )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    os.makedirs(
        RESULTS_DIR,
        exist_ok=True
    )

    results_df = pd.DataFrame(
        results
    )

    results_df.to_csv(
        RESULT_FILE,
        index=False
    )

    print(
        "\nResults saved:"
    )

    print(
        RESULT_FILE
    )

    # --------------------------------------------------------
    # Best model
    # --------------------------------------------------------

    best = results_df.loc[
        results_df["f1"].idxmax()
    ]

    print(
        "\n========================================"
    )

    print(
        " BEST CONFIGURATION"
    )

    print(
        "========================================"
    )

    print(
        f"Configuration: "
        f"{best['configuration']}"
    )

    print(
        f"Accuracy: "
        f"{best['accuracy']:.4f}"
    )

    print(
        f"Precision: "
        f"{best['precision']:.4f}"
    )

    print(
        f"Recall: "
        f"{best['recall']:.4f}"
    )

    print(
        f"F1: "
        f"{best['f1']:.4f}"
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
        " ABLATION EXPERIMENT COMPLETED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()