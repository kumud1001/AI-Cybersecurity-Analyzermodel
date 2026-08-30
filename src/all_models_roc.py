import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from tensorflow.keras.models import load_model
from sklearn.metrics import roc_curve, roc_auc_score


# ============================================================
# PATHS
# ============================================================

DATA_DIR = "data/processed/ml"
MODEL_DIR = "models"
RESULTS_DIR = "experiments/results"

X_TEST_FILE = os.path.join(DATA_DIR, "X_test.csv")
Y_TEST_FILE = os.path.join(DATA_DIR, "y_test.csv")

RF_MODEL_FILE = os.path.join(MODEL_DIR, "random_forest.pkl")
XGB_MODEL_FILE = os.path.join(MODEL_DIR, "xgboost.pkl")
IF_MODEL_FILE = os.path.join(MODEL_DIR, "isolation_forest.pkl")
LSTM_MODEL_FILE = os.path.join(MODEL_DIR, "lstm_autoencoder.keras")
LSTM_SCALER_FILE = os.path.join(MODEL_DIR, "lstm_scaler.pkl")


# ============================================================
# SETTINGS
# ============================================================

RANDOM_STATE = 42
TEST_SAMPLE_SIZE = 20000

XGB_WEIGHT = 0.40
RF_WEIGHT = 0.30
IF_WEIGHT = 0.15
LSTM_WEIGHT = 0.15

LSTM_THRESHOLD_PERCENTILE = 95


# ============================================================
# LOAD DATA
# ============================================================

print("Loading test data...")

X_test = pd.read_csv(X_TEST_FILE)
y_test = pd.read_csv(Y_TEST_FILE)["label"]

print(f"Full test set: {len(X_test):,} samples")

# Match the existing Hybrid AI experiment:
# randomly select 20,000 samples using seed 42

if len(X_test) > TEST_SAMPLE_SIZE:

    rng = np.random.RandomState(RANDOM_STATE)

    indices = rng.choice(
        len(X_test),
        size=TEST_SAMPLE_SIZE,
        replace=False
    )

    X_test = X_test.iloc[indices].reset_index(drop=True)
    y_test = y_test.iloc[indices].reset_index(drop=True)

print(f"ROC test set: {len(X_test):,} samples")


# ============================================================
# BINARY LABEL
# ============================================================

# CIC-IDS2017:
# 0 = BENIGN
# anything else = ATTACK

y_binary = np.where(
    y_test == 0,
    0,
    1
)

print("\nBinary class distribution:")
print(pd.Series(y_binary).value_counts())


# ============================================================
# LOAD MODELS
# ============================================================

print("\nLoading models...")

rf_model = joblib.load(RF_MODEL_FILE)
xgb_model = joblib.load(XGB_MODEL_FILE)
if_model = joblib.load(IF_MODEL_FILE)

lstm_model = load_model(
    LSTM_MODEL_FILE
)

lstm_scaler = joblib.load(
    LSTM_SCALER_FILE
)

print("All models loaded successfully.")


# ============================================================
# RANDOM FOREST SCORE
# ============================================================

print("\nCalculating Random Forest ROC...")

rf_probabilities = rf_model.predict_proba(
    X_test
)

# Probability of ATTACK
rf_score = 1.0 - rf_probabilities[:, 0]

rf_auc = roc_auc_score(
    y_binary,
    rf_score
)

rf_fpr, rf_tpr, _ = roc_curve(
    y_binary,
    rf_score
)

print(f"Random Forest AUC: {rf_auc:.6f}")


# ============================================================
# XGBOOST SCORE
# ============================================================

print("\nCalculating XGBoost ROC...")

xgb_probabilities = xgb_model.predict_proba(
    X_test
)

# Probability of ATTACK
xgb_score = 1.0 - xgb_probabilities[:, 0]

xgb_auc = roc_auc_score(
    y_binary,
    xgb_score
)

xgb_fpr, xgb_tpr, _ = roc_curve(
    y_binary,
    xgb_score
)

print(f"XGBoost AUC: {xgb_auc:.6f}")


# ============================================================
# ISOLATION FOREST SCORE
# ============================================================

print("\nCalculating Isolation Forest ROC...")

# Isolation Forest decision_function:
# higher = more normal
# lower = more anomalous
#
# Therefore negate it so:
# higher score = more anomalous

if_score = -if_model.decision_function(
    X_test
)

if_auc = roc_auc_score(
    y_binary,
    if_score
)

if_fpr, if_tpr, _ = roc_curve(
    y_binary,
    if_score
)

print(f"Isolation Forest AUC: {if_auc:.6f}")


# ============================================================
# LSTM RECONSTRUCTION ERROR
# ============================================================

print("\nCalculating LSTM ROC...")

# Load training data to calculate the same
# 95th percentile threshold used by Hybrid AI

X_train = pd.read_csv(
    os.path.join(DATA_DIR, "X_train.csv")
)

y_train = pd.read_csv(
    os.path.join(DATA_DIR, "y_train.csv")
)["label"]


# Keep only BENIGN training samples

X_benign = X_train[
    y_train == 0
].copy()

print(
    f"Benign training samples: "
    f"{len(X_benign):,}"
)


# ------------------------------------------------------------
# Scale benign training data
# ------------------------------------------------------------

X_benign_scaled = lstm_scaler.transform(
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


# ------------------------------------------------------------
# Benign reconstruction error
# ------------------------------------------------------------

benign_reconstructed = lstm_model.predict(
    X_benign_scaled,
    verbose=0
)

benign_errors = np.mean(
    np.square(
        X_benign_scaled -
        benign_reconstructed
    ),
    axis=(1, 2)
)


# Same threshold as Hybrid experiment

lstm_threshold = np.percentile(
    benign_errors,
    LSTM_THRESHOLD_PERCENTILE
)

print(
    f"LSTM threshold: "
    f"{lstm_threshold:.6f}"
)


# ------------------------------------------------------------
# Test reconstruction error
# ------------------------------------------------------------

X_test_scaled = lstm_scaler.transform(
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


test_reconstructed = lstm_model.predict(
    X_test_scaled,
    verbose=0
)


# Reconstruction error is the continuous
# anomaly score

lstm_score = np.mean(
    np.square(
        X_test_scaled -
        test_reconstructed
    ),
    axis=(1, 2)
)


lstm_auc = roc_auc_score(
    y_binary,
    lstm_score
)

lstm_fpr, lstm_tpr, _ = roc_curve(
    y_binary,
    lstm_score
)

print(
    f"LSTM Autoencoder AUC: "
    f"{lstm_auc:.6f}"
)


# ============================================================
# HYBRID SCORE
# ============================================================

print("\nCalculating Hybrid ROC...")

# IMPORTANT:
# To reproduce your existing Hybrid experiment,
# Isolation Forest and LSTM use BINARY anomaly flags.

if_predictions = if_model.predict(
    X_test
)

if_anomaly = np.where(
    if_predictions == -1,
    1.0,
    0.0
)


lstm_anomaly = np.where(
    lstm_score > lstm_threshold,
    1.0,
    0.0
)


# Exact weights from hybrid_detector.py

hybrid_score = (
    XGB_WEIGHT * xgb_score
    +
    RF_WEIGHT * rf_score
    +
    IF_WEIGHT * if_anomaly
    +
    LSTM_WEIGHT * lstm_anomaly
)


hybrid_auc = roc_auc_score(
    y_binary,
    hybrid_score
)

hybrid_fpr, hybrid_tpr, _ = roc_curve(
    y_binary,
    hybrid_score
)

print(
    f"Hybrid AI AUC: "
    f"{hybrid_auc:.6f}"
)


# ============================================================
# PRINT FINAL RESULTS
# ============================================================

print("\n========================================")
print(" ROC-AUC RESULTS")
print("========================================")

print(
    f"Random Forest       : {rf_auc:.6f}"
)

print(
    f"XGBoost             : {xgb_auc:.6f}"
)

print(
    f"Isolation Forest    : {if_auc:.6f}"
)

print(
    f"LSTM Autoencoder    : {lstm_auc:.6f}"
)

print(
    f"Hybrid AI           : {hybrid_auc:.6f}"
)


# ============================================================
# SAVE AUC TABLE
# ============================================================

os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)

auc_results = pd.DataFrame({
    "Model": [
        "Random Forest",
        "XGBoost",
        "Isolation Forest",
        "LSTM Autoencoder",
        "Hybrid AI"
    ],
    "AUC": [
        rf_auc,
        xgb_auc,
        if_auc,
        lstm_auc,
        hybrid_auc
    ]
})

auc_file = os.path.join(
    RESULTS_DIR,
    "all_models_auc.csv"
)

auc_results.to_csv(
    auc_file,
    index=False
)


# ============================================================
# COMBINED ROC CURVE
# ============================================================

plt.figure(
    figsize=(9, 7)
)

plt.plot(
    rf_fpr,
    rf_tpr,
    linewidth=2,
    label=f"Random Forest (AUC = {rf_auc:.6f})"
)

plt.plot(
    xgb_fpr,
    xgb_tpr,
    linewidth=2,
    label=f"XGBoost (AUC = {xgb_auc:.6f})"
)

plt.plot(
    if_fpr,
    if_tpr,
    linewidth=2,
    label=f"Isolation Forest (AUC = {if_auc:.6f})"
)

plt.plot(
    lstm_fpr,
    lstm_tpr,
    linewidth=2,
    label=f"LSTM Autoencoder (AUC = {lstm_auc:.6f})"
)

plt.plot(
    hybrid_fpr,
    hybrid_tpr,
    linewidth=3,
    label=f"Hybrid AI (AUC = {hybrid_auc:.6f})"
)

# Random classifier

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
    "ROC Curves of AI-Based Intrusion Detection Models"
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
    "all_models_roc_curve.png"
)

plt.savefig(
    roc_file,
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ============================================================
# SAVE ROC DATA
# ============================================================

roc_data = pd.DataFrame({
    "RF_FPR": pd.Series(rf_fpr),
    "RF_TPR": pd.Series(rf_tpr),

    "XGB_FPR": pd.Series(xgb_fpr),
    "XGB_TPR": pd.Series(xgb_tpr),

    "IF_FPR": pd.Series(if_fpr),
    "IF_TPR": pd.Series(if_tpr),

    "LSTM_FPR": pd.Series(lstm_fpr),
    "LSTM_TPR": pd.Series(lstm_tpr),

    "Hybrid_FPR": pd.Series(hybrid_fpr),
    "Hybrid_TPR": pd.Series(hybrid_tpr)
})

roc_data_file = os.path.join(
    RESULTS_DIR,
    "all_models_roc_data.csv"
)

roc_data.to_csv(
    roc_data_file,
    index=False
)


# ============================================================
# FINISHED
# ============================================================

print("\n========================================")
print(" COMPLETED")
print("========================================")

print(
    f"AUC table saved to:\n{auc_file}"
)

print(
    f"ROC curve saved to:\n{roc_file}"
)

print(
    f"ROC data saved to:\n{roc_data_file}"
)