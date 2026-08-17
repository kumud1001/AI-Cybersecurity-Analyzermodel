import os
import time
import joblib
import pandas as pd

from xgboost import XGBClassifier

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

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "xgboost.pkl"
)

RESULT_FILE = os.path.join(
    RESULTS_DIR,
    "xgboost_results.csv"
)


# ============================================================
# LOAD DATA
# ============================================================

def load_data():

    print("\nLoading training and testing data...")

    X_train = pd.read_csv(
        os.path.join(DATA_DIR, "X_train.csv")
    )

    X_test = pd.read_csv(
        os.path.join(DATA_DIR, "X_test.csv")
    )

    y_train = pd.read_csv(
        os.path.join(DATA_DIR, "y_train.csv")
    )["label"]

    y_test = pd.read_csv(
        os.path.join(DATA_DIR, "y_test.csv")
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

    print(
        f"Number of classes: {y_train.nunique()}"
    )

    return X_train, X_test, y_train, y_test


# ============================================================
# TRAIN XGBOOST
# ============================================================

def train_model(X_train, y_train):

    print("\n========================================")
    print(" TRAINING XGBOOST")
    print("========================================")

    model = XGBClassifier(

        n_estimators=200,

        max_depth=8,

        learning_rate=0.1,

        subsample=0.8,

        colsample_bytree=0.8,

        objective="multi:softprob",

        eval_metric="mlogloss",

        tree_method="hist",

        random_state=42,

        n_jobs=-1
    )

    start_time = time.time()

    model.fit(
        X_train,
        y_train
    )

    training_time = (
        time.time() - start_time
    )

    print(
        f"\nTraining time: "
        f"{training_time:.2f} seconds"
    )

    return model, training_time


# ============================================================
# EVALUATE
# ============================================================

def evaluate_model(
    model,
    X_test,
    y_test
):

    print("\n========================================")
    print(" EVALUATING XGBOOST")
    print("========================================")

    start_time = time.time()

    predictions = model.predict(
        X_test
    )

    inference_time = (
        time.time() - start_time
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Print results
    # --------------------------------------------------------

    print("\n========================================")
    print(" XGBOOST RESULTS")
    print("========================================")

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

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    print("\nConfusion Matrix:")

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print(matrix)

    results = {

        "model":
            "XGBoost",

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

        "inference_time_seconds":
            inference_time
    }

    return results


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

    print("\nModel saved:")
    print(MODEL_FILE)


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

    result_df = pd.DataFrame(
        [results]
    )

    result_df.to_csv(
        RESULT_FILE,
        index=False
    )

    print("\nResults saved:")
    print(RESULT_FILE)


# ============================================================
# MAIN
# ============================================================

def main():

    print("========================================")
    print(" CIC-IDS2017 XGBOOST EXPERIMENT")
    print(" Experiment 3.2.0")
    print(" XGBoost Version: 3.2.0")
    print("========================================")

    # Load data

    (
        X_train,
        X_test,
        y_train,
        y_test
    ) = load_data()

    # Train

    (
        model,
        training_time
    ) = train_model(
        X_train,
        y_train
    )

    # Evaluate

    results = evaluate_model(
        model,
        X_test,
        y_test
    )

    # Save model

    save_model(
        model
    )

    # Save results

    save_results(
        results,
        training_time
    )

    print("\n========================================")
    print(" XGBOOST EXPERIMENT COMPLETED")
    print("========================================")


if __name__ == "__main__":
    main()