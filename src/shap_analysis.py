import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import shap


# ============================================================
# PATHS
# ============================================================

DATA_DIR = "data/processed/ml"
MODEL_DIR = "models"

RESULTS_DIR = "experiments/results"
FIGURES_DIR = "experiments/figures"

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "xgboost.pkl"
)

X_TEST_FILE = os.path.join(
    DATA_DIR,
    "X_test.csv"
)

Y_TEST_FILE = os.path.join(
    DATA_DIR,
    "y_test.csv"
)

FEATURE_IMPORTANCE_FILE = os.path.join(
    RESULTS_DIR,
    "shap_feature_importance.csv"
)

SUMMARY_PLOT = os.path.join(
    FIGURES_DIR,
    "shap_summary.png"
)

BAR_PLOT = os.path.join(
    FIGURES_DIR,
    "shap_feature_importance.png"
)

SAMPLE_SIZE = 1000
RANDOM_STATE = 42


# ============================================================
# LOAD MODEL AND DATA
# ============================================================

def load_data():

    print("\n========================================")
    print(" LOADING XGBOOST MODEL AND TEST DATA")
    print("========================================")

    model = joblib.load(
        MODEL_FILE
    )

    X_test = pd.read_csv(
        X_TEST_FILE
    )

    y_test = pd.read_csv(
        Y_TEST_FILE
    )["label"]

    print(
        f"Test samples available: {len(X_test):,}"
    )

    print(
        f"Features: {X_test.shape[1]}"
    )

    return model, X_test, y_test


# ============================================================
# SAMPLE DATA
# ============================================================

def sample_data(
    X_test,
    y_test
):

    sample_size = min(
        SAMPLE_SIZE,
        len(X_test)
    )

    indices = np.random.RandomState(
        RANDOM_STATE
    ).choice(
        len(X_test),
        size=sample_size,
        replace=False
    )

    X_sample = X_test.iloc[
        indices
    ].copy()

    y_sample = y_test.iloc[
        indices
    ].copy()

    print(
        f"\nSHAP samples used: {len(X_sample):,}"
    )

    return X_sample, y_sample


# ============================================================
# CREATE SHAP EXPLAINER
# ============================================================

def calculate_shap_values(
    model,
    X_sample
):

    print(
        "\n========================================"
    )

    print(
        " CALCULATING SHAP VALUES"
    )

    print(
        "========================================"
    )

    explainer = shap.TreeExplainer(
        model
    )

    shap_values = explainer.shap_values(
        X_sample
    )

    print(
        "\nSHAP calculation completed."
    )

    return shap_values


# ============================================================
# NORMALIZE SHAP OUTPUT
# ============================================================

def get_global_importance(
    shap_values,
    feature_names
):

    # SHAP can return either:
    #
    # 2D array:
    # samples x features
    #
    # or
    #
    # 3D array:
    # samples x features x classes

    if isinstance(
        shap_values,
        list
    ):

        values = np.stack(
            shap_values,
            axis=2
        )

        importance = np.mean(
            np.abs(values),
            axis=(0, 2)
        )

    elif shap_values.ndim == 3:

        importance = np.mean(
            np.abs(shap_values),
            axis=(0, 2)
        )

    else:

        importance = np.mean(
            np.abs(shap_values),
            axis=0
        )

    importance_df = pd.DataFrame({
        "feature": feature_names,
        "mean_abs_shap": importance
    })

    importance_df = (
        importance_df
        .sort_values(
            "mean_abs_shap",
            ascending=False
        )
        .reset_index(drop=True)
    )

    return importance_df


# ============================================================
# SAVE FEATURE IMPORTANCE
# ============================================================

def save_feature_importance(
    importance_df
):

    os.makedirs(
        RESULTS_DIR,
        exist_ok=True
    )

    importance_df.to_csv(
        FEATURE_IMPORTANCE_FILE,
        index=False
    )

    print(
        "\nFeature importance saved:"
    )

    print(
        FEATURE_IMPORTANCE_FILE
    )


# ============================================================
# SHAP SUMMARY PLOT
# ============================================================

def create_summary_plot(
    shap_values,
    X_sample
):

    os.makedirs(
        FIGURES_DIR,
        exist_ok=True
    )

    print(
        "\nCreating SHAP summary plot..."
    )

    shap.summary_plot(
        shap_values,
        X_sample,
        show=False
    )

    plt.tight_layout()

    plt.savefig(
        SUMMARY_PLOT,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        "Summary plot saved:"
    )

    print(
        SUMMARY_PLOT
    )


# ============================================================
# BAR IMPORTANCE PLOT
# ============================================================

def create_bar_plot(
    importance_df
):

    top_features = (
        importance_df
        .head(20)
        .sort_values(
            "mean_abs_shap"
        )
    )

    plt.figure(
        figsize=(10, 8)
    )

    plt.barh(
        top_features["feature"],
        top_features["mean_abs_shap"]
    )

    plt.xlabel(
        "Mean Absolute SHAP Value"
    )

    plt.ylabel(
        "Feature"
    )

    plt.title(
        "Top 20 Features Based on SHAP Importance"
    )

    plt.tight_layout()

    plt.savefig(
        BAR_PLOT,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        "\nBar plot saved:"
    )

    print(
        BAR_PLOT
    )


# ============================================================
# DISPLAY TOP FEATURES
# ============================================================

def display_top_features(
    importance_df
):

    print(
        "\n========================================"
    )

    print(
        " TOP 20 SHAP FEATURES"
    )

    print(
        "========================================"
    )

    print(
        importance_df.head(20).to_string(
            index=False
        )
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "========================================"
    )

    print(
        " SHAP EXPLAINABLE AI EXPERIMENT"
    )

    print(
        " Experiment 3.5.0"
    )

    print(
        "========================================"
    )

    model, X_test, y_test = load_data()

    X_sample, y_sample = sample_data(
        X_test,
        y_test
    )

    shap_values = calculate_shap_values(
        model,
        X_sample
    )

    importance_df = get_global_importance(
        shap_values,
        X_sample.columns
    )

    save_feature_importance(
        importance_df
    )

    display_top_features(
        importance_df
    )

    create_summary_plot(
        shap_values,
        X_sample
    )

    create_bar_plot(
        importance_df
    )

    print(
        "\n========================================"
    )

    print(
        " SHAP EXPERIMENT COMPLETED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()