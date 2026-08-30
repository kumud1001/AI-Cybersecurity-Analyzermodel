"""
SHAP Analysis
AI Cybersecurity Analyzer
CIC-IDS2017 XGBoost Model
"""

import os
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import shap
import joblib

warnings.filterwarnings("ignore")


# ============================================================
# PROJECT PATHS
# ============================================================

# shap_analysis.py is located at:
# backend/app/ml/shap_analysis.py

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Go from:
# backend/app/ml
#       -> backend/app
#       -> backend
#       -> project root

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        CURRENT_DIR,
        "..",
        "..",
        ".."
    )
)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "xgboost.pkl"
)

TEST_X_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "processed",
    "ml",
    "X_test.csv"
)

TEST_Y_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "processed",
    "ml",
    "y_test.csv"
)

OUTPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "backend",
    "app",
    "ml",
    "shap_results"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


# ============================================================
# SETTINGS
# ============================================================

MAX_SHAP_SAMPLES = 5000
TOP_FEATURES = 20


# ============================================================
# PRINT HEADER
# ============================================================

def header(text):

    print("\n")
    print("=" * 70)
    print(text)
    print("=" * 70)


# ============================================================
# CHECK FILE
# ============================================================

def check_file(path, name):

    if not os.path.exists(path):

        print(f"\nERROR: {name} not found:")
        print(path)

        return False

    return True


# ============================================================
# LOAD MODEL
# ============================================================

header(
    "STEP 1 - LOADING XGBOOST MODEL"
)

print(
    "Project root:",
    PROJECT_ROOT
)

print(
    "Model path:",
    MODEL_PATH
)

if not check_file(
    MODEL_PATH,
    "XGBoost model"
):

    raise FileNotFoundError(
        MODEL_PATH
    )

model = joblib.load(
    MODEL_PATH
)

print(
    "\nModel loaded successfully."
)

print(
    "Model type:",
    type(model)
)


# ============================================================
# LOAD TEST DATA
# ============================================================

header(
    "STEP 2 - LOADING TEST DATA"
)

print(
    "Test data:",
    TEST_X_PATH
)

if not check_file(
    TEST_X_PATH,
    "X_test.csv"
):

    raise FileNotFoundError(
        TEST_X_PATH
    )

X_test = pd.read_csv(
    TEST_X_PATH
)

print(
    "\nX_test shape:",
    X_test.shape
)


# ============================================================
# LOAD Y TEST
# ============================================================

if os.path.exists(TEST_Y_PATH):

    y_test = pd.read_csv(
        TEST_Y_PATH
    )

    print(
        "y_test shape:",
        y_test.shape
    )

else:

    y_test = None

    print(
        "y_test.csv not found."
    )


# ============================================================
# CLEAN DATA
# ============================================================

header(
    "STEP 3 - PREPARING TEST DATA"
)

# Clean column names

X_test.columns = [
    str(column).strip()
    for column in X_test.columns
]


# Convert all columns to numeric

for column in X_test.columns:

    X_test[column] = pd.to_numeric(
        X_test[column],
        errors="coerce"
    )


# Replace infinite values

X_test = X_test.replace(
    [np.inf, -np.inf],
    np.nan
)


# Replace missing values

X_test = X_test.fillna(0)


print(
    "Cleaned X_test shape:",
    X_test.shape
)

print(
    "Number of features:",
    len(X_test.columns)
)


# ============================================================
# MODEL FEATURE CHECK
# ============================================================

header(
    "STEP 4 - CHECKING MODEL FEATURES"
)

try:

    expected_features = (
        model.n_features_in_
    )

    print(
        "Model expects:",
        expected_features,
        "features"
    )

    print(
        "X_test contains:",
        X_test.shape[1],
        "features"
    )

    if expected_features != X_test.shape[1]:

        raise ValueError(
            "\nFeature mismatch!\n"
            f"Model expects {expected_features}, "
            f"but X_test has {X_test.shape[1]}."
        )

except AttributeError:

    print(
        "Model feature count unavailable."
    )


# ============================================================
# SELECT SHAP SAMPLE
# ============================================================

header(
    "STEP 5 - SELECTING SHAP SAMPLE"
)

sample_size = min(
    MAX_SHAP_SAMPLES,
    len(X_test)
)

X_shap = X_test.sample(
    n=sample_size,
    random_state=42
)

print(
    "Total test samples:",
    len(X_test)
)

print(
    "SHAP samples:",
    len(X_shap)
)

print(
    "SHAP input shape:",
    X_shap.shape
)


# ============================================================
# CREATE EXPLAINER
# ============================================================

header(
    "STEP 6 - CREATING SHAP EXPLAINER"
)

try:

    explainer = shap.TreeExplainer(
        model
    )

    print(
        "TreeExplainer created successfully."
    )

except Exception as error:

    print(
        "TreeExplainer failed:"
    )

    print(error)

    print(
        "\nUsing generic SHAP Explainer..."
    )

    explainer = shap.Explainer(
        model,
        X_shap
    )

    print(
        "Generic SHAP Explainer created."
    )


# ============================================================
# CALCULATE SHAP VALUES
# ============================================================

header(
    "STEP 7 - CALCULATING SHAP VALUES"
)

print(
    "Calculating SHAP values..."
)

try:

    shap_values = explainer.shap_values(
        X_shap
    )

except Exception as error:

    print(
        "\nOld SHAP API failed:"
    )

    print(error)

    print(
        "\nTrying new SHAP API..."
    )

    shap_explanation = explainer(
        X_shap
    )

    shap_values = (
        shap_explanation.values
    )


print(
    "\nSHAP calculation completed."
)

print(
    "SHAP output type:",
    type(shap_values)
)


# ============================================================
# CONVERT SHAP VALUES TO MATRIX
# ============================================================

header(
    "STEP 8 - PROCESSING SHAP VALUES"
)


def convert_shap_to_matrix(values):

    """
    Converts SHAP output to:

        samples x features
    """

    # --------------------------------------------------------
    # SHAP list output
    # --------------------------------------------------------

    if isinstance(values, list):

        print(
            "SHAP returned a list."
        )

        print(
            "Number of outputs:",
            len(values)
        )

        arrays = [
            np.asarray(v)
            for v in values
        ]

        for i, array in enumerate(arrays):

            print(
                f"SHAP[{i}] shape:",
                array.shape
            )

        # Binary classification

        if len(arrays) == 2:

            matrix = arrays[1]

        else:

            # Multiclass

            stacked = np.stack(
                arrays,
                axis=0
            )

            matrix = np.mean(
                np.abs(stacked),
                axis=0
            )

    else:

        matrix = np.asarray(
            values
        )

    print(
        "Initial SHAP shape:",
        matrix.shape
    )

    # --------------------------------------------------------
    # 3D output
    # --------------------------------------------------------

    if matrix.ndim == 3:

        print(
            "3D SHAP output detected."
        )

        # samples x features x classes

        matrix = np.mean(
            np.abs(matrix),
            axis=2
        )

    # --------------------------------------------------------
    # 1D output
    # --------------------------------------------------------

    elif matrix.ndim == 1:

        matrix = matrix.reshape(
            -1,
            1
        )

    # --------------------------------------------------------
    # Unsupported
    # --------------------------------------------------------

    elif matrix.ndim > 3:

        raise ValueError(
            "Unsupported SHAP dimensions: "
            f"{matrix.ndim}"
        )

    return matrix


shap_matrix = convert_shap_to_matrix(
    shap_values
)

print(
    "Processed SHAP shape:",
    shap_matrix.shape
)


# ============================================================
# CHECK SHAP DIMENSIONS
# ============================================================

header(
    "STEP 9 - VERIFYING SHAP DIMENSIONS"
)

print(
    "X_shap shape:",
    X_shap.shape
)

print(
    "SHAP shape:",
    shap_matrix.shape
)


# Check rows

if shap_matrix.shape[0] != len(X_shap):

    print(
        "\nSHAP row count does not match."
    )

    # Check if transposed

    if shap_matrix.shape[1] == len(X_shap):

        print(
            "Transposing SHAP matrix..."
        )

        shap_matrix = shap_matrix.T

    else:

        raise ValueError(
            "\nSHAP dimensions are incompatible.\n"
            f"SHAP: {shap_matrix.shape}\n"
            f"X_shap: {X_shap.shape}"
        )


# Check features

if shap_matrix.shape[1] != len(X_shap.columns):

    raise ValueError(
        "\nSHAP feature count mismatch.\n"
        f"SHAP features: {shap_matrix.shape[1]}\n"
        f"X features: {len(X_shap.columns)}"
    )


print(
    "\nSHAP dimension check PASSED."
)


# ============================================================
# CALCULATE FEATURE IMPORTANCE
# ============================================================

header(
    "STEP 10 - CALCULATING FEATURE IMPORTANCE"
)

feature_importance = np.mean(
    np.abs(shap_matrix),
    axis=0
)

# VERY IMPORTANT:
# Convert to exactly 1-dimensional array

feature_importance = np.asarray(
    feature_importance
).reshape(-1)

feature_names = np.asarray(
    X_shap.columns
).reshape(-1)


print(
    "Feature names shape:",
    feature_names.shape
)

print(
    "Importance shape:",
    feature_importance.shape
)


# ============================================================
# CREATE DATAFRAME
# ============================================================

header(
    "STEP 11 - CREATING SHAP DATAFRAME"
)

shap_importance = pd.DataFrame(
    {
        "Feature": feature_names,
        "Mean_Absolute_SHAP": feature_importance
    }
)

shap_importance = shap_importance.sort_values(
    by="Mean_Absolute_SHAP",
    ascending=False
).reset_index(
    drop=True
)


print(
    "\nTop 20 SHAP Features:"
)

print(
    shap_importance.head(
        TOP_FEATURES
    ).to_string(
        index=False
    )
)


# ============================================================
# SAVE CSV
# ============================================================

importance_csv = os.path.join(
    OUTPUT_DIR,
    "shap_feature_importance.csv"
)

shap_importance.to_csv(
    importance_csv,
    index=False
)

print(
    "\nSaved:",
    importance_csv
)


# ============================================================
# SAVE TOP 20
# ============================================================

top_csv = os.path.join(
    OUTPUT_DIR,
    "top_20_shap_features.csv"
)

shap_importance.head(
    TOP_FEATURES
).to_csv(
    top_csv,
    index=False
)

print(
    "Saved:",
    top_csv
)


# ============================================================
# SHAP SUMMARY PLOT
# ============================================================

header(
    "STEP 12 - GENERATING SHAP SUMMARY PLOT"
)

summary_path = os.path.join(
    OUTPUT_DIR,
    "shap_summary_plot.png"
)

plt.figure(
    figsize=(12, 8)
)

shap.summary_plot(
    shap_matrix,
    X_shap,
    max_display=TOP_FEATURES,
    show=False
)

plt.title(
    "SHAP Summary Plot - XGBoost Intrusion Detection"
)

plt.tight_layout()

plt.savefig(
    summary_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print(
    "Saved:",
    summary_path
)


# ============================================================
# SHAP BAR PLOT
# ============================================================

header(
    "STEP 13 - GENERATING SHAP BAR PLOT"
)

bar_path = os.path.join(
    OUTPUT_DIR,
    "shap_feature_importance_bar.png"
)

top_features = (
    shap_importance
    .head(TOP_FEATURES)
    .sort_values(
        by="Mean_Absolute_SHAP"
    )
)

plt.figure(
    figsize=(12, 8)
)

plt.barh(
    top_features["Feature"],
    top_features["Mean_Absolute_SHAP"]
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
    bar_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print(
    "Saved:",
    bar_path
)


# ============================================================
# WATERFALL PLOT
# ============================================================

header(
    "STEP 14 - GENERATING SHAP WATERFALL"
)

waterfall_path = os.path.join(
    OUTPUT_DIR,
    "shap_waterfall_example.png"
)

try:

    expected_value = (
        explainer.expected_value
    )

    expected_value = np.asarray(
        expected_value
    ).reshape(-1)

    base_value = float(
        expected_value[0]
    )

    explanation = shap.Explanation(
        values=shap_matrix[0],
        base_values=base_value,
        data=X_shap.iloc[0].values,
        feature_names=X_shap.columns.tolist()
    )

    shap.plots.waterfall(
        explanation,
        max_display=15,
        show=False
    )

    plt.tight_layout()

    plt.savefig(
        waterfall_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        "Saved:",
        waterfall_path
    )

except Exception as error:

    print(
        "\nWaterfall plot skipped."
    )

    print(
        "Reason:",
        error
    )


# ============================================================
# FINAL RESULTS
# ============================================================

header(
    "SHAP ANALYSIS COMPLETED"
)

print(
    "Model:",
    type(model).__name__
)

print(
    "Total test samples:",
    len(X_test)
)

print(
    "SHAP samples:",
    len(X_shap)
)

print(
    "Number of features:",
    len(X_shap.columns)
)

print(
    "\nOutput folder:"
)

print(
    OUTPUT_DIR
)

print(
    "\nGenerated files:"
)

print(
    "1. shap_feature_importance.csv"
)

print(
    "2. top_20_shap_features.csv"
)

print(
    "3. shap_summary_plot.png"
)

print(
    "4. shap_feature_importance_bar.png"
)

print(
    "5. shap_waterfall_example.png"
)

print(
    "\nTop 20 features:"
)

for i, row in shap_importance.head(
    TOP_FEATURES
).iterrows():

    print(
        f"{i + 1:2d}. "
        f"{row['Feature']:<40} "
        f"{row['Mean_Absolute_SHAP']:.6f}"
    )

print(
    "\nSHAP analysis finished successfully."
)