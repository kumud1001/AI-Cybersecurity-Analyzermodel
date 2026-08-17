import os
import joblib
import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

# Project root:
# C:\AI- CYBERSECURITY ANALYZER

MODEL_PATH = os.path.join(
    "models",
    "xgboost.pkl"
)

LABEL_PATH = os.path.join(
    "data",
    "processed",
    "ml",
    "label_classes.csv"
)


# ============================================================
# LOAD XGBOOST MODEL
# ============================================================

print("Loading XGBoost model...")

try:
    model = joblib.load(MODEL_PATH)
    print("XGBoost model loaded successfully.")

except FileNotFoundError as exc:
    raise FileNotFoundError(
        f"XGBoost model not found: {MODEL_PATH}"
    ) from exc

except Exception as exc:
    raise RuntimeError(
        f"Unable to load XGBoost model: {exc}"
    ) from exc


# ============================================================
# LOAD LABEL MAPPING
# ============================================================

try:
    label_mapping = pd.read_csv(
        LABEL_PATH
    )

except FileNotFoundError as exc:
    raise FileNotFoundError(
        f"Label mapping not found: {LABEL_PATH}"
    ) from exc


required_mapping_columns = {
    "encoded_value",
    "attack_label"
}

if not required_mapping_columns.issubset(
    label_mapping.columns
):
    raise ValueError(
        "label_classes.csv must contain "
        "'encoded_value' and 'attack_label' columns."
    )


# Create:
# encoded class -> attack name

label_classes = {}

for _, row in label_mapping.iterrows():

    encoded_value = int(
        row["encoded_value"]
    )

    attack_label = str(
        row["attack_label"]
    )

    label_classes[
        encoded_value
    ] = attack_label


# ============================================================
# CIC-IDS2017 MODEL FEATURES
# ============================================================

MODEL_FEATURES = [
    "destination_port",
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "flow_bytes_s",
    "flow_packets_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    "fwd_psh_flags",
    "bwd_psh_flags",
    "fwd_urg_flags",
    "bwd_urg_flags",
    "fwd_header_length",
    "bwd_header_length",
    "fwd_packets_s",
    "bwd_packets_s",
    "min_packet_length",
    "max_packet_length",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "cwe_flag_count",
    "ece_flag_count",
    "down_up_ratio",
    "average_packet_size",
    "avg_fwd_segment_size",
    "avg_bwd_segment_size",
    "fwd_header_length.1",
    "fwd_avg_bytes_bulk",
    "fwd_avg_packets_bulk",
    "fwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk",
    "bwd_avg_packets_bulk",
    "bwd_avg_bulk_rate",
    "subflow_fwd_packets",
    "subflow_fwd_bytes",
    "subflow_bwd_packets",
    "subflow_bwd_bytes",
    "init_win_bytes_forward",
    "init_win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "active_mean",
    "active_std",
    "active_max",
    "active_min",
    "idle_mean",
    "idle_std",
    "idle_max",
    "idle_min"
]


# ============================================================
# API-TO-MODEL FEATURE NAME MAPPING
# ============================================================

# Pydantic cannot conveniently use a field such as:
#
# fwd_header_length.1
#
# Therefore our API schema uses:
#
# fwd_header_length_1
#
# and we map it back to the actual model feature name.

API_FEATURE_MAPPING = {
    "fwd_header_length_1": "fwd_header_length.1"
}


# ============================================================
# VERIFY MODEL FEATURE COUNT
# ============================================================

try:

    model_feature_count = (
        int(model.n_features_in_)
    )

except AttributeError:

    model_feature_count = len(
        MODEL_FEATURES
    )


if model_feature_count != len(
    MODEL_FEATURES
):

    raise ValueError(
        "Feature-count mismatch. "
        f"XGBoost expects {model_feature_count} "
        f"features, but predictor.py defines "
        f"{len(MODEL_FEATURES)} features."
    )


# ============================================================
# SEVERITY CALCULATION
# ============================================================

def calculate_severity(
    attack_type: str,
    confidence: float
) -> str:

    attack_type_normalized = (
        attack_type
        .strip()
        .upper()
    )

    # BENIGN traffic
    if attack_type_normalized == "BENIGN":
        return "LOW"

    # Malicious traffic
    if confidence >= 0.90:
        return "CRITICAL"

    if confidence >= 0.75:
        return "HIGH"

    if confidence >= 0.50:
        return "MEDIUM"

    return "LOW"


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(
    attack_type: str,
    confidence: float
) -> float:

    if (
        attack_type
        .strip()
        .upper()
        == "BENIGN"
    ):
        return 0.0

    # For now, use model confidence as
    # the basic attack risk score.
    return float(confidence)


# ============================================================
# PREPARE INPUT FEATURES
# ============================================================

def prepare_features(
    flow_data: dict
) -> pd.DataFrame:

    if not isinstance(
        flow_data,
        dict
    ):
        raise TypeError(
            "flow_data must be a dictionary."
        )

    # --------------------------------------------------------
    # Copy input so the original dictionary
    # is not modified.
    # --------------------------------------------------------

    normalized_data = dict(
        flow_data
    )

    # --------------------------------------------------------
    # Convert API field names to
    # actual model feature names.
    # --------------------------------------------------------

    for api_name, model_name in (
        API_FEATURE_MAPPING.items()
    ):

        if api_name in normalized_data:

            normalized_data[model_name] = (
                normalized_data.pop(
                    api_name
                )
            )

    # --------------------------------------------------------
    # Create a row with exactly the
    # same feature order used by training.
    # --------------------------------------------------------

    row = {}

    missing_features = []

    for feature in MODEL_FEATURES:

        if feature in normalized_data:

            value = normalized_data[
                feature
            ]

        else:

            # For backward compatibility with
            # the current API prototype.
            value = 0

            missing_features.append(
                feature
            )

        row[feature] = value

    # --------------------------------------------------------
    # Create DataFrame
    # --------------------------------------------------------

    df = pd.DataFrame(
        [row],
        columns=MODEL_FEATURES
    )

    # --------------------------------------------------------
    # Convert everything to numeric
    # --------------------------------------------------------

    for column in MODEL_FEATURES:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    # --------------------------------------------------------
    # Replace invalid values
    # --------------------------------------------------------

    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    df = df.fillna(0)

    # --------------------------------------------------------
    # Validate final shape
    # --------------------------------------------------------

    if df.shape[1] != model_feature_count:

        raise ValueError(
            "Prepared feature count does not match "
            f"the model. Prepared={df.shape[1]}, "
            f"expected={model_feature_count}."
        )

    return df


# ============================================================
# PREDICT ATTACK
# ============================================================

def predict_attack(
    flow_data: dict
) -> dict:

    # --------------------------------------------------------
    # Prepare input
    # --------------------------------------------------------

    features = prepare_features(
        flow_data
    )

    # --------------------------------------------------------
    # Predict probabilities
    # --------------------------------------------------------

    try:

        probabilities = (
            model.predict_proba(
                features
            )[0]
        )

    except Exception as exc:

        raise RuntimeError(
            f"XGBoost prediction failed: {exc}"
        ) from exc

    # --------------------------------------------------------
    # Predicted class
    # --------------------------------------------------------

    predicted_class = int(
        np.argmax(
            probabilities
        )
    )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = float(
        probabilities[
            predicted_class
        ]
    )

    # --------------------------------------------------------
    # Attack label
    # --------------------------------------------------------

    attack_type = label_classes.get(
        predicted_class,
        f"UNKNOWN_CLASS_{predicted_class}"
    )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    severity = calculate_severity(
        attack_type,
        confidence
    )

    # --------------------------------------------------------
    # Risk score
    # --------------------------------------------------------

    risk_score = calculate_risk_score(
        attack_type,
        confidence
    )

    # --------------------------------------------------------
    # Probability distribution
    # --------------------------------------------------------

    class_probabilities = {}

    for class_index, probability in (
        enumerate(probabilities)
    ):

        class_name = label_classes.get(
            class_index,
            f"UNKNOWN_CLASS_{class_index}"
        )

        class_probabilities[
            class_name
        ] = round(
            float(probability),
            6
        )

    # --------------------------------------------------------
    # Top 3 predictions
    # --------------------------------------------------------

    top_indices = np.argsort(
        probabilities
    )[::-1][:3]

    top_predictions = []

    for index in top_indices:

        class_index = int(
            index
        )

        class_name = label_classes.get(
            class_index,
            f"UNKNOWN_CLASS_{class_index}"
        )

        top_predictions.append({
            "attack_type": class_name,
            "probability": round(
                float(
                    probabilities[
                        class_index
                    ]
                ),
                6
            )
        })

    # --------------------------------------------------------
    # Return final result
    # --------------------------------------------------------

    return {

        "attack_type":
            attack_type,

        "confidence":
            round(
                confidence,
                4
            ),

        "severity":
            severity,

        "risk_score":
            round(
                risk_score,
                4
            ),

        "predicted_class":
            predicted_class,

        "class_probabilities":
            class_probabilities,

        "top_predictions":
            top_predictions
    }


# ============================================================
# MODEL INFORMATION
# ============================================================

def get_model_info() -> dict:

    return {

        "model":
            "XGBoost",

        "feature_count":
            model_feature_count,

        "classes":
            label_classes,

        "feature_names":
            MODEL_FEATURES
    }