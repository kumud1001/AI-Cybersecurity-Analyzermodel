"""
Isolation Forest prediction
"""

import os
import joblib
import pandas as pd

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "isolation_forest.pkl"
)

model = joblib.load(MODEL_PATH)

FEATURE_COLUMNS = [
    "packet_size",
    "protocol",
    "src_port",
    "dst_port",
    "payload_size",
]


def predict_anomaly(features):

    df = pd.DataFrame([{
        "packet_size": features.get("packet_size", 0),
        "protocol": features.get("protocol", 0),
        "src_port": features.get("src_port", 0),
        "dst_port": features.get("dst_port", 0),
        "payload_size": features.get("payload_size", 0),
    }], columns=FEATURE_COLUMNS)

    prediction = model.predict(df)
    score = model.decision_function(df)

    return {
        "anomaly": prediction[0] == -1,
        "score": float(score[0]),
        "message": "Suspicious network behavior detected"
    }