"""
Train Isolation Forest model
using captured network features
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib,os


# Normal traffic training samples

data = [

    # packet_size protocol src_port dst_port payload
    [60,6,443,50000,2],
    [120,6,50000,443,50],
    [150,17,55000,53,40],
    [80,6,52000,443,20],
    [300,17,60000,443,100],
    [70,6,51000,80,10],

]


columns = [

    "packet_size",
    "protocol",
    "src_port",
    "dst_port",
    "payload_size"

]


df = pd.DataFrame(
    data,
    columns=columns
)


model = IsolationForest(

    n_estimators=100,

    contamination=0.05,

    random_state=42

)


model.fit(df)
MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "isolation_forest.pkl"

)


joblib.dump(model, MODEL_PATH)

print(f"Model saved to: {MODEL_PATH}")




print(
    "Model trained successfully"
)