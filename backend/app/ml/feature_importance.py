import joblib
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# Project root
BASE_DIR = Path(__file__).resolve().parents[3]

# Load trained XGBoost model
MODEL_PATH = BASE_DIR / "models" / "xgboost.pkl"

model = joblib.load(MODEL_PATH)

# Get feature names from the trained model
feature_names = model.feature_names_in_

# Get XGBoost feature importance
importance = model.feature_importances_

# Create dataframe
importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importance
})

# Sort from highest to lowest
importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
)

# Display top 20
print("\nTop 20 XGBoost Features:")
print(importance_df.head(20).to_string(index=False))

# Save complete results
OUTPUT_DIR = BASE_DIR / "results"
OUTPUT_DIR.mkdir(exist_ok=True)

importance_df.to_csv(
    OUTPUT_DIR / "xgboost_feature_importance.csv",
    index=False
)

# Plot top 20 features
top20 = importance_df.head(20).sort_values(
    by="Importance",
    ascending=True
)

plt.figure(figsize=(10, 8))
plt.barh(top20["Feature"], top20["Importance"])
plt.xlabel("Feature Importance")
plt.ylabel("Network Traffic Feature")
plt.title("XGBoost Feature Importance - CIC-IDS2017")
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "xgboost_feature_importance.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()

print("\nFiles saved:")
print(OUTPUT_DIR / "xgboost_feature_importance.csv")
print(OUTPUT_DIR / "xgboost_feature_importance.png")