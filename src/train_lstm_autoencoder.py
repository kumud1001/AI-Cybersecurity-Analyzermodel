import os
import time
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input,
    LSTM,
    RepeatVector,
    TimeDistributed,
    Dense
)
from tensorflow.keras.callbacks import EarlyStopping

from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# SETTINGS
# ============================================================

DATA_DIR = "data/processed/ml"

MODEL_DIR = "models"

RESULTS_DIR = "experiments/results"

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "lstm_autoencoder.keras"
)

SCALER_FILE = os.path.join(
    MODEL_DIR,
    "lstm_scaler.pkl"
)

RESULT_FILE = os.path.join(
    RESULTS_DIR,
    "lstm_autoencoder_results.csv"
)

RANDOM_STATE = 42

# Keep this moderate because CIC-IDS2017 is large.
MAX_NORMAL_TRAIN = 20000
MAX_TEST = 20000

EPOCHS = 10
BATCH_SIZE = 128


# ============================================================
# RANDOM SEED
# ============================================================

np.random.seed(RANDOM_STATE)
tf.random.set_seed(RANDOM_STATE)


# ============================================================
# LOAD DATA
# ============================================================

def load_data():

    print("\n========================================")
    print(" LOADING CIC-IDS2017 DATA")
    print("========================================")

    X_train = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "X_train.csv"
        )
    )

    X_test = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "X_test.csv"
        )
    )

    y_train = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "y_train.csv"
        )
    )["label"]

    y_test = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "y_test.csv"
        )
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

    return X_train, X_test, y_train, y_test


# ============================================================
# PREPARE DATA
# ============================================================

def prepare_data(
    X_train,
    X_test,
    y_train,
    y_test
):

    print("\n========================================")
    print(" PREPARING LSTM DATA")
    print("========================================")

    # --------------------------------------------------------
    # Train ONLY on benign traffic
    # --------------------------------------------------------

    benign_mask = (
        y_train == 0
    )

    X_normal = X_train[
        benign_mask
    ].copy()

    print(
        f"Available benign training flows: "
        f"{len(X_normal):,}"
    )

    # Limit training size for manageable runtime

    if len(X_normal) > MAX_NORMAL_TRAIN:

        X_normal = X_normal.sample(
            n=MAX_NORMAL_TRAIN,
            random_state=RANDOM_STATE
        )

    print(
        f"Benign flows used for training: "
        f"{len(X_normal):,}"
    )

    # --------------------------------------------------------
    # Test data
    # --------------------------------------------------------

    if len(X_test) > MAX_TEST:

        rng = np.random.RandomState(
            RANDOM_STATE
        )

        indices = rng.choice(
            len(X_test),
            size=MAX_TEST,
            replace=False
        )

        X_test_sample = X_test.iloc[
            indices
        ].copy()

        y_test_sample = y_test.iloc[
            indices
        ].copy()

    else:

        X_test_sample = X_test.copy()

        y_test_sample = y_test.copy()

    # --------------------------------------------------------
    # Scale features
    # --------------------------------------------------------

    scaler = StandardScaler()

    X_normal_scaled = scaler.fit_transform(
        X_normal
    )

    X_test_scaled = scaler.transform(
        X_test_sample
    )

    # --------------------------------------------------------
    # Replace invalid numerical values
    # --------------------------------------------------------

    X_normal_scaled = np.nan_to_num(
        X_normal_scaled,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )

    X_test_scaled = np.nan_to_num(
        X_test_scaled,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )

    # --------------------------------------------------------
    # LSTM expects:
    #
    # samples × timesteps × features
    #
    # We treat each network flow as one timestep
    # --------------------------------------------------------

    X_normal_scaled = np.expand_dims(
        X_normal_scaled,
        axis=1
    )

    X_test_scaled = np.expand_dims(
        X_test_scaled,
        axis=1
    )

    # Binary test labels:
    #
    # 0 = BENIGN
    # 1 = ATTACK

    y_binary = np.where(
        y_test_sample == 0,
        0,
        1
    )

    print(
        f"Test samples used: "
        f"{len(X_test_sample):,}"
    )

    print(
        f"Attack samples: "
        f"{np.sum(y_binary):,}"
    )

    print(
        f"Benign samples: "
        f"{np.sum(y_binary == 0):,}"
    )

    return (
        X_normal_scaled,
        X_test_scaled,
        y_binary,
        scaler
    )


# ============================================================
# BUILD MODEL
# ============================================================

def build_model(
    n_features
):

    print("\n========================================")
    print(" BUILDING LSTM AUTOENCODER")
    print("========================================")

    inputs = Input(
        shape=(1, n_features)
    )

    # Encoder

    encoded = LSTM(
        64,
        activation="tanh"
    )(inputs)

    # Repeat latent representation

    repeated = RepeatVector(
        1
    )(encoded)

    # Decoder

    decoded = LSTM(
        64,
        activation="tanh",
        return_sequences=True
    )(repeated)

    outputs = TimeDistributed(
        Dense(n_features)
    )(decoded)

    model = Model(
        inputs,
        outputs
    )

    model.compile(
        optimizer="adam",
        loss="mse"
    )

    model.summary()

    return model


# ============================================================
# TRAIN
# ============================================================

def train_model(
    model,
    X_train
):

    print("\n========================================")
    print(" TRAINING LSTM AUTOENCODER")
    print("========================================")

    early_stopping = EarlyStopping(
        monitor="loss",
        patience=3,
        restore_best_weights=True
    )

    start_time = time.time()

    history = model.fit(

        X_train,

        X_train,

        epochs=EPOCHS,

        batch_size=BATCH_SIZE,

        shuffle=True,

        validation_split=0.1,

        callbacks=[
            early_stopping
        ],

        verbose=1
    )

    training_time = (
        time.time() - start_time
    )

    print(
        f"\nTraining time: "
        f"{training_time:.2f} seconds"
    )

    return (
        model,
        history,
        training_time
    )


# ============================================================
# CALCULATE RECONSTRUCTION ERROR
# ============================================================

def reconstruction_errors(
    model,
    X
):

    reconstructed = model.predict(
        X,
        verbose=0
    )

    errors = np.mean(
        np.square(
            X - reconstructed
        ),
        axis=(1, 2)
    )

    return errors


# ============================================================
# EVALUATE
# ============================================================

def evaluate_model(
    model,
    X_train,
    X_test,
    y_test
):

    print("\n========================================")
    print(" EVALUATING LSTM AUTOENCODER")
    print("========================================")

    # --------------------------------------------------------
    # Reconstruction error on normal training data
    # --------------------------------------------------------

    train_errors = reconstruction_errors(
        model,
        X_train
    )

    # --------------------------------------------------------
    # Threshold
    #
    # 95th percentile of benign reconstruction errors
    # --------------------------------------------------------

    threshold = np.percentile(
        train_errors,
        95
    )

    print(
        f"\nReconstruction threshold: "
        f"{threshold:.6f}"
    )

    # --------------------------------------------------------
    # Test reconstruction
    # --------------------------------------------------------

    start_time = time.time()

    test_errors = reconstruction_errors(
        model,
        X_test
    )

    inference_time = (
        time.time() - start_time
    )

    # --------------------------------------------------------
    # Prediction
    #
    # error > threshold = attack
    # error <= threshold = benign
    # --------------------------------------------------------

    predictions = np.where(
        test_errors > threshold,
        1,
        0
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    print("\n========================================")
    print(" LSTM AUTOENCODER RESULTS")
    print("========================================")

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
        f"Threshold      : {threshold:.6f}"
    )

    print(
        f"Inference Time : "
        f"{inference_time:.4f} seconds"
    )

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "BENIGN",
                "ATTACK"
            ],
            zero_division=0
        )
    )

    print("\nConfusion Matrix:")

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print(matrix)

    results = {

        "model":
            "LSTM Autoencoder",

        "accuracy":
            accuracy,

        "precision":
            precision,

        "recall":
            recall,

        "f1":
            f1,

        "threshold":
            threshold,

        "inference_time_seconds":
            inference_time
    }

    return results


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(
    model,
    scaler
):

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    model.save(
        MODEL_FILE
    )

    joblib.dump(
        scaler,
        SCALER_FILE
    )

    print("\nModel saved:")
    print(MODEL_FILE)

    print("\nScaler saved:")
    print(SCALER_FILE)


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

    df = pd.DataFrame(
        [results]
    )

    df.to_csv(
        RESULT_FILE,
        index=False
    )

    print("\nResults saved:")
    print(RESULT_FILE)


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "========================================"
    )

    print(
        " CIC-IDS2017 LSTM AUTOENCODER"
    )

    print(
        " Experiment 3.4.0"
    )

    print(
        "========================================"
    )

    # Load

    (
        X_train,
        X_test,
        y_train,
        y_test
    ) = load_data()

    # Prepare

    (
        X_normal,
        X_test,
        y_binary,
        scaler
    ) = prepare_data(
        X_train,
        X_test,
        y_train,
        y_test
    )

    # Number of features

    n_features = X_normal.shape[2]

    # Build

    model = build_model(
        n_features
    )

    # Train

    (
        model,
        history,
        training_time
    ) = train_model(
        model,
        X_normal
    )

    # Evaluate

    results = evaluate_model(
        model,
        X_normal,
        X_test,
        y_binary
    )

    # Save

    save_model(
        model,
        scaler
    )

    save_results(
        results,
        training_time
    )

    print(
        "\n========================================"
    )

    print(
        " LSTM AUTOENCODER EXPERIMENT COMPLETED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()