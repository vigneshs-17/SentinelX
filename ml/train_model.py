import pandas as pd
from pathlib import Path
import joblib

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = (
    BASE_DIR / "data" / "network_traffic.csv"
)

MODEL_PATH = (
    BASE_DIR / "models" / "sentinelx_model.pkl"
)


# ---------------------------------------------------------
# Training
# ---------------------------------------------------------

def train_model():

    print("[*] Loading dataset...")

    dataset = pd.read_csv(DATASET_PATH)

    print(
        f"[+] Dataset loaded: "
        f"{len(dataset)} samples"
    )

    # -----------------------------------------------------
    # Features
    # -----------------------------------------------------

    features = [
        "packet_size",
        "source_port",
        "destination_port",
        "protocol",
        "tcp_syn"
    ]

    X = dataset[features]
    y = dataset["label"]

    # -----------------------------------------------------
    # Feature types
    # -----------------------------------------------------

    numeric_features = [
        "packet_size",
        "source_port",
        "destination_port",
        "tcp_syn"
    ]

    categorical_features = [
        "protocol"
    ]

    # -----------------------------------------------------
    # Preprocessing
    # -----------------------------------------------------

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore"
                ),
                categorical_features
            )
        ],
        remainder="passthrough"
    )

    # -----------------------------------------------------
    # Random Forest model
    # -----------------------------------------------------

    classifier = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    # -----------------------------------------------------
    # Complete ML pipeline
    # -----------------------------------------------------

    model = Pipeline(
        steps=[
            (
                "preprocessor",
                preprocessor
            ),
            (
                "classifier",
                classifier
            )
        ]
    )

    # -----------------------------------------------------
    # Train / test split
    # -----------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print(
        f"[+] Training samples: "
        f"{len(X_train)}"
    )

    print(
        f"[+] Testing samples: "
        f"{len(X_test)}"
    )

    # -----------------------------------------------------
    # Train
    # -----------------------------------------------------

    print(
        "[*] Training Random Forest "
        "with categorical preprocessing..."
    )

    model.fit(
        X_train,
        y_train
    )

    # -----------------------------------------------------
    # Evaluation
    # -----------------------------------------------------

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print(
        f"\n[+] Model accuracy: "
        f"{accuracy:.4f}"
    )

    print(
        "\n[+] Classification report:"
    )

    print(
        classification_report(
            y_test,
            predictions
        )
    )

    # -----------------------------------------------------
    # Save model
    # -----------------------------------------------------

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_PATH
    )

    print(
        f"[+] Model saved to: "
        f"{MODEL_PATH}"
    )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":
    train_model()