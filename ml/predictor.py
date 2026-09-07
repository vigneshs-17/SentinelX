import joblib
import pandas as pd
from pathlib import Path

from ml.feature_extractor import extract_features


# ---------------------------------------------------------
# Model path
# ---------------------------------------------------------

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "models"
    / "sentinelx_model.pkl"
)


# ---------------------------------------------------------
# Load trained ML pipeline
# ---------------------------------------------------------

model = joblib.load(MODEL_PATH)


# ---------------------------------------------------------
# Feature columns
# ---------------------------------------------------------

FEATURE_COLUMNS = [
    "packet_size",
    "source_port",
    "destination_port",
    "protocol",
    "tcp_syn"
]


# ---------------------------------------------------------
# Threat prediction
# ---------------------------------------------------------

def predict_threat(packet_data):

    features = extract_features(packet_data)

    feature_values = {
        column: features.get(column, 0)
        for column in FEATURE_COLUMNS
    }

    input_data = pd.DataFrame(
        [feature_values],
        columns=FEATURE_COLUMNS
    )

    prediction = model.predict(input_data)[0]

    return prediction


# ---------------------------------------------------------
# Test predictor
# ---------------------------------------------------------

if __name__ == "__main__":

    sample_packet = {
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "packet_size": 60,
        "tcp_syn": True
    }

    result = predict_threat(sample_packet)

    print(
        f"ML Prediction: {result}"
    )