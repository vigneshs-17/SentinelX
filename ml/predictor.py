import joblib
import pandas as pd
from pathlib import Path
from typing import Tuple, Optional, Any

from ml.feature_extractor import extract_features


# ---------------------------------------------------------
# Model path
# ---------------------------------------------------------

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "models"
    / "sentinelx_model.pkl"
)

# Feature columns matching training schema
FEATURE_COLUMNS = [
    "packet_size",
    "source_port",
    "destination_port",
    "protocol",
    "tcp_syn",
]

# Cached model instance
_cached_model = None


def get_model(custom_path: Optional[Path] = None):
    """Safely returns the loaded ML model, with deterministic caching."""
    global _cached_model
    path = custom_path or MODEL_PATH
    if _cached_model is None or custom_path is not None:
        if not path.exists():
            raise FileNotFoundError(f"Trained model not found at: {path}")
        _cached_model = joblib.load(path)
    return _cached_model


# Load default model at import time for backward compatibility
try:
    model = get_model()
except Exception:
    model = None


# ---------------------------------------------------------
# Threat prediction
# ---------------------------------------------------------

def predict_threat(packet_data: dict) -> str:
    """
    Predicts threat category ('NORMAL', 'PORT_SCAN', 'HIGH_TRAFFIC')
    from packet dictionary. Preserves 100% backward compatibility.
    """
    prediction, _ = predict_threat_with_confidence(packet_data)
    return prediction


def predict_threat_with_confidence(packet_data: dict) -> Tuple[str, float]:
    """
    Predicts threat category along with statistical confidence (probability)
    derived from the Random Forest ensemble votes.
    
    Returns: (predicted_label: str, confidence_score: float)
    """
    active_model = get_model()
    features = extract_features(packet_data)

    feature_values = {
        column: features.get(column, 0)
        for column in FEATURE_COLUMNS
    }

    input_data = pd.DataFrame(
        [feature_values],
        columns=FEATURE_COLUMNS,
    )

    # Prediction
    prediction = active_model.predict(input_data)[0]

    # Probability estimation
    confidence = 0.80
    if hasattr(active_model, "predict_proba"):
        try:
            probabilities = active_model.predict_proba(input_data)[0]
            classes = list(active_model.classes_)
            if prediction in classes:
                class_idx = classes.index(prediction)
                confidence = float(probabilities[class_idx])
        except Exception:
            pass

    return str(prediction), round(confidence, 4)


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
        "tcp_syn": True,
    }

    pred, conf = predict_threat_with_confidence(sample_packet)
    print(f"ML Prediction: {pred} (Confidence: {conf:.2%})")