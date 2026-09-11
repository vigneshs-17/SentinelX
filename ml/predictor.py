import hashlib
import json
import joblib
import pandas as pd
from pathlib import Path
import threading
from typing import Tuple, Optional, Any

from ml.feature_extractor import extract_features


class ModelIntegrityError(ValueError):
    """Raised when machine learning model cryptographic checksum verification fails."""
    pass


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

# ---------------------------------------------------------
# Concurrency lock & Cache Management
# ---------------------------------------------------------

_model_lock = threading.RLock()
_cached_model = None


def invalidate_model_cache() -> None:
    """Invalidates the in-memory cached model instance so the next inference reload pulls fresh bytes."""
    global _cached_model
    with _model_lock:
        _cached_model = None


def calculate_model_sha256(path: Path) -> str:
    """Computes SHA256 checksum of the target model file."""
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def verify_model_integrity(model_path: Path, metadata_path: Optional[Path] = None) -> str:
    """
    Verifies that model_path matches the cryptographic SHA256 recorded in metadata.
    Raises ModelIntegrityError if metadata is missing, malformed, or checksum mismatches.
    Returns: verified expected SHA256 hash string.
    """
    meta_file = metadata_path or (model_path.parent / "model_metadata.json")
    if not meta_file.exists():
        raise ModelIntegrityError(f"Model metadata file missing: {meta_file}")

    try:
        with open(meta_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except Exception as err:
        raise ModelIntegrityError(f"Malformed model metadata JSON in {meta_file}: {err}") from err

    expected_sha256 = metadata.get("model_sha256")
    if not expected_sha256:
        raise ModelIntegrityError(f"Missing 'model_sha256' in model metadata: {meta_file}")

    actual_sha256 = calculate_model_sha256(model_path)
    if actual_sha256.lower() != expected_sha256.lower():
        raise ModelIntegrityError(
            f"Model integrity verification failed for {model_path}. "
            f"Expected SHA256: {expected_sha256}, Actual: {actual_sha256}. "
            f"Model file may have been tampered with or corrupted."
        )

    return expected_sha256.lower()


def get_model(custom_path: Optional[Path] = None, metadata_path: Optional[Path] = None):
    """Safely verifies SHA256 checksum and returns the loaded ML model, with deterministic caching."""
    global _cached_model
    with _model_lock:
        path = Path(custom_path) if custom_path else MODEL_PATH
        if _cached_model is None or custom_path is not None:
            if not path.exists():
                raise FileNotFoundError(f"Trained model not found at: {path}")

            # P0 Security: Verify cryptographic hash BEFORE calling joblib.load
            verify_model_integrity(path, metadata_path=metadata_path)

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