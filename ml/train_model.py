"""
SentinelX Machine Learning Training Entrypoint.
Delegates to the standardized, cross-validated training pipeline in ml.evaluation.train_model.
"""

from ml.evaluation.train_model import train_and_evaluate_improved_model


def train_model():
    """Execute standardized model training and cross-validation."""
    return train_and_evaluate_improved_model()


if __name__ == "__main__":
    train_model()
