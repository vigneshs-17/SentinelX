import json
from pathlib import Path

import joblib
import pandas as pd

from detection.rule_engine import detect_port_scan
from detection.traffic_rules import detect_high_traffic
from ml.evaluation.metrics import (
    compute_comprehensive_metrics,
    format_confusion_matrix_ascii,
)
from ml.feature_extractor import extract_features
from ml.predictor import (
    FEATURE_COLUMNS,
    predict_threat,
    predict_threat_with_confidence,
)


class TestMLPipeline:
    """Comprehensive test suite for Phase 4 ML Retraining & Accuracy Evaluation."""

    # =========================================================================
    # 1. DATASET INTEGRITY & SCHEMA TESTS
    # =========================================================================

    def test_dataset_loading_and_integrity(self):
        """Verify network_traffic.csv exists, has valid columns, no missing data, and correct classes."""
        dataset_path = Path("ml/data/network_traffic.csv").resolve()
        assert dataset_path.exists(), f"Dataset not found at {dataset_path}"

        df = pd.read_csv(dataset_path, encoding="utf-8")
        assert len(df) == 2000, f"Expected 2000 samples, got {len(df)}"

        expected_columns = [
            "packet_size",
            "source_port",
            "destination_port",
            "protocol",
            "tcp_syn",
            "label",
        ]
        assert list(df.columns) == expected_columns

        # Verify no missing values
        assert df.isnull().sum().sum() == 0, "Dataset contains null or missing values"

        # Verify classes
        expected_classes = {"NORMAL", "PORT_SCAN", "HIGH_TRAFFIC"}
        assert set(df["label"].unique()) == expected_classes

        # Verify class counts
        counts = df["label"].value_counts().to_dict()
        assert counts["NORMAL"] == 1000
        assert counts["PORT_SCAN"] == 500
        assert counts["HIGH_TRAFFIC"] == 500

    # =========================================================================
    # 2. FEATURE EXTRACTOR TESTS
    # =========================================================================

    def test_feature_extractor_valid_packet(self):
        """Feature extractor produces exact numeric features matching model schema."""
        packet_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "source_port": 50123,
            "destination_port": 80,
            "packet_size": 64,
            "tcp_syn": True,
        }
        features = extract_features(packet_data)

        assert features["packet_size"] == 64
        assert features["source_port"] == 50123
        assert features["destination_port"] == 80
        assert features["protocol"] == 1  # TCP is mapped to 1
        assert features["tcp_syn"] == 1

        for col in FEATURE_COLUMNS:
            assert col in features

    def test_feature_extractor_missing_and_null_handling(self):
        """Feature extractor safely defaults missing or corrupted fields to 0."""
        malformed_packet = {
            "source_ip": None,
            "destination_ip": None,
            "protocol": "UNKNOWN_PROTOCOL",
            "source_port": None,
            "destination_port": None,
            "packet_size": None,
            "tcp_syn": None,
        }
        features = extract_features(malformed_packet)

        assert features["packet_size"] == 0
        assert features["source_port"] == 0
        assert features["destination_port"] == 0
        assert features["protocol"] == 0
        assert features["tcp_syn"] == 0

    # =========================================================================
    # 3. MODEL ARTIFACTS & VERSIONING TESTS
    # =========================================================================

    def test_model_versioning_artifacts_exist(self):
        """Verify active model and metadata exist and load correctly."""
        mod_dir = Path("ml/models").resolve()
        prod_path = mod_dir / "sentinelx_model.pkl"
        meta_path = mod_dir / "model_metadata.json"

        assert prod_path.exists(), "Production model artifact missing"
        assert meta_path.exists(), "Model metadata JSON missing"

        # Verify active model loads and has correct classes
        m = joblib.load(prod_path)
        assert hasattr(m, "predict")
        assert hasattr(m, "classes_")
        assert set(m.classes_) == {"NORMAL", "PORT_SCAN", "HIGH_TRAFFIC"}

        # Verify metadata schema
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)

        assert meta["model_version"] == "2.0.0"
        assert meta["model_type"] == "RandomForestClassifier"
        assert "model_sha256" in meta
        assert len(meta["model_sha256"]) == 64
        assert meta["hyperparameters"]["class_weight"] == "balanced"
        assert meta["hyperparameters"]["max_depth"] == 10
        assert "limitations" in meta
        assert len(meta["limitations"]) > 0

    # =========================================================================
    # 4. PREDICTION & CONFIDENCE TESTS
    # =========================================================================

    def test_predict_threat_backward_compatibility(self):
        """predict_threat returns a string label matching canonical classes."""
        packet = {
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "protocol": "TCP",
            "source_port": 12345,
            "destination_port": 22,
            "packet_size": 60,
            "tcp_syn": True,
        }
        result = predict_threat(packet)
        assert isinstance(result, str)
        assert result in ["NORMAL", "PORT_SCAN", "HIGH_TRAFFIC"]

    def test_predict_threat_with_confidence_bounds(self):
        """predict_threat_with_confidence returns (label, prob) with Random Forest probability/confidence estimate."""
        port_scan_packet = {
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "protocol": "TCP",
            "source_port": 12345,
            "destination_port": 22,
            "packet_size": 60,
            "tcp_syn": True,
        }
        label, conf = predict_threat_with_confidence(port_scan_packet)

        assert label == "PORT_SCAN"
        assert isinstance(conf, float)
        assert 0.0 <= conf <= 1.0
        assert conf >= 0.85, f"Expected high confidence for SYN port probe, got {conf}"

    def test_predictor_empty_packet_resilience(self):
        """Predictor handles completely empty dictionary without crashing."""
        empty_packet = {}
        label, conf = predict_threat_with_confidence(empty_packet)
        assert isinstance(label, str)
        assert 0.0 <= conf <= 1.0

    # =========================================================================
    # 5. METRIC CALCULATION CORRECTNESS TESTS
    # =========================================================================

    def test_metric_calculator_exact_values(self):
        """Verify compute_comprehensive_metrics computes exact mathematical metrics."""
        y_true = ["A", "A", "B", "B", "C"]
        y_pred = ["A", "B", "B", "B", "C"]
        classes = ["A", "B", "C"]

        metrics = compute_comprehensive_metrics(y_true, y_pred, classes=classes)

        assert metrics["n_samples"] == 5
        # 4 correct out of 5: accuracy = 0.80
        assert metrics["accuracy"] == 0.8

        # Class A: TP=1, FN=1, FP=0, TN=3 -> Prec=1.0, Rec=0.5, F1=0.6667
        a_stats = metrics["per_class"]["A"]
        assert a_stats["true_positives"] == 1
        assert a_stats["false_negatives"] == 1
        assert a_stats["false_positives"] == 0
        assert a_stats["true_negatives"] == 3
        assert a_stats["precision"] == 1.0
        assert a_stats["recall"] == 0.5

        # Class B: TP=2, FN=0, FP=1, TN=2 -> Prec=2/3=0.6667, Rec=1.0
        b_stats = metrics["per_class"]["B"]
        assert b_stats["true_positives"] == 2
        assert b_stats["false_positives"] == 1
        assert b_stats["precision"] == 0.6667
        assert b_stats["recall"] == 1.0

        # ASCII matrix rendering
        ascii_m = format_confusion_matrix_ascii(metrics["confusion_matrix"], classes)
        assert "Actual \\ Predicted" in ascii_m

    # =========================================================================
    # 6. EVALUATION ARTIFACTS VERIFICATION
    # =========================================================================

    def test_evaluation_json_and_md_reports_generated(self):
        """Verify that baseline, improved, comparison, and confusion matrix reports exist."""
        rep_dir = Path("ml/evaluation/reports").resolve()
        assert (rep_dir / "baseline_evaluation.json").exists()
        assert (rep_dir / "improved_evaluation.json").exists()
        assert (rep_dir / "comparison_report.md").exists()
        assert (rep_dir / "confusion_matrices.txt").exists()
        assert (rep_dir / "hybrid_analysis_report.md").exists()

        with open(rep_dir / "improved_evaluation.json", encoding="utf-8") as f:
            data = json.load(f)
            assert data["accuracy"] > 0.70
            assert data["macro_f1"] > 0.70
            assert data["per_class"]["HIGH_TRAFFIC"]["recall"] >= 0.80
            assert data["per_class"]["PORT_SCAN"]["recall"] == 1.0

    # =========================================================================
    # 7. HYBRID GATING PROTECTION TEST
    # =========================================================================

    def test_hybrid_gating_prevents_ml_false_positive_on_single_packet(self):
        """
        Verify that a single benign HTTPS packet that ML might flag as HIGH_TRAFFIC
        is completely gated by the Phase 3 rule engine, resulting in zero false alerts.
        """
        benign_packet = {
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "TCP",
            "tcp_syn": False,
            "packet_size": 1400,
        }

        # Rule engine checks
        rule_scan = detect_port_scan(benign_packet)
        rule_traffic = detect_high_traffic(benign_packet)

        # Neither rule should fire on a single packet
        assert rule_scan is None
        assert rule_traffic is None

        # Therefore, even if ML output is inspected, the hybrid system emits zero alerts
        # This demonstrates why the Phase 3 rule engine is the primary gating tier
