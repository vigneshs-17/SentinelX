import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ml.evaluation.train_model import (
    FEATURE_COLUMNS,
    ModelActivationError,
    train_and_evaluate_improved_model,
)
from ml.manage_model_hash import (
    calculate_file_sha256,
    inspect_model_checksum,
    update_model_checksum,
)
from ml.predictor import (
    calculate_model_sha256,
    invalidate_model_cache,
    verify_model_integrity,
)


@pytest.fixture
def temp_dir():
    """Windows-safe temporary directory fixture avoiding pytest-of-user permission collisions."""
    with tempfile.TemporaryDirectory(prefix="sentinelx_ml_sec_") as d:
        yield Path(d)


class TestModelChecksumToolingSafety:
    """Tests ensuring model checksum tooling operates purely on raw bytes and never unpickles."""

    def test_calculate_file_sha256_binary_accuracy(self, temp_dir):
        """Verify calculate_file_sha256 accurately computes SHA256 on arbitrary binary data."""
        binary_data = os.urandom(1024 * 64)  # 64 KB random binary
        test_file = temp_dir / "test_model.bin"
        test_file.write_bytes(binary_data)

        expected_hash = hashlib.sha256(binary_data).hexdigest().lower()
        actual_hash = calculate_file_sha256(test_file)
        assert actual_hash == expected_hash

    def test_calculate_file_sha256_rejects_missing_file(self, temp_dir):
        """Verify FileNotFoundError is raised if target model file does not exist."""
        missing_file = temp_dir / "non_existent.pkl"
        with pytest.raises(FileNotFoundError):
            calculate_file_sha256(missing_file)

    def test_calculate_file_sha256_rejects_empty_file(self, temp_dir):
        """Verify ValueError is raised if target model file is empty (0 bytes)."""
        empty_file = temp_dir / "empty.pkl"
        empty_file.write_bytes(b"")
        with pytest.raises(ValueError, match="empty"):
            calculate_file_sha256(empty_file)

    def test_tool_never_calls_pickle_or_joblib_load(self, temp_dir):
        """Verify joblib.load and pickle.load are NEVER called, even on executable pickle payloads."""
        malicious_payload = b"cos\nsystem\n(S'echo EXPLOIT_TEST'\ntR."
        fake_model = temp_dir / "payload.pkl"
        fake_model.write_bytes(malicious_payload)
        fake_meta = temp_dir / "model_metadata.json"
        fake_meta.write_text("{}", encoding="utf-8")

        with patch("joblib.load") as mock_joblib, patch("pickle.load") as mock_pickle:
            # 1. Inspection must not load
            actual_hash, expected, is_match = inspect_model_checksum(fake_model, fake_meta)
            assert actual_hash == hashlib.sha256(malicious_payload).hexdigest().lower()
            mock_joblib.assert_not_called()
            mock_pickle.assert_not_called()

            # 2. Update must not load
            update_model_checksum(fake_model, fake_meta, confirm=True)
            mock_joblib.assert_not_called()
            mock_pickle.assert_not_called()

    def test_update_requires_explicit_confirmation(self, temp_dir):
        """Verify update_model_checksum refuses to execute without confirm=True."""
        model_file = temp_dir / "model.pkl"
        model_file.write_bytes(b"MODEL_DATA_123")
        meta_file = temp_dir / "model_metadata.json"
        meta_file.write_text("{}", encoding="utf-8")

        with pytest.raises(ValueError, match="confirmation"):
            update_model_checksum(model_file, meta_file, confirm=False)

    def test_update_creates_backup_and_preserves_existing_metadata(self, temp_dir):
        """Verify update_model_checksum creates a .bak copy and preserves all other fields."""
        model_file = temp_dir / "model.pkl"
        model_file.write_bytes(b"UPDATED_MODEL_BYTES_456")
        expected_hash = hashlib.sha256(b"UPDATED_MODEL_BYTES_456").hexdigest().lower()

        meta_file = temp_dir / "model_metadata.json"
        original_metadata = {
            "model_version": "2.0.0",
            "model_type": "RandomForestClassifier",
            "model_sha256": "OLD_HASH_123",
            "classes": ["NORMAL", "PORT_SCAN"],
            "custom_note": "Production deployment note",
        }
        meta_file.write_text(json.dumps(original_metadata, indent=2), encoding="utf-8")

        # Update checksum
        updated_hash = update_model_checksum(model_file, meta_file, confirm=True)
        assert updated_hash == expected_hash

        # Verify backup exists and contains original hash
        backup_file = temp_dir / "model_metadata.json.bak"
        assert backup_file.exists()
        with open(backup_file, encoding="utf-8") as f:
            backup_data = json.load(f)
        assert backup_data["model_sha256"] == "OLD_HASH_123"

        # Verify new metadata file contains updated hash and all preserved fields
        with open(meta_file, encoding="utf-8") as f:
            new_data = json.load(f)
        assert new_data["model_sha256"] == expected_hash
        assert new_data["model_version"] == "2.0.0"
        assert new_data["classes"] == ["NORMAL", "PORT_SCAN"]
        assert new_data["custom_note"] == "Production deployment note"


class TestTrainingPipelineAutomatedChecksum:
    """Tests ensuring the training pipeline automatically computes and records SHA256."""

    def test_training_pipeline_generates_matching_checksum_and_full_metadata(self, temp_dir):
        """Verify train_and_evaluate_improved_model generates a valid model_sha256 matching the artifact."""
        # Create a tiny synthetic dataset in temp_dir
        data_path = temp_dir / "mini_traffic.csv"
        rows = []
        # Add 30 samples (10 per class) to allow StratifiedKFold cv=2
        for i in range(10):
            rows.append(
                {
                    "packet_size": 60,
                    "source_port": 1000 + i,
                    "destination_port": 80,
                    "protocol": 6,
                    "tcp_syn": 1,
                    "label": "PORT_SCAN",
                }
            )
            rows.append(
                {
                    "packet_size": 1500,
                    "source_port": 5000 + i,
                    "destination_port": 443,
                    "protocol": 17,
                    "tcp_syn": 0,
                    "label": "HIGH_TRAFFIC",
                }
            )
            rows.append(
                {
                    "packet_size": 250,
                    "source_port": 8000 + i,
                    "destination_port": 53,
                    "protocol": 17,
                    "tcp_syn": 0,
                    "label": "NORMAL",
                }
            )

        import pandas as pd

        pd.DataFrame(rows).to_csv(data_path, index=False)

        mod_dir = temp_dir / "models"
        rep_dir = temp_dir / "reports"

        # Run training pipeline with cv_folds=2 on mini dataset with fast grid
        fast_grid = {"n_estimators": [5], "max_depth": [3]}
        train_and_evaluate_improved_model(
            dataset_path=str(data_path),
            models_dir=str(mod_dir),
            reports_dir=str(rep_dir),
            random_state=42,
            cv_folds=2,
            param_grid=fast_grid,
        )

        prod_model = mod_dir / "sentinelx_model.pkl"
        meta_file = mod_dir / "model_metadata.json"

        assert prod_model.exists(), "Production model file must exist"
        assert meta_file.exists(), "Metadata file must exist"

        # 1. Verify model_sha256 is in metadata
        with open(meta_file, encoding="utf-8") as f:
            metadata = json.load(f)

        assert "model_sha256" in metadata, "model_sha256 missing from model_metadata.json"
        stored_hash = metadata["model_sha256"]

        # 2. Verify stored hash matches exact byte-stream hash of the model file
        actual_hash = calculate_file_sha256(prod_model)
        assert stored_hash == actual_hash

        # 3. Verify all metadata fields exist
        assert metadata["model_version"] == "2.0.0"
        assert metadata["model_type"] == "RandomForestClassifier"
        assert "features" in metadata
        assert metadata["features"] == FEATURE_COLUMNS
        assert "classes" in metadata
        assert set(metadata["classes"]) == {"NORMAL", "PORT_SCAN", "HIGH_TRAFFIC"}
        assert "hyperparameters" in metadata
        assert "cross_validation" in metadata
        assert "performance" in metadata
        assert "training_accuracy" in metadata["performance"]
        assert "test_accuracy" in metadata["performance"]
        assert "provenance" in metadata
        assert "limitations" in metadata

        # 4. Verify runtime verify_model_integrity succeeds on the freshly trained model
        verified = verify_model_integrity(prod_model, meta_file)
        assert verified == actual_hash

    def test_failed_training_preserves_existing_metadata(self, temp_dir):
        """Verify that if training aborts before completion, existing metadata is untouched."""
        mod_dir = temp_dir / "models"
        mod_dir.mkdir(parents=True, exist_ok=True)
        meta_file = mod_dir / "model_metadata.json"

        original_content = {"model_version": "1.0.0", "model_sha256": "PRESERVED_HASH"}
        meta_file.write_text(json.dumps(original_content), encoding="utf-8")

        # Call with non-existent dataset -> raises FileNotFoundError
        with pytest.raises(FileNotFoundError):
            train_and_evaluate_improved_model(
                dataset_path=str(temp_dir / "missing.csv"),
                models_dir=str(mod_dir),
            )

        # Verify metadata file is still intact with original content
        with open(meta_file, encoding="utf-8") as f:
            data = json.load(f)
        assert data["model_sha256"] == "PRESERVED_HASH"


def _make_mini_dataset(temp_dir: Path) -> Path:
    """Helper to create a mini synthetic traffic dataset for fast isolated training tests."""
    data_path = temp_dir / "mini_traffic.csv"
    rows = []
    for i in range(10):
        rows.append(
            {
                "packet_size": 60,
                "source_port": 1000 + i,
                "destination_port": 80,
                "protocol": 6,
                "tcp_syn": 1,
                "label": "PORT_SCAN",
            }
        )
        rows.append(
            {
                "packet_size": 1500,
                "source_port": 5000 + i,
                "destination_port": 443,
                "protocol": 17,
                "tcp_syn": 0,
                "label": "HIGH_TRAFFIC",
            }
        )
        rows.append(
            {
                "packet_size": 250,
                "source_port": 8000 + i,
                "destination_port": 53,
                "protocol": 17,
                "tcp_syn": 0,
                "label": "NORMAL",
            }
        )
    import pandas as pd

    pd.DataFrame(rows).to_csv(data_path, index=False)
    return data_path


class TestModelActivationConsistencyAndRollback:
    """Tests verifying two-phase staging, atomic activation, rollback, and malformed metadata preservation."""

    def test_malformed_metadata_creates_corrupt_backup_and_warning(self, temp_dir):
        """Verify that malformed JSON in model_metadata.json produces a timestamped .corrupt backup, emits a warning, and builds fresh metadata."""
        data_path = _make_mini_dataset(temp_dir)
        mod_dir = temp_dir / "models"
        rep_dir = temp_dir / "reports"
        mod_dir.mkdir(parents=True, exist_ok=True)
        meta_file = mod_dir / "model_metadata.json"

        corrupt_content = '{"model_sha256": "broken_truncated_json...{'
        meta_file.write_text(corrupt_content, encoding="utf-8")

        with pytest.warns(UserWarning, match="malformed JSON"):
            train_and_evaluate_improved_model(
                dataset_path=str(data_path),
                models_dir=str(mod_dir),
                reports_dir=str(rep_dir),
                random_state=42,
                cv_folds=2,
                param_grid={"n_estimators": [5], "max_depth": [3]},
            )

        # 1. Verify corrupt backup file was created
        corrupt_backups = list(mod_dir.glob("model_metadata.json.corrupt.*.bak"))
        assert len(corrupt_backups) == 1, f"Expected 1 corrupt backup file, found {len(corrupt_backups)}"
        assert corrupt_backups[0].read_text(encoding="utf-8") == corrupt_content

        # 2. Verify fresh model_metadata.json is valid and complete
        assert meta_file.exists()
        with open(meta_file, encoding="utf-8") as f:
            new_meta = json.load(f)

        assert new_meta["model_version"] == "2.0.0"
        assert new_meta["model_type"] == "RandomForestClassifier"
        assert "model_sha256" in new_meta
        prod_model = mod_dir / "sentinelx_model.pkl"
        assert new_meta["model_sha256"] == calculate_file_sha256(prod_model)

    def test_valid_metadata_fields_preserved_across_retrain(self, temp_dir):
        """Verify that valid pre-existing metadata fields are preserved during retraining."""
        data_path = _make_mini_dataset(temp_dir)
        mod_dir = temp_dir / "models"
        rep_dir = temp_dir / "reports"
        mod_dir.mkdir(parents=True, exist_ok=True)
        meta_file = mod_dir / "model_metadata.json"

        initial_metadata = {
            "custom_deployment_id": "DEP-PROD-9900",
            "audit_tag": "security_approved",
            "model_sha256": "OLD_STALE_HASH",
        }
        meta_file.write_text(json.dumps(initial_metadata, indent=2), encoding="utf-8")

        train_and_evaluate_improved_model(
            dataset_path=str(data_path),
            models_dir=str(mod_dir),
            reports_dir=str(rep_dir),
            random_state=42,
            cv_folds=2,
            param_grid={"n_estimators": [5], "max_depth": [3]},
        )

        # Verify no corrupt backups were created
        corrupt_backups = list(mod_dir.glob("model_metadata.json.corrupt.*.bak"))
        assert len(corrupt_backups) == 0

        # Verify custom fields were preserved
        with open(meta_file, encoding="utf-8") as f:
            updated_meta = json.load(f)

        assert updated_meta["custom_deployment_id"] == "DEP-PROD-9900"
        assert updated_meta["audit_tag"] == "security_approved"
        assert updated_meta["model_sha256"] != "OLD_STALE_HASH"
        prod_model = mod_dir / "sentinelx_model.pkl"
        assert updated_meta["model_sha256"] == calculate_file_sha256(prod_model)

    def test_candidate_model_hashed_in_staging_before_activation(self, temp_dir):
        """Verify candidate model is cryptographically hashed while staged (.tmp) before replacing active model."""
        data_path = _make_mini_dataset(temp_dir)
        mod_dir = temp_dir / "models"
        rep_dir = temp_dir / "reports"

        hashed_paths = []
        original_hash_fn = calculate_model_sha256

        def spy_calculate_sha256(path):
            hashed_paths.append(str(path))
            return original_hash_fn(path)

        with patch("ml.evaluation.train_model.calculate_model_sha256", side_effect=spy_calculate_sha256):
            train_and_evaluate_improved_model(
                dataset_path=str(data_path),
                models_dir=str(mod_dir),
                reports_dir=str(rep_dir),
                random_state=42,
                cv_folds=2,
                param_grid={"n_estimators": [5], "max_depth": [3]},
            )

        # 1. Staged candidate model must have been hashed first
        assert any(p.endswith("sentinelx_model.pkl.tmp") for p in hashed_paths), (
            f"Expected sentinelx_model.pkl.tmp to be hashed during staging. Calls: {hashed_paths}"
        )
        first_call = hashed_paths[0]
        assert first_call.endswith("sentinelx_model.pkl.tmp")

        # 2. Post-activation verification call must have verified live model
        assert any(p.endswith("sentinelx_model.pkl") for p in hashed_paths)

    def test_activation_failure_triggers_rollback(self, temp_dir):
        """Verify that a failure during metadata activation rolls back the active model to its prior version and raises ModelActivationError."""
        data_path = _make_mini_dataset(temp_dir)
        mod_dir = temp_dir / "models"
        rep_dir = temp_dir / "reports"
        mod_dir.mkdir(parents=True, exist_ok=True)

        prod_model = mod_dir / "sentinelx_model.pkl"
        meta_file = mod_dir / "model_metadata.json"

        # Seed existing active model and metadata
        prior_model_bytes = b"ORIGINAL_PRIOR_MODEL_BYTES_ABC_123"
        prod_model.write_bytes(prior_model_bytes)
        prior_meta = {"model_version": "1.0.0", "model_sha256": "ORIGINAL_HASH_123"}
        meta_file.write_text(json.dumps(prior_meta), encoding="utf-8")

        # Simulate failure during metadata activation (.replace on model_metadata.json fails)
        orig_replace = Path.replace

        def failing_replace(self, target):
            target_path = Path(target)
            if target_path.name == "model_metadata.json":
                raise OSError("Simulated disk I/O failure during metadata atomic swap")
            return orig_replace(self, target)

        with patch.object(Path, "replace", failing_replace):
            with pytest.raises(ModelActivationError, match="safely rolled back"):
                train_and_evaluate_improved_model(
                    dataset_path=str(data_path),
                    models_dir=str(mod_dir),
                    reports_dir=str(rep_dir),
                    random_state=42,
                    cv_folds=2,
                    param_grid={"n_estimators": [5], "max_depth": [3]},
                )

        # 1. Verify active model was rolled back to prior bytes
        assert prod_model.exists()
        assert prod_model.read_bytes() == prior_model_bytes

        # 2. Verify active metadata was untouched / rolled back
        assert meta_file.exists()
        with open(meta_file, encoding="utf-8") as f:
            active_meta = json.load(f)
        assert active_meta["model_version"] == "1.0.0"
        assert active_meta["model_sha256"] == "ORIGINAL_HASH_123"

        # 3. Verify backup and temporary files were cleaned up
        assert not (mod_dir / "sentinelx_model.pkl.prev").exists()
        assert not (mod_dir / "model_metadata.json.prev").exists()
        assert not (mod_dir / "sentinelx_model.pkl.tmp").exists()
        assert not (mod_dir / "model_metadata.json.tmp").exists()

    def test_post_activation_checksum_mismatch_triggers_rollback(self, temp_dir):
        """Verify that a checksum mismatch during post-activation check triggers full rollback."""
        data_path = _make_mini_dataset(temp_dir)
        mod_dir = temp_dir / "models"
        rep_dir = temp_dir / "reports"
        mod_dir.mkdir(parents=True, exist_ok=True)

        prod_model = mod_dir / "sentinelx_model.pkl"
        meta_file = mod_dir / "model_metadata.json"

        prior_model_bytes = b"ORIGINAL_STABLE_MODEL"
        prod_model.write_bytes(prior_model_bytes)
        prior_meta = {"model_version": "1.0.0", "model_sha256": "STABLE_HASH"}
        meta_file.write_text(json.dumps(prior_meta), encoding="utf-8")

        real_calculate = calculate_model_sha256

        def spoofed_post_activation_hash(path):
            path_obj = Path(path)
            # Return corrupt hash only on post-activation verification check of prod_model
            if path_obj.name == "sentinelx_model.pkl":
                return "0000000000000000000000000000000000000000000000000000000000000000"
            return real_calculate(path)

        with patch("ml.evaluation.train_model.calculate_model_sha256", side_effect=spoofed_post_activation_hash):
            with pytest.raises(ModelActivationError, match="Post-activation checksum mismatch"):
                train_and_evaluate_improved_model(
                    dataset_path=str(data_path),
                    models_dir=str(mod_dir),
                    reports_dir=str(rep_dir),
                    random_state=42,
                    cv_folds=2,
                    param_grid={"n_estimators": [5], "max_depth": [3]},
                )

        # Verify rollback restored original model and metadata
        assert prod_model.read_bytes() == prior_model_bytes
        with open(meta_file, encoding="utf-8") as f:
            active_meta = json.load(f)
        assert active_meta["model_sha256"] == "STABLE_HASH"

    def test_cache_invalidation_mechanism(self):
        """Verify that invalidate_model_cache safely resets _cached_model under _model_lock."""
        import ml.predictor as pred_module

        with pred_module._model_lock:
            pred_module._cached_model = "DUMMY_CACHED_MODEL"

        invalidate_model_cache()
        assert pred_module._cached_model is None

    def test_manage_model_hash_cli_raw_byte_safety_never_imports_code_executors(self):
        """Confirm that ml/manage_model_hash.py operates purely on raw bytes without unpickling or importing pickle/joblib/torch."""
        cli_path = Path("ml/manage_model_hash.py").resolve()
        source_code = cli_path.read_text(encoding="utf-8")

        forbidden_imports = [
            "import pickle",
            "from pickle",
            "import joblib",
            "from joblib",
            "import torch",
            "from torch",
        ]
        for forbidden in forbidden_imports:
            assert forbidden not in source_code, f"Found unsafe code deserializer import '{forbidden}' in {cli_path}"
