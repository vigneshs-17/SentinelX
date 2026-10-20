"""
Model artifact security (D12): signed skops files, no unverified deserialization, no pickle.

Defence layers on load, in order:
  1. HMAC-SHA256 over the exact model bytes, key from env SENTINELX_MODEL_KEY (never in the repo),
     checked with hmac.compare_digest BEFORE any deserialization. Stops a tampered or swapped model file.
  2. skops.io with an explicit trusted-types allow-list. Stops a model file from instantiating arbitrary
     classes (the pickle code-execution route) even if it were somehow signed.
  3. Schema checks: feature names must equal the current extractor's, so a model trained on a different
     feature set is refused.
  4. Runtime only: a signed gate.json bound to this exact model's SHA-256 must say PASS.

Does NOT stop: a compromised training machine, a stolen/leaked SENTINELX_MODEL_KEY, or poisoned training
data. Whoever holds the key can sign any model. See docs/ML_REPORT.md ("Model artifact security").
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
from pathlib import Path
from typing import Any

import skops.io as sio

from ml.flows import FEATURE_NAMES

KEY_ENV = "SENTINELX_MODEL_KEY"
MODEL_FILE = "flow_model.skops"
GATE_FILE = "gate.json"
FORMAT_VERSION = 1
MIN_KEY_BYTES = 16

# Explicit allow-list. Never computed from the file being loaded.
TRUSTED_TYPES: list[str] = [
    # Everything else a HistGradientBoostingClassifier needs is already trusted by skops itself.
    "sklearn.ensemble._hist_gradient_boosting.predictor.TreePredictor",
]


class ModelSecurityError(ValueError):
    """Model artifact failed verification; it was not deserialized."""


def get_key(key: bytes | str | None = None) -> bytes:
    raw = key if key is not None else os.environ.get(KEY_ENV)
    if raw is None or raw == "":
        raise ModelSecurityError(f"{KEY_ENV} is not set; refusing to sign or load a model")
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(data) < MIN_KEY_BYTES:
        raise ModelSecurityError(f"{KEY_ENV} must be at least {MIN_KEY_BYTES} bytes")
    return data


def sign_bytes(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _sig_path(path: Path) -> Path:
    return path.with_name(path.name + ".sig")


def _verify(path: Path, key: bytes) -> bytes:
    sig_file = _sig_path(path)
    if not path.is_file() or not sig_file.is_file():
        raise ModelSecurityError(f"model file or signature missing: {path.name}")
    data = path.read_bytes()
    expected = sign_bytes(data, key)
    actual = sig_file.read_text(encoding="ascii", errors="replace").strip()
    if not hmac.compare_digest(expected, actual):
        raise ModelSecurityError(
            f"signature mismatch for {path.name}: file is tampered, swapped or signed with another key"
        )
    return data


def save_bundle(bundle: dict[str, Any], out_dir: Path | str, key: bytes | str | None = None) -> Path:
    """Serialize with skops, sign with HMAC-SHA256, write model + .sig. Returns the model path."""
    hmac_key = get_key(key)
    bundle = {**bundle, "format": FORMAT_VERSION, "feature_names": list(FEATURE_NAMES)}
    buf = io.BytesIO()
    sio.dump(bundle, buf)
    data = buf.getvalue()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    model_path = out / MODEL_FILE
    model_path.write_bytes(data)
    _sig_path(model_path).write_text(sign_bytes(data, hmac_key), encoding="ascii")
    return model_path


def load_bundle(
    model_dir: Path | str,
    key: bytes | str | None = None,
    require_gate: bool = True,
) -> dict[str, Any]:
    """Verify then load a model bundle. Raises ModelSecurityError on any failure; never loads unverified bytes."""
    hmac_key = get_key(key)
    model_path = Path(model_dir) / MODEL_FILE
    data = _verify(model_path, hmac_key)
    try:
        untrusted = set(sio.get_untrusted_types(data=data))
        extra = untrusted - set(TRUSTED_TYPES)
        if extra:
            raise ModelSecurityError(f"model contains types outside the allow-list: {sorted(extra)}")
        bundle = sio.loads(data, trusted=TRUSTED_TYPES)
    except ModelSecurityError:
        raise
    except Exception as exc:
        raise ModelSecurityError(f"model could not be loaded safely: {type(exc).__name__}: {exc}") from exc

    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT_VERSION:
        raise ModelSecurityError("unsupported model bundle format")
    if list(bundle.get("feature_names", [])) != list(FEATURE_NAMES):
        raise ModelSecurityError("model feature schema does not match the current flow extractor")
    for field_name in ("model", "classes", "benign_label", "threshold", "medium_threshold"):
        if field_name not in bundle:
            raise ModelSecurityError(f"model bundle missing field: {field_name}")

    if require_gate:
        gate = read_gate(model_dir, hmac_key)
        if gate.get("decision") != "PASS":
            raise ModelSecurityError(
                f"decision gate is {gate.get('decision')!r}, not PASS; ML stays out of the alert path"
            )
        if gate.get("model_sha256") != hashlib.sha256(data).hexdigest():
            raise ModelSecurityError("gate.json is bound to a different model file")
    bundle["model_sha256"] = hashlib.sha256(data).hexdigest()
    return bundle


def write_gate(model_dir: Path | str, decision: dict[str, Any], key: bytes | str | None = None) -> Path:
    """Write signed gate.json bound to the SHA-256 of the current model file."""
    hmac_key = get_key(key)
    model_path = Path(model_dir) / MODEL_FILE
    payload = {**decision, "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest()}
    gate_path = Path(model_dir) / GATE_FILE
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    gate_path.write_bytes(data)
    _sig_path(gate_path).write_text(sign_bytes(data, hmac_key), encoding="ascii")
    return gate_path


def read_gate(model_dir: Path | str, key: bytes | str | None = None) -> dict[str, Any]:
    hmac_key = get_key(key)
    data = _verify(Path(model_dir) / GATE_FILE, hmac_key)
    try:
        gate = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ModelSecurityError("gate.json is not valid JSON") from exc
    if not isinstance(gate, dict):
        raise ModelSecurityError("gate.json has wrong shape")
    return gate
