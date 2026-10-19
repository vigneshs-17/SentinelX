"""
SentinelX Model Checksum Management Utility
Provides safe, read-only hash inspection and guarded metadata update.
STRICT SECURITY GUARANTEE: Never unpickles or executes model files.
Operates exclusively on raw file bytes.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

SECURITY_WARNING = (
    "[SECURITY NOTICE] Cryptographic SHA256 checksums verify binary file identity\n"
    "and detect accidental corruption or tampering. They DO NOT prove model provenance,\n"
    "safety, or trustworthiness. Never bless or update checksums for unverified files."
)


def calculate_file_sha256(path: Path) -> str:
    """Computes SHA256 checksum by streaming raw file bytes. Never loads/unpickles."""
    if not path.exists():
        raise FileNotFoundError(f"Target file does not exist: {path}")
    if path.stat().st_size == 0:
        raise ValueError(f"Target file is empty (0 bytes): {path}")

    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest().lower()


def inspect_model_checksum(
    model_path: Path,
    metadata_path: Path,
) -> tuple[str, str | None, bool]:
    """
    Safely inspects the target model file and compares against metadata.
    Returns: (actual_file_hash, metadata_hash_or_none, is_match)
    """
    actual_hash = calculate_file_sha256(model_path)

    expected_hash = None
    if metadata_path.exists():
        try:
            with open(metadata_path, encoding="utf-8") as f:
                meta = json.load(f)
            expected_hash = meta.get("model_sha256")
            if expected_hash:
                expected_hash = expected_hash.lower()
        except Exception:
            expected_hash = None

    is_match = (expected_hash is not None) and (actual_hash == expected_hash)
    return actual_hash, expected_hash, is_match


def update_model_checksum(
    model_path: Path,
    metadata_path: Path,
    confirm: bool = False,
) -> str:
    """
    Updates model_sha256 in metadata_path after creating a backup copy.
    Requires confirm=True to prevent accidental updates.
    """
    if not confirm:
        raise ValueError("Updating model checksum requires explicit confirmation (confirm=True or --confirm).")

    actual_hash = calculate_file_sha256(model_path)

    existing_meta = {}
    if metadata_path.exists():
        # Create backup copy before any modification
        backup_path = metadata_path.with_name(f"{metadata_path.name}.bak")
        backup_path.write_bytes(metadata_path.read_bytes())

        try:
            with open(metadata_path, encoding="utf-8") as f:
                existing_meta = json.load(f)
        except Exception:
            existing_meta = {}

    existing_meta["model_sha256"] = actual_hash

    # Atomic replacement via temporary file
    temp_path = metadata_path.with_name(f"{metadata_path.name}.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(existing_meta, f, indent=2)
    temp_path.replace(metadata_path)

    return actual_hash


def main():
    parser = argparse.ArgumentParser(
        description="SentinelX Safe Model Checksum Inspector & Manager (Raw byte streaming only)"
    )
    default_model = Path(__file__).resolve().parent / "models" / "sentinelx_model.pkl"
    default_meta = Path(__file__).resolve().parent / "models" / "model_metadata.json"

    parser.add_argument("--model", type=Path, default=default_model, help="Path to model file")
    parser.add_argument("--metadata", type=Path, default=default_meta, help="Path to metadata JSON")
    parser.add_argument("--update", action="store_true", help="Update metadata with calculated hash")
    parser.add_argument("--confirm", action="store_true", help="Explicit confirmation required to modify metadata")

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print(" SentinelX Model Integrity Tool (Safe Byte Inspection)")
    print("=" * 70)
    print(SECURITY_WARNING)
    print("-" * 70)

    try:
        actual_hash, expected_hash, is_match = inspect_model_checksum(args.model, args.metadata)
        file_size = args.model.stat().st_size

        print(f"Model Path       : {args.model}")
        print(f"Model File Size  : {file_size:,} bytes")
        print(f"Calculated SHA256: {actual_hash}")
        print(f"Metadata SHA256  : {expected_hash or '<NOT FOUND>'}")
        print(f"Integrity Status : {'VERIFIED (Match)' if is_match else 'MISMATCH OR UNRECORDED'}")

        if args.update:
            if not args.confirm:
                print("\n[ERROR] --update was specified without --confirm.")
                print("Refusing to modify metadata without explicit confirmation.")
                sys.exit(1)

            new_hash = update_model_checksum(args.model, args.metadata, confirm=True)
            print(f"\n[+] Successfully updated metadata with hash: {new_hash}")
            print(f"[+] Backup saved to: {args.metadata}.bak")
            sys.exit(0)

        sys.exit(0 if is_match else 1)

    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
