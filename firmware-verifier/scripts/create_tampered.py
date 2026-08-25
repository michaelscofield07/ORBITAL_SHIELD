"""
ORBITAL SHIELD — Create Tampered Firmware Artifact
Utility to create or update a tampered firmware artifact for attack simulation testing.
"""

import hashlib
from pathlib import Path
import sys

def create_tampered_firmware(
    original_path: Path,
    output_path: Path,
    tamper_description: str = "Modified execution authorization flag"
) -> None:
    if not original_path.exists():
        raise FileNotFoundError(f"Original firmware not found at: {original_path}")

    data = bytearray(original_path.read_bytes())
    original_sha256 = hashlib.sha256(data).hexdigest()

    # Apply alteration
    idx = data.find(b"AUTHORISED")
    if idx != -1:
        data[idx:idx+10] = b"COMPROMISE"
    else:
        # Flip bit
        data[64] = (data[64] ^ 0xFF)

    output_path.write_bytes(bytes(data))
    tampered_sha256 = hashlib.sha256(bytes(data)).hexdigest()

    print(f"[+] Tampered firmware created: {output_path}")
    print(f"    Original SHA-256: {original_sha256}")
    print(f"    Tampered SHA-256: {tampered_sha256}")
    print(f"    Tamper note:      {tamper_description}")


if __name__ == "__main__":
    base = Path(__file__).parent.parent
    orig = base / "artifacts" / "firmware_v1.bin"
    tamp = base / "artifacts" / "firmware_v1_tampered.bin"
    create_tampered_firmware(orig, tamp)
