"""
ORBITAL SHIELD — Setup Keys & Firmware Artifacts
Automated initialization script:
1. Generates authentic satellite flight software binary: `artifacts/firmware_v1.bin`.
2. Generates Cosign-compatible signing keypair (`cosign.pub` and private key).
3. Signs `firmware_v1.bin` to produce `artifacts/firmware_v1.bin.sig`.
4. Creates tampered binary `artifacts/firmware_v1_tampered.bin`.
5. Ensures private keys are never committed or exposed.
"""

from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

# Allow running standalone
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.key_manager import KeyManager


def generate_sample_firmware_binary() -> bytes:
    """
    Simulates a flight software binary image for an On-Board Computer (OBC).
    Contains realistic spacecraft telemetry routines, headers, and CRC sections.
    """
    header = b"ORBITAL_SHIELD_OBC_FLIGHT_FIRMWARE_V1.0.0_BUILD_20260824\x00\x00\x00"
    code_section = (
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\xb7\x00\x01\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00"
        b"ORBITAL_FLIGHT_EXEC: TASK_TELEMETRY_INIT; TASK_ADCS_STABILIZE; TASK_PAYLOAD_SAFE;"
        b"SEC_LEVEL=AUTHORISED; GROUND_SIGNER_ID=ORBITAL_SIGSTORE_CA_ROOT;"
        b"\x90\x90\x90\x90\xeb\xfe"
    )
    # Pad to realistic firmware size (e.g. 4096 bytes)
    padding = b"\x00" * (4096 - len(header) - len(code_section))
    return header + code_section + padding


def main():
    base_dir = Path(__file__).parent.parent
    artifacts_dir = base_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    secrets_dir = base_dir / ".secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("ORBITAL SHIELD — Firmware & Key Setup")
    print("=" * 70)

    # 1. Create valid firmware artifact
    fw_v1_path = artifacts_dir / "firmware_v1.bin"
    fw_content = generate_sample_firmware_binary()
    fw_v1_path.write_bytes(fw_content)
    fw_sha256 = hashlib.sha256(fw_content).hexdigest()
    print(f"[+] Created authentic firmware binary: {fw_v1_path}")
    print(f"    Size: {len(fw_content)} bytes")
    print(f"    SHA-256: {fw_sha256}")

    # 2. Key Generation
    cosign_pub_path = artifacts_dir / "cosign.pub"
    cosign_key_path = secrets_dir / "cosign.key"

    # Use KeyManager for cryptographic generation
    private_key, public_key = KeyManager.generate_keypair()
    KeyManager.save_public_key(public_key, cosign_pub_path)
    KeyManager.save_private_key(private_key, cosign_key_path)

    print(f"[+] Generated Cosign-compatible keypair:")
    print(f"    Public Key (committed/trusted): {cosign_pub_path}")
    print(f"    Private Key (ignored/secret):   {cosign_key_path}")

    # 3. Sign authentic firmware
    sig_path = artifacts_dir / "firmware_v1.bin.sig"
    signature_bytes = KeyManager.sign_bytes(fw_content, private_key)
    sig_path.write_bytes(signature_bytes)
    print(f"[+] Signed firmware successfully:")
    print(f"    Signature: {sig_path} ({len(signature_bytes)} bytes)")

    # 4. Create tampered firmware artifact
    tampered_path = artifacts_dir / "firmware_v1_tampered.bin"
    # Tamper with payload: replace 'SEC_LEVEL=AUTHORISED' with 'SEC_LEVEL=OVERRIDDEN'
    tampered_bytes = bytearray(fw_content)
    # Find and alter bytes
    idx = tampered_bytes.find(b"AUTHORISED")
    if idx != -1:
        tampered_bytes[idx:idx+10] = b"OVERRIDDEN"
    else:
        tampered_bytes[100] = (tampered_bytes[100] + 1) % 256
    
    tampered_path.write_bytes(bytes(tampered_bytes))
    tampered_sha256 = hashlib.sha256(bytes(tampered_bytes)).hexdigest()
    print(f"[+] Created tampered firmware binary: {tampered_path}")
    print(f"    Tampered SHA-256: {tampered_sha256}")

    print("-" * 70)
    print("[OK] Setup completed successfully!")
    print("=" * 70)



if __name__ == "__main__":
    main()
