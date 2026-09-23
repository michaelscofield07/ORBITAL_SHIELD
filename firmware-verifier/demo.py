"""
ORBITAL SHIELD — Firmware Verification Interactive Demo (Module 3)
Demonstrates:
1. Verification of authentic signed firmware (firmware_v1.bin) -> SUCCESS (VERIFIED, INFO).
2. Verification of tampered firmware (firmware_v1_tampered.bin) -> FAILURE (FAILED, HIGH).
3. Production of structured JSON security events.
4. Optional event forwarding to ML Correlation Brain (port 8005).

Usage:
  python demo.py
  python demo.py --valid-only
  python demo.py --tampered-only
  python demo.py --forward-to-brain
"""

from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
import httpx

# Ensure local imports work cleanly
sys.path.insert(0, str(Path(__file__).parent))

from core.cosign_verifier import CosignVerifier
from core.event_generator import EventGenerator
from models.schemas import VerificationStatus

BASE_DIR = Path(__file__).parent
ARTIFACTS_DIR = BASE_DIR / "artifacts"
DEFAULT_PUBKEY = ARTIFACTS_DIR / "cosign.pub"
ML_BRAIN_URL = os.environ.get("ML_BRAIN_URL", "http://localhost:8005/events/ingest")


def print_banner(title: str):
    print("\n" + "=" * 76)
    print(f"  {title}")
    print("=" * 76)


def run_demo(forward_to_brain: bool = False, valid_only: bool = False, tampered_only: bool = False):
    verifier = CosignVerifier(default_public_key_path=DEFAULT_PUBKEY)

    print_banner("ORBITAL SHIELD -- MODULE 3: GROUND-SIDE FIRMWARE VERIFIER")
    print(f"[*] Artifacts Directory: {ARTIFACTS_DIR}")
    print(f"[*] Trusted Public Key:  {DEFAULT_PUBKEY.name}")
    print(f"[*] Cosign CLI Detected: {verifier.is_cosign_installed()} ({verifier.cosign_binary or 'Using Crypto Engine Fallback'})")
    print(f"[*] ML Brain Endpoint:   {ML_BRAIN_URL}")

    # -------------------------------------------------------------
    # DEMO 1: AUTHENTIC FIRMWARE
    # -------------------------------------------------------------
    if not tampered_only:
        print_banner("DEMO 1: Verifying Authentic Firmware Artifact (firmware_v1.bin)")
        fw_valid = ARTIFACTS_DIR / "firmware_v1.bin"
        sig_valid = ARTIFACTS_DIR / "firmware_v1.bin.sig"

        print(f"[*] Target Binary:     {fw_valid.name}")
        print(f"[*] Target Signature:  {sig_valid.name}")
        print("[*] Executing Cosign verification routine...")

        outcome_valid = verifier.verify_firmware(
            firmware_path=fw_valid,
            signature_path=sig_valid,
            public_key_path=DEFAULT_PUBKEY,
            firmware_name="firmware_v1.bin",
            firmware_version="1.0"
        )
        sec_event_valid = EventGenerator.generate_security_event(outcome_valid)

        print("\n[RESULT] Verification Output:")
        formatted_json = json.dumps(
            {
                "module": sec_event_valid.module,
                "firmware_name": sec_event_valid.firmware_name,
                "firmware_version": sec_event_valid.firmware_version,
                "verification_status": sec_event_valid.verification_status.value,
                "verification_method": sec_event_valid.verification_method,
                "severity": sec_event_valid.severity.value,
                "timestamp": sec_event_valid.timestamp,
            },
            indent=2
        )
        print(formatted_json)

        if sec_event_valid.verification_status == VerificationStatus.VERIFIED:
            print("\n[OK] SUCCESS: Firmware is authentic, signed by trusted key, and unaltered.")
        else:
            print("\n[FAIL] Unexpected verification failure for authentic firmware.")

    # -------------------------------------------------------------
    # DEMO 2: TAMPERED FIRMWARE
    # -------------------------------------------------------------
    if not valid_only:
        print_banner("DEMO 2: Verifying Tampered Firmware Artifact (firmware_v1_tampered.bin)")
        fw_tampered = ARTIFACTS_DIR / "firmware_v1_tampered.bin"
        sig_valid = ARTIFACTS_DIR / "firmware_v1.bin.sig"

        print(f"[*] Target Binary:     {fw_tampered.name} (Simulated Unauthorized Code Modification)")
        print(f"[*] Target Signature:  {sig_valid.name} (Original Signature)")
        print("[*] Executing Cosign verification routine...")

        outcome_tampered = verifier.verify_firmware(
            firmware_path=fw_tampered,
            signature_path=sig_valid,
            public_key_path=DEFAULT_PUBKEY,
            firmware_name="firmware_v1_tampered.bin",
            firmware_version="1.0"
        )
        sec_event_tampered = EventGenerator.generate_security_event(outcome_tampered)

        print("\n[RESULT] Verification Output:")
        formatted_json_tampered = json.dumps(
            {
                "module": sec_event_tampered.module,
                "firmware_name": sec_event_tampered.firmware_name,
                "firmware_version": sec_event_tampered.firmware_version,
                "verification_status": sec_event_tampered.verification_status.value,
                "verification_method": sec_event_tampered.verification_method,
                "severity": sec_event_tampered.severity.value,
                "reason": sec_event_tampered.reason,
                "timestamp": sec_event_tampered.timestamp,
            },
            indent=2
        )
        print(formatted_json_tampered)

        if sec_event_tampered.verification_status == VerificationStatus.FAILED:
            print("\n[OK] SUCCESS (TAMPER DETECTED): Ground station caught illegal modification before uplink!")
        else:
            print("\n[FAIL] Security check failed to detect tampered firmware.")

        # Optional ML Brain Forwarding
        if forward_to_brain:
            print_banner("DEMO 3: Forwarding Security Incident to ML Correlation Brain")
            ml_event = EventGenerator.generate_ml_brain_event(
                outcome=outcome_tampered,
                satellite_id="SAT-COM-01",
                subsystem="OBC",
                operator_id="OP-03",
                session_id="SESSION-GAMMA-001"
            )
            print("[*] Generated ML Brain Incident Payload:")
            print(json.dumps(ml_event.model_dump(), indent=2))

            print(f"\n[*] Attempting POST to {ML_BRAIN_URL}...")
            try:
                with httpx.Client(timeout=3.0) as client:
                    resp = client.post(ML_BRAIN_URL, json=ml_event.model_dump())
                    print(f"[+] ML Brain Response ({resp.status_code}):")
                    print(json.dumps(resp.json(), indent=2))
            except Exception as e:
                print(f"[!] Note: ML Brain service is currently offline on port 8005 ({str(e)}).")
                print("    When ml-brain (Person 5) is running, this event triggers RULE_003 (SUPPLY_CHAIN_RISK).")

    print("\n" + "=" * 76)
    print("  [OK] Demonstration Complete.")
    print("=" * 76 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ORBITAL SHIELD Module 3 Demo")
    parser.add_argument("--valid-only", action="store_true", help="Run only valid firmware verification")
    parser.add_argument("--tampered-only", action="store_true", help="Run only tampered firmware verification")
    parser.add_argument("--forward-to-brain", action="store_true", help="Forward security event to ML Brain")
    args = parser.parse_args()

    run_demo(
        forward_to_brain=args.forward_to_brain,
        valid_only=args.valid_only,
        tampered_only=args.tampered_only
    )
