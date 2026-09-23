"""
ORBITAL SHIELD — Firmware Verification Test Suite (Module 3)
Tests all verification logic, error cases, security events, and FastAPI endpoints.
"""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from core.cosign_verifier import CosignVerifier, VerificationOutcome
from core.event_generator import EventGenerator
from core.key_manager import KeyManager
from models.schemas import VerificationStatus, SeverityLevel, FirmwareSecurityEvent
from main import app

BASE_DIR = Path(__file__).parent.parent
ARTIFACTS_DIR = BASE_DIR / "artifacts"
VALID_FW = ARTIFACTS_DIR / "firmware_v1.bin"
VALID_SIG = ARTIFACTS_DIR / "firmware_v1.bin.sig"
TAMPERED_FW = ARTIFACTS_DIR / "firmware_v1_tampered.bin"
PUBLIC_KEY = ARTIFACTS_DIR / "cosign.pub"

client = TestClient(app)
verifier = CosignVerifier(default_public_key_path=PUBLIC_KEY)


def test_valid_firmware_verification_success():
    """Verify that authentic firmware with valid signature passes verification."""
    assert VALID_FW.exists(), "firmware_v1.bin must exist"
    assert VALID_SIG.exists(), "firmware_v1.bin.sig must exist"
    assert PUBLIC_KEY.exists(), "cosign.pub must exist"

    outcome = verifier.verify_firmware(
        firmware_path=VALID_FW,
        signature_path=VALID_SIG,
        public_key_path=PUBLIC_KEY,
        firmware_name="firmware_v1.bin",
        firmware_version="1.0"
    )

    assert outcome.status == VerificationStatus.VERIFIED
    assert outcome.severity == SeverityLevel.INFO
    assert outcome.reason is None
    assert outcome.sha256_hash is not None

    sec_event = EventGenerator.generate_security_event(outcome)
    assert sec_event.module == "firmware_verification"
    assert sec_event.firmware_name == "firmware_v1.bin"
    assert sec_event.verification_status == VerificationStatus.VERIFIED
    assert sec_event.verification_method == "cosign"
    assert sec_event.severity == SeverityLevel.INFO


def test_tampered_firmware_verification_failure():
    """Verify that tampered firmware with valid signature FAILS verification."""
    assert TAMPERED_FW.exists(), "firmware_v1_tampered.bin must exist"

    outcome = verifier.verify_firmware(
        firmware_path=TAMPERED_FW,
        signature_path=VALID_SIG,
        public_key_path=PUBLIC_KEY,
        firmware_name="firmware_v1_tampered.bin",
        firmware_version="1.0"
    )

    assert outcome.status == VerificationStatus.FAILED
    assert outcome.severity == SeverityLevel.HIGH
    assert outcome.reason == "Invalid or mismatched signature"

    sec_event = EventGenerator.generate_security_event(outcome)
    assert sec_event.module == "firmware_verification"
    assert sec_event.firmware_name == "firmware_v1_tampered.bin"
    assert sec_event.verification_status == VerificationStatus.FAILED
    assert sec_event.verification_method == "cosign"
    assert sec_event.severity == SeverityLevel.HIGH
    assert sec_event.reason == "Invalid or mismatched signature"


def test_firmware_file_missing_error():
    """Verify that missing firmware file returns clean FAILED result."""
    missing_fw = ARTIFACTS_DIR / "non_existent_firmware.bin"

    outcome = verifier.verify_firmware(
        firmware_path=missing_fw,
        signature_path=VALID_SIG,
        public_key_path=PUBLIC_KEY,
        firmware_name="non_existent_firmware.bin"
    )

    assert outcome.status == VerificationStatus.FAILED
    assert outcome.severity == SeverityLevel.HIGH
    assert "Firmware file not found" in (outcome.reason or "")


def test_signature_file_missing_error():
    """Verify that missing signature file returns clean FAILED result."""
    missing_sig = ARTIFACTS_DIR / "non_existent.sig"

    outcome = verifier.verify_firmware(
        firmware_path=VALID_FW,
        signature_path=missing_sig,
        public_key_path=PUBLIC_KEY,
        firmware_name="firmware_v1.bin"
    )

    assert outcome.status == VerificationStatus.FAILED
    assert outcome.severity == SeverityLevel.HIGH
    assert "Signature file not found" in (outcome.reason or "")


def test_public_key_missing_error():
    """Verify that missing public key returns clean FAILED result."""
    missing_key = ARTIFACTS_DIR / "non_existent.pub"

    outcome = verifier.verify_firmware(
        firmware_path=VALID_FW,
        signature_path=VALID_SIG,
        public_key_path=missing_key,
        firmware_name="firmware_v1.bin"
    )

    assert outcome.status == VerificationStatus.FAILED
    assert outcome.severity == SeverityLevel.HIGH
    assert "public key not found" in (outcome.reason or "").lower()


def test_corrupted_signature_error(tmp_path):
    """Verify that corrupted signature bytes return FAILED result."""
    bad_sig_file = tmp_path / "corrupted.sig"
    bad_sig_file.write_bytes(b"INVALID_SIGNATURE_BYTES_1234567890")

    outcome = verifier.verify_firmware(
        firmware_path=VALID_FW,
        signature_path=bad_sig_file,
        public_key_path=PUBLIC_KEY,
        firmware_name="firmware_v1.bin"
    )

    assert outcome.status == VerificationStatus.FAILED
    assert outcome.severity == SeverityLevel.HIGH


def test_ml_brain_event_structure():
    """Verify that ML Brain event strictly matches ML-Brain schema expectations."""
    outcome_tampered = verifier.verify_firmware(
        firmware_path=TAMPERED_FW,
        signature_path=VALID_SIG,
        public_key_path=PUBLIC_KEY,
        firmware_name="firmware_v1_tampered.bin"
    )

    ml_event = EventGenerator.generate_ml_brain_event(
        outcome=outcome_tampered,
        satellite_id="SAT-COM-01",
        subsystem="OBC",
        operator_id="OP-03",
        session_id="SESSION-GAMMA-001"
    )

    assert ml_event.source == "FIRMWARE"
    assert ml_event.event_type == "FIRMWARE_TAMPERING"
    assert ml_event.severity == "CRITICAL"
    assert ml_event.confidence >= 0.95
    assert ml_event.satellite_id == "SAT-COM-01"
    assert ml_event.operator_id == "OP-03"
    assert ml_event.session_id == "SESSION-GAMMA-001"
    assert "firmware_name" in ml_event.evidence


# -------------------------------------------------------------
# FASTAPI ENDPOINT TESTS
# -------------------------------------------------------------

def test_api_health_endpoint():
    """Test GET /health returns module information."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["module"] == "firmware_verification"
    assert data["status"] == "HEALTHY"
    assert data["port"] == 8003


def test_api_verify_valid_sample():
    """Test POST /verify/sample/valid returns VERIFIED."""
    response = client.post("/verify/sample/valid")
    assert response.status_code == 200
    data = response.json()
    assert data["verification_status"] == "VERIFIED"
    assert data["severity"] == "INFO"
    assert data["firmware_name"] == "firmware_v1.bin"


def test_api_verify_tampered_sample():
    """Test POST /verify/sample/tampered returns FAILED."""
    response = client.post("/verify/sample/tampered")
    assert response.status_code == 200
    data = response.json()
    assert data["verification_status"] == "FAILED"
    assert data["severity"] == "HIGH"
    assert data["reason"] == "Invalid or mismatched signature"


def test_api_custom_verify_request():
    """Test POST /verify with custom JSON body."""
    payload = {
        "firmware_path": str(VALID_FW.resolve()),
        "signature_path": str(VALID_SIG.resolve()),
        "public_key_path": str(PUBLIC_KEY.resolve()),
        "firmware_name": "firmware_v1.bin",
        "firmware_version": "1.0"
    }
    response = client.post("/verify", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verification_status"] == "VERIFIED"
