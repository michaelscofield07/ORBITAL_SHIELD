"""
ORBITAL SHIELD — Firmware Verification Service (Module 3)
FastAPI service exposing ground-side firmware verification API endpoints.

Default Port: 8003
Swagger UI: http://localhost:8003/docs
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict, Optional
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.cosign_verifier import CosignVerifier
from core.event_generator import EventGenerator
from models.schemas import (
    FirmwareVerificationRequest,
    FirmwareSecurityEvent,
    MLBrainIncomingEvent,
    VerificationSummary,
    VerificationStatus,
)

BASE_DIR = Path(__file__).parent
ARTIFACTS_DIR = BASE_DIR / "artifacts"
DEFAULT_PUBKEY = ARTIFACTS_DIR / "cosign.pub"

# Load shared .env from repo root
from dotenv import load_dotenv
_REPO_ENV = Path(__file__).resolve().parent.parent / ".env"
if _REPO_ENV.exists():
    load_dotenv(dotenv_path=_REPO_ENV, override=False)
else:
    load_dotenv()

ML_BRAIN_URL = os.environ.get("MLBRAIN_URL", os.environ.get("ML_BRAIN_URL", "http://localhost:8005/events/ingest"))
AUDIT_URL = os.environ.get("AUDIT_URL", "http://localhost:8006/audit/events")
_FIRMWARE_PORT = int(os.environ.get("FIRMWARE_PORT", "8003"))

app = FastAPI(
    title="ORBITAL SHIELD — Firmware Verification (Module 3)",
    version="1.0.0",
    description="Ground-side firmware integrity & supply chain verification using Cosign / Sigstore standards."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global verifier instance
verifier = CosignVerifier(default_public_key_path=DEFAULT_PUBKEY)


@app.get("/health", summary="Health and Verifier Status")
def get_health() -> Dict[str, Any]:
    """
    Returns module status, Cosign CLI detection, and key paths.
    """
    cosign_installed = verifier.is_cosign_installed()
    return {
        "module": "firmware_verification",
        "status": "HEALTHY",
        "port": _FIRMWARE_PORT,
        "cosign_installed": cosign_installed,
        "cosign_binary": verifier.cosign_binary or "NOT_FOUND",
        "default_public_key": str(DEFAULT_PUBKEY.resolve()) if DEFAULT_PUBKEY.exists() else "MISSING",
        "ml_brain_endpoint": ML_BRAIN_URL,
        "audit_endpoint": AUDIT_URL
    }


@app.post("/verify", response_model=FirmwareSecurityEvent, summary="Verify Firmware Artifact")
def verify_firmware_endpoint(request: FirmwareVerificationRequest) -> FirmwareSecurityEvent:
    """
    Verifies a firmware binary artifact against its Cosign signature and trusted public key.
    Returns standard structured security event (SUCCESS / FAILURE).
    """
    outcome = verifier.verify_firmware(
        firmware_path=request.firmware_path,
        signature_path=request.signature_path,
        public_key_path=request.public_key_path,
        firmware_name=request.firmware_name,
        firmware_version=request.firmware_version or "1.0"
    )
    event = EventGenerator.generate_security_event(outcome)
    return event


@app.post("/verify-and-forward", response_model=VerificationSummary, summary="Verify & Forward to ML Brain")
async def verify_and_forward_endpoint(request: FirmwareVerificationRequest) -> VerificationSummary:
    """
    Verifies a firmware binary artifact and forwards the resulting security event
    to the ML Correlation Brain (Person 5 / port 8005).
    """
    outcome = verifier.verify_firmware(
        firmware_path=request.firmware_path,
        signature_path=request.signature_path,
        public_key_path=request.public_key_path,
        firmware_name=request.firmware_name,
        firmware_version=request.firmware_version or "1.0"
    )
    security_event = EventGenerator.generate_security_event(outcome)
    ml_brain_event = EventGenerator.generate_ml_brain_event(
        outcome=outcome,
        satellite_id=request.satellite_id or "SAT-COM-01",
        subsystem=request.subsystem or "OBC",
        operator_id=request.operator_id,
        session_id=request.session_id
    )

    forwarded = False
    brain_resp_data = None

    # Forward to ML Brain via async HTTP POST
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                ML_BRAIN_URL,
                json=ml_brain_event.model_dump()
            )
            if resp.status_code in (200, 201, 202):
                forwarded = True
                brain_resp_data = resp.json()
            else:
                brain_resp_data = {"http_status": resp.status_code, "body": resp.text}
    except Exception as e:
        brain_resp_data = {"error": f"Could not reach ML Brain: {str(e)}"}

    # B11 fix: also forward to audit service (fire-and-forget, non-blocking)
    import asyncio
    asyncio.ensure_future(_forward_fw_to_audit(ml_brain_event))

    return VerificationSummary(
        security_event=security_event,
        ml_brain_event=ml_brain_event,
        ml_brain_forwarded=forwarded,
        ml_brain_response=brain_resp_data
    )


async def _forward_fw_to_audit(event) -> None:
    """Fire-and-forget audit forwarding for firmware events."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(AUDIT_URL, json=event.model_dump())
    except Exception as exc:
        import logging as _log
        _log.getLogger("FirmwareVerifier").warning(f"Audit forward failed: {exc}")


@app.post("/verify/sample/valid", response_model=FirmwareSecurityEvent, summary="Test Sample Valid Firmware")
def verify_sample_valid() -> FirmwareSecurityEvent:
    """
    Quick test endpoint: verifies the built-in authentic firmware (firmware_v1.bin).
    """
    sample_path = ARTIFACTS_DIR / "firmware_v1.bin"
    outcome = verifier.verify_firmware(
        firmware_path=sample_path,
        firmware_name="firmware_v1.bin",
        firmware_version="1.0"
    )
    return EventGenerator.generate_security_event(outcome)


@app.post("/verify/sample/tampered", response_model=FirmwareSecurityEvent, summary="Test Sample Tampered Firmware")
def verify_sample_tampered() -> FirmwareSecurityEvent:
    """
    Quick test endpoint: verifies the built-in tampered firmware (firmware_v1_tampered.bin).
    Should fail verification and return HIGH severity security event.
    """
    sample_path = ARTIFACTS_DIR / "firmware_v1_tampered.bin"
    sig_path = ARTIFACTS_DIR / "firmware_v1.bin.sig"  # using valid signature against altered binary
    outcome = verifier.verify_firmware(
        firmware_path=sample_path,
        signature_path=sig_path,
        firmware_name="firmware_v1_tampered.bin",
        firmware_version="1.0"
    )
    return EventGenerator.generate_security_event(outcome)


def run():
    """Start uvicorn server on port 8003."""
    uvicorn.run("main:app", host="0.0.0.0", port=8003, reload=True)


if __name__ == "__main__":
    run()
