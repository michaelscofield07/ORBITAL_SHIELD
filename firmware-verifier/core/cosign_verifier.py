"""
ORBITAL SHIELD — Cosign Firmware Verifier
Core engine for validating firmware artifacts against cryptographic signatures using Cosign / Sigstore standards.
"""

from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass, field

from .key_manager import KeyManager
try:
    from models.schemas import VerificationStatus, SeverityLevel
except ImportError:
    from ..models.schemas import VerificationStatus, SeverityLevel



@dataclass
class VerificationOutcome:
    """Internal outcome model for verification results."""
    status: VerificationStatus
    firmware_path: str
    firmware_name: str
    firmware_version: str
    severity: SeverityLevel
    verification_method: str = "cosign"
    reason: Optional[str] = None
    sha256_hash: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    is_cosign_cli: bool = False


class CosignVerifier:
    """
    Ground-side firmware verification engine.
    Verifies firmware binary authenticity and integrity using Cosign.
    """

    def __init__(
        self,
        default_public_key_path: Optional[str | Path] = None,
        cosign_binary_path: Optional[str] = None,
        prefer_cli: bool = True
    ):
        self.default_public_key_path = (
            Path(default_public_key_path)
            if default_public_key_path
            else Path(__file__).parent.parent / "artifacts" / "cosign.pub"
        )
        self.cosign_binary = (
            cosign_binary_path
            or os.environ.get("COSIGN_PATH")
            or shutil.which("cosign")
            or shutil.which("cosign.exe")
            or shutil.which("cosign-windows-amd64.exe")
        )
        self.prefer_cli = prefer_cli

    @staticmethod
    def calculate_sha256(file_path: Path) -> str:
        """Calculate SHA-256 hex digest of a file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def is_cosign_installed(self) -> bool:
        """Check if Cosign executable is available in PATH or configured path."""
        if not self.cosign_binary:
            return False
        try:
            res = subprocess.run(
                [self.cosign_binary, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return res.returncode == 0
        except Exception:
            return False

    def verify_firmware(
        self,
        firmware_path: str | Path,
        signature_path: Optional[str | Path] = None,
        public_key_path: Optional[str | Path] = None,
        firmware_name: Optional[str] = None,
        firmware_version: str = "1.0",
        force_cli: bool = False
    ) -> VerificationOutcome:
        """
        Main verification entry point.
        Checks artifact existence, cryptographic signature, and returns a structured VerificationOutcome.
        """
        fw_path = Path(firmware_path)
        display_name = firmware_name or fw_path.name

        # 1. Error Check: Firmware file missing
        if not fw_path.exists() or not fw_path.is_file():
            return VerificationOutcome(
                status=VerificationStatus.FAILED,
                firmware_path=str(fw_path),
                firmware_name=display_name,
                firmware_version=firmware_version,
                severity=SeverityLevel.HIGH,
                verification_method="cosign",
                reason=f"Firmware file not found at path: '{fw_path}'",
                details={"error_code": "FIRMWARE_FILE_MISSING", "path": str(fw_path)}
            )

        # Calculate firmware SHA256
        fw_sha256 = self.calculate_sha256(fw_path)

        # 2. Resolve signature path
        sig_path = (
            Path(signature_path)
            if signature_path
            else fw_path.with_name(f"{fw_path.name}.sig")
        )

        # Error Check: Signature file missing
        if not sig_path.exists() or not sig_path.is_file():
            return VerificationOutcome(
                status=VerificationStatus.FAILED,
                firmware_path=str(fw_path),
                firmware_name=display_name,
                firmware_version=firmware_version,
                severity=SeverityLevel.HIGH,
                verification_method="cosign",
                reason=f"Signature file not found: '{sig_path}'",
                sha256_hash=fw_sha256,
                details={"error_code": "SIGNATURE_FILE_MISSING", "sig_path": str(sig_path)}
            )

        # 3. Resolve public key path
        pub_path = (
            Path(public_key_path)
            if public_key_path
            else self.default_public_key_path
        )

        # Error Check: Public key missing
        if not pub_path.exists() or not pub_path.is_file():
            return VerificationOutcome(
                status=VerificationStatus.FAILED,
                firmware_path=str(fw_path),
                firmware_name=display_name,
                firmware_version=firmware_version,
                severity=SeverityLevel.HIGH,
                verification_method="cosign",
                reason=f"Trusted signing key / public key not found: '{pub_path}'",
                sha256_hash=fw_sha256,
                details={"error_code": "PUBLIC_KEY_MISSING", "key_path": str(pub_path)}
            )

        # 4. Perform Verification
        # If Cosign CLI is installed and preferred, execute cosign verify-blob
        cli_available = self.is_cosign_installed()

        if force_cli and not cli_available:
            return VerificationOutcome(
                status=VerificationStatus.FAILED,
                firmware_path=str(fw_path),
                firmware_name=display_name,
                firmware_version=firmware_version,
                severity=SeverityLevel.HIGH,
                verification_method="cosign",
                reason="Cosign executable not installed or not found in system PATH",
                sha256_hash=fw_sha256,
                details={"error_code": "COSIGN_NOT_INSTALLED"}
            )

        if cli_available and self.prefer_cli:
            return self._verify_via_cosign_cli(
                fw_path=fw_path,
                sig_path=sig_path,
                pub_path=pub_path,
                display_name=display_name,
                firmware_version=firmware_version,
                fw_sha256=fw_sha256
            )
        else:
            # Dual-layer verification via Cosign-compatible cryptography engine
            return self._verify_via_crypto_engine(
                fw_path=fw_path,
                sig_path=sig_path,
                pub_path=pub_path,
                display_name=display_name,
                firmware_version=firmware_version,
                fw_sha256=fw_sha256
            )

    def _verify_via_cosign_cli(
        self,
        fw_path: Path,
        sig_path: Path,
        pub_path: Path,
        display_name: str,
        firmware_version: str,
        fw_sha256: str
    ) -> VerificationOutcome:
        """
        Verify blob using official Cosign CLI subprocess:
        `cosign verify-blob --key <pub> --signature <sig> --tlog-upload=false <fw>`
        """
        cmd = [
            self.cosign_binary,
            "verify-blob",
            "--key", str(pub_path.resolve()),
            "--signature", str(sig_path.resolve()),
            "--insecure-ignore-tlog",
            str(fw_path.resolve())
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return VerificationOutcome(
                    status=VerificationStatus.VERIFIED,
                    firmware_path=str(fw_path),
                    firmware_name=display_name,
                    firmware_version=firmware_version,
                    severity=SeverityLevel.INFO,
                    verification_method="cosign",
                    sha256_hash=fw_sha256,
                    is_cosign_cli=True,
                    details={
                        "engine": "cosign-cli",
                        "public_key": str(pub_path),
                        "stdout": result.stdout.strip(),
                        "stderr": result.stderr.strip()
                    }
                )
            else:
                stderr_clean = result.stderr.strip() or result.stdout.strip() or "Verification failed"
                return VerificationOutcome(
                    status=VerificationStatus.FAILED,
                    firmware_path=str(fw_path),
                    firmware_name=display_name,
                    firmware_version=firmware_version,
                    severity=SeverityLevel.HIGH,
                    verification_method="cosign",
                    reason="Invalid or mismatched signature",
                    sha256_hash=fw_sha256,
                    is_cosign_cli=True,
                    details={
                        "engine": "cosign-cli",
                        "exit_code": result.returncode,
                        "error_output": stderr_clean
                    }
                )
        except subprocess.TimeoutExpired:
            return VerificationOutcome(
                status=VerificationStatus.FAILED,
                firmware_path=str(fw_path),
                firmware_name=display_name,
                firmware_version=firmware_version,
                severity=SeverityLevel.HIGH,
                verification_method="cosign",
                reason="Verification command timed out",
                sha256_hash=fw_sha256,
                details={"error_code": "TIMEOUT"}
            )
        except Exception as e:
            return VerificationOutcome(
                status=VerificationStatus.FAILED,
                firmware_path=str(fw_path),
                firmware_name=display_name,
                firmware_version=firmware_version,
                severity=SeverityLevel.HIGH,
                verification_method="cosign",
                reason=f"Verification command failure: {str(e)}",
                sha256_hash=fw_sha256,
                details={"error_code": "COMMAND_FAILURE", "exception": str(e)}
            )

    def _verify_via_crypto_engine(
        self,
        fw_path: Path,
        sig_path: Path,
        pub_path: Path,
        display_name: str,
        firmware_version: str,
        fw_sha256: str
    ) -> VerificationOutcome:
        """
        Verify blob using Cosign-compatible cryptography engine (ECDSA P-256 / Ed25519).
        """
        try:
            pub_key = KeyManager.load_public_key_from_pem(pub_path)
            data = fw_path.read_bytes()
            sig_bytes = sig_path.read_bytes()

            is_valid = KeyManager.verify_bytes(data, sig_bytes, pub_key)

            if is_valid:
                return VerificationOutcome(
                    status=VerificationStatus.VERIFIED,
                    firmware_path=str(fw_path),
                    firmware_name=display_name,
                    firmware_version=firmware_version,
                    severity=SeverityLevel.INFO,
                    verification_method="cosign",
                    sha256_hash=fw_sha256,
                    is_cosign_cli=False,
                    details={
                        "engine": "cosign-crypto-engine",
                        "public_key": str(pub_path),
                        "verified_ok": True
                    }
                )
            else:
                return VerificationOutcome(
                    status=VerificationStatus.FAILED,
                    firmware_path=str(fw_path),
                    firmware_name=display_name,
                    firmware_version=firmware_version,
                    severity=SeverityLevel.HIGH,
                    verification_method="cosign",
                    reason="Invalid or mismatched signature",
                    sha256_hash=fw_sha256,
                    is_cosign_cli=False,
                    details={
                        "engine": "cosign-crypto-engine",
                        "verified_ok": False
                    }
                )
        except Exception as e:
            return VerificationOutcome(
                status=VerificationStatus.FAILED,
                firmware_path=str(fw_path),
                firmware_name=display_name,
                firmware_version=firmware_version,
                severity=SeverityLevel.HIGH,
                verification_method="cosign",
                reason=f"Verification failure: {str(e)}",
                sha256_hash=fw_sha256,
                details={"error_code": "CRYPTO_ERROR", "exception": str(e)}
            )
