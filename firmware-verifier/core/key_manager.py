"""
ORBITAL SHIELD — Key Manager
Handles Cosign-compatible cryptographic keys (ECDSA P-256 / Ed25519).
Supports key generation, public key export, signing, and verification.
"""

from __future__ import annotations
import base64
import os
from pathlib import Path
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature


class KeyManager:
    """
    Manages Cosign-compatible asymmetric signing keys (ECDSA SECP256R1).
    Ensures private keys are protected and never hardcoded in source code.
    """

    @staticmethod
    def generate_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate a new ECDSA SECP256R1 (P-256) key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def save_public_key(public_key: ec.EllipticCurvePublicKey, output_path: str | Path) -> str:
        """
        Save public key in PEM format (Cosign cosign.pub format).
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pem)
        return str(path.resolve())

    @staticmethod
    def save_private_key(
        private_key: ec.EllipticCurvePrivateKey,
        output_path: str | Path,
        password: Optional[str] = None
    ) -> str:
        """
        Save private key in PEM format. If password provided, encrypts with BestAvailableEncryption.
        """
        encryption = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pem)
        return str(path.resolve())

    @staticmethod
    def load_public_key_from_pem(pem_path_or_bytes: str | bytes | Path) -> ec.EllipticCurvePublicKey:
        """
        Load an ECDSA public key from a PEM file path or raw bytes.
        """
        if isinstance(pem_path_or_bytes, (str, Path)):
            p = Path(pem_path_or_bytes)
            if not p.exists():
                raise FileNotFoundError(f"Public key file not found: {p}")
            data = p.read_bytes()
        else:
            data = pem_path_or_bytes

        public_key = serialization.load_pem_public_key(data)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Key is not a valid Elliptic Curve public key")
        return public_key

    @staticmethod
    def load_private_key_from_pem(
        pem_path_or_bytes: str | bytes | Path,
        password: Optional[str] = None
    ) -> ec.EllipticCurvePrivateKey:
        """
        Load an ECDSA private key from a PEM file path or raw bytes.
        """
        if isinstance(pem_path_or_bytes, (str, Path)):
            p = Path(pem_path_or_bytes)
            if not p.exists():
                raise FileNotFoundError(f"Private key file not found: {p}")
            data = p.read_bytes()
        else:
            data = pem_path_or_bytes

        pwd = password.encode("utf-8") if password else None
        private_key = serialization.load_pem_private_key(data, password=pwd)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Key is not a valid Elliptic Curve private key")
        return private_key

    @classmethod
    def sign_bytes(cls, data: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """
        Sign binary payload using ECDSA SHA-256 (standard Cosign blob signature format).
        Returns raw DER signature bytes.
        """
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    @classmethod
    def verify_bytes(
        cls,
        data: bytes,
        signature: bytes,
        public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        """
        Verify raw or base64 DER signature against payload using public key.
        """
        # Handle potential base64 encoding
        sig_to_verify = signature
        try:
            # If it decodes cleanly to base64 and looks like DER, use it
            decoded = base64.b64decode(signature)
            if len(decoded) > 10 and decoded[0] == 0x30:
                sig_to_verify = decoded
        except Exception:
            sig_to_verify = signature

        try:
            public_key.verify(
                sig_to_verify,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            # Try raw signature if DER decoding failed
            return False
