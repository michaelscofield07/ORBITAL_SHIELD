# ORBITAL SHIELD — Module 3: Ground-Side Firmware Verification

> **Module 3** | Smart India Hackathon 2026  
> **Service Port:** `8003` | **ML Brain Ingest Port:** `8005`

---

## 1. What Module 3 Does

Module 3 is the **Ground-Side Firmware / Supply Chain Verification Component** for ORBITAL SHIELD. 

Before any flight software update or payload patch is uplinked to a satellite in orbit, this module verifies:
1. **Authenticity / Trusted Source**: Validates that the firmware was signed by an authorized, trusted ground authority using **Cosign (Sigstore)** cryptographic signatures.
2. **Integrity / Tamper Prevention**: Ensures that the firmware binary has not been modified, corrupted, or backdoored after signing.

### Verification Workflow
```
   Incoming Firmware Update Event
                 ↓
      Firmware Binary Received
                 ↓
    Cosign Signature Verification
                 ↓
  Check Signature & Trusted Public Key
        ↙                     ↘
 [VALID]                      [INVALID]
    ↓                             ↓
 Status: VERIFIED              Status: FAILED
 Severity: INFO                Severity: HIGH / CRITICAL
    ↓                             ↓
  Generate Structured Security Event (JSON)
                 ↓
 Forward to ML Brain (Port 8005) + Audit Log + Dashboard
```

---

## 2. Firmware Artifacts We Are Verifying

The module operates on simulated satellite flight software binaries located in `artifacts/`:

| File | Purpose |
|------|---------|
| `artifacts/firmware_v1.bin` | Authentic satellite On-Board Computer (OBC) flight software binary. |
| `artifacts/firmware_v1.bin.sig` | Cryptographic signature of `firmware_v1.bin` generated using the trusted key. |
| `artifacts/cosign.pub` | Trusted public key used to verify firmware signatures. |
| `artifacts/firmware_v1_tampered.bin` | Modified copy of the firmware binary with altered payload bytes to simulate an attacker tampering with the binary. |

---

## 3. How to Install Cosign

Cosign is the Sigstore container and blob signing/verification tool.

### On Windows
```powershell
# Option A: Via Winget
winget install Sigstore.Cosign

# Option B: Via Scoop
scoop bucket add main
scoop install cosign

# Option C: Direct Binary Download
Invoke-WebRequest -Uri "https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe" -OutFile "$HOME\bin\cosign.exe"
# Ensure $HOME\bin is added to your PATH
```

### On Linux / macOS
```bash
# Linux
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign

# macOS
brew install cosign
```

> **Note:** Module 3 features a **dual-layer verifier engine**: if the `cosign` binary is installed in your PATH, it executes native `cosign verify-blob`. If `cosign` is not in PATH, it seamlessly falls back to the embedded Cosign-compatible cryptographic engine (ECDSA P-256 / Ed25519) so the module works out-of-the-box anywhere.

---

## 4. How to Generate Signing Keys

Signing keys are generated as asymmetric ECDSA P-256 / Ed25519 keypairs.

### Via Cosign CLI
```powershell
cosign generate-key-pair
# Generates cosign.key (private key) and cosign.pub (public key)
```

### Via Module 3 Automated Setup Script
```powershell
python scripts/setup_keys_and_sign.py
```
> **Security Rule:** Private signing keys (`*.key`) are strictly ignored by Git in `.gitignore` and kept out of the repository. Only the public key (`cosign.pub`) is stored in `artifacts/`.

---

## 5. How to Sign Firmware

### Via Cosign CLI
```powershell
cosign sign-blob --key .secrets/cosign.key --tlog-upload=false --output-signature artifacts/firmware_v1.bin.sig artifacts/firmware_v1.bin
```

### Via Python Script
```powershell
python scripts/setup_keys_and_sign.py
```

---

## 6. How to Verify Firmware

### Via Cosign CLI
```powershell
cosign verify-blob --key artifacts/cosign.pub --signature artifacts/firmware_v1.bin.sig --tlog-upload=false artifacts/firmware_v1.bin
```

### Via Python Engine / API
```python
from core.cosign_verifier import CosignVerifier

verifier = CosignVerifier(default_public_key_path="artifacts/cosign.pub")
outcome = verifier.verify_firmware(
    firmware_path="artifacts/firmware_v1.bin",
    signature_path="artifacts/firmware_v1.bin.sig"
)
print(outcome.status)  # VerificationStatus.VERIFIED
```

---

## 7. How to Create a Tampered Firmware File

To simulate an attacker modifying the firmware payload:

```powershell
python scripts/create_tampered.py
```
This reads `firmware_v1.bin`, flips authorization flags in the executable header, and saves `artifacts/firmware_v1_tampered.bin`.

---

## 8. How to Run the Module

### 1. Install Dependencies
```powershell
cd firmware-verifier
pip install -r requirements.txt
```

### 2. Start the API Server (FastAPI)
```powershell
python main.py
# Server starts on http://localhost:8003
# Interactive Swagger Documentation: http://localhost:8003/docs
```

### 3. Run the Interactive CLI Demo
```powershell
python demo.py
```

---

## 9. How to Test Valid Firmware

### Via CLI Demo:
```powershell
python demo.py --valid-only
```

### Via HTTP API:
```powershell
curl -X POST http://localhost:8003/verify/sample/valid
```
Or with custom payload:
```powershell
curl -X POST http://localhost:8003/verify \
  -H "Content-Type: application/json" \
  -d '{
    "firmware_path": "artifacts/firmware_v1.bin",
    "signature_path": "artifacts/firmware_v1.bin.sig",
    "firmware_name": "firmware_v1.bin",
    "firmware_version": "1.0"
  }'
```

---

## 10. How to Test Tampered Firmware

### Via CLI Demo:
```powershell
python demo.py --tampered-only
```

### Via HTTP API:
```powershell
curl -X POST http://localhost:8003/verify/sample/tampered
```

### Via Forwarding to ML Correlation Brain (Port 8005):
```powershell
python demo.py --forward-to-brain
```

---

## 11. Expected Output

### Success Output (Valid Firmware)
```json
{
  "module": "firmware_verification",
  "firmware_name": "firmware_v1.bin",
  "firmware_version": "1.0",
  "verification_status": "VERIFIED",
  "verification_method": "cosign",
  "severity": "INFO",
  "timestamp": "2026-08-24T12:00:00.000000+00:00"
}
```

### Failure Output (Tampered Firmware)
```json
{
  "module": "firmware_verification",
  "firmware_name": "firmware_v1_tampered.bin",
  "firmware_version": "1.0",
  "verification_status": "FAILED",
  "verification_method": "cosign",
  "severity": "HIGH",
  "reason": "Invalid or mismatched signature",
  "timestamp": "2026-08-24T12:00:00.000000+00:00"
}
```

### ML Correlation Brain Integration Event (`POST http://localhost:8005/events/ingest`)
```json
{
  "event_id": "EVT-FW-A1B2C3D4",
  "timestamp": "2026-08-24T12:00:00.000000+00:00",
  "source": "FIRMWARE",
  "satellite_id": "SAT-COM-01",
  "event_type": "FIRMWARE_TAMPERING",
  "severity": "CRITICAL",
  "confidence": 0.99,
  "description": "Firmware signature verification FAILED for 'firmware_v1_tampered.bin' on SAT-COM-01 (OBC). Reason: Invalid or mismatched signature.",
  "action": "REVIEW",
  "evidence": {
    "firmware_name": "firmware_v1_tampered.bin",
    "firmware_version": "1.0",
    "subsystem": "OBC",
    "verification_method": "cosign",
    "verification_status": "FAILED",
    "sha256": "dccc3a8d787fa9d71d0be58a1500f842009b12f38fc89bb830a059005207e227",
    "reason": "Invalid or mismatched signature"
  },
  "related_events": [],
  "operator_id": "OP-03",
  "session_id": "SESSION-GAMMA-001"
}
```

---

## Error Handling Matrix

| Error Scenario | Verification Status | Severity | Reason / Description |
|----------------|---------------------|----------|----------------------|
| **Firmware file missing** | `FAILED` | `HIGH` | `Firmware file not found at path: ...` |
| **Signature file missing** | `FAILED` | `HIGH` | `Signature file not found: ...` |
| **Public key missing** | `FAILED` | `HIGH` | `Trusted signing key / public key not found: ...` |
| **Tampered / Corrupted signature** | `FAILED` | `HIGH` | `Invalid or mismatched signature` |
| **Cosign execution error** | `FAILED` | `HIGH` | `Verification command failure: ...` |

---

## Running Automated Tests

```powershell
pytest tests/test_verifier.py -v
```
All 11 unit tests test edge cases, error conditions, API routes, and schema conformity.
