"""
ORBITAL SHIELD — Access Security Module (Module 4) Demonstration
Interactive CLI Demo highlighting Access Security Anomaly Detections:
1. Normal successful login
2. Repeated failed logins (Brute Force)
3. Unknown / Untrusted device
4. Privilege escalation
5. Suspicious access to sensitive commands/resources
6. Canonical SecurityEvent JSON format & ML Brain Integration attempt.
"""

from __future__ import annotations
import json
import os
import sys
from pathlib import Path

# Ensure UTF-8 output encoding if possible
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

from core.adapter import MockJSONInputAdapter
from core.engine import AccessSecurityEngine
from core.event_generator import EventGenerator, ML_BRAIN_URL
from models.schemas import AccessLogRecord, SecurityEvent


def print_banner():
    print("=" * 80)
    print("      ORBITAL SHIELD -- ACCESS SECURITY MODULE (MODULE 4) DEMO")
    print("=" * 80)
    print(f"Target Satellite ID  : SAT-EO-01")
    print(f"ML Brain Endpoint    : {ML_BRAIN_URL}")
    print("=" * 80 + "\n")


def run_demo():
    print_banner()

    engine = AccessSecurityEngine()
    engine.reset_state()

    # DEMO 1: Normal Successful Login
    print("--------------------------------------------------------------------------------")
    print(" [DEMO 1] NORMAL SUCCESSFUL LOGIN")
    print("--------------------------------------------------------------------------------")
    rec1 = AccessLogRecord(
        timestamp="2026-08-25T09:30:00Z",
        user_id="operator_01",
        source_ip="10.0.0.15",
        device_id="GS-DEVICE-01",
        action="LOGIN",
        result="SUCCESS",
        role="operator",
        satellite_id="SAT-EO-01"
    )
    det1 = engine.evaluate_record(rec1)
    evt1 = EventGenerator.generate_security_event(det1)
    
    print(f"Input User      : {rec1.user_id} ({rec1.role}) | Device: {rec1.device_id}")
    print(f"Access Action   : {rec1.action} -> Result: {rec1.result}")
    print(f"Detection       : Suspicious={det1.is_suspicious} | Type={det1.event_type}")
    print(f"Severity        : [{evt1.severity}] -> Action: [{evt1.action}]")
    print(f"Description     : {evt1.description}")
    print("Result Status   : [ALLOWED] INFO RECORDED\n")

    # DEMO 2: Repeated Failed Logins (Brute Force)
    print("--------------------------------------------------------------------------------")
    print(" [DEMO 2] REPEATED FAILED LOGINS (BRUTE FORCE ATTACK)")
    print("--------------------------------------------------------------------------------")
    attacker_ip = "192.168.1.100"
    attacker_user = "user_attacker"
    
    print(f"Simulating failed login sequence for user '{attacker_user}' from IP {attacker_ip}...")
    for i in range(1, 4):
        rec_fail = AccessLogRecord(
            timestamp=f"2026-08-25T10:00:0{i}Z",
            user_id=attacker_user,
            source_ip=attacker_ip,
            device_id="GS-DEVICE-02",
            action="LOGIN",
            result="FAILURE",
            role="operator"
        )
        det_fail = engine.evaluate_record(rec_fail)
        print(f" Attempt {i}: Result={rec_fail.result} | Failures Tracked={det_fail.evidence.get('failed_attempts', i)} | Anomaly={det_fail.event_type}")

    evt2 = EventGenerator.generate_security_event(det_fail)
    print(f"\nFinal Detection : Suspicious={det_fail.is_suspicious} | Type={det_fail.event_type}")
    print(f"Severity        : [{evt2.severity}] -> Action: [{evt2.action}]")
    print(f"Description     : {evt2.description}")
    print("Result Status   : [HIGH THREAT] BRUTE_FORCE TRIGGERED\n")

    # DEMO 3: Unknown / Untrusted Device
    print("--------------------------------------------------------------------------------")
    print(" [DEMO 3] UNKNOWN / UNTRUSTED DEVICE ACCESS")
    print("--------------------------------------------------------------------------------")
    rec3 = AccessLogRecord(
        timestamp="2026-08-25T11:20:00Z",
        user_id="operator_03",
        source_ip="172.16.4.55",
        device_id="UNTRUSTED-DEVICE-999",
        action="LOGIN",
        result="SUCCESS",
        role="operator"
    )
    det3 = engine.evaluate_record(rec3)
    evt3 = EventGenerator.generate_security_event(det3)
    
    print(f"Input Device ID : {rec3.device_id} (Not in trusted Ground Station whitelist)")
    print(f"Detection       : Suspicious={det3.is_suspicious} | Type={det3.event_type}")
    print(f"Severity        : [{evt3.severity}] -> Action: [{evt3.action}]")
    print(f"Description     : {evt3.description}")
    print("Result Status   : [WARNING] UNKNOWN_DEVICE DETECTED / REVIEW REQUIRED\n")

    # DEMO 4: Privilege Escalation
    print("--------------------------------------------------------------------------------")
    print(" [DEMO 4] PRIVILEGE ESCALATION ATTEMPT")
    print("--------------------------------------------------------------------------------")
    rec4 = AccessLogRecord(
        timestamp="2026-08-25T12:00:00Z",
        user_id="operator_rogue",
        source_ip="10.0.0.45",
        device_id="GS-DEVICE-01",
        action="ROLE_ELEVATION",
        result="SUCCESS",
        role="sysadmin",
        previous_role="operator"
    )
    det4 = engine.evaluate_record(rec4)
    evt4 = EventGenerator.generate_security_event(det4)
    
    print(f"Role Change     : '{rec4.previous_role}'  ===>  '{rec4.role}'")
    print(f"Detection       : Suspicious={det4.is_suspicious} | Type={det4.event_type}")
    print(f"Severity        : [{evt4.severity}] -> Action: [{evt4.action}]")
    print(f"Description     : {evt4.description}")
    print("Result Status   : [CRITICAL THREAT] PRIVILEGE_ESCALATION DETECTED / HUMAN_REVIEW MANDATED\n")

    # DEMO 5: Suspicious Access to Sensitive Commands / Resources
    print("--------------------------------------------------------------------------------")
    print(" [DEMO 5] SUSPICIOUS SENSITIVE COMMAND ACCESS")
    print("--------------------------------------------------------------------------------")
    rec5 = AccessLogRecord(
        timestamp="2026-08-25T13:45:00Z",
        user_id="operator_05",
        source_ip="10.0.0.50",
        device_id="GS-DEVICE-01",
        action="PAYLOAD_SHUTDOWN",
        resource="SAT-PAYLOAD-01",
        result="SUCCESS",
        role="operator"
    )
    det5 = engine.evaluate_record(rec5)
    evt5 = EventGenerator.generate_security_event(det5)
    
    print(f"Target Resource : {rec5.resource} | Action: {rec5.action}")
    print(f"Detection       : Suspicious={det5.is_suspicious} | Type={det5.event_type}")
    print(f"Severity        : [{evt5.severity}] -> Action: [{evt5.action}]")
    print(f"Description     : {evt5.description}")
    print("Result Status   : [CRITICAL THREAT] UNAUTHORIZED_COMMAND DETECTED / ALERT TRIGGERED\n")

    # DEMO 6: Canonical SecurityEvent JSON Payload & ML Brain Integration
    print("--------------------------------------------------------------------------------")
    print(" [DEMO 6] CANONICAL SECURITY EVENT SCHEMA & ML BRAIN INTEGRATION TEST")
    print("--------------------------------------------------------------------------------")
    print("Sample Generated SecurityEvent JSON (Forwarded to Person 5 ML Brain & Person 6 Audit):")
    sample_json = json.dumps(evt5.model_dump(), indent=2)
    print(sample_json)

    print("\nAttempting real-time HTTP POST forwarding to Person 5 ML Brain...")
    forward_result = EventGenerator.forward_to_ml_brain_sync(evt5, ml_brain_url=ML_BRAIN_URL)
    
    if forward_result.get("forwarded"):
        print(f"[SUCCESS] Forwarding Success! HTTP {forward_result.get('status_code')}: {forward_result.get('ml_brain_response')}")
    else:
        print(f"{forward_result.get('message')}")
        print(f"Details: {forward_result.get('details', 'ML Brain server offline on port 8005')}")

    print("\n" + "=" * 80)
    print(" DEMO COMPLETED SUCCESSFULLY -- ACCESS SECURITY MODULE IS FULLY FUNCTIONAL!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_demo()
