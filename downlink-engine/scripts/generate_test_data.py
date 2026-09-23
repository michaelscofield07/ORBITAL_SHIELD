"""Test data generator and attack simulator for Downlink Security Engine."""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta
import urllib.request
import urllib.error

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.utils.hashing import compute_telemetry_hash
from app.core.logging_config import setup_logging, get_logger

setup_logging()
logger = get_logger("scripts.generate_test_data")

TEST_DATA_DIR = BASE_DIR / "data" / "test"


def generate_normal_scenario(start_seq: int = 1001, count: int = 3, start_time: datetime = None) -> list:
    """Generate a batch of nominal sequential telemetry packets with valid hashes."""
    base_time = start_time or datetime.now(timezone.utc)
    packets = []
    for i in range(count):
        ts = (base_time + timedelta(seconds=i * 6)).strftime("%Y-%m-%dT%H:%M:%SZ")
        pkt = {
            "timestamp": ts,
            "satellite_id": "SAT-EO-01",
            "sequence_number": start_seq + i,
            "temperature": round(23.5 + (i * 0.1), 2),
            "battery": round(88.0 - (i * 0.05), 2),
            "signal_strength": round(-70.5 + (i * 0.05), 2),
            "latitude": round(11.0168 + (i * 0.05), 4),
            "longitude": round(76.9558 + (i * 0.05), 4),
            "packet_hash": None,
            "signature": None
        }
        pkt["packet_hash"] = compute_telemetry_hash(pkt)
        packets.append(pkt)
    return packets


def generate_thermal_spike_scenario(start_seq: int = 1004, start_time: datetime = None) -> list:
    """Generate thermal spoofing attack (temperature jumps from nominal 24.0°C to 82.5°C)."""
    base_time = start_time or datetime.now(timezone.utc)
    packets = []
    
    # 1. Normal baseline packet
    p1 = {
        "timestamp": (base_time).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "satellite_id": "SAT-EO-01",
        "sequence_number": start_seq,
        "temperature": 24.0,
        "battery": 87.8,
        "signal_strength": -70.4,
        "latitude": 11.20,
        "longitude": 77.10,
        "packet_hash": None,
        "signature": None
    }
    p1["packet_hash"] = compute_telemetry_hash(p1)
    packets.append(p1)

    # 2. Thermal Spike Spoofing Packet
    p2 = {
        "timestamp": (base_time + timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "satellite_id": "SAT-EO-01",
        "sequence_number": start_seq + 1,
        "temperature": 82.5,  # Extreme thermal spike!
        "battery": 87.4,
        "signal_strength": -71.2,
        "latitude": 11.25,
        "longitude": 77.15,
        "packet_hash": None,
        "signature": None
    }
    p2["packet_hash"] = compute_telemetry_hash(p2)
    packets.append(p2)
    return packets


def generate_signal_drop_scenario(start_seq: int = 3000, start_time: datetime = None) -> list:
    """Generate severe RF link degradation (-70 dBm -> -122 dBm)."""
    base_time = start_time or datetime.now(timezone.utc)
    packets = []
    
    p1 = {
        "timestamp": base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "satellite_id": "SAT-EO-01",
        "sequence_number": start_seq,
        "temperature": 23.0,
        "battery": 86.0,
        "signal_strength": -70.0,
        "latitude": 12.0,
        "longitude": 77.0,
        "packet_hash": None,
        "signature": None
    }
    p1["packet_hash"] = compute_telemetry_hash(p1)
    packets.append(p1)

    p2 = {
        "timestamp": (base_time + timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "satellite_id": "SAT-EO-01",
        "sequence_number": start_seq + 1,
        "temperature": 23.1,
        "battery": 85.9,
        "signal_strength": -122.5,  # Severe RF attenuation
        "latitude": 12.05,
        "longitude": 77.05,
        "packet_hash": None,
        "signature": None
    }
    p2["packet_hash"] = compute_telemetry_hash(p2)
    packets.append(p2)
    return packets


def generate_burst_flood_scenario(start_seq: int = 4000, start_time: datetime = None) -> list:
    """Generate high-frequency telemetry flood burst (300 packets/min)."""
    base_time = start_time or datetime.now(timezone.utc)
    packets = []
    for i in range(10):
        # 0.2s interval between packets -> 300 pkts/min
        ts = (base_time + timedelta(milliseconds=i * 200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        pkt = {
            "timestamp": ts,
            "satellite_id": "SAT-EO-01",
            "sequence_number": start_seq + i,
            "temperature": 24.0,
            "battery": 85.0,
            "signal_strength": -70.0,
            "latitude": 13.0,
            "longitude": 78.0,
            "packet_hash": None,
            "signature": None
        }
        pkt["packet_hash"] = compute_telemetry_hash(pkt)
        packets.append(pkt)
    return packets


def generate_sequence_anomaly_scenario(start_seq: int = 5000, start_time: datetime = None) -> list:
    """Generate sequence jump (100 -> 101 -> 150 -> 151)."""
    base_time = start_time or datetime.now(timezone.utc)
    packets = [
        {
            "timestamp": (base_time).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "satellite_id": "SAT-EO-01",
            "sequence_number": start_seq,
            "temperature": 23.5,
            "battery": 88.0,
            "signal_strength": -70.0,
            "latitude": 14.0,
            "longitude": 79.0,
            "packet_hash": None,
            "signature": None
        },
        {
            "timestamp": (base_time + timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "satellite_id": "SAT-EO-01",
            "sequence_number": start_seq + 1,
            "temperature": 23.6,
            "battery": 87.9,
            "signal_strength": -70.1,
            "latitude": 14.05,
            "longitude": 79.05,
            "packet_hash": None,
            "signature": None
        },
        {
            "timestamp": (base_time + timedelta(seconds=12)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "satellite_id": "SAT-EO-01",
            "sequence_number": start_seq + 50,  # Jump by 50!
            "temperature": 23.7,
            "battery": 87.8,
            "signal_strength": -70.2,
            "latitude": 14.10,
            "longitude": 79.10,
            "packet_hash": None,
            "signature": None
        },
        {
            "timestamp": (base_time + timedelta(seconds=18)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "satellite_id": "SAT-EO-01",
            "sequence_number": start_seq + 51,
            "temperature": 23.8,
            "battery": 87.7,
            "signal_strength": -70.3,
            "latitude": 14.15,
            "longitude": 79.15,
            "packet_hash": None,
            "signature": None
        }
    ]
    for p in packets:
        p["packet_hash"] = compute_telemetry_hash(p)
    return packets


def generate_replay_scenario(start_seq: int = 6000, start_time: datetime = None) -> list:
    """Generate telemetry replay attack (re-injecting duplicate sequence & timestamp)."""
    base_time = start_time or datetime.now(timezone.utc)
    original_pkt = {
        "timestamp": base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "satellite_id": "SAT-EO-01",
        "sequence_number": start_seq,
        "temperature": 24.0,
        "battery": 85.0,
        "signal_strength": -70.0,
        "latitude": 15.0,
        "longitude": 80.0,
        "packet_hash": None,
        "signature": None
    }
    original_pkt["packet_hash"] = compute_telemetry_hash(original_pkt)

    # Replayed identical packet
    replayed_pkt = dict(original_pkt)

    return [original_pkt, replayed_pkt]


def generate_hash_tampering_scenario(start_seq: int = 1006, start_time: datetime = None) -> list:
    """Generate hash tampering attack (payload modified without recalculating hash)."""
    base_time = start_time or datetime.now(timezone.utc)
    original_pkt = {
        "timestamp": base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "satellite_id": "SAT-EO-01",
        "sequence_number": start_seq,
        "temperature": 24.1,
        "battery": 87.2,
        "signal_strength": -70.5,
        "latitude": 11.30,
        "longitude": 77.20,
        "packet_hash": None,
        "signature": None
    }
    # Compute genuine hash for original packet
    genuine_hash = compute_telemetry_hash(original_pkt)

    # Attacker alters temperature and sequence jump, but leaves old hash attached
    tampered_pkt = {
        "timestamp": (base_time + timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "satellite_id": "SAT-EO-01",
        "sequence_number": start_seq + 25,  # Unexpected Sequence jump!
        "temperature": 75.0,                # Tampered high temperature
        "battery": 45.0,                    # Tampered depleted battery
        "signal_strength": -70.0,
        "latitude": 11.35,
        "longitude": 77.25,
        "packet_hash": genuine_hash,        # Stale/Tampered hash mismatch!
        "signature": None
    }
    return [original_pkt, tampered_pkt]


def write_test_files():
    """Export all test scenario datasets to data/test/."""
    TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

    normal_data = generate_normal_scenario(1001, count=10)
    with open(TEST_DATA_DIR / "normal_telemetry.json", "w", encoding="utf-8") as f:
        json.dump(normal_data, f, indent=2)

    anomalous_data = {
        "thermal_spike": generate_thermal_spike_scenario(2001),
        "signal_drop": generate_signal_drop_scenario(3001),
        "burst_flood": generate_burst_flood_scenario(4001)
    }
    with open(TEST_DATA_DIR / "anomalous_telemetry.json", "w", encoding="utf-8") as f:
        json.dump(anomalous_data, f, indent=2)

    tampered_data = {
        "sequence_jump": generate_sequence_anomaly_scenario(5001),
        "replay_attack": generate_replay_scenario(6001),
        "hash_tampering": generate_hash_tampering_scenario(7001)
    }
    with open(TEST_DATA_DIR / "tampered_telemetry.json", "w", encoding="utf-8") as f:
        json.dump(tampered_data, f, indent=2)

    logger.info(f"Test datasets written successfully to '{TEST_DATA_DIR}'")


def send_packet_http(url: str, packet: dict) -> dict:
    """Send a telemetry packet to the Downlink Engine via HTTP POST."""
    req = urllib.request.Request(
        url,
        data=json.dumps(packet).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        return {"error": e.code, "detail": body}


def reset_engine_database(base_url: str) -> bool:
    """Reset engine database before starting a clean demonstration."""
    reset_url = base_url.replace("/analyze", "/reset")
    try:
        req = urllib.request.Request(reset_url, data=b"{}", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            return resp.status == 200
    except Exception:
        return False


def run_live_demonstration(api_url: str = "http://127.0.0.1:8000/downlink/analyze", reset: bool = True):
    """Execute live simulation across all 3 key demo scenarios."""
    print("=" * 75)
    print("      ORBITAL SHIELD — DOWNLINK SECURITY ENGINE LIVE DEMONSTRATION")
    print("=" * 75)

    if reset:
        print("[SETUP] Resetting Telemetry Database for clean demonstration...")
        reset_engine_database(api_url)

    curr_time = datetime.now(timezone.utc) - timedelta(seconds=60)

    # 1. NORMAL TELEMETRY SCENARIO
    print("\n" + "-" * 75)
    print("[SCENARIO 1] Submitting Normal Telemetry (Sequential Nominal Flight Profile)...")
    print("-" * 75)
    normal_pkts = generate_normal_scenario(start_seq=1001, count=3, start_time=curr_time)
    curr_time += timedelta(seconds=len(normal_pkts) * 6)
    for pkt in normal_pkts:
        res = send_packet_http(api_url, pkt)
        integrity = res.get("integrity", {}).get("integrity_status")
        is_anomaly = res.get("anomaly", {}).get("is_anomaly")
        event = res.get("security_event")
        print(f"  --> Seq {pkt['sequence_number']}: Temp={pkt['temperature']}°C | Integrity={integrity} | Anomaly={is_anomaly} | SecurityEvent={'None' if not event else event['event_id']}")

    # 2. BEHAVIORAL ANOMALY / THERMAL SPOOF SCENARIO
    print("\n" + "-" * 75)
    print("[SCENARIO 2] Submitting Telemetry Spoof / Thermal Anomaly (24.0°C -> 82.5°C)...")
    print("-" * 75)
    spike_pkts = generate_thermal_spike_scenario(start_seq=1004, start_time=curr_time)
    curr_time += timedelta(seconds=len(spike_pkts) * 6)
    for pkt in spike_pkts:
        res = send_packet_http(api_url, pkt)
        is_anomaly = res.get("anomaly", {}).get("is_anomaly")
        severity = res.get("anomaly", {}).get("severity")
        event = res.get("security_event")
        print(f"  --> Seq {pkt['sequence_number']}: Temp={pkt['temperature']}°C | Anomaly={is_anomaly} | Severity={severity}")
        if event:
            print(f"      [SECURITY EVENT GENERATED]")
            print(f"      Event ID:    {event['event_id']}")
            print(f"      Event Type:  {event['event_type']}")
            print(f"      Severity:    {event['severity']}")
            print(f"      Action:      {event['action']}")
            print(f"      Confidence:  {event['confidence']}")
            print(f"      Description: {event['description']}")
            print(f"      Evidence:    {json.dumps(event['evidence'])}")

    # 3. PACKET TAMPERING SCENARIO (Hash Mismatch + Sequence Jump)
    print("\n" + "-" * 75)
    print("[SCENARIO 3] Submitting Cryptographic Hash Tampering + Sequence Jump...")
    print("-" * 75)
    tamper_pkts = generate_hash_tampering_scenario(start_seq=1006, start_time=curr_time)
    for pkt in tamper_pkts:
        res = send_packet_http(api_url, pkt)
        integrity = res.get("integrity", {}).get("integrity_status")
        issues = res.get("integrity", {}).get("integrity_issues")
        event = res.get("security_event")
        print(f"  --> Seq {pkt['sequence_number']}: Integrity={integrity} | Issues={issues}")
        if event:
            print(f"      [CRITICAL SECURITY EVENT GENERATED]")
            print(f"      Event ID:    {event['event_id']}")
            print(f"      Event Type:  {event['event_type']}")
            print(f"      Severity:    {event['severity']}")
            print(f"      Action:      {event['action']}")
            print(f"      Confidence:  {event['confidence']}")
            print(f"      Description: {event['description']}")
            print(f"      Evidence:    {json.dumps(event['evidence'])}")

    print("\n" + "=" * 75)
    print("                Demonstration Completed Successfully.")
    print("=" * 75)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test data generator and attack simulator for Downlink Engine")
    parser.add_argument("--export", action="store_true", help="Generate and save test JSON datasets")
    parser.add_argument("--demo", action="store_true", help="Run live attack demonstration against running API")
    parser.add_argument("--no-reset", action="store_true", help="Do not reset database before demo")
    parser.add_argument("--url", default="http://127.0.0.1:8000/downlink/analyze", help="Downlink API endpoint URL")

    args = parser.parse_args()

    # Always ensure test files exist
    write_test_files()

    if args.demo:
        run_live_demonstration(api_url=args.url, reset=not args.no_reset)
