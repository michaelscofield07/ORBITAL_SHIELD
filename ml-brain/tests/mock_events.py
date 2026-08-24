"""
ORBITAL SHIELD -- ML Correlation Brain
Mock Event Generator

Generates realistic fake security events for standalone testing and demo purposes.
This script does NOT require any of the other four upstream modules to be running.

Usage:
  python tests/mock_events.py                  # run full demo scenario
  python tests/mock_events.py --scenario 1     # scenario 1 only
  python tests/mock_events.py --replay         # replay as HTTP POST to running server

Scenarios:
  1. cross_module_same_session   -> RULE_001 (CROSS_MODULE_ATTACK)
  2. escalating_severity         -> RULE_002 (ESCALATING_INCIDENT)
  3. firmware_plus_access        -> RULE_003 (SUPPLY_CHAIN_RISK)
  4. multi_vector_attack         -> RULE_004 (MULTI_VECTOR_ATTACK)
  5. mixed_low_noise             -> should NOT trigger (below thresholds)
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

# -------------------------------------------------------------
# Scenario definitions
# -------------------------------------------------------------

BASE_TIME = datetime.now(timezone.utc)


def _ts(delta_seconds: int = 0) -> str:
    return (BASE_TIME + timedelta(seconds=delta_seconds)).isoformat()


# --------------------------------------------------------------
# SCENARIO 1: Cross-module attack on same session
# Expected: RULE_001 fires -> CROSS_MODULE_ATTACK
# Three different sources, same session_id, within 5 minutes
# --------------------------------------------------------------
SCENARIO_1_EVENTS = [
    {
        "event_id":     "EVT-S1-001",
        "timestamp":    _ts(0),
        "source":       "ACCESS",
        "satellite_id": "SAT-EO-01",
        "event_type":   "SUSPICIOUS_LOGIN",
        "severity":     "MEDIUM",
        "confidence":   0.87,
        "description":  "Operator OP-02 logged in from an unrecognised IP at 03:47 UTC. Location anomaly detected.",
        "action":       "REVIEW",
        "evidence":     {"ip": "185.220.101.48", "location": "TOR_EXIT_NODE", "usual_location": "IN/Bangalore"},
        "related_events": [],
        "operator_id":  "OP-02",
        "session_id":   "SESSION-ALPHA-001",
    },
    {
        "event_id":     "EVT-S1-002",
        "timestamp":    _ts(90),   # 1m 30s later
        "source":       "UPLINK",
        "satellite_id": "SAT-EO-01",
        "event_type":   "UNAUTHORIZED_COMMAND",
        "severity":     "HIGH",
        "confidence":   0.95,
        "description":  "Command C-OVERRIDE-SAFE-MODE sent without required dual authorisation. Operator session SESSION-ALPHA-001.",
        "action":       "REVIEW",
        "evidence":     {"command": "C-OVERRIDE-SAFE-MODE", "auth_required": 2, "auth_provided": 1},
        "related_events": [],
        "operator_id":  "OP-02",
        "session_id":   "SESSION-ALPHA-001",
    },
    {
        "event_id":     "EVT-S1-003",
        "timestamp":    _ts(200),  # 3m 20s after first
        "source":       "DOWNLINK",
        "satellite_id": "SAT-EO-01",
        "event_type":   "TELEMETRY_ANOMALY",
        "severity":     "HIGH",
        "confidence":   0.91,
        "description":  "Unexpected thermal increase (+12°C) on main bus coinciding with unauthorized command window.",
        "action":       "REVIEW",
        "evidence":     {"sensor": "THERMAL-01", "delta_celsius": 12.4, "threshold": 5.0},
        "related_events": [],
        "operator_id":  "OP-02",
        "session_id":   "SESSION-ALPHA-001",
    },
]

# --------------------------------------------------------------
# SCENARIO 2: Escalating severity chain on same satellite
# Expected: RULE_002 fires -> ESCALATING_INCIDENT
# LOW -> MEDIUM -> HIGH over 10 minutes
# --------------------------------------------------------------
SCENARIO_2_EVENTS = [
    {
        "event_id":     "EVT-S2-001",
        "timestamp":    _ts(0),
        "source":       "DOWNLINK",
        "satellite_id": "SAT-EO-02",
        "event_type":   "SIGNAL_INTERFERENCE",
        "severity":     "LOW",
        "confidence":   0.65,
        "description":  "Minor signal-to-noise ratio degradation detected on downlink band. Within tolerance.",
        "action":       "MONITOR",
        "evidence":     {"snr_db": -2.1, "threshold_db": -5.0},
        "related_events": [],
        "operator_id":  "OP-01",
        "session_id":   "SESSION-BETA-001",
    },
    {
        "event_id":     "EVT-S2-002",
        "timestamp":    _ts(240),   # 4 minutes later
        "source":       "UPLINK",
        "satellite_id": "SAT-EO-02",
        "event_type":   "REPLAY_ATTACK",
        "severity":     "MEDIUM",
        "confidence":   0.78,
        "description":  "Uplink command sequence matches a previously transmitted packet. Possible replay attack.",
        "action":       "REVIEW",
        "evidence":     {"packet_hash": "a3f9bc12", "original_timestamp": _ts(-3600)},
        "related_events": [],
        "operator_id":  "OP-01",
        "session_id":   "SESSION-BETA-001",
    },
    {
        "event_id":     "EVT-S2-003",
        "timestamp":    _ts(480),   # 8 minutes after first
        "source":       "ACCESS",
        "satellite_id": "SAT-EO-02",
        "event_type":   "ACCESS_VIOLATION",
        "severity":     "HIGH",
        "confidence":   0.89,
        "description":  "Operator attempted to access CLASSIFIED-UPLINK-KEY without clearance. Access denied.",
        "action":       "ALERT",
        "evidence":     {"resource": "CLASSIFIED-UPLINK-KEY", "clearance_required": "TS", "clearance_held": "SECRET"},
        "related_events": [],
        "operator_id":  "OP-01",
        "session_id":   "SESSION-BETA-001",
    },
]

# --------------------------------------------------------------
# SCENARIO 3: Firmware tampering + access anomaly (supply chain)
# Expected: RULE_003 fires -> SUPPLY_CHAIN_RISK
# --------------------------------------------------------------
SCENARIO_3_EVENTS = [
    {
        "event_id":     "EVT-S3-001",
        "timestamp":    _ts(0),
        "source":       "FIRMWARE",
        "satellite_id": "SAT-COM-01",
        "event_type":   "FIRMWARE_TAMPERING",
        "severity":     "CRITICAL",
        "confidence":   0.97,
        "description":  "Firmware image hash mismatch on OBC subsystem. Expected SHA256 does not match uploaded image.",
        "action":       "REVIEW",
        "evidence":     {
            "expected_hash": "e3b0c44298fc1c149afb",
            "actual_hash":   "d41d8cd98f00b204e980",
            "subsystem":     "OBC",
        },
        "related_events": [],
        "operator_id":  "OP-03",
        "session_id":   "SESSION-GAMMA-001",
    },
    {
        "event_id":     "EVT-S3-002",
        "timestamp":    _ts(420),  # 7 minutes later
        "source":       "ACCESS",
        "satellite_id": "SAT-COM-01",
        "event_type":   "SUSPICIOUS_LOGIN",
        "severity":     "HIGH",
        "confidence":   0.88,
        "description":  "Operator OP-03 authenticated with a revoked certificate. Certificate revoked 2 days ago.",
        "action":       "ALERT",
        "evidence":     {"cert_serial": "0F:A2:11:BC", "revoked_at": "2026-08-22T08:00:00Z"},
        "related_events": [],
        "operator_id":  "OP-03",
        "session_id":   "SESSION-GAMMA-002",
    },
]

# --------------------------------------------------------------
# SCENARIO 4: Multi-vector attack (3+ modules, same satellite)
# Expected: RULE_004 fires -> MULTI_VECTOR_ATTACK
# --------------------------------------------------------------
SCENARIO_4_EVENTS = [
    {
        "event_id":     "EVT-S4-001",
        "timestamp":    _ts(0),
        "source":       "DOWNLINK",
        "satellite_id": "SAT-RECON-01",
        "event_type":   "TELEMETRY_ANOMALY",
        "severity":     "HIGH",
        "confidence":   0.90,
        "description":  "GPS coordinates in telemetry deviate from predicted orbit by 4.2km. Possible spoofing.",
        "action":       "REVIEW",
        "evidence":     {"deviation_km": 4.2, "predicted_pos": "LEO-TLE-2026-08-24"},
        "related_events": [],
        "operator_id":  "OP-04",
        "session_id":   "SESSION-DELTA-001",
    },
    {
        "event_id":     "EVT-S4-002",
        "timestamp":    _ts(120),
        "source":       "UPLINK",
        "satellite_id": "SAT-RECON-01",
        "event_type":   "UNAUTHORIZED_COMMAND",
        "severity":     "HIGH",
        "confidence":   0.93,
        "description":  "Attitude control command injected from unregistered ground station IP block.",
        "action":       "REVIEW",
        "evidence":     {"command": "ATTITUDE-ADJUST", "source_ip": "192.0.2.100", "registered": False},
        "related_events": [],
        "operator_id":  "OP-04",
        "session_id":   "SESSION-DELTA-001",
    },
    {
        "event_id":     "EVT-S4-003",
        "timestamp":    _ts(250),
        "source":       "ACCESS",
        "satellite_id": "SAT-RECON-01",
        "event_type":   "SUSPICIOUS_LOGIN",
        "severity":     "MEDIUM",
        "confidence":   0.79,
        "description":  "Second login to same operator account from different device within 4 minutes -- possible session hijack.",
        "action":       "REVIEW",
        "evidence":     {"first_device": "CONSOLE-A", "second_device": "CONSOLE-B"},
        "related_events": [],
        "operator_id":  "OP-04",
        "session_id":   "SESSION-DELTA-002",
    },
]

# --------------------------------------------------------------
# SCENARIO 5: Low-noise events -- should NOT trigger any rule
# Different satellites, sessions, and sources spread over time
# --------------------------------------------------------------
SCENARIO_5_EVENTS = [
    {
        "event_id":     "EVT-S5-001",
        "timestamp":    _ts(0),
        "source":       "DOWNLINK",
        "satellite_id": "SAT-EO-03",
        "event_type":   "TELEMETRY_ANOMALY",
        "severity":     "LOW",
        "confidence":   0.60,
        "description":  "Marginal battery voltage variation. Within safe operating limits.",
        "action":       "MONITOR",
        "evidence":     {"voltage_v": 3.27, "nominal_v": 3.3},
        "related_events": [],
        "operator_id":  "OP-05",
        "session_id":   "SESSION-EPS-001",
    },
    {
        "event_id":     "EVT-S5-002",
        "timestamp":    _ts(900),  # 15 minutes later, different satellite
        "source":       "UPLINK",
        "satellite_id": "SAT-COM-02",
        "event_type":   "REPLAY_ATTACK",
        "severity":     "LOW",
        "confidence":   0.55,
        "description":  "Marginal packet timing variance. Likely network jitter, not replay.",
        "action":       "LOG",
        "evidence":     {"jitter_ms": 8.2, "threshold_ms": 10.0},
        "related_events": [],
        "operator_id":  "OP-06",
        "session_id":   "SESSION-NET-001",
    },
]

ALL_SCENARIOS = {
    "1": ("cross_module_same_session",   SCENARIO_1_EVENTS, "RULE_001 -> CROSS_MODULE_ATTACK"),
    "2": ("escalating_severity",         SCENARIO_2_EVENTS, "RULE_002 -> ESCALATING_INCIDENT"),
    "3": ("firmware_plus_access",        SCENARIO_3_EVENTS, "RULE_003 -> SUPPLY_CHAIN_RISK"),
    "4": ("multi_vector_attack",         SCENARIO_4_EVENTS, "RULE_004 -> MULTI_VECTOR_ATTACK"),
    "5": ("low_noise_no_trigger",        SCENARIO_5_EVENTS, "No rule should fire"),
}


# -------------------------------------------------------------
# HTTP replay mode -- POST events to a running server
# -------------------------------------------------------------

def replay_to_server(events: list[dict], base_url: str = "http://localhost:8005",
                     delay: float = 0.5, verbose: bool = True) -> list[dict]:
    """Send events to a running ML Brain server and collect responses."""
    try:
        import httpx
    except ImportError:
        print("httpx not installed. Run: pip install httpx")
        sys.exit(1)

    results = []
    with httpx.Client(timeout=10) as client:
        for event in events:
            try:
                resp = client.post(f"{base_url}/events/ingest", json=event)
                data = resp.json()
                results.append({"event_id": event["event_id"], "status": resp.status_code, "response": data})
                if verbose:
                    corr = data.get("correlations_triggered", [])
                    print(f"  [OK] {event['event_id']} -> HTTP {resp.status_code} | incidents: {corr or 'none'}")
            except Exception as exc:
                print(f"  ✗ {event['event_id']} -> ERROR: {exc}")
                results.append({"event_id": event["event_id"], "error": str(exc)})
            time.sleep(delay)
    return results


# -------------------------------------------------------------
# Standalone in-process simulation (no server needed)
# -------------------------------------------------------------

def run_in_process(events: list[dict]) -> list[dict]:
    """
    Run correlation engine in-process without a server.
    Returns list of generated incidents.
    """
    from db import database as db_mod
    from core import ingestion as ing_mod, correlation_engine as ce_mod, scoring as sc_mod

    db_mod.init_db()
    window = ing_mod.init_window(window_seconds=1800)

    incidents = []
    for event_raw in events:
        # Build IncomingEvent manually
        from models.schemas import IncomingEvent
        event = IncomingEvent(**event_raw)
        event_dict = ing_mod.ingest_event(event)
        window_events = window.get_all()
        features = ing_mod.extract_features(event_dict, window_events)
        fired = ce_mod.evaluate_rules(event_dict, window_events)
        existing = db_mod.fetch_open_incidents()
        for match in fired:
            matched_ids = [e["event_id"] for e in match["matched_events"]]
            if not ce_mod.is_duplicate_incident(match["rule_id"], matched_ids, existing):
                incident = sc_mod.compute_risk_score(match)
                db_mod.insert_incident(incident)
                incidents.append(incident)
    return incidents


# -------------------------------------------------------------
# CLI entry point
# -------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ORBITAL SHIELD -- ML Brain Mock Event Generator"
    )
    parser.add_argument("--scenario", choices=["1", "2", "3", "4", "5", "all"],
                        default="all", help="Which scenario to run")
    parser.add_argument("--replay", action="store_true",
                        help="POST events to a running server instead of in-process")
    parser.add_argument("--url", default="http://localhost:8005",
                        help="Base URL of running ML Brain server (default: localhost:8005)")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="Seconds between events when replaying (default: 0.3)")
    parser.add_argument("--dump-json", action="store_true",
                        help="Print events as JSON to stdout instead of running them")
    args = parser.parse_args()

    scenarios_to_run = (
        list(ALL_SCENARIOS.keys()) if args.scenario == "all"
        else [args.scenario]
    )

    print("\n" + "=" * 65)
    print("  ORBITAL SHIELD -- ML Correlation Brain")
    print("  Mock Event Generator")
    print("=" * 65)

    if args.dump_json:
        all_events = []
        for s_id in scenarios_to_run:
            _, events, _ = ALL_SCENARIOS[s_id]
            all_events.extend(events)
        print(json.dumps(all_events, indent=2, default=str))
        return

    for s_id in scenarios_to_run:
        name, events, expected = ALL_SCENARIOS[s_id]
        print(f"\n>> Scenario {s_id}: {name}")
        print(f"   Expected: {expected}")
        print(f"   Events:   {len(events)}")
        print("   " + "-" * 55)

        if args.replay:
            print(f"   Mode: HTTP replay -> {args.url}")
            results = replay_to_server(events, base_url=args.url,
                                       delay=args.delay, verbose=True)
        else:
            print("   Mode: in-process (no server required)")
            incidents = run_in_process(events)
            for inc in incidents:
                print(f"  [OK] Incident: {inc['event_id']} | {inc['event_type']} | "
                      f"severity={inc['severity']} | score={inc['risk_score']}")
            if not incidents:
                print("  [i] No incidents generated (correct for scenario 5)")

    print("\n" + "=" * 65)
    print("  Mock event replay complete.")
    if not args.replay:
        print("  Tip: run with --replay to POST events to a live server.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
