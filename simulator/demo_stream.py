import json
from pathlib import Path
import sys

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from fastapi.testclient import TestClient
from simulator.main import app

def run_demo():
    print("=" * 70)
    print("      ORBITAL_SHIELD - LIVE WEBSOCKET TELEMETRY STREAM DEMO")
    print("=" * 70)
    print("Endpoint: ws://127.0.0.1:8000/telemetry/stream?limit=3&interval=0.05")
    print("Connecting...")

    client = TestClient(app)
    with client.websocket_connect("/telemetry/stream?limit=3&interval=0.05") as ws:
        for i in range(3):
            raw_text = ws.receive_text()
            event = json.loads(raw_text)
            print(f"\n[STREAMED FRAME #{i+1}]")
            print(f" - Event ID     : {event['event_id']}")
            print(f" - Timestamp    : {event['timestamp']}")
            print(f" - Source       : {event['source']}")
            print(f" - Satellite ID : {event['satellite_id']}")
            print(f" - Event Type   : {event['event_type']}")
            print(" - Telemetry Data (Sample):")
            data = event['data']
            print(f"     MsgId: {data['MsgId']} | CmdCode: {data['CmdCode']} | ApId: {data['ApId']} | MsgLength: {data['MsgLength']}")
            print(f"     MemoryAnonMB: {data['MemoryAnonMB']:.4f} MB | MemoryFileMB: {data['MemoryFileMB']:.4f} MB")
            print(f"     MessageRateInWindow: {data['MessageRateInWindow']} | SlidingWindowMeanInterval: {data['SlidingWindowMeanIntervalSec']:.4f}s")
            print(f"     Ground-truth Class Label: {data['Label']}")

    print("\n" + "=" * 70)
    print("WebSocket stream demonstration completed successfully.")
    print("=" * 70)

if __name__ == "__main__":
    run_demo()
