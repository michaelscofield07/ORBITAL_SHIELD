from datetime import datetime
from schemas import SecurityEvent, Severity, Action
from hash_chain import compute_record_hash, GENESIS_HASH

event = SecurityEvent(
    event_id='EVT-100',
    timestamp=datetime.now(),
    source='DOWNLINK',
    event_type='TELEMETRY_ANOMALY',
    severity=Severity.HIGH,
    confidence=0.93,
    description='Unexpected thermal increase',
    action=Action.REVIEW,
)

hash1 = compute_record_hash(event, GENESIS_HASH)
print('Hash:', hash1)
