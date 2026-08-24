"""
Retrain accuracy validation script.
Run from ml-brain/ directory:  python db/run_accuracy_test.py
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ['DB_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'retrain_accuracy_test.db')

from db import database as db
from core import ingestion as ing, correlation_engine as ce, scoring as sc, feedback as fb_mod
from models.schemas import IncomingEvent

db.init_db()
win = ing.init_window(window_seconds=1800)

from tests.mock_events import (
    SCENARIO_1_EVENTS, SCENARIO_2_EVENTS, SCENARIO_3_EVENTS,
    SCENARIO_4_EVENTS, SCENARIO_6_EVENTS, SCENARIO_7_EVENTS, SCENARIO_8_EVENTS
)

all_events = (
    SCENARIO_1_EVENTS + SCENARIO_2_EVENTS + SCENARIO_3_EVENTS +
    SCENARIO_4_EVENTS + SCENARIO_6_EVENTS + SCENARIO_7_EVENTS + SCENARIO_8_EVENTS
)

incidents = []
for raw in all_events:
    event = IncomingEvent(**raw)
    event_dict = ing.ingest_event(event)
    window_events = win.get_all()
    features = ing.extract_features(event_dict, window_events)
    fired = ce.evaluate_rules(event_dict, window_events)
    existing = db.fetch_open_incidents()
    for match in fired:
        matched_ids = [e['event_id'] for e in match['matched_events']]
        if not ce.is_duplicate_incident(match['rule_id'], matched_ids, existing):
            incident = sc.compute_risk_score(match)
            incident['features_json'] = features
            db.insert_incident(incident)
            db.mark_events_correlated(matched_ids)
            incidents.append(incident)

print("=== Incidents created: %d ===" % len(incidents))
for inc in incidents:
    print("  %s | %s | score=%d | rule=%s" % (
        inc['event_id'], inc['event_type'], inc['risk_score'], inc['rule_id']
    ))

# Mixed feedback: score >= 80 = CONFIRMED_REAL (clearly dangerous), < 80 = FALSE_POSITIVE
# This ensures both classes are present for the ML classifier
print("\n=== Submitting feedback ===")
for i, inc in enumerate(incidents):
    verdict = 'CONFIRMED_REAL' if inc['risk_score'] >= 80 else 'FALSE_POSITIVE'
    fb_mod.submit_feedback(
        incident_id=inc['event_id'],
        verdict=verdict,
        reviewer='accuracy_test_runner',
        notes='Auto-labeled score=%d' % inc['risk_score']
    )
    print("  Feedback %d: %s -> %s (score=%d)" % (i+1, inc['event_id'], verdict, inc['risk_score']))

all_fb = db.fetch_all_feedback()
with_features = sum(1 for f in all_fb if f.get('features_json') is not None)
print("\n=== Feedback summary ===")
print("Total records: %d" % len(all_fb))
print("Records WITH features_json: %d / %d" % (with_features, len(all_fb)))

# Run retrain
print("\n=== Running retrain job ===")
result = fb_mod.run_retrain_job()
print("Status:       %s" % result['status'])
print("ML retrained: %s" % result['ml_retrained'])
print("ML accuracy:  %s" % result.get('ml_accuracy'))
print("Message: %s" % result['message'])
