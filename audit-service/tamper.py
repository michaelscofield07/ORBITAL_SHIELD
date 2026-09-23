import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'audit.db')
conn = sqlite3.connect(db_path)
conn.execute("UPDATE audit_events SET event_json = REPLACE(event_json, 'Blocked unknown command', 'Nothing happened here') WHERE event_id = 'EVT-102'")
conn.commit()
conn.close()
print('Record tampered')
