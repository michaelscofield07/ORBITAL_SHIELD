// dashboard/src/api/mlbrainclient.js
// Centralized API module for all ML Correlation Brain interactions.
// Uses VITE_MLBRAIN_URL env var (set in dashboard/.env or injected by Docker).

const MLBRAIN_BASE = import.meta.env.VITE_MLBRAIN_URL || "http://127.0.0.1:8005";

// ── Active correlations ──────────────────────────────────────

export async function getActiveCorrelations() {
  const res = await fetch(`${MLBRAIN_BASE}/correlations/active`);
  if (!res.ok) throw new Error(`ML Brain /correlations/active returned ${res.status}`);
  return res.json();
}

// ── Single incident detail ────────────────────────────────────

export async function getIncidentDetail(incidentId) {
  const res = await fetch(`${MLBRAIN_BASE}/correlations/${incidentId}`);
  if (!res.ok) throw new Error(`ML Brain /correlations/${incidentId} returned ${res.status}`);
  return res.json();
}

// ── CISO Feedback ─────────────────────────────────────────────

/**
 * Submit CISO verdict on a flagged incident.
 * @param {string} incidentId  - INC-xxx identifier
 * @param {"CONFIRMED_REAL"|"FALSE_POSITIVE"} verdict
 * @param {string} reviewer    - CISO identity string
 * @param {string} [notes]     - Optional notes
 */
export async function submitFeedback(incidentId, verdict, reviewer, notes = "") {
  const res = await fetch(`${MLBRAIN_BASE}/brain/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      incident_id: incidentId,
      verdict,
      reviewer,
      notes: notes || undefined,
    }),
  });
  if (!res.ok) throw new Error(`ML Brain /brain/feedback returned ${res.status}`);
  return res.json();
}

// ── Retrain ───────────────────────────────────────────────────

export async function triggerRetrain() {
  const res = await fetch(`${MLBRAIN_BASE}/brain/retrain`, { method: "POST" });
  if (!res.ok) throw new Error(`ML Brain /brain/retrain returned ${res.status}`);
  return res.json();
}

// ── SSE stream ────────────────────────────────────────────────

/**
 * Open an EventSource to /brain/stream.
 * @param {(msg: {source: string, event_type: string, timestamp: string, status: string}) => void} onMessage
 * @returns {EventSource}  call .close() to disconnect
 */
export function streamModuleEvents(onMessage) {
  const es = new EventSource(`${MLBRAIN_BASE}/brain/stream`);
  es.onmessage = (e) => {
    try {
      onMessage(JSON.parse(e.data));
    } catch {
      // ignore malformed heartbeat / non-JSON messages
    }
  };
  return es;
}
