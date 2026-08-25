/**
 * CorrelationPanel — polls GET /correlations/active on ML Brain every 5s
 * and displays a list of open incidents (not just the most recent one).
 * Calls onInvestigate({ ...incident }) when the INVESTIGATE button is clicked.
 */
import { useState, useEffect } from "react";
import { getActiveCorrelations } from "../api/mlbrainclient";

function IncidentRow({ incident, onInvestigate }) {
  return (
    <div className="border hairline rounded-md bg-panel/20 backdrop-blur-md px-6 py-5 shadow-2xl relative overflow-hidden mb-3">
      <div className="absolute top-0 right-0 w-32 h-32 bg-alertRed/10 rounded-full blur-[50px] -z-10 mix-blend-screen" />

      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2 glow-text-alert">
            <span className="w-2 h-2 rounded-full bg-alertRed status-dot shadow-[0_0_8px_#E8544B]" />
            <span className="text-xs font-mono tracking-widest text-alertRed">
              {incident.severity} · {incident.event_type?.replace(/_/g, " ")}
            </span>
            <span className="text-xs font-mono text-mist/30 ml-2">{incident.event_id}</span>
          </div>

          <p className="text-mist text-sm mb-3">{incident.description}</p>

          <div className="flex items-center gap-2 text-xs font-mono text-mist/50">
            {incident.related_events?.map((evt, i) => (
              <span key={evt} className="flex items-center gap-2">
                {evt}
                {i < incident.related_events.length - 1 && (
                  <span className="text-mist/30">→</span>
                )}
              </span>
            ))}
          </div>
        </div>

        <div className="flex flex-col items-end gap-3">
          <span className="text-xs font-mono text-mist/50">
            CONFIDENCE {Math.round((incident.confidence || 0) * 100)}%
          </span>
          <span className="text-xs font-mono text-mist/40">
            RISK {incident.risk_score}
          </span>
          <button
            onClick={() => onInvestigate?.(incident)}
            className="text-xs font-mono tracking-widest text-void bg-alertRed px-5 py-2.5 rounded-sm hover:opacity-90 transition-all glow-box-alert font-bold"
          >
            INVESTIGATE
          </button>
        </div>
      </div>
    </div>
  );
}

function CorrelationPanel({ onInvestigate }) {
  const [incidents, setIncidents] = useState([]);
  const [error, setError] = useState(false);

  useEffect(() => {
    const load = () => {
      getActiveCorrelations()
        .then(setIncidents)
        .catch((err) => {
          console.error("CorrelationPanel:", err);
          setError(true);
        });
    };

    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  if (error) {
    return (
      <div className="text-mist/50 text-xs font-mono py-2">
        [ unable to load ML correlation — is ML Brain running on port 8005? ]
      </div>
    );
  }

  if (incidents.length === 0) {
    return (
      <div className="text-mist/30 text-xs font-mono py-2">
        [ no active correlation incidents ]
      </div>
    );
  }

  return (
    <div>
      <div className="text-xs tracking-widest text-mist/60 mb-3">
        ACTIVE INCIDENTS ({incidents.length})
      </div>
      {incidents.map((inc) => (
        <IncidentRow key={inc.event_id} incident={inc} onInvestigate={onInvestigate} />
      ))}
    </div>
  );
}

export default CorrelationPanel;