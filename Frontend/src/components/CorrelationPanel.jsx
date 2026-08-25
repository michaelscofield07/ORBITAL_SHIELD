import { useState, useEffect } from "react";
import { fetchEvents } from "../api/auditclient";

function CorrelationPanel({ onInvestigate }) {
  const [incident, setIncident] = useState(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetchEvents()
      .then((records) => {
        const mlEvents = records
          .map((r) => ({ ...r.event_json, db_id: r.event_id }))
          .filter((e) => e.source === "ML_BRAIN");
        
        if (mlEvents.length > 0) {
          setIncident(mlEvents[0]); // most recent
        } else {
          setIncident(null);
        }
      })
      .catch((err) => {
        console.error(err);
        setError(true);
      });
  }, []);

  if (error) {
    return <div className="text-mist/50 text-xs font-mono py-2">[ unable to load ML correlation ]</div>;
  }

  if (!incident) return null;

  return (
    <div className="border hairline rounded-md bg-panel/20 backdrop-blur-md px-6 py-5 shadow-2xl relative overflow-hidden">
      {/* Subtle background glow effect */}
      <div className="absolute top-0 right-0 w-32 h-32 bg-alertRed/10 rounded-full blur-[50px] -z-10 mix-blend-screen" />
      
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2 glow-text-alert">
            <span className="w-2 h-2 rounded-full bg-alertRed status-dot shadow-[0_0_8px_#E8544B]" />
            <span className="text-xs font-mono tracking-widest text-alertRed">
              {incident.severity}
            </span>
          </div>

          <p className="text-mist text-sm mb-3">{incident.description}</p>

          <div className="flex items-center gap-2 text-xs font-mono text-mist/50">
            {incident.related_events && incident.related_events.map((event, i) => (
              <span key={event} className="flex items-center gap-2">
                {event}
                {i < incident.related_events.length - 1 && (
                  <span className="text-mist/30">→</span>
                )}
              </span>
            ))}
          </div>
        </div>

        <div className="flex flex-col items-end gap-3">
          <span className="text-xs font-mono text-mist/50">
            CONFIDENCE {Math.round(incident.confidence * 100)}%
          </span>
          <button
            onClick={() => onInvestigate?.({ ...incident, id: incident.db_id })}
            className="text-xs font-mono tracking-widest text-void bg-alertRed px-5 py-2.5 rounded-sm hover:opacity-90 transition-all glow-box-alert font-bold"
          >
            INVESTIGATE
          </button>
        </div>
      </div>
    </div>
  );
}

export default CorrelationPanel;