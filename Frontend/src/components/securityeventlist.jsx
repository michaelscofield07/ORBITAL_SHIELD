import { useState, useEffect } from "react";

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#E8544B", label: "🔴" },
  HIGH: { color: "#E8544B", label: "🔴" },
  MEDIUM: { color: "#E8A33D", label: "🟠" },
  LOW: { color: "#4FD1C5", label: "🟢" },
};

import { fetchEvents } from "../api/auditclient";

function SecurityEventsList() {
  const [events, setEvents] = useState([]);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetchEvents()
      .then(setEvents)
      .catch((err) => {
        console.error(err);
        setError(true);
      });
  }, []);

  if (error) {
    return <div className="text-mist/50 text-xs font-mono py-2">[ unable to load events ]</div>;
  }

  return (
    <div className="flex flex-col gap-2">
      {events.map((dbRecord) => {
        const event = dbRecord.event_json;
        const config = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.LOW;
        const timeFormatted = new Date(event.timestamp).toLocaleTimeString("en-US", { hour12: false });
        return (
          <div
            key={dbRecord.event_id}
            className="flex items-center justify-between text-sm py-2 border-b hairline last:border-b-0 hover:bg-mist/5 transition-colors cursor-default rounded-sm px-2 -mx-2"
          >
            <div className="flex items-center gap-3">
              <span
                className="w-2 h-2 rounded-full shadow-[0_0_8px_currentColor]"
                style={{ backgroundColor: config.color }}
              />
              <span className="text-mist">{event.event_type.replace(/_/g, " ")}</span>
            </div>
            <div className="flex items-center gap-4 text-mist/50 font-mono text-xs">
              <span>{event.source}</span>
              <span>{timeFormatted}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default SecurityEventsList;