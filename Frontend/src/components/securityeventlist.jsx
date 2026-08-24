import { useState, useEffect } from "react";

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#E8544B", label: "🔴" },
  HIGH: { color: "#E8544B", label: "🔴" },
  MEDIUM: { color: "#E8A33D", label: "🟠" },
  LOW: { color: "#4FD1C5", label: "🟢" },
};

// Placeholder mock events — replace with real API fetch later
const MOCK_EVENTS = [
  { id: "EVT-401", source: "ACCESS", type: "SUSPICIOUS_LOGIN", severity: "HIGH", time: "14:32:05" },
  { id: "EVT-201", source: "UPLINK", type: "UNAUTHORIZED_COMMAND", severity: "CRITICAL", time: "14:31:58" },
  { id: "EVT-301", source: "FIRMWARE", type: "FIRMWARE_VERIFIED", severity: "LOW", time: "14:30:12" },
  { id: "EVT-100", source: "DOWNLINK", type: "TELEMETRY_ANOMALY", severity: "MEDIUM", time: "14:29:47" },
];

function SecurityEventsList() {
  const [events, setEvents] = useState(MOCK_EVENTS);

  // Later: replace this with a real fetch to GET /audit/events
  useEffect(() => {
    // fetchEvents().then(setEvents);
  }, []);

  return (
    <div className="flex flex-col gap-2">
      {events.map((event) => {
        const config = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.LOW;
        return (
          <div
            key={event.id}
            className="flex items-center justify-between text-sm py-2 border-b hairline last:border-b-0 hover:bg-mist/5 transition-colors cursor-default rounded-sm px-2 -mx-2"
          >
            <div className="flex items-center gap-3">
              <span
                className="w-2 h-2 rounded-full shadow-[0_0_8px_currentColor]"
                style={{ backgroundColor: config.color }}
              />
              <span className="text-mist">{event.type.replace(/_/g, " ")}</span>
            </div>
            <div className="flex items-center gap-4 text-mist/50 font-mono text-xs">
              <span>{event.source}</span>
              <span>{event.time}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default SecurityEventsList;