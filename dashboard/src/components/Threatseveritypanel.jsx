import { useState, useEffect } from "react";
import { fetchEvents } from "../api/auditclient";

const SEVERITY_COLORS = {
  CRITICAL: "#E8544B",
  HIGH: "#E8544B",
  MEDIUM: "#E8A33D",
  LOW: "#4FD1C5",
};

function ThreatSeverityPanel() {
  const [counts, setCounts] = useState({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  const [error, setError] = useState(false);

  useEffect(() => {
    const loadSeverities = () => {
      fetchEvents()
        .then((records) => {
          const newCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
          records.forEach((rec) => {
            const sev = rec.event_json.severity;
            if (newCounts[sev] !== undefined) {
              newCounts[sev]++;
            }
          });
          setCounts(newCounts);
        })
        .catch((err) => {
          console.error(err);
          setError(true);
        });
    };

    loadSeverities();
    const interval = setInterval(loadSeverities, 5000);
    return () => clearInterval(interval);
  }, []);

  if (error) {
    return <div className="text-mist/50 text-xs font-mono py-2">[ unable to load severities ]</div>;
  }

  const levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((label) => ({
    label,
    count: counts[label],
    color: SEVERITY_COLORS[label],
  }));

  const maxCount = Math.max(...levels.map((s) => s.count), 1);

  return (
    <div className="flex flex-col gap-3">
      {levels.map((level) => (
        <div key={level.label} className="flex items-center gap-3 group">
          <span className="text-xs font-mono text-mist/60 w-16 group-hover:text-mist transition-colors">
            {level.label}
          </span>
          <div className="flex-1 h-2 bg-panel/50 rounded-sm overflow-hidden border hairline shadow-inner">
            <div
              className="h-full rounded-sm shadow-[0_0_10px_currentColor]"
              style={{
                width: `${(level.count / maxCount) * 100}%`,
                backgroundColor: level.color,
              }}
            />
          </div>
          <span className="text-sm font-mono text-mist w-6 text-right">
            {level.count}
          </span>
        </div>
      ))}
    </div>
  );
}

export default ThreatSeverityPanel;