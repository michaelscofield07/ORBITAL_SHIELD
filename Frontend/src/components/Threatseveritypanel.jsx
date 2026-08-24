const SEVERITY_LEVELS = [
  { label: "CRITICAL", count: 2, color: "#E8544B" },
  { label: "HIGH", count: 3, color: "#E8544B" },
  { label: "MEDIUM", count: 2, color: "#E8A33D" },
  { label: "LOW", count: 5, color: "#4FD1C5" },
];

function ThreatSeverityPanel() {
  const maxCount = Math.max(...SEVERITY_LEVELS.map((s) => s.count));

  return (
    <div className="flex flex-col gap-3">
      {SEVERITY_LEVELS.map((level) => (
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