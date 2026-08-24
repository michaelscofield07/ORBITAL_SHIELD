function IncidentDetailModal({ incident, onClose }) {
  if (!incident) return null;

  const timeline = [
    { label: "Suspicious Login", detail: "Operator login at unusual time", source: "ACCESS" },
    { label: "Unauthorized Command", detail: "Command outside operator's role", source: "UPLINK" },
    { label: "Telemetry Anomaly", detail: "Unexpected thermal increase detected", source: "DOWNLINK" },
    { label: "Correlation", detail: `Confidence ${Math.round(incident.confidence * 100)}%`, source: "ML_BRAIN" },
  ];

  return (
    <div
      className="fixed inset-0 bg-void/60 backdrop-blur-md flex items-center justify-center z-50 px-6 transition-all"
      onClick={onClose}
    >
      <div
        className="bg-panel/60 backdrop-blur-2xl border hairline rounded-md max-w-2xl w-full p-6 shadow-[0_0_40px_rgba(232,84,75,0.1)] relative overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="absolute top-0 right-0 w-64 h-64 bg-alertRed/10 rounded-full blur-[80px] -z-10 mix-blend-screen pointer-events-none" />
        
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="flex items-center gap-2 mb-1 glow-text-alert">
              <span className="w-2 h-2 rounded-full bg-alertRed shadow-[0_0_8px_#E8544B]" />
              <span className="text-xs font-mono tracking-widest text-alertRed font-bold">
                {incident.severity}
              </span>
              <span className="text-xs font-mono text-mist/40">{incident.id}</span>
            </div>
            <h2 className="text-mist font-display text-lg">
              {incident.description}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-mist/50 hover:text-mist text-xl leading-none"
          >
            ×
          </button>
        </div>

        <div className="flex flex-col gap-4 mb-6">
          {timeline.map((step, i) => (
            <div key={step.label} className="flex items-start gap-4">
              <div className="flex flex-col items-center">
                <span className="w-2 h-2 rounded-full bg-signal shadow-[0_0_5px_#4FD1C5]" />
                {i < timeline.length - 1 && (
                  <span className="w-px h-8 bg-mist/20 mt-1" />
                )}
              </div>
              <div className="flex-1 -mt-1">
                <div className="flex items-center justify-between">
                  <span className="text-mist text-sm">{step.label}</span>
                  <span className="text-xs font-mono text-mist/40">
                    {step.source}
                  </span>
                </div>
                <p className="text-mist/50 text-xs mt-1">{step.detail}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="flex items-center justify-between pt-4 border-t hairline">
          <span className="text-xs font-mono text-mist/50">
            RECOMMENDED ACTION: {incident.relatedEvents ? "HUMAN_REVIEW" : "MONITOR"}
          </span>
          <div className="flex gap-2">
            <button className="text-xs font-mono tracking-widest text-mist border hairline px-4 py-2 rounded-sm hover:bg-mist/5 transition-colors">
              MARK INVESTIGATING
            </button>
            <button className="text-xs font-mono tracking-widest text-void bg-signal px-4 py-2 rounded-sm hover:opacity-90 transition-opacity">
              MARK RESOLVED
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default IncidentDetailModal;