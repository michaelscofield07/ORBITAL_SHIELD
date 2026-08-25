import { useState } from "react";

async function submitReview(eventId, status, reviewedBy = "admin_user") {
  const response = await fetch(
    `http://127.0.0.1:8001/audit/${eventId}/review?status=${status}&reviewed_by=${reviewedBy}`,
    { method: "POST" }
  );
  if (!response.ok) throw new Error("Review update failed");
  return response.json();
}

function IncidentDetailModal({ incident, onClose }) {
  const [status, setStatus] = useState("OPEN");
  const [loading, setLoading] = useState(false);

  if (!incident) return null;

  const timeline = [
    { label: "Suspicious Login", detail: "Operator login at unusual time", source: "ACCESS" },
    { label: "Unauthorized Command", detail: "Command outside operator's role", source: "UPLINK" },
    { label: "Telemetry Anomaly", detail: "Unexpected thermal increase detected", source: "DOWNLINK" },
    { label: "Correlation", detail: `Confidence ${Math.round(incident.confidence * 100)}%`, source: "ML_BRAIN" },
  ];

  const handleReview = async (newStatus) => {
    setLoading(true);
    try {
      await submitReview(incident.id, newStatus);
      setStatus(newStatus);
    } catch (err) {
      console.error(err);
      alert("Failed to update review status");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 bg-void/80 flex items-center justify-center z-50 px-6"
      onClick={onClose}
    >
      <div
        className="bg-panel border hairline rounded-sm max-w-2xl w-full p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="w-2 h-2 rounded-full bg-alertRed" />
              <span className="text-xs font-mono tracking-widest text-alertRed">
                {incident.severity}
              </span>
              <span className="text-xs font-mono text-mist/40">{incident.id}</span>
              <span className="text-xs font-mono text-mist/40 ml-2">
                [{status}]
              </span>
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
                <span className="w-2 h-2 rounded-full bg-signal" />
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
            RECOMMENDED ACTION: HUMAN_REVIEW
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => handleReview("INVESTIGATING")}
              disabled={loading}
              className="text-xs font-mono tracking-widest text-mist border hairline px-4 py-2 rounded-sm hover:bg-mist/5 transition-colors disabled:opacity-50"
            >
              MARK INVESTIGATING
            </button>
            <button
              onClick={() => handleReview("RESOLVED")}
              disabled={loading}
              className="text-xs font-mono tracking-widest text-void bg-signal px-4 py-2 rounded-sm hover:opacity-90 transition-opacity disabled:opacity-50"
            >
              MARK RESOLVED
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default IncidentDetailModal;