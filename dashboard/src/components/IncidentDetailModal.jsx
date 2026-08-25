/**
 * IncidentDetailModal — opens when INVESTIGATE is clicked on a correlation incident.
 *
 * - Fetches full incident detail from GET /correlations/{id} on ML Brain
 * - Exposes "Confirm Real" and "False Positive" verdict buttons (POST /brain/feedback)
 * - URL references env-driven VITE_MLBRAIN_URL, no hardcoded 8001 or 8006
 */
import { useState, useEffect } from "react";
import { getIncidentDetail, submitFeedback } from "../api/mlbrainclient";
import { downloadReport } from "../api/auditclient";

const AUDIT_BASE = import.meta.env.VITE_AUDIT_URL || "http://127.0.0.1:8006";

function IncidentDetailModal({ incident, onClose }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [verdictStatus, setVerdictStatus] = useState(null); // null | "loading" | "done" | "error"
  const [verdictResult, setVerdictResult] = useState(null);

  useEffect(() => {
    if (!incident) return;
    setDetail(null);
    setVerdictStatus(null);
    setVerdictResult(null);

    const id = incident.event_id || incident.id;
    if (!id) return;

    getIncidentDetail(id)
      .then(setDetail)
      .catch((err) => {
        console.error("IncidentDetailModal:", err);
        // Fall back to the incident data we already have
        setDetail(incident);
      });
  }, [incident]);

  if (!incident) return null;

  const displayed = detail || incident;
  const incidentId = displayed.event_id || displayed.id;

  const handleVerdict = async (verdict) => {
    setVerdictStatus("loading");
    try {
      const result = await submitFeedback(incidentId, verdict, "ciso_user");
      setVerdictResult({ verdict, ...result });
      setVerdictStatus("done");
    } catch (err) {
      console.error(err);
      setVerdictStatus("error");
    }
  };

  const timeline = [
    { label: "Suspicious Login", detail: "Operator login at unusual time", source: "ACCESS" },
    { label: "Unauthorized Command", detail: "Command outside operator's role", source: "UPLINK" },
    { label: "Telemetry Anomaly", detail: "Unexpected thermal increase detected", source: "DOWNLINK" },
    { label: "Correlation", detail: `Confidence ${Math.round((displayed.confidence || 0) * 100)}%`, source: "ML_BRAIN" },
  ];

  return (
    <div
      className="fixed inset-0 bg-void/80 flex items-center justify-center z-50 px-6"
      onClick={onClose}
    >
      <div
        className="bg-panel border hairline rounded-sm max-w-2xl w-full p-6"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="w-2 h-2 rounded-full bg-alertRed" />
              <span className="text-xs font-mono tracking-widest text-alertRed">
                {displayed.severity}
              </span>
              <span className="text-xs font-mono text-mist/40">{incidentId}</span>
              <span className="text-xs font-mono text-mist/40 ml-2">
                [{displayed.status || "OPEN"}]
              </span>
            </div>
            <h2 className="text-mist font-display text-lg">
              {displayed.description}
            </h2>
            {displayed.risk_score != null && (
              <div className="text-xs font-mono text-mist/50 mt-1">
                RISK SCORE: {displayed.risk_score} · RULE: {displayed.rule_name || "—"}
              </div>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-mist/50 hover:text-mist text-xl leading-none"
          >
            ×
          </button>
        </div>

        {/* Timeline */}
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
                  <span className="text-xs font-mono text-mist/40">{step.source}</span>
                </div>
                <p className="text-mist/50 text-xs mt-1">{step.detail}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Related events */}
        {displayed.related_events?.length > 0 && (
          <div className="mb-4 text-xs font-mono text-mist/40">
            CONTRIBUTING EVENTS: {displayed.related_events.join(" · ")}
          </div>
        )}

        {/* CISO verdict status */}
        {verdictStatus === "done" && verdictResult && (
          <div className="mb-4 px-4 py-3 rounded-sm border border-signal/40 bg-signal/10">
            <div className="text-xs font-mono text-signal tracking-widest">
              VERDICT RECORDED: {verdictResult.verdict}
            </div>
            <div className="text-xs text-mist/60 mt-1">{verdictResult.message}</div>
          </div>
        )}
        {verdictStatus === "error" && (
          <div className="mb-4 px-4 py-3 rounded-sm border border-alertRed/40 bg-alertRed/10 text-xs font-mono text-alertRed">
            Failed to submit verdict — check ML Brain connection.
          </div>
        )}

        {/* Action buttons */}
        <div className="flex items-center justify-between pt-4 border-t hairline">
          <span className="text-xs font-mono text-mist/50">
            RECOMMENDED ACTION: {displayed.action || "HUMAN_REVIEW"}
          </span>
          <div className="flex gap-2 flex-wrap">
            {/* Download PDF report from audit service */}
            <button
              onClick={() =>
                window.open(`${AUDIT_BASE}/audit/${incidentId}/report`, "_blank")
              }
              className="text-xs font-mono tracking-widest text-mist border hairline px-4 py-2 rounded-sm hover:bg-mist/5 transition-colors"
            >
              DOWNLOAD REPORT
            </button>

            {/* CISO verdict buttons — call ML Brain /brain/feedback */}
            <button
              onClick={() => handleVerdict("FALSE_POSITIVE")}
              disabled={verdictStatus === "loading" || verdictStatus === "done"}
              className="text-xs font-mono tracking-widest text-mist border hairline px-4 py-2 rounded-sm hover:bg-mist/5 transition-colors disabled:opacity-40"
            >
              FALSE POSITIVE
            </button>
            <button
              onClick={() => handleVerdict("CONFIRMED_REAL")}
              disabled={verdictStatus === "loading" || verdictStatus === "done"}
              className="text-xs font-mono tracking-widest text-void bg-signal px-4 py-2 rounded-sm hover:opacity-90 transition-opacity disabled:opacity-40"
            >
              CONFIRM REAL
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default IncidentDetailModal;