import { useState, useEffect } from "react";
import ThreatSeverityPanel from "./components/Threatseveritypanel";
import SecurityEventsList from "./components/SecurityEventsList";
import LiveTelemetryChart from "./components/Livetelemetrychart";
import CorrelationPanel from "./components/CorrelationPanel";
import IncidentDetailModal from "./components/IncidentDetailModal";
import ModuleHealthStrip from "./components/ModuleHealthStrip";
import { fetchEvents } from "./api/auditclient";
import { triggerRetrain } from "./api/mlbrainclient";
import ScenarioControl from "./pages/ScenarioControl";
import "./styles/index.css";

// Simple in-memory role state — in a real deployment this would be JWT-based.
// For the jury demo, toggle via the CISO button in the header.
const ROLES = ["SOC_ANALYST", "CISO"];

function App() {
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [activeTab, setActiveTab] = useState("SOC DASHBOARD");
  const [role, setRole] = useState("SOC_ANALYST");

  const [threats, setThreats] = useState("00");
  const [incidents, setIncidents] = useState("00");

  // Retrain state
  const [retraining, setRetraining] = useState(false);
  const [retrainResult, setRetrainResult] = useState(null);
  const [retrainError, setRetrainError] = useState(null);

  useEffect(() => {
    const updateStats = () => {
      fetchEvents()
        .then((records) => {
          let tCount = 0;
          let iCount = 0;
          records.forEach((rec) => {
            const ev = rec.event_json;
            if (ev.severity === "HIGH" || ev.severity === "CRITICAL") tCount++;
            if (ev.source === "ML_BRAIN") iCount++;
          });
          setThreats(tCount.toString().padStart(2, "0"));
          setIncidents(iCount.toString().padStart(2, "0"));
        })
        .catch(console.error);
    };

    updateStats();
    const interval = setInterval(updateStats, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleRetrain = async () => {
    setRetraining(true);
    setRetrainResult(null);
    setRetrainError(null);
    try {
      const result = await triggerRetrain();
      setRetrainResult(result);
    } catch (err) {
      setRetrainError(err.message || "Retrain failed");
    } finally {
      setRetraining(false);
    }
  };

  return (
    <div className="min-h-screen bg-void text-mist font-body flex flex-col">
      {/* Top bar */}
      <header className="flex items-center justify-between px-6 py-4 border-b hairline bg-panel/30 backdrop-blur-xl sticky top-0 z-20 shadow-lg">
        <div className="flex items-center gap-8">
          <h1 className="font-display text-lg tracking-wide text-mist drop-shadow-md">
            ORBITAL SHIELD
          </h1>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-1 bg-void/50 p-1 rounded-sm border hairline">
            {["SOC DASHBOARD", "SCENARIO CONTROL"].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-1.5 text-xs font-mono tracking-widest rounded-sm transition-colors ${
                  activeTab === tab
                    ? "bg-signal text-void font-bold shadow-[0_0_10px_rgba(79,209,197,0.3)]"
                    : "text-mist/60 hover:text-mist hover:bg-panel"
                }`}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>

        <div className="flex items-center gap-4">
          {/* Role toggle */}
          <button
            id="role-toggle-btn"
            onClick={() => setRole((r) => (r === "SOC_ANALYST" ? "CISO" : "SOC_ANALYST"))}
            className={`text-xs font-mono px-3 py-1 rounded-sm border transition-colors ${
              role === "CISO"
                ? "border-signal text-signal bg-signal/10"
                : "border-mist/20 text-mist/40 hover:border-mist/40"
            }`}
          >
            ROLE: {role}
          </button>

          <div className="flex items-center gap-2 text-xs font-mono text-signal glow-text-signal">
            <span className="w-2 h-2 rounded-full bg-signal status-dot shadow-[0_0_8px_#4FD1C5]" />
            LIVE
          </div>
        </div>
      </header>

      {/* Module health strip — always visible */}
      <ModuleHealthStrip />

      {/* Main Content Area */}
      <main className="flex-1 overflow-auto">
        {activeTab === "SOC DASHBOARD" && (
          <div className="animate-in fade-in duration-500">
            {/* Stat strip */}
            <section className="grid grid-cols-4 border-b hairline bg-panel/10 backdrop-blur-sm">
              {[
                { label: "SATELLITES", value: "24" },
                { label: "THREATS", value: threats },
                { label: "INCIDENTS", value: incidents },
                { label: "COMPLIANCE", value: "94%" },
              ].map((stat) => (
                <div
                  key={stat.label}
                  className="px-6 py-4 border-r hairline last:border-r-0"
                >
                  <div className="font-mono text-2xl text-mist">{stat.value}</div>
                  <div className="text-xs tracking-widest text-mist/60">
                    {stat.label}
                  </div>
                </div>
              ))}
            </section>

            <LiveTelemetryChart />

            {/* Event feed + Severity panel */}
            <section className="grid grid-cols-2">
              <div className="px-6 py-6 border-r hairline">
                <div className="text-xs tracking-widest text-mist/60 mb-3">
                  EVENT FEED
                </div>
                <SecurityEventsList />
              </div>
              <div className="px-6 py-6">
                <div className="text-xs tracking-widest text-mist/60 mb-3">
                  SEVERITY BREAKDOWN
                </div>
                <ThreatSeverityPanel />
              </div>
            </section>

            {/* Correlation alert */}
            <section className="px-6 py-6 border-t hairline">
              <CorrelationPanel onInvestigate={setSelectedIncident} />
            </section>

            {/* CISO retrain panel — only visible when role === CISO */}
            {role === "CISO" && (
              <section className="px-6 py-6 border-t hairline bg-panel/5">
                <div className="text-xs tracking-widest text-mist/60 mb-3">
                  CISO — ML BRAIN RETRAIN CYCLE
                </div>
                <div className="flex items-center gap-4">
                  <button
                    id="retrain-btn"
                    onClick={handleRetrain}
                    disabled={retraining}
                    className="text-xs font-mono tracking-widest text-void bg-signal px-6 py-2.5 rounded-sm hover:opacity-90 transition-opacity disabled:opacity-50"
                  >
                    {retraining ? "RETRAINING…" : "RUN RETRAIN CYCLE"}
                  </button>
                  <span className="text-xs font-mono text-mist/40">
                    Triggers /brain/retrain · updates ML thresholds from CISO feedback
                  </span>
                </div>

                {/* Retrain result display — key jury-facing evidence */}
                {retrainResult && (
                  <div className="mt-4 p-4 rounded-sm border border-signal/40 bg-signal/5">
                    <div className="grid grid-cols-3 gap-4">
                      <div>
                        <div className="text-xs font-mono text-mist/50 mb-1">ML RETRAINED</div>
                        <div
                          className={`font-mono text-lg ${
                            retrainResult.ml_retrained ? "text-signal" : "text-mist/40"
                          }`}
                        >
                          {retrainResult.ml_retrained ? "TRUE ✓" : "FALSE"}
                        </div>
                      </div>
                      <div>
                        <div className="text-xs font-mono text-mist/50 mb-1">ML ACCURACY</div>
                        <div className="font-mono text-lg text-mist">
                          {retrainResult.ml_accuracy != null
                            ? `${(retrainResult.ml_accuracy * 100).toFixed(1)}%`
                            : "N/A"}
                        </div>
                      </div>
                      <div>
                        <div className="text-xs font-mono text-mist/50 mb-1">THRESHOLDS CHANGED</div>
                        <div className="font-mono text-lg text-mist">
                          {Array.isArray(retrainResult.thresholds_changed)
                            ? retrainResult.thresholds_changed.length
                            : 0}
                        </div>
                      </div>
                    </div>
                    {retrainResult.message && (
                      <div className="text-xs font-mono text-mist/50 mt-3 border-t border-signal/20 pt-3">
                        {retrainResult.message}
                      </div>
                    )}
                    {Array.isArray(retrainResult.thresholds_changed) &&
                      retrainResult.thresholds_changed.length > 0 && (
                        <div className="text-xs font-mono text-mist/40 mt-2">
                          {retrainResult.thresholds_changed.map((tc, i) => (
                            <span key={i} className="mr-4">
                              {tc.rule_id}: {tc.old_threshold} → {tc.new_threshold}
                            </span>
                          ))}
                        </div>
                      )}
                  </div>
                )}

                {retrainError && (
                  <div className="mt-4 px-4 py-3 rounded-sm border border-alertRed/40 bg-alertRed/10 text-xs font-mono text-alertRed">
                    Retrain failed: {retrainError}
                  </div>
                )}
              </section>
            )}
          </div>
        )}

        {activeTab === "SCENARIO CONTROL" && (
          <div className="animate-in fade-in duration-500">
            <ScenarioControl />
          </div>
        )}
      </main>

      <IncidentDetailModal
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
      />
    </div>
  );
}

export default App;