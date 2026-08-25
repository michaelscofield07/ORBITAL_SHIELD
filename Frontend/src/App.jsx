import { useState, useEffect } from "react";
import ThreatSeverityPanel from "./components/ThreatSeverityPanel";
import SecurityEventsList from "./components/SecurityEventsList";
import LiveTelemetryChart from "./components/LiveTelemetryChart";
import CorrelationPanel from "./components/CorrelationPanel";
import IncidentDetailModal from "./components/IncidentDetailModal";
import { fetchEvents } from "./api/auditclient";
import ScenarioControl from "./pages/ScenarioControl";
import "./styles/index.css";

function App() {
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [activeTab, setActiveTab] = useState("SOC DASHBOARD");
  
  const [threats, setThreats] = useState("00");
  const [incidents, setIncidents] = useState("00");

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

        <div className="flex items-center gap-2 text-xs font-mono text-signal glow-text-signal">
          <span className="w-2 h-2 rounded-full bg-signal status-dot shadow-[0_0_8px_#4FD1C5]" />
          LIVE
        </div>
      </header>

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

            <LiveTelemetryChart/>

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

            {/* Correlation alert placeholder */}
            <section className="px-6 py-6 border-t hairline">
              <CorrelationPanel onInvestigate={setSelectedIncident} />
            </section>
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