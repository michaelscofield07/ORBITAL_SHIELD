import { useState } from "react";
import ThreatSeverityPanel from "./components/threatseveritypanel";
import SecurityEventsList from "./components/securityeventlist";
import LiveTelemetryChart from "./components/Livetelemetrychart";
import CorrelationPanel from "./components/CorrelationPanel";
import IncidentDetailModal from "./components/incidentdetailmodel";
import "./styles/index.css";

function App() {
  const [selectedIncident, setSelectedIncident] = useState(null);

  return (
    <div className="min-h-screen bg-void text-mist font-body">
      {/* Top bar */}
      <header className="flex items-center justify-between px-6 py-4 border-b hairline bg-panel/30 backdrop-blur-xl sticky top-0 z-10 shadow-lg">
        <h1 className="font-display text-lg tracking-wide text-mist drop-shadow-md">
          ORBITAL SHIELD
        </h1>
        <div className="flex items-center gap-2 text-xs font-mono text-signal glow-text-signal">
          <span className="w-2 h-2 rounded-full bg-signal status-dot shadow-[0_0_8px_#4FD1C5]" />
          LIVE
        </div>
      </header>

      {/* Stat strip */}
      <section className="grid grid-cols-4 border-b hairline bg-panel/10 backdrop-blur-sm">
        {[
          { label: "SATELLITES", value: "24" },
          { label: "THREATS", value: "07" },
          { label: "INCIDENTS", value: "03" },
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

      <IncidentDetailModal
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
      />
    </div>
  );
}

export default App;